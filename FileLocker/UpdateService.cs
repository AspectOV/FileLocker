using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace FileLocker;

internal static class UpdateService
{
    private const string Owner = "AspectOV";
    private const string Repo = "FileLocker";
    private const string GitHubApiVersion = "2022-11-28";
    private static readonly Uri LatestReleaseUri = new($"https://api.github.com/repos/{Owner}/{Repo}/releases/latest");
    private static readonly HttpClient HttpClient = CreateHttpClient();
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    internal static TimeSpan AutomaticCheckInterval => TimeSpan.FromHours(24);
    internal static string GitHubRepositoryUrl => $"https://github.com/{Owner}/{Repo}";

    internal static UpdateSettings LoadSettings()
    {
        string path = GetSettingsPath();
        if (!File.Exists(path))
        {
            return new UpdateSettings();
        }

        try
        {
            return JsonSerializer.Deserialize<UpdateSettings>(File.ReadAllText(path), JsonOptions) ?? new UpdateSettings();
        }
        catch
        {
            return new UpdateSettings();
        }
    }

    internal static void SaveSettings(UpdateSettings settings)
    {
        Directory.CreateDirectory(GetUpdaterDataDirectory());
        string json = JsonSerializer.Serialize(settings, JsonOptions);
        File.WriteAllText(GetSettingsPath(), json);
    }

    internal static bool ShouldPerformAutomaticCheck(UpdateSettings settings, DateTimeOffset utcNow)
    {
        if (!settings.AutoCheckEnabled)
        {
            return false;
        }

        return !settings.LastCheckedUtc.HasValue || utcNow - settings.LastCheckedUtc.Value >= AutomaticCheckInterval;
    }

    internal static string GetCurrentVersionLabel() => FormatVersion(GetCurrentVersion());

    internal static Version GetCurrentVersion()
    {
        string? fileVersion = FileVersionInfo.GetVersionInfo(Environment.ProcessPath ?? string.Empty).FileVersion;
        return TryParseVersion(fileVersion, out Version version)
            ? version
            : new Version(0, 0, 0, 0);
    }

    internal static async Task<UpdateCheckResult> CheckForUpdatesAsync(CancellationToken cancellationToken)
    {
        Version currentVersion = GetCurrentVersion();

        using var request = new HttpRequestMessage(HttpMethod.Get, LatestReleaseUri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        request.Headers.Add("X-GitHub-Api-Version", GitHubApiVersion);

        using HttpResponseMessage response = await HttpClient.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return new UpdateCheckResult(
                currentVersion,
                null,
                false,
                "No GitHub releases are published yet.");
        }

        response.EnsureSuccessStatusCode();

        await using Stream contentStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        GitHubReleaseResponse? release = await JsonSerializer.DeserializeAsync<GitHubReleaseResponse>(
            contentStream,
            JsonOptions,
            cancellationToken);

        if (release == null)
        {
            throw new InvalidOperationException("GitHub returned an empty release payload.");
        }

        if (!TryCreateReleaseInfo(release, out UpdateReleaseInfo update, out string failureReason))
        {
            return new UpdateCheckResult(currentVersion, null, false, failureReason);
        }

        bool isUpdateAvailable = update.Version > currentVersion;
        string message = isUpdateAvailable
            ? $"Update available: {update.DisplayVersion}"
            : $"Up to date ({FormatVersion(currentVersion)})";

        return new UpdateCheckResult(currentVersion, update, isUpdateAvailable, message);
    }

    internal static async Task<string> DownloadInstallerAsync(
        UpdateReleaseInfo release,
        CancellationToken cancellationToken)
    {
        string downloadDirectory = GetDownloadsDirectory();
        Directory.CreateDirectory(downloadDirectory);

        string installerPath = Path.Combine(downloadDirectory, release.InstallerFileName);
        string tempPath = installerPath + ".download";

        if (File.Exists(installerPath) && await VerifyDigestAsync(installerPath, release.Sha256DigestHex, cancellationToken))
        {
            return installerPath;
        }

        if (File.Exists(tempPath))
        {
            File.Delete(tempPath);
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, release.InstallerDownloadUrl);
        using HttpResponseMessage response = await HttpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        response.EnsureSuccessStatusCode();

        await using (Stream httpStream = await response.Content.ReadAsStreamAsync(cancellationToken))
        await using (FileStream outputStream = new(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            await httpStream.CopyToAsync(outputStream, cancellationToken);
        }

        if (!await VerifyDigestAsync(tempPath, release.Sha256DigestHex, cancellationToken))
        {
            File.Delete(tempPath);
            throw new InvalidOperationException("The downloaded installer did not match the SHA-256 digest published on GitHub.");
        }

        File.Move(tempPath, installerPath, overwrite: true);
        CleanupOlderInstallers(downloadDirectory, installerPath);
        return installerPath;
    }

    private static async Task<bool> VerifyDigestAsync(string filePath, string? expectedSha256Hex, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(expectedSha256Hex))
        {
            return File.Exists(filePath);
        }

        await using FileStream stream = File.OpenRead(filePath);
        byte[] digest = await SHA256.HashDataAsync(stream, cancellationToken);
        string actual = Convert.ToHexString(digest);
        return string.Equals(actual, expectedSha256Hex, StringComparison.OrdinalIgnoreCase);
    }

    private static void CleanupOlderInstallers(string downloadDirectory, string currentInstallerPath)
    {
        foreach (string file in Directory.EnumerateFiles(downloadDirectory, "*.exe"))
        {
            if (!string.Equals(file, currentInstallerPath, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    File.Delete(file);
                }
                catch
                {
                    // ignore cleanup issues
                }
            }
        }
    }

    private static bool TryCreateReleaseInfo(
        GitHubReleaseResponse release,
        out UpdateReleaseInfo update,
        out string failureReason)
    {
        update = null!;

        if (!TryParseVersion(release.TagName, out Version version))
        {
            failureReason = $"The latest GitHub release tag '{release.TagName}' is not a supported version format.";
            return false;
        }

        GitHubReleaseAsset? installerAsset = release.Assets
            .Where(asset =>
                string.Equals(asset.State, "uploaded", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(asset.BrowserDownloadUrl) &&
                asset.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(asset => asset.Name.Contains("setup", StringComparison.OrdinalIgnoreCase))
            .ThenBy(asset => asset.Name, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();

        if (installerAsset == null)
        {
            failureReason = "The latest GitHub release does not contain an uploaded .exe installer asset.";
            return false;
        }

        string? sha256 = null;
        if (!string.IsNullOrWhiteSpace(installerAsset.Digest) &&
            installerAsset.Digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
        {
            sha256 = installerAsset.Digest["sha256:".Length..];
        }

        update = new UpdateReleaseInfo(
            version,
            FormatVersion(version),
            release.TagName,
            release.HtmlUrl,
            release.Body ?? string.Empty,
            installerAsset.Name,
            installerAsset.BrowserDownloadUrl,
            sha256);

        failureReason = string.Empty;
        return true;
    }

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient();
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("FileLocker", "1.0"));
        return client;
    }

    private static bool TryParseVersion(string? rawVersion, out Version version)
    {
        version = new Version(0, 0, 0, 0);
        if (string.IsNullOrWhiteSpace(rawVersion))
        {
            return false;
        }

        string normalized = rawVersion.Trim();
        if (normalized.StartsWith("v", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[1..];
        }

        int suffixIndex = normalized.IndexOfAny(['-', '+']);
        if (suffixIndex >= 0)
        {
            normalized = normalized[..suffixIndex];
        }

        string[] parts = normalized
            .Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (parts.Length is < 2 or > 4)
        {
            return false;
        }

        int[] values = [0, 0, 0, 0];
        for (int i = 0; i < parts.Length; i++)
        {
            if (!int.TryParse(parts[i], out values[i]) || values[i] < 0)
            {
                return false;
            }
        }

        version = new Version(values[0], values[1], values[2], values[3]);
        return true;
    }

    private static string FormatVersion(Version version)
    {
        if (version.Revision > 0)
        {
            return $"{version.Major}.{version.Minor}.{version.Build}.{version.Revision}";
        }

        if (version.Build > 0)
        {
            return $"{version.Major}.{version.Minor}.{version.Build}";
        }

        return $"{version.Major}.{version.Minor}";
    }

    private static string GetUpdaterDataDirectory()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FileLocker",
            "Updater");
    }

    private static string GetDownloadsDirectory() => Path.Combine(GetUpdaterDataDirectory(), "Downloads");

    private static string GetSettingsPath() => Path.Combine(GetUpdaterDataDirectory(), "settings.json");

    private sealed class GitHubReleaseResponse
    {
        [JsonPropertyName("tag_name")]
        public string TagName { get; set; } = string.Empty;

        [JsonPropertyName("html_url")]
        public string HtmlUrl { get; set; } = string.Empty;

        [JsonPropertyName("body")]
        public string? Body { get; set; }

        [JsonPropertyName("assets")]
        public GitHubReleaseAsset[] Assets { get; set; } = [];
    }

    private sealed class GitHubReleaseAsset
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("browser_download_url")]
        public string BrowserDownloadUrl { get; set; } = string.Empty;

        [JsonPropertyName("state")]
        public string State { get; set; } = string.Empty;

        [JsonPropertyName("digest")]
        public string? Digest { get; set; }
    }
}

internal sealed record UpdateCheckResult(
    Version CurrentVersion,
    UpdateReleaseInfo? Release,
    bool IsUpdateAvailable,
    string StatusMessage);

internal sealed record UpdateReleaseInfo(
    Version Version,
    string DisplayVersion,
    string TagName,
    string HtmlUrl,
    string Notes,
    string InstallerFileName,
    string InstallerDownloadUrl,
    string? Sha256DigestHex);

internal sealed class UpdateSettings
{
    public bool AutoCheckEnabled { get; set; } = true;
    public DateTimeOffset? LastCheckedUtc { get; set; }
    public string? SkippedVersion { get; set; }
}
