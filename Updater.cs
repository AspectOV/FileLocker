using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Windows;


namespace FileLocker
{
    public class Updater
    {
        private const string GITHUB_API_URL = "https://api.github.com/repos/AspectOV/FileLocker/releases/latest";
        private readonly HttpClient httpClient;
        private readonly Version currentVersion;

        private GitHubRelease? latestRelease;

        public Updater()
        {
            httpClient = new HttpClient();
            httpClient.Timeout = TimeSpan.FromSeconds(15);
            httpClient.DefaultRequestHeaders.Add("User-Agent", "FileLocker-Updater");
            httpClient.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");
            httpClient.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
            currentVersion = GetCurrentVersion();
        }

        public async Task CheckForUpdatesAsync(bool silent = false)
        {
            try
            {
                latestRelease = await FetchLatestReleaseAsync(!silent);
                if (latestRelease == null)
                {
                    return;
                }

                var latestVersion = ParseVersion(latestRelease.TagName);
                if (latestVersion == null)
                {
                    if (!silent)
                    {
                        await ShowErrorDialogAsync("Unable to read version information from the latest release.");
                    }
                    return;
                }

                if (IsNewVersionAvailable(latestVersion))
                {
                    if (!silent)
                    {
                        var result = await ShowUpdateDialogAsync(latestVersion);
                        if (result)
                        {
                            await DownloadAndInstallUpdateAsync();
                        }
                    }
                }
                else if (!silent)
                {
                    await ShowNoUpdateDialogAsync();
                }
            }
            catch (Exception ex)
            {
                if (!silent)
                {
                    await ShowErrorDialogAsync($"Error checking for updates: {ex.Message}");
                }
            }
        }

        // Replace all instances of 'if (xamlRoot == null)' with 'if (xamlRoot is null)'
        // and 'if (xamlRoot != null)' with 'if (xamlRoot is not null)'

        // Example fix for all relevant methods:

        private Task<bool> ShowUpdateDialogAsync(Version latestVersion)
        {
            var result = MessageBox.Show(
                $"A new version ({latestVersion}) is available. Current version: {currentVersion}\n\nWould you like to download it now?",
                "Update Available",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            return Task.FromResult(result == MessageBoxResult.Yes);
        }

        private Task ShowNoUpdateDialogAsync()
        {
            MessageBox.Show("You are running the latest version.", "No Updates Available", MessageBoxButton.OK, MessageBoxImage.Information);
            return Task.CompletedTask;
        }

        private Task ShowErrorDialogAsync(string message)
        {
            MessageBox.Show(message, "Update Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return Task.CompletedTask;
        }

        private bool IsNewVersionAvailable(Version latestVersion)
        {
            return latestVersion > currentVersion;
        }

        private static Version GetCurrentVersion()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var informationalVersion = assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion;

            if (TryParseSanitizedVersion(informationalVersion, out var parsed))
            {
                return parsed;
            }

            if (assembly.GetName().Version is Version assemblyVersion)
            {
                return assemblyVersion;
            }

            return new Version(1, 0, 2);
        }

        private static bool TryParseSanitizedVersion(string? versionString, out Version parsedVersion)
        {
            if (!string.IsNullOrWhiteSpace(versionString))
            {
                var sanitized = versionString.Split('+', '-')[0].Trim().TrimStart('v', 'V');
                if (Version.TryParse(sanitized, out parsedVersion))
                {
                    return true;
                }
            }

            parsedVersion = default!;
            return false;
        }

        private async Task DownloadAndInstallUpdateAsync()
        {
            try
            {
                if (latestRelease == null)
                {
                    await ShowErrorDialogAsync("The updater has no release details to download. Please check again.");
                    return;
                }

                var downloadUrl = GetDownloadUrl(latestRelease);
                if (string.IsNullOrEmpty(downloadUrl))
                {
                    await ShowErrorDialogAsync("Could not find update installer download URL.");
                    return;
                }

                var tempPath = Path.Combine(Path.GetTempPath(), "FileLockerUpdate.exe");

                using (var response = await httpClient.GetStreamAsync(downloadUrl))
                using (var fileStream = File.Create(tempPath))
                {
                    await response.CopyToAsync(fileStream);
                }

                if (!VerifyFile(tempPath))
                {
                    await ShowErrorDialogAsync("The downloaded update could not be verified. Please download manually from my website, https://www.jeremymhayes.com");
                    return;
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = tempPath,
                    UseShellExecute = true
                });

                Application.Current.Exit();
            }
            catch (Exception ex)
            {
                await ShowErrorDialogAsync($"Error downloading update: {ex.Message}\nPlease download manually from my website, https://www.jeremymhayes.com");
            }
        }

        private async Task<GitHubRelease?> FetchLatestReleaseAsync(bool showErrors)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, GITHUB_API_URL);
                using var response = await httpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    throw new HttpRequestException($"GitHub API returned status {response.StatusCode}");
                }

                var content = await response.Content.ReadAsStringAsync();
                if (string.IsNullOrWhiteSpace(content))
                {
                    throw new InvalidOperationException("GitHub returned an empty response.");
                }

                return JsonSerializer.Deserialize<GitHubRelease>(content, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
            }
            catch (Exception ex)
            {
                if (showErrors)
                {
                    await ShowErrorDialogAsync($"Update check failed: {ex.Message}");
                }
                return null;
            }
        }

        private static string? GetDownloadUrl(GitHubRelease release)
        {
            var installerAsset = release.Assets?
                .OrderByDescending(static a => GetInstallerPriority(a.Name))
                .FirstOrDefault();

            return installerAsset?.BrowserDownloadUrl;
        }

        private static int GetInstallerPriority(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return int.MinValue;

            if (name.EndsWith(".msix", StringComparison.OrdinalIgnoreCase)) return 3;
            if (name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)) return 2;
            if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return 1;
            return 0;
        }

        private static Version? ParseVersion(string? tagName)
        {
            if (string.IsNullOrWhiteSpace(tagName)) return null;

            var sanitized = tagName.Trim().TrimStart('v', 'V');
            return Version.TryParse(sanitized, out var version) ? version : null;
        }

        private bool VerifyFile(string filePath)
        {
            try
            {
                // Simple check if file exists
                // Ideally i should verify hash/signature here
                return File.Exists(filePath);
            }
            catch
            {
                return false;
            }
        }

        private class GitHubRelease
        {
            [JsonPropertyName("tag_name")]
            public string? TagName { get; set; }

            [JsonPropertyName("assets")]
            public Asset[]? Assets { get; set; }

            [JsonPropertyName("name")]
            public string? Name { get; set; }

            [JsonPropertyName("body")]
            public string? Body { get; set; }

            [JsonPropertyName("prerelease")]
            public bool Prerelease { get; set; }

            [JsonPropertyName("published_at")]
            public DateTime PublishedAt { get; set; }
        }

        private class Asset
        {
            [JsonPropertyName("name")]
            public string? Name { get; set; }

            [JsonPropertyName("browser_download_url")]
            public string? BrowserDownloadUrl { get; set; }
        }
    }
}
