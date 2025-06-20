using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Linq;
using System.Windows;

namespace FileLocker
{
    public class Updater
    {
        private const string GITHUB_API_URL = "https://api.github.com/repos/AspectOV/FileLocker/releases/latest";
        private readonly HttpClient httpClient;
        private readonly string currentVersion;

        public Updater()
        {
            httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("User-Agent", "FileLocker-Updater");
            // Get version from the assembly, which is set in FileLocker.csproj
            currentVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0.4";
        }

        public async Task CheckForUpdatesAsync(bool silent = false)
        {
            try
            {
                var latestVersion = await GetLatestVersionAsync();
                if (latestVersion == null) return;

                if (IsNewVersionAvailable(latestVersion))
                {
                    if (!silent)
                    {
                        var result = MessageBox.Show(
                            $"A new version ({latestVersion}) is available. Current version: {currentVersion}\n\nWould you like to download it now?",
                            "Update Available",
                            MessageBoxButton.YesNo,
                            MessageBoxImage.Information
                        );

                        if (result == MessageBoxResult.Yes)
                        {
                            await DownloadAndInstallUpdateAsync();
                        }
                    }
                }
                else if (!silent)
                {
                    MessageBox.Show(
                        "You are running the latest version.",
                        "No Updates Available",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information
                    );
                }
            }
            catch (Exception ex)
            {
                if (!silent)
                {
                    MessageBox.Show(
                        $"Error checking for updates: {ex.Message}",
                        "Update Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error
                    );
                }
            }
        }

        private async Task<string> GetLatestVersionAsync()
        {
            try
            {
                var response = await httpClient.GetStringAsync(GITHUB_API_URL);
                var releaseInfo = JsonSerializer.Deserialize<GitHubRelease>(response, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                return releaseInfo?.TagName?.TrimStart('v');
            }
            catch
            {
                return null;
            }
        }

        private bool IsNewVersionAvailable(string latestVersion)
        {
            if (string.IsNullOrEmpty(latestVersion)) return false;

            var current = Version.Parse(currentVersion);
            var latest = Version.Parse(latestVersion);

            return latest > current;
        }

        private async Task DownloadAndInstallUpdateAsync()
        {
            try
            {
                var downloadUrl = await GetDownloadUrlAsync();
                if (string.IsNullOrEmpty(downloadUrl))
                {
                    MessageBox.Show("Could not find update installer download URL.");
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
                    MessageBox.Show("The downloaded update could not be verified. Please download manually from my website, https://www.jeremymhayes.com");
                    return;
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = tempPath,
                    UseShellExecute = true
                });

                Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error downloading update: {ex.Message}\nPlease download manually from my website, https://www.jeremymhayes.com");
            }
        }

        private async Task<string> GetDownloadUrlAsync()
        {
            try
            {
                var response = await httpClient.GetStringAsync(GITHUB_API_URL);
                var releaseInfo = JsonSerializer.Deserialize<GitHubRelease>(response, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                // Find the first asset with an .exe file extension
                var installerAsset = releaseInfo?.Assets?.FirstOrDefault(a => a.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
                return installerAsset?.BrowserDownloadUrl;
            }
            catch
            {
                return null;
            }
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
            public string? TagName { get; set; }
            public Asset[]? Assets { get; set; }
            public string? Name { get; set; }
            public string? Body { get; set; }
            public bool Prerelease { get; set; }
            public DateTime PublishedAt { get; set; }
        }

        private class Asset
        {
            public string? Name { get; set; }
            public string? BrowserDownloadUrl { get; set; }
        }
    }
} 