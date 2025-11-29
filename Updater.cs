using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace FileLocker
{
    public class Updater
    {
        private const string GITHUB_API_URL = "https://api.github.com/repos/AspectOV/FileLocker/releases/latest";
        private readonly HttpClient httpClient;
        private readonly string currentVersion;
        private XamlRoot? xamlRoot;

        public Updater()
        {
            httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("User-Agent", "FileLocker-Updater");
            // Get version from the assembly, which is set in FileLocker.csproj
            currentVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.2";
        }

        public void SetXamlRoot(XamlRoot root)
        {
            xamlRoot = root;
        }

        public async Task CheckForUpdatesAsync(bool silent = false)
        {
            try
            {
                var latestVersion = await GetLatestVersionAsync();
                if (latestVersion == null)
                {
                    if (!silent)
                    {
                        await ShowErrorDialogAsync("Could not check for updates. Please check your internet connection and try again.");
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

        private async Task<bool> ShowUpdateDialogAsync(string latestVersion)
        {
            if (xamlRoot == null) return false;

            var dialog = new ContentDialog
            {
                Title = "Update Available",
                Content = $"A new version ({latestVersion}) is available. Current version: {currentVersion}\n\nWould you like to download it now?",
                PrimaryButtonText = "Yes",
                SecondaryButtonText = "No",
                XamlRoot = xamlRoot
            };

            var result = await dialog.ShowAsync();
            return result == ContentDialogResult.Primary;
        }

        private async Task ShowNoUpdateDialogAsync()
        {
            if (xamlRoot == null) return;

            var dialog = new ContentDialog
            {
                Title = "No Updates Available",
                Content = "You are running the latest version.",
                PrimaryButtonText = "OK",
                XamlRoot = xamlRoot
            };

            await dialog.ShowAsync();
        }

        private async Task ShowErrorDialogAsync(string message)
        {
            if (xamlRoot == null) return;

            var dialog = new ContentDialog
            {
                Title = "Update Error",
                Content = message,
                PrimaryButtonText = "OK",
                XamlRoot = xamlRoot
            };

            await dialog.ShowAsync();
        }

        private async Task<string?> GetLatestVersionAsync()
        {
            try
            {
                var response = await httpClient.GetStringAsync(GITHUB_API_URL);
                var releaseInfo = JsonSerializer.Deserialize<GitHubRelease>(response, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                return releaseInfo?.TagName?.TrimStart('v') ?? null;
            }
            catch (Exception ex)
            {
                await ShowErrorDialogAsync($"Update check failed: {ex.Message}");
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

        private async Task<string?> GetDownloadUrlAsync()
        {
            try
            {
                var response = await httpClient.GetStringAsync(GITHUB_API_URL);
                var releaseInfo = JsonSerializer.Deserialize<GitHubRelease>(response, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                // Ensure null safety by checking if Assets is null before accessing it
                var installerAsset = releaseInfo?.Assets?.FirstOrDefault(static a => a.Name?.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) == true);
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
