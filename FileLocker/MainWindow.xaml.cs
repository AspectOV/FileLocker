using FileLocker;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Text.Json;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;


namespace FileLocker
{

    public sealed partial class MainWindow : Window
    {
        private const string ENCRYPTED_EXTENSION = ".locked";
        private const int SALT_SIZE = 32;
        private const int IV_SIZE = 12; // GCM uses 12-byte IV
        private const int KEY_SIZE = 32;
        private const int TAG_SIZE = 16; // GCM authentication tag
        private const byte FORMAT_VERSION = 2; // Version for compatibility
        private const int MIN_PADDING_SIZE = 1024; // Minimum padding to hide file size
        private const int MAX_PADDING_SIZE = 8192; // Maximum padding
        private const string STEGO_CHUNK_TYPE = "flDR";
        private const string DefaultDropLabelText = "Drop files here or click to browse";
        private const string ActiveDropLabelText = "Release to queue items";
        private const int MaxHistoryEntries = 20;
        private static readonly byte[] StegoCarrierPng = Convert.FromBase64String(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII=");
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true
        };

        private readonly List<string> selectedPaths = [];
        private readonly Dictionary<string, string> _queueBaseLabelByPath = new(StringComparer.OrdinalIgnoreCase);
        private readonly ObservableCollection<PreflightIssueItem> _preflightItems = [];
        private readonly ObservableCollection<JobHistoryItem> _jobHistoryItems = [];
        private readonly List<OperationHistoryEntry> _operationHistory = [];
        private readonly List<EncryptionProfile> _customProfiles = [];
        private bool isDarkTheme = true;
        public ObservableCollection<string> FileList { get; set; } = [];
        public string StatusText { get; set; } = "Queue is empty. Add files or folders to begin.";
        private AppWindow? _appWindow;
        private bool _isUpdatingModeOptions;
        private bool _isApplyingProfile;
        private CancellationTokenSource? _processingCancellation;
        private bool _isProcessing;
        private bool _isUiReady;
        private readonly UpdateSettings _updateSettings = UpdateService.LoadSettings();
        private string _aboutUpdateStatusText = "Updates: automatic checks enabled";
        private bool _isCheckingForUpdates;
        private bool _isDownloadingUpdate;
        private bool _hasStartedAutomaticUpdateCheck;

        // UI element references (resolved after InitializeComponent)
        private  ListView _fileListBox = null!;
        private  Button _themeToggleButton = null!;
        private  TextBlock _dropLabel = null!;
        private  TextBlock _statusLabel = null!;
        private  PasswordBox _passwordBox = null!;
        private  ProgressBar _passwordStrengthBar = null!;
        private  TextBlock _passwordStrengthText = null!;
        private  Button _encryptButton = null!;
        private  Button _decryptButton = null!;
        private  Button _clearListButton = null!;
        private  Border _dropPanel = null!;
        private  ComboBox _operationModeCombo = null!;
        private  ComboBox _algorithmCombo = null!;
        private  ComboBox _keySizeCombo = null!;
        private  Border _hashHelperPanel = null!;
        private  TextBox _hashInputBox = null!;
        private  TextBox _hashOutputBox = null!;
        private  TextBox _metadataNameBox = null!;
        private  TextBox _metadataNotesBox = null!;
        private  TextBox _metadataCreatedBox = null!;
        private  TextBox _metadataModifiedBox = null!;
        private  ToggleSwitch _metadataRandomizeToggle = null!;
        private  TextBlock _metadataHelperText = null!;
        private  TextBlock _algorithmHintText = null!;

        // Advanced options properties
        public bool IsCompressModeEnabled { get; set; } = true;
        public bool IsScrambleNamesEnabled { get; set; } = false;
        public bool IsSteganographyEnabled { get; set; } = false;
        private  Random _random = new();
        private  string[] _encryptionAlgorithms = ["AES-GCM", "AES-CBC"];
        private  string[] _hashAlgorithms = ["SHA-256", "SHA-512", "Base64"];

        private record struct PasswordStrengthResult(
            int Score,
            string Feedback,
            Windows.UI.Color BarColor);

        private enum PreflightSeverity
        {
            Info,
            Warning,
            Error
        }

        private sealed record MetadataOverridesSnapshot(
            string Label,
            string Notes,
            bool Randomize,
            string CreatedText,
            string ModifiedText);

        private sealed record ProcessingRunOptions(
            bool CompressFiles,
            bool ScrambleNames,
            bool UseSteganography,
            string Algorithm,
            string Mode,
            int KeySizeBits,
            bool RemoveOriginalsAfterSuccess,
            bool SecureDeleteOriginals,
            bool VerifyAfterWrite,
            string BackupFolderPath,
            string? KeyfilePath,
            byte[]? KeyfileBytes,
            string ProfileName,
            MetadataOverridesSnapshot Metadata);

        private sealed class PreflightIssueItem
        {
            public required string IconGlyph { get; init; }
            public required string SeverityText { get; init; }
            public required string Message { get; init; }
        }

        private sealed class FileOperationResult
        {
            public required string SourcePath { get; init; }
            public string? OutputPath { get; init; }
            public string? BackupPath { get; init; }
            public required string Status { get; init; }
            public string? Message { get; init; }
            public bool OriginalRetained { get; init; }
            public bool OutputVerified { get; init; }
        }

        private sealed class OperationHistoryEntry
        {
            public required string Id { get; init; }
            public DateTime TimestampUtc { get; init; }
            public required string Operation { get; init; }
            public required string ProfileName { get; init; }
            public required string Algorithm { get; init; }
            public required string Mode { get; init; }
            public int KeySizeBits { get; init; }
            public bool UsedKeyfile { get; init; }
            public bool RemoveOriginalsAfterSuccess { get; init; }
            public bool SecureDeleteOriginals { get; init; }
            public bool VerifyAfterWrite { get; init; }
            public string BackupFolderPath { get; init; } = string.Empty;
            public bool Cancelled { get; init; }
            public int SuccessCount { get; init; }
            public int FailureCount { get; init; }
            public List<FileOperationResult> Results { get; init; } = [];
        }

        private sealed class JobHistoryItem
        {
            public required string Id { get; init; }
            public required string Title { get; init; }
            public required string Subtitle { get; init; }
            public required string ResultSummary { get; init; }
        }

        private sealed class EncryptionProfile
        {
            public required string Name { get; init; }
            public string Description { get; init; } = string.Empty;
            public required string Algorithm { get; init; }
            public int KeySizeBits { get; init; }
            public bool CompressFiles { get; init; }
            public bool ScrambleNames { get; init; }
            public bool UseSteganography { get; init; }
            public bool RandomizeMetadata { get; init; }
            public bool RemoveOriginalsAfterSuccess { get; init; }
            public bool SecureDeleteOriginals { get; init; }
            public bool VerifyAfterWrite { get; init; }
            public string BackupFolderPath { get; init; } = string.Empty;
            public string KeyfilePath { get; init; } = string.Empty;
            public bool IsBuiltIn { get; init; }
        }

        public MainWindow()
        {
            InitializeComponent();

            if (Content is not FrameworkElement root)
            {
                // If XAML failed to load, fail clearly instead of crashing later
                throw new InvalidOperationException("MainWindow XAML did not load any root content.");
            }

            InitializeControlReferences();
            InitializeUiState(root);

            // Safely get AppWindow (older OS / failures won’t crash the app)
            try
            {
                var hWnd = WindowNative.GetWindowHandle(this);
                var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hWnd);
                _appWindow = AppWindow.GetFromWindowId(windowId);

                if (_appWindow != null)
                {
                    _appWindow.SetPresenter(AppWindowPresenterKind.Default);
                    _appWindow.ResizeClient(new SizeInt32(800, 900));

                    var minSize = new SizeInt32(800, 900);
                    _appWindow.Changed += (s, args) =>
                    {
                        try
                        {
                            var sz = s.Size;
                            int w = Math.Max(sz.Width, minSize.Width);
                            int h = Math.Max(sz.Height, minSize.Height);
                            if (w != sz.Width || h != sz.Height)
                            {
                                s.Resize(new SizeInt32(w, h));
                            }
                        }
                        catch
                        {
                            // ignore window sizing errors
                        }
                    };
                }
            }
            catch
            {
                // Don’t kill the app if AppWindow APIs aren’t available
            }

            _ = StartAutomaticUpdateCheckAsync();
        }

        private void InitializeControlReferences()
        {
            _fileListBox = FileListBox;
            _themeToggleButton = ThemeToggleButton;
            _dropLabel = DropLabel;
            _statusLabel = StatusLabel;
            _passwordBox = PasswordBox;
            _passwordStrengthBar = PasswordStrengthBar;
            _passwordStrengthText = PasswordStrengthText;
            _encryptButton = EncryptButton;
            _decryptButton = DecryptButton;
            _clearListButton = ClearListButton;
            _dropPanel = DropPanel;
            _operationModeCombo = OperationModeCombo;
            _algorithmCombo = AlgorithmCombo;
            _keySizeCombo = KeySizeCombo;
            _hashHelperPanel = HashHelperPanel;
            _hashInputBox = HashInputBox;
            _hashOutputBox = HashOutputBox;
            _metadataNameBox = MetadataNameBox;
            _metadataNotesBox = MetadataNotesBox;
            _metadataCreatedBox = MetadataCreatedBox;
            _metadataModifiedBox = MetadataModifiedBox;
            _metadataRandomizeToggle = MetadataRandomizeToggle;
            _metadataHelperText = MetadataHelperText;
            _algorithmHintText = AlgorithmHintText;
        }

        private void InitializeUiState(FrameworkElement root)
        {
            _fileListBox.ItemsSource = FileList;
            PreflightListView.ItemsSource = _preflightItems;
            RecentJobsListView.ItemsSource = _jobHistoryItems;
            root.RequestedTheme = isDarkTheme ? ElementTheme.Dark : ElementTheme.Light;

            var passwordStrength = CalculatePasswordStrength(string.Empty);
            _passwordStrengthBar.Value = passwordStrength.Score;
            _passwordStrengthText.Text = passwordStrength.Feedback;
            _passwordStrengthBar.Foreground = new SolidColorBrush(passwordStrength.BarColor);

            LoadProfiles();
            LoadHistory();
            UpdateThemeToggleVisual();
            AnimateDropPanel(false);
            _dropLabel.Text = DefaultDropLabelText;
            _dropLabel.FontWeight = FontWeights.SemiBold;
            SafetyOption_Toggled(RemoveOriginalsToggle, new RoutedEventArgs());
            ConfigureModeOptions();
            RefreshQueueSummary();
            RefreshPreflightPreview();
            UpdateStatusLabel();
            _isUiReady = true;
            ApplyAdvancedModeVisibility();
            ApplyInspectorView("Setup");
            UpdateProfilePresentation(FindProfile(ProfileCombo.SelectedItem as string));
            UpdateAboutMenuInfo();
        }

        private static string GetAppDataDirectory()
        {
            string path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FileLocker");
            Directory.CreateDirectory(path);
            return path;
        }

        private static string GetProfilesPath() => Path.Combine(GetAppDataDirectory(), "profiles.json");

        private static string GetHistoryPath() => Path.Combine(GetAppDataDirectory(), "history.json");

        private static IEnumerable<EncryptionProfile> GetBuiltInProfiles()
        {
            return
            [
                new EncryptionProfile
                {
                    Name = "Recommended",
                    Description = "Balanced default. AES-GCM, verify writes, keep originals, and avoid destructive cleanup.",
                    Algorithm = "AES-GCM",
                    KeySizeBits = 256,
                    CompressFiles = true,
                    ScrambleNames = false,
                    UseSteganography = false,
                    RandomizeMetadata = false,
                    RemoveOriginalsAfterSuccess = false,
                    SecureDeleteOriginals = false,
                    VerifyAfterWrite = true,
                    IsBuiltIn = true
                },
                new EncryptionProfile
                {
                    Name = "Private Archive",
                    Description = "Good for long-term private storage. Scrambles names and randomizes metadata while keeping source files.",
                    Algorithm = "AES-GCM",
                    KeySizeBits = 256,
                    CompressFiles = true,
                    ScrambleNames = true,
                    UseSteganography = false,
                    RandomizeMetadata = true,
                    RemoveOriginalsAfterSuccess = false,
                    SecureDeleteOriginals = false,
                    VerifyAfterWrite = true,
                    IsBuiltIn = true
                },
                new EncryptionProfile
                {
                    Name = "Fast Local Lock",
                    Description = "Optimized for speed on already-compressed media. Keeps originals and skips compression.",
                    Algorithm = "AES-GCM",
                    KeySizeBits = 256,
                    CompressFiles = false,
                    ScrambleNames = false,
                    UseSteganography = false,
                    RandomizeMetadata = false,
                    RemoveOriginalsAfterSuccess = false,
                    SecureDeleteOriginals = false,
                    VerifyAfterWrite = true,
                    IsBuiltIn = true
                },
                new EncryptionProfile
                {
                    Name = "Transfer Copy",
                    Description = "Creates an encrypted payload and removes the source only after a verified successful write.",
                    Algorithm = "AES-GCM",
                    KeySizeBits = 256,
                    CompressFiles = true,
                    ScrambleNames = false,
                    UseSteganography = false,
                    RandomizeMetadata = false,
                    RemoveOriginalsAfterSuccess = true,
                    SecureDeleteOriginals = false,
                    VerifyAfterWrite = true,
                    IsBuiltIn = true
                },
                new EncryptionProfile
                {
                    Name = "Shred After Lock",
                    Description = "Most aggressive cleanup. Verifies output, then securely deletes originals after success.",
                    Algorithm = "AES-GCM",
                    KeySizeBits = 256,
                    CompressFiles = true,
                    ScrambleNames = true,
                    UseSteganography = false,
                    RandomizeMetadata = true,
                    RemoveOriginalsAfterSuccess = true,
                    SecureDeleteOriginals = true,
                    VerifyAfterWrite = true,
                    IsBuiltIn = true
                },
                new EncryptionProfile
                {
                    Name = "Stealth PNG",
                    Description = "Wraps the encrypted payload in a PNG container for less conspicuous file handling.",
                    Algorithm = "AES-GCM",
                    KeySizeBits = 256,
                    CompressFiles = true,
                    ScrambleNames = false,
                    UseSteganography = true,
                    RandomizeMetadata = true,
                    RemoveOriginalsAfterSuccess = false,
                    SecureDeleteOriginals = false,
                    VerifyAfterWrite = true,
                    IsBuiltIn = true
                }
            ];
        }

        private void LoadProfiles()
        {
            _customProfiles.Clear();
            string path = GetProfilesPath();
            if (File.Exists(path))
            {
                try
                {
                    var loaded = JsonSerializer.Deserialize<List<EncryptionProfile>>(File.ReadAllText(path), JsonOptions);
                    if (loaded != null)
                    {
                        _customProfiles.AddRange(loaded.Where(profile => !profile.IsBuiltIn));
                    }
                }
                catch
                {
                    // Ignore malformed profile file and continue with built-in defaults.
                }
            }

            RefreshProfileCombo();
        }

        private void SaveProfiles()
        {
            string path = GetProfilesPath();
            string json = JsonSerializer.Serialize(_customProfiles, JsonOptions);
            File.WriteAllText(path, json);
        }

        private void RefreshProfileCombo()
        {
            _isApplyingProfile = true;
            try
            {
                string? currentSelection = ProfileCombo.SelectedItem as string;
                ProfileCombo.Items.Clear();

                foreach (var profile in GetBuiltInProfiles().Concat(_customProfiles))
                {
                    ProfileCombo.Items.Add(profile.Name);
                }

                string targetSelection = string.IsNullOrWhiteSpace(currentSelection) ? "Recommended" : currentSelection;
                ProfileCombo.SelectedItem = ProfileCombo.Items.OfType<string>().FirstOrDefault(item =>
                    string.Equals(item, targetSelection, StringComparison.OrdinalIgnoreCase))
                    ?? "Recommended";
            }
            finally
            {
                _isApplyingProfile = false;
            }

            UpdateProfilePresentation(FindProfile(ProfileCombo.SelectedItem as string));
        }

        private EncryptionProfile? FindProfile(string? name)
        {
            return GetBuiltInProfiles()
                .Concat(_customProfiles)
                .FirstOrDefault(profile => string.Equals(profile.Name, name, StringComparison.OrdinalIgnoreCase));
        }

        private static string BuildCustomProfileDescription(EncryptionProfile profile)
        {
            var parts = new List<string>
            {
                $"{profile.Algorithm} {profile.KeySizeBits}-bit"
            };

            if (profile.CompressFiles) parts.Add("compression");
            if (profile.ScrambleNames) parts.Add("scrambled names");
            if (profile.UseSteganography) parts.Add("PNG container");
            if (profile.RandomizeMetadata) parts.Add("randomized metadata");
            if (profile.RemoveOriginalsAfterSuccess)
            {
                parts.Add(profile.SecureDeleteOriginals ? "secure source removal" : "source removal");
            }
            else
            {
                parts.Add("keeps originals");
            }

            return string.Join(" • ", parts);
        }

        private void UpdateProfilePresentation(EncryptionProfile? profile)
        {
            string profileName = profile?.Name ?? "Recommended";
            ProfileDescriptionText.Text = profile == null
                ? "Balanced default for most files."
                : string.IsNullOrWhiteSpace(profile.Description)
                    ? BuildCustomProfileDescription(profile)
                    : profile.Description;

            SaveProfileButton.Content = profile != null && !profile.IsBuiltIn
                ? "Update Profile"
                : "Save As Profile";
            UpdateAboutMenuInfo();
        }

        private void LoadHistory()
        {
            _operationHistory.Clear();
            _jobHistoryItems.Clear();

            string path = GetHistoryPath();
            if (File.Exists(path))
            {
                try
                {
                    var loaded = JsonSerializer.Deserialize<List<OperationHistoryEntry>>(File.ReadAllText(path), JsonOptions);
                    if (loaded != null)
                    {
                        _operationHistory.AddRange(loaded.OrderByDescending(entry => entry.TimestampUtc));
                    }
                }
                catch
                {
                    // Ignore malformed history and continue with an empty view.
                }
            }

            RefreshHistoryItems();
        }

        private void SaveHistory()
        {
            string path = GetHistoryPath();
            string json = JsonSerializer.Serialize(_operationHistory.Take(MaxHistoryEntries).ToList(), JsonOptions);
            File.WriteAllText(path, json);
        }

        private void RefreshHistoryItems()
        {
            _jobHistoryItems.Clear();
            foreach (var entry in _operationHistory.Take(MaxHistoryEntries))
            {
                _jobHistoryItems.Add(new JobHistoryItem
                {
                    Id = entry.Id,
                    Title = $"{entry.Operation} • {entry.TimestampUtc.ToLocalTime():g}",
                    Subtitle = $"{entry.Algorithm} {entry.KeySizeBits}-bit • Profile: {entry.ProfileName}",
                    ResultSummary = entry.Cancelled
                        ? $"Cancelled after {entry.SuccessCount} success(es)"
                        : $"{entry.SuccessCount} success • {entry.FailureCount} failed"
                });
            }

            if (_jobHistoryItems.Count > 0)
            {
                RecentJobsListView.SelectedIndex = 0;
            }
        }

        private void UpdateThemeToggleVisual()
        {
            ThemeToggleLabel.Text = isDarkTheme ? "Dark" : "Light";
            ToolTipService.SetToolTip(
                _themeToggleButton,
                isDarkTheme ? "Switch to light mode" : "Switch to dark mode");
        }

        private void ApplyAdvancedModeVisibility()
        {
            bool isAdvanced = AdvancedModeToggle.IsOn;
            KeyfilePanel.Visibility = isAdvanced ? Visibility.Visible : Visibility.Collapsed;
            SecurityAdvancedPanel.Visibility = isAdvanced ? Visibility.Visible : Visibility.Collapsed;
            OutputSafetySection.Visibility = isAdvanced ? Visibility.Visible : Visibility.Collapsed;
            AdvancedHandlingPanel.Visibility = isAdvanced ? Visibility.Visible : Visibility.Collapsed;
        }

        private void ApplyInspectorView(string view)
        {
            bool showSetup = string.Equals(view, "Setup", StringComparison.OrdinalIgnoreCase);
            bool showChecks = string.Equals(view, "Checks", StringComparison.OrdinalIgnoreCase);
            bool showJobs = string.Equals(view, "Jobs", StringComparison.OrdinalIgnoreCase);

            InspectorSetupPanel.Visibility = showSetup ? Visibility.Visible : Visibility.Collapsed;
            InspectorChecksPanel.Visibility = showChecks ? Visibility.Visible : Visibility.Collapsed;
            InspectorJobsPanel.Visibility = showJobs ? Visibility.Visible : Visibility.Collapsed;

            SetupViewButton.Background = showSetup ? GetBrushResource("AccentSoftBrush") : GetBrushResource("ButtonGhostBrush");
            ChecksViewButton.Background = showChecks ? GetBrushResource("AccentSoftBrush") : GetBrushResource("ButtonGhostBrush");
            JobsViewButton.Background = showJobs ? GetBrushResource("AccentSoftBrush") : GetBrushResource("ButtonGhostBrush");
        }

        private static string GetReportsDirectory()
        {
            string path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "FileLocker Reports");
            Directory.CreateDirectory(path);
            return path;
        }

        private void UpdateAboutMenuInfo()
        {
            string? version = FileVersionInfo.GetVersionInfo(Environment.ProcessPath ?? string.Empty).FileVersion;
            int profileCount = GetBuiltInProfiles().Count() + _customProfiles.Count;

            AboutVersionMenuItem.Text = $"Version {version ?? "Unknown"}";
            AboutProfilesMenuItem.Text = $"Profiles available: {profileCount}";
            AboutUpdateStatusMenuItem.Text = _aboutUpdateStatusText;
        }

        private static TElement GetElement<TElement>(FrameworkElement root, string name)
            where TElement : class
        {
            var element = root.FindName(name) as TElement;
            if (element == null)
            {
                throw new InvalidOperationException(
                    $"Unable to locate element '{name}'. Check x:Name in MainWindow.xaml.");
            }
            return element;
        }


        private void InitializeAppWindow()
        {
            var hwnd = WindowNative.GetWindowHandle(this);
            var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
            _appWindow = AppWindow.GetFromWindowId(windowId);
            _appWindow?.MoveAndResize(new Windows.Graphics.RectInt32(100, 100, 600, 800));
        }

        private void ThemeToggleButton_Click(object sender, RoutedEventArgs e)
        {
            if (_themeToggleButton is Button button)
            {
                isDarkTheme = !isDarkTheme;

                if (Content is FrameworkElement root)
                {
                    root.RequestedTheme = isDarkTheme ? ElementTheme.Dark : ElementTheme.Light;
                }

                UpdateThemeToggleVisual();
            }
        }


        // --- Drag & Drop ---
        private void DropPanel_DragOver(object sender, DragEventArgs e)
        {
            if (e.DataView.Contains(StandardDataFormats.StorageItems))
            {
                e.AcceptedOperation = DataPackageOperation.Copy;
                AnimateDropPanel(true);
                _dropLabel.Text = ActiveDropLabelText;
                _dropLabel.FontWeight = FontWeights.Bold;
            }
        }

        private async void DropPanel_Drop(object sender, DragEventArgs e)
        {
            AnimateDropPanel(false);
            _dropLabel.Text = DefaultDropLabelText;
            _dropLabel.FontWeight = FontWeights.SemiBold;

            if (e.DataView.Contains(StandardDataFormats.StorageItems))
            {
                await ProcessDroppedFilesAsync(e.DataView);
            }
        }

        private async Task ProcessDroppedFilesAsync(DataPackageView dataView)
        {
            try
            {
                var items = await dataView.GetStorageItemsAsync();
                var files = new List<string>();

                foreach (var item in items)
                {
                    if (item is StorageFile file)
                    {
                        files.Add(file.Path);
                    }
                    else if (item is StorageFolder folder)
                    {
                        files.Add(folder.Path);
                    }
                }

                if (files.Count > 0)
                {
                    AddFilesToList([.. files]);
                    SetStatus($"Added {files.Count} file(s)");
                }
            }
            catch (Exception ex)
            {
                await ShowErrorDialogAsync($"Error processing dropped files: {ex.Message}");
            }
        }

        private void DropPanel_PointerPressed(object sender, PointerRoutedEventArgs e)
        {
            _ = BrowseFiles();
        }

        private async Task BrowseFiles()
        {
            var picker = new FileOpenPicker();

            // Initialize the picker with the window handle
            var hwnd = WindowNative.GetWindowHandle(this);
            InitializeWithWindow.Initialize(picker, hwnd);

            picker.FileTypeFilter.Add("*");
            picker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;

            var files = await picker.PickMultipleFilesAsync();
            if (files.Count > 0)
            {
                var filePaths = files.Select(f => f.Path).ToArray();
                AddFilesToList(filePaths);
                SetStatus($"Added {filePaths.Length} file(s)");
            }
        }

        private async void BrowseFiles_Click(object sender, RoutedEventArgs e)
        {
            await BrowseFiles();
        }

        // --- File List and Status Binding ---
        private void AddFilesToList(string[] paths)
        {
            int addedCount = 0;
            int duplicateCount = 0;

            foreach (string path in paths)
            {
                if (!selectedPaths.Contains(path))
                {
                    selectedPaths.Add(path);
                    string displayName = BuildQueueDisplayLabel(path);
                    _queueBaseLabelByPath[path] = displayName;
                    FileList.Add(FormatQueueDisplay(displayName, "Queued"));
                    addedCount++;
                }
                else
                {
                    duplicateCount++;
                }
            }

            RefreshQueueSummary();
            RefreshPreflightPreview();
            UpdateStatusLabel();

            if (addedCount > 0 || duplicateCount > 0)
            {
                SetStatus(duplicateCount > 0
                    ? $"Added {addedCount} item(s). Skipped {duplicateCount} duplicate(s)."
                    : $"Added {addedCount} item(s).");
            }
        }

        private string BuildQueueDisplayLabel(string path)
        {
            string displayName = Path.GetFileName(path);
            if (Directory.Exists(path))
            {
                return $"{displayName} (Folder)";
            }

            if (File.Exists(path))
            {
                var fileInfo = new FileInfo(path);
                return $"{displayName} ({FormatFileSize(fileInfo.Length)})";
            }

            return displayName;
        }

        private static string FormatQueueDisplay(string baseLabel, string status)
        {
            return $"{baseLabel} [{status}]";
        }

        private void SetQueueItemStatus(string path, string status)
        {
            int index = selectedPaths.FindIndex(existing => string.Equals(existing, path, StringComparison.OrdinalIgnoreCase));
            if (index < 0 || index >= FileList.Count)
            {
                return;
            }

            string baseLabel = _queueBaseLabelByPath.TryGetValue(path, out string? value)
                ? value
                : BuildQueueDisplayLabel(path);

            FileList[index] = FormatQueueDisplay(baseLabel, status);
        }

        private void RefreshQueueSummary()
        {
            int folderCount = selectedPaths.Count(Directory.Exists);
            int fileCount = selectedPaths.Count(File.Exists);
            long totalSize = selectedPaths
                .Where(File.Exists)
                .Select(path =>
                {
                    try
                    {
                        return new FileInfo(path).Length;
                    }
                    catch
                    {
                        return 0L;
                    }
                })
                .Sum();

            QueueSummaryText.Text = fileCount == 0 && folderCount == 0
                ? "No items queued"
                : $"{fileCount} file(s) • {folderCount} folder(s) • {FormatFileSize(totalSize)}";
        }

        private static string FormatFileSize(long bytes)
        {
            string[] sizes = ["B", "KB", "MB", "GB"];
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        private void ClearListButton_Click(object sender, RoutedEventArgs e)
        {
            selectedPaths.Clear();
            _queueBaseLabelByPath.Clear();
            FileList.Clear();
            RefreshQueueSummary();
            RefreshPreflightPreview();
            UpdateStatusLabel();
        }

        private void SetStatus(string text)
        {
            StatusText = text;
            _statusLabel.Text = text;
        }

        private void UpdateStatusLabel()
        {
            if (selectedPaths.Count == 0)
                SetStatus("Queue is empty. Add files or folders to begin.");
            else
                SetStatus($"Queue ready. {selectedPaths.Count} item(s) selected.");
        }

        private void OperationModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_algorithmHintText == null) return;
            if (_isUpdatingModeOptions) return;
            ConfigureModeOptions();
            RefreshPreflightPreview();
        }

        private void AlgorithmCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_algorithmHintText == null) return;
            UpdateKeySizeInteractivity();
            UpdateAlgorithmHelper();
            RefreshPreflightPreview();
        }

        private void KeySizeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_algorithmHintText == null) return;
            UpdateAlgorithmHelper();
            RefreshPreflightPreview();
        }

        private void RecommendedModeButton_Click(object sender, RoutedEventArgs e)
        {
            SetComboSelection(_operationModeCombo, "Encrypt / Decrypt");
            if (_isUpdatingModeOptions) return;
            ConfigureModeOptions();
            SetComboSelection(_algorithmCombo, "AES-GCM");
            SetComboSelection(_keySizeCombo, "256");
            RemoveOriginalsToggle.IsOn = false;
            SecureDeleteOriginalsToggle.IsOn = false;
            VerifyAfterWriteToggle.IsOn = true;
            UpdateAlgorithmHelper();
            RefreshPreflightPreview();
            SetStatus("Recommended mode applied: AES-256-GCM");
        }

        private void ProfileCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_isApplyingProfile || !_isUiReady)
            {
                return;
            }

            ApplySelectedProfile();
        }

        private void AdvancedModeToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (!_isUiReady)
            {
                return;
            }

            ApplyAdvancedModeVisibility();
        }

        private void SetupViewButton_Click(object sender, RoutedEventArgs e) => ApplyInspectorView("Setup");

        private void ChecksViewButton_Click(object sender, RoutedEventArgs e) => ApplyInspectorView("Checks");

        private void JobsViewButton_Click(object sender, RoutedEventArgs e) => ApplyInspectorView("Jobs");

        private void ApplySelectedProfile()
        {
            var profile = FindProfile(ProfileCombo.SelectedItem as string);
            if (profile == null)
            {
                return;
            }

            _isApplyingProfile = true;
            try
            {
                SetComboSelection(_operationModeCombo, "Encrypt / Decrypt");
                ConfigureModeOptions();
                SetComboSelection(_algorithmCombo, profile.Algorithm);
                SetComboSelection(_keySizeCombo, profile.KeySizeBits.ToString(CultureInfo.InvariantCulture));
                CompressModeToggle.IsOn = profile.CompressFiles;
                ScrambleNamesToggle.IsOn = profile.ScrambleNames;
                SteganographyToggle.IsOn = profile.UseSteganography;
                MetadataRandomizeToggle.IsOn = profile.RandomizeMetadata;
                RemoveOriginalsToggle.IsOn = profile.RemoveOriginalsAfterSuccess;
                SecureDeleteOriginalsToggle.IsOn = profile.SecureDeleteOriginals;
                VerifyAfterWriteToggle.IsOn = profile.VerifyAfterWrite;
                BackupFolderBox.Text = profile.BackupFolderPath;
                KeyfilePathBox.Text = profile.KeyfilePath;
            }
            finally
            {
                _isApplyingProfile = false;
            }

            UpdateAlgorithmHelper();
            UpdateProfilePresentation(profile);
            RefreshPreflightPreview();
            SetStatus($"Profile applied: {profile.Name}");
        }

        private async void SaveProfileButton_Click(object sender, RoutedEventArgs e)
        {
            string? profileName = await PromptForTextAsync(
                "Save Profile",
                "Enter a name for this profile:",
                ProfileCombo.SelectedItem as string ?? "Custom Profile");

            if (string.IsNullOrWhiteSpace(profileName))
            {
                return;
            }

            profileName = profileName.Trim();
            _customProfiles.RemoveAll(profile => string.Equals(profile.Name, profileName, StringComparison.OrdinalIgnoreCase));
            _customProfiles.Add(new EncryptionProfile
            {
                Name = profileName,
                Description = $"Custom profile saved on {DateTime.Now:g}",
                Algorithm = GetComboContent(_algorithmCombo) ?? "AES-GCM",
                KeySizeBits = ParseKeySizeSelection(),
                CompressFiles = CompressModeToggle.IsOn,
                ScrambleNames = ScrambleNamesToggle.IsOn,
                UseSteganography = SteganographyToggle.IsOn,
                RandomizeMetadata = MetadataRandomizeToggle.IsOn,
                RemoveOriginalsAfterSuccess = RemoveOriginalsToggle.IsOn,
                SecureDeleteOriginals = SecureDeleteOriginalsToggle.IsOn,
                VerifyAfterWrite = VerifyAfterWriteToggle.IsOn,
                BackupFolderPath = BackupFolderBox.Text?.Trim() ?? string.Empty,
                KeyfilePath = KeyfilePathBox.Text?.Trim() ?? string.Empty,
                IsBuiltIn = false
            });

            SaveProfiles();
            RefreshProfileCombo();
            ProfileCombo.SelectedItem = profileName;
            UpdateProfilePresentation(FindProfile(profileName));
            SetStatus($"Saved profile: {profileName}");
        }

        private void ConfigureModeOptions()
        {
            _isUpdatingModeOptions = true;
            try
            {
                bool isHashMode = (GetComboContent(_operationModeCombo) ?? string.Empty)
                    .Contains("Hash", StringComparison.OrdinalIgnoreCase);
                string? currentAlgorithm = GetComboContent(_algorithmCombo);

                PopulateComboWithValues(
                    _algorithmCombo,
                    isHashMode ? _hashAlgorithms : _encryptionAlgorithms,
                    string.IsNullOrWhiteSpace(currentAlgorithm)
                        ? isHashMode ? "SHA-256" : "AES-GCM"
                        : currentAlgorithm);

                PopulateKeySizes(isHashMode);

                _hashHelperPanel.Visibility = isHashMode ? Visibility.Visible : Visibility.Collapsed;
                _metadataHelperText.Text = isHashMode
                    ? "Hash mode only uses the helper panel and does not write encrypted files."
                    : "Metadata will be preserved and can be randomized if desired.";

                UpdateKeySizeInteractivity();
                UpdateAlgorithmHelper();
                UpdateStatusLabel();
            }
            finally
            {
                _isUpdatingModeOptions = false;
            }
        }
        private static string GetComboValue(ComboBox combo, string defaultValue)
        {
            if (combo.SelectedItem is ComboBoxItem item)
            {
                if (item.Tag is string tag && !string.IsNullOrWhiteSpace(tag))
                    return tag;

                if (item.Content is string content && !string.IsNullOrWhiteSpace(content))
                    return content;
            }

            return defaultValue;
        }
        private static void PopulateComboWithValues(ComboBox comboBox, IEnumerable<string> values, string? preferredSelection)
        {
            comboBox.Items.Clear();
            int selectedIndex = 0;
            int index = 0;

            foreach (string value in values)
            {
                comboBox.Items.Add(new ComboBoxItem { Content = value });
                if (!string.IsNullOrWhiteSpace(preferredSelection) &&
                    string.Equals(value, preferredSelection, StringComparison.OrdinalIgnoreCase))
                {
                    selectedIndex = index;
                }
                index++;
            }

            comboBox.SelectedIndex = Math.Clamp(selectedIndex, 0, Math.Max(0, comboBox.Items.Count - 1));
        }

        private void PopulateKeySizes(bool isHashMode)
        {
            _keySizeCombo.Items.Clear();
            int[] sizes = isHashMode ? [256, 512] : [128, 192, 256];
            for (int i = 0; i < sizes.Length; i++)
            {
                _keySizeCombo.Items.Add(new ComboBoxItem { Content = sizes[i].ToString() });
            }

            _keySizeCombo.SelectedIndex = isHashMode ? 0 : sizes.Length - 1;
        }

        private void UpdateKeySizeInteractivity()
        {
            string? mode = GetComboContent(_operationModeCombo);
            string? algorithm = GetComboContent(_algorithmCombo);
            bool isHashMode = mode != null && mode.Contains("Hash", StringComparison.OrdinalIgnoreCase);
            bool usesKeySize = !string.Equals(algorithm, "Base64", StringComparison.OrdinalIgnoreCase);
            _keySizeCombo.IsEnabled = !isHashMode || usesKeySize;
            _keySizeCombo.Opacity = _keySizeCombo.IsEnabled ? 1 : 0.6;
        }

        private void UpdateAlgorithmHelper()
        {
            string algorithm = GetComboContent(_algorithmCombo) ?? "AES-GCM";
            int keySize = ParseKeySizeSelection();
            string mode = GetComboContent(_operationModeCombo) ?? "Encrypt / Decrypt";
            bool isHashMode = mode.Contains("Hash", StringComparison.OrdinalIgnoreCase);

            if (isHashMode)
            {
                string detail = algorithm.StartsWith("SHA", StringComparison.OrdinalIgnoreCase)
                    ? $"{algorithm} ({keySize}-bit digest)"
                    : "Base64 text helper";
                _algorithmHintText.Text = $"Preset: {detail}";
            }
            else
            {
                _algorithmHintText.Text = $"Preset: {algorithm} with {keySize}-bit key ({mode})";
            }
        }

        // --- Password Section ---
        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            var evaluation = CalculatePasswordStrength(_passwordBox.Password);
            _passwordStrengthBar.Value = evaluation.Score;
            _passwordStrengthText.Text = evaluation.Feedback;
            _passwordStrengthBar.Foreground = new SolidColorBrush(evaluation.BarColor);
        }

        private static PasswordStrengthResult CalculatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return new PasswordStrengthResult(0, "Enter a password to begin.", Microsoft.UI.Colors.Gray);
            }

            int score = Math.Min(password.Length * 4, 30);
            bool hasLower = password.Any(char.IsLower);
            bool hasUpper = password.Any(char.IsUpper);
            bool hasDigit = password.Any(char.IsDigit);
            bool hasSpecial = password.Any(ch => !char.IsLetterOrDigit(ch));

            score += hasLower ? 5 : 0;
            score += hasUpper ? 5 : 0;
            score += hasDigit ? 10 : 0;
            score += hasSpecial ? 15 : 0;

            int uniqueChars = password.Distinct().Count();
            score += Math.Min(uniqueChars * 2, 10);

            if (password.Length >= 12 && hasLower && hasUpper && hasDigit && hasSpecial)
            {
                score += 15;
            }

            string lowered = password.ToLowerInvariant();
            string[] commonPasswords = ["password", "123456", "qwerty", "letmein", "welcome", "admin"];
            if (commonPasswords.Any(p => lowered.Contains(p)))
            {
                score = Math.Min(score, 20);
            }

            int finalScore = Math.Clamp(score, 0, 100);

            // New: normalize very strong passwords to 100%
            if (finalScore >= 90)
            {
                finalScore = 100;
            }

            if (finalScore < 35)
            {
                return new PasswordStrengthResult(finalScore, "Weak - use upper, lower, numbers, and symbols", Microsoft.UI.Colors.Red);
            }

            if (finalScore < 70)
            {
                return new PasswordStrengthResult(finalScore, "Fair - add more length for better security", Microsoft.UI.Colors.Orange);
            }

            return new PasswordStrengthResult(finalScore, "Strong - great mix of length and characters", Microsoft.UI.Colors.Green);
        }


        // --- Encrypt/Decrypt ---
        private async void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (!await ValidateInputAsync()) return;
            await ProcessFilesAsync(true);
        }

        private async void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (!await ValidateInputAsync()) return;
            await ProcessFilesAsync(false);
        }

        private async Task<bool> ValidateInputAsync()
        {
            if (selectedPaths.Count == 0)
            {
                await ShowErrorDialogAsync("Please select files or folders to process.");
                return false;
            }

            if (string.IsNullOrWhiteSpace(_passwordBox.Password))
            {
                await ShowErrorDialogAsync("Please enter a password.");
                return false;
            }

            if (_passwordBox.Password.Length < 8)
            {
                bool proceed = await ShowConfirmDialogAsync(
                    "Password is very weak. Use at least 8 characters with mixed types.\n\nContinue anyway?",
                    "Weak Password");

                if (!proceed)
                {
                    return false;
                }
            }

            return true;
        }

        private async Task<bool> ConfirmPreflightAsync(bool encrypt, ProcessingRunOptions options)
        {
            var issues = BuildPreflightIssues(encrypt, options);
            DisplayPreflightIssues(issues);

            int errorCount = issues.Count(issue => issue.Severity == PreflightSeverity.Error);
            int warningCount = issues.Count(issue => issue.Severity == PreflightSeverity.Warning);

            if (errorCount > 0)
            {
                string details = string.Join(
                    "\n",
                    issues
                        .Where(issue => issue.Severity == PreflightSeverity.Error)
                        .Take(5)
                        .Select(issue => $"- {issue.Message}"));

                await ShowErrorDialogAsync(
                    $"Preflight found {errorCount} blocking issue(s).\n\n{details}");
                return false;
            }

            if (warningCount > 0)
            {
                string details = string.Join(
                    "\n",
                    issues
                        .Where(issue => issue.Severity == PreflightSeverity.Warning)
                        .Take(5)
                        .Select(issue => $"- {issue.Message}"));

                return await ShowConfirmDialogAsync(
                    $"Preflight found {warningCount} warning(s).\n\n{details}\n\nContinue anyway?",
                    "Preflight Warnings");
            }

            return true;
        }

        private byte[]? ReadKeyfileBytesIfConfigured(string? keyfilePath)
        {
            if (string.IsNullOrWhiteSpace(keyfilePath))
            {
                return null;
            }

            string trimmed = keyfilePath.Trim();
            if (!File.Exists(trimmed))
            {
                throw new FileNotFoundException("The selected keyfile could not be found.", trimmed);
            }

            return File.ReadAllBytes(trimmed);
        }

        private async void HashRunButton_Click(object sender, RoutedEventArgs e)
        {
            string input = _hashInputBox.Text;
            if (string.IsNullOrWhiteSpace(input))
            {
                await ShowErrorDialogAsync("Enter text to hash or encode.");
                return;
            }

            string algorithm = GetComboContent(_algorithmCombo) ?? "AES-GCM";
            int keySize = ParseKeySizeSelection();

            try
            {
                byte[]? keyfileBytes = ReadKeyfileBytesIfConfigured(KeyfilePathBox.Text);
                string output = await Task.Run(() => RunHashOrEncode(input, algorithm, keySize, keyfileBytes));
                _hashOutputBox.Text = output;
                SetStatus($"Generated output using {algorithm} ({keySize}-bit)");
            }
            catch (Exception ex)
            {
                await ShowErrorDialogAsync($"Failed to generate output: {ex.Message}");
            }
        }

        private string RunHashOrEncode(string input, string algorithm, int keySize, byte[]? keyfileBytes)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            if (algorithm.Contains("SHA", StringComparison.OrdinalIgnoreCase))
            {
                byte[] hash = keySize >= 512 ? SHA512.HashData(inputBytes) : SHA256.HashData(inputBytes);
                return Convert.ToHexString(hash);
            }

            if (algorithm.Contains("Base64", StringComparison.OrdinalIgnoreCase))
            {
                return Convert.ToBase64String(inputBytes);
            }

            return EncryptTextWithAes(inputBytes, algorithm, keySize, keyfileBytes);
        }

        private string EncryptTextWithAes(byte[] inputBytes, string algorithm, int keySize, byte[]? keyfileBytes)
        {
            if (string.IsNullOrWhiteSpace(_passwordBox.Password))
            {
                throw new InvalidOperationException("Enter a password for AES-based helpers.");
            }

            byte[] salt = GenerateRandomBytes(16);
            int keySizeBytes = Math.Max(16, keySize / 8);
            byte[] key = DeriveKey(_passwordBox.Password, salt, keyfileBytes, keySizeBytes);

            if (algorithm.Contains("GCM", StringComparison.OrdinalIgnoreCase))
            {
                return EncodeAesGcmPayload(inputBytes, key, salt, keySize);
            }

            return EncodeAesCbcPayload(inputBytes, key, salt, keySize);
        }

        private static string EncodeAesGcmPayload(byte[] inputBytes, byte[] key, byte[] salt, int keySize)
        {
            byte[] iv = GenerateRandomBytes(IV_SIZE);
            byte[] ciphertext = new byte[inputBytes.Length];
            byte[] tag = new byte[TAG_SIZE];

            using (var aes = new AesGcm(key, TAG_SIZE))
            {
                aes.Encrypt(iv, inputBytes, ciphertext, tag);
            }

            return EncodeLabeledPayload("AES-GCM", keySize, salt, iv, tag, ciphertext);
        }

        private static string EncodeAesCbcPayload(byte[] inputBytes, byte[] key, byte[] salt, int keySize)
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = Math.Min(keySize, 256);
            aes.Key = key;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            byte[] ciphertext = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
            return EncodeLabeledPayload("AES-CBC", keySize, salt, aes.IV, [], ciphertext);
        }

        private static string EncodeLabeledPayload(string label, int keySize, byte[] salt, byte[] iv, byte[] tag, byte[] ciphertext)
        {
            using var stream = new MemoryStream();
            WriteLengthPrefixed(stream, salt);
            WriteLengthPrefixed(stream, iv);
            WriteLengthPrefixed(stream, tag);
            WriteLengthPrefixed(stream, ciphertext);

            return $"{label} ({keySize}-bit): {Convert.ToBase64String(stream.ToArray())}";
        }

        private static void WriteLengthPrefixed(Stream stream, byte[] data)
        {
            ushort length = (ushort)data.Length;
            stream.Write(BitConverter.GetBytes(length), 0, sizeof(ushort));
            stream.Write(data, 0, data.Length);
        }

        private void ApplyMetadataOverrides(FileMetadata metadata, string filePath, ProcessingRunOptions options)
        {
            metadata.MetadataLabel = string.IsNullOrWhiteSpace(options.Metadata.Label)
                ? metadata.OriginalFileName
                : options.Metadata.Label;
            metadata.CustomNote = options.Metadata.Notes;
            metadata.Algorithm = options.Algorithm;
            metadata.Mode = options.Mode;
            metadata.KeySizeBits = options.KeySizeBits;

            if (options.Metadata.Randomize)
            {
                var (created, modified) = GenerateRandomizedDates();
                metadata.CreationTime = created;
                metadata.LastWriteTime = modified;
            }
            else
            {
                metadata.CreationTime = ParseDateOrDefault(options.Metadata.CreatedText, File.GetCreationTime(filePath));
                metadata.LastWriteTime = ParseDateOrDefault(options.Metadata.ModifiedText, File.GetLastWriteTime(filePath));
            }
        }

        private (DateTime created, DateTime modified) GenerateRandomizedDates()
        {
            DateTime now = DateTime.UtcNow;
            int backDays = _random.Next(7, 1800);
            DateTime created = now.AddDays(-backDays).AddMinutes(_random.Next(0, 1440));
            DateTime modified = created.AddMinutes(_random.Next(5, 1200));
            return (created, modified);
        }

        private void MetadataRandomizeToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (!_isUiReady)
            {
                return;
            }

            if (_metadataRandomizeToggle.IsOn)
            {
                ApplyRandomizedMetadataFields();
            }
            else
            {
                _metadataHelperText.Text = "Manual metadata values will be used.";
            }

            RefreshPreflightPreview();
        }

        private void MetadataRandomizeButton_Click(object sender, RoutedEventArgs e)
        {
            _metadataRandomizeToggle.IsOn = true;
            ApplyRandomizedMetadataFields();
        }

        private void ApplyRandomizedMetadataFields()
        {
            _metadataNameBox.Text = GenerateRandomAlias();
            _metadataNotesBox.Text = $"Randomized note ({DateTime.UtcNow:HH:mm:ss})";
            var (created, modified) = GenerateRandomizedDates();
            _metadataCreatedBox.Text = created.ToString("o", CultureInfo.InvariantCulture);
            _metadataModifiedBox.Text = modified.ToString("o", CultureInfo.InvariantCulture);
            _metadataHelperText.Text = "Randomized metadata will override file timestamps.";
            RefreshPreflightPreview();
        }

        private static string GenerateRandomAlias()
        {
            byte[] aliasBytes = GenerateRandomBytes(6);
            return $"meta-{Convert.ToHexString(aliasBytes).ToLowerInvariant()}";
        }

        private static DateTime ParseDateOrDefault(string? input, DateTime fallback)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                return fallback;
            }

            if (DateTime.TryParse(
                input,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.RoundtripKind,
                out DateTime parsedInvariant))
            {
                return parsedInvariant.Kind == DateTimeKind.Utc
                    ? parsedInvariant
                    : parsedInvariant.ToUniversalTime();
            }

            if (DateTime.TryParse(
                input,
                CultureInfo.CurrentCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeLocal,
                out DateTime parsedCurrent))
            {
                return parsedCurrent.ToUniversalTime();
            }

            return fallback;
        }

        private static string? GetComboContent(ComboBox comboBox)
        {
            if (comboBox.SelectedItem is ComboBoxItem item && item.Content is string text)
            {
                return text;
            }

            return comboBox.SelectedValue as string;
        }

        private static void SetComboSelection(ComboBox comboBox, string content)
        {
            for (int i = 0; i < comboBox.Items.Count; i++)
            {
                if (comboBox.Items[i] is ComboBoxItem item &&
                    item.Content is string value &&
                    string.Equals(value, content, StringComparison.OrdinalIgnoreCase))
                {
                    comboBox.SelectedIndex = i;
                    return;
                }
            }
        }

        private int ParseKeySizeSelection()
        {
            string? keySizeText = GetComboContent(_keySizeCombo);
            if (int.TryParse(keySizeText, out int keySize))
            {
                return keySize;
            }

            return 256;
        }
        private void ShowPasswordCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            _passwordBox.PasswordRevealMode = PasswordRevealMode.Visible;
        }

        private void ShowPasswordCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            _passwordBox.PasswordRevealMode = PasswordRevealMode.Peek;
        }

        private async Task ProcessFilesAsync(bool encrypt)
        {
            try
            {
                SetUIEnabled(false);
                _isProcessing = true;
                _processingCancellation = new CancellationTokenSource();
                CancelRunButton.IsEnabled = true;

                string password = _passwordBox.Password;
                ProcessingRunOptions runOptions = CaptureProcessingRunOptions();
                if (!await ConfirmPreflightAsync(encrypt, runOptions))
                {
                    return;
                }

                if (encrypt)
                {
                    _metadataHelperText.Text = runOptions.Metadata.Randomize
                        ? "Randomized metadata will be applied during encryption."
                        : "Manual metadata values will be applied during encryption.";
                }

                var allFiles = ExpandPathsToFiles(selectedPaths);
                int processed = 0;
                List<string> failedPaths = [];
                List<string> pendingPaths = [];
                List<FileOperationResult> results = [];
                bool cancelled = false;

                for (int fileIndex = 0; fileIndex < allFiles.Count; fileIndex++)
                {
                    string filePath = allFiles[fileIndex];
                    if (_processingCancellation.IsCancellationRequested)
                    {
                        cancelled = true;
                        pendingPaths.AddRange(allFiles.Skip(fileIndex));
                        foreach (string pendingPath in pendingPaths)
                        {
                            SetQueueItemStatus(pendingPath, "Cancelled");
                        }
                        break;
                    }

                    try
                    {
                        SetQueueItemStatus(filePath, "Processing");
                        FileOperationResult result;
                        if (encrypt)
                        {
                            result = await Task.Run(() => EncryptFileAdvanced(filePath, password, runOptions));
                        }
                        else
                        {
                            result = await Task.Run(() => DecryptFileAdvanced(filePath, password, runOptions));
                        }

                        results.Add(result);
                        processed++;
                        SetQueueItemStatus(filePath, "Completed");
                        SetStatus($"Processed {processed}/{allFiles.Count} item(s)...");
                    }
                    catch (Exception ex)
                    {
                        failedPaths.Add(filePath);
                        results.Add(new FileOperationResult
                        {
                            SourcePath = filePath,
                            Status = "Failed",
                            Message = ex.Message,
                            OriginalRetained = true,
                            OutputVerified = false
                        });
                        SetQueueItemStatus(filePath, "Failed");
                        await ShowErrorDialogAsync($"Error processing {Path.GetFileName(filePath)}: {ex.Message}");
                    }
                }

                AppendHistory(encrypt ? "Encrypt" : "Decrypt", runOptions, results, cancelled);

                selectedPaths.Clear();
                _queueBaseLabelByPath.Clear();
                FileList.Clear();

                if (failedPaths.Count > 0 || pendingPaths.Count > 0)
                {
                    AddFilesToList([.. failedPaths, .. pendingPaths]);
                    foreach (string failedPath in failedPaths)
                    {
                        SetQueueItemStatus(failedPath, "Needs attention");
                    }
                    foreach (string pendingPath in pendingPaths)
                    {
                        SetQueueItemStatus(pendingPath, "Queued");
                    }

                    SetStatus(cancelled
                        ? $"Stopped after {processed} item(s). {failedPaths.Count} failed and {pendingPaths.Count} remain queued."
                        : processed > 0
                            ? $"Completed {processed} item(s). {failedPaths.Count} item(s) still need attention."
                            : $"No items were completed. {failedPaths.Count} item(s) need attention.");
                }
                else
                {
                    SetStatus(cancelled
                        ? $"Stopped after {processed} item(s)."
                        : $"Completed {processed} item(s).");
                }

                RefreshQueueSummary();
                RefreshPreflightPreview();
            }
            catch (Exception ex)
            {
                await ShowErrorDialogAsync($"Error: {ex.Message}");
            }
            finally
            {
                _isProcessing = false;
                _processingCancellation?.Dispose();
                _processingCancellation = null;
                CancelRunButton.IsEnabled = false;
                SetUIEnabled(true);
            }
        }

        // --- Encryption/Decryption Logic ---
        private ProcessingRunOptions CaptureProcessingRunOptions()
        {
            string keyfilePath = KeyfilePathBox.Text?.Trim() ?? string.Empty;
            byte[]? keyfileBytes = ReadKeyfileBytesIfConfigured(keyfilePath);

            return new ProcessingRunOptions(
                IsCompressModeEnabled,
                IsScrambleNamesEnabled,
                IsSteganographyEnabled,
                GetComboContent(_algorithmCombo) ?? "AES-GCM",
                GetComboContent(_operationModeCombo) ?? "Encrypt / Decrypt",
                ParseKeySizeSelection(),
                RemoveOriginalsToggle.IsOn,
                SecureDeleteOriginalsToggle.IsOn,
                VerifyAfterWriteToggle.IsOn,
                BackupFolderBox.Text?.Trim() ?? string.Empty,
                string.IsNullOrWhiteSpace(keyfilePath) ? null : keyfilePath,
                keyfileBytes,
                ProfileCombo.SelectedItem as string ?? "Recommended",
                new MetadataOverridesSnapshot(
                    _metadataNameBox.Text?.Trim() ?? string.Empty,
                    _metadataNotesBox.Text?.Trim() ?? string.Empty,
                    _metadataRandomizeToggle.IsOn,
                    _metadataCreatedBox.Text ?? string.Empty,
                    _metadataModifiedBox.Text ?? string.Empty));
        }

        private FileOperationResult EncryptFileAdvanced(string filePath, string password, ProcessingRunOptions options)
        {
            string? backupPath = null;
            string encryptedPath = string.Empty;
            string tempPath = string.Empty;

            try
            {
                byte[] salt = GenerateRandomBytes(SALT_SIZE);
                byte[] iv = GenerateRandomBytes(IV_SIZE);
                byte[] key = DeriveKeyArgon2(password, salt, options.KeyfileBytes);
                byte[] fileData = File.ReadAllBytes(filePath);
                string originalFileName = Path.GetFileName(filePath) ?? string.Empty;

                FileMetadata metadata = new()
                {
                    OriginalFileName = originalFileName,
                    OriginalSize = fileData.Length,
                    CreationTime = File.GetCreationTimeUtc(filePath),
                    LastWriteTime = File.GetLastWriteTimeUtc(filePath),
                    LastAccessTime = File.GetLastAccessTimeUtc(filePath),
                    OriginalAttributes = File.GetAttributes(filePath),
                    IsSteganographyContainer = options.UseSteganography
                };

                ApplyMetadataOverrides(metadata, filePath, options);

                byte[] dataToEncrypt = fileData;
                if (options.CompressFiles)
                {
                    dataToEncrypt = CompressData(fileData, out bool compressed);
                    metadata.IsCompressed = compressed;
                    if (!compressed)
                    {
                        dataToEncrypt = fileData;
                    }
                }

                metadata.ContentHash = ComputeSha256(fileData);

                byte[] padding = GenerateRandomBytes(GenerateRandomPaddingSize());
                byte[] metadataBytes = SerializeMetadata(metadata);
                byte[] combined = new byte[4 + metadataBytes.Length + 4 + padding.Length + dataToEncrypt.Length];
                int offset = 0;
                Buffer.BlockCopy(BitConverter.GetBytes(metadataBytes.Length), 0, combined, offset, 4);
                offset += 4;
                Buffer.BlockCopy(metadataBytes, 0, combined, offset, metadataBytes.Length);
                offset += metadataBytes.Length;
                Buffer.BlockCopy(BitConverter.GetBytes(padding.Length), 0, combined, offset, 4);
                offset += 4;
                Buffer.BlockCopy(padding, 0, combined, offset, padding.Length);
                offset += padding.Length;
                Buffer.BlockCopy(dataToEncrypt, 0, combined, offset, dataToEncrypt.Length);

                byte[] ciphertext = new byte[combined.Length];
                byte[] tag = new byte[TAG_SIZE];
                using (var aes = new AesGcm(key, TAG_SIZE))
                {
                    aes.Encrypt(iv, combined, ciphertext, tag);
                }

                byte[] payload = BuildEncryptedPayload(salt, iv, tag, ciphertext);
                encryptedPath = BuildOutputPath(filePath, options.ScrambleNames, options.UseSteganography);
                tempPath = encryptedPath + ".tmp";
                byte[] outputBytes = options.UseSteganography ? EmbedInPngContainer(payload) : payload;

                if (!string.IsNullOrWhiteSpace(options.BackupFolderPath))
                {
                    backupPath = CreateBackupCopy(filePath, options.BackupFolderPath);
                }

                File.WriteAllBytes(tempPath, outputBytes);
                if (options.VerifyAfterWrite)
                {
                    VerifyWrittenFile(tempPath, outputBytes);
                }

                File.Move(tempPath, encryptedPath, overwrite: false);
                File.SetCreationTime(encryptedPath, new DateTime(2020, 1, 1));
                File.SetLastWriteTime(encryptedPath, new DateTime(2020, 1, 1));

                bool retained = true;
                if (options.RemoveOriginalsAfterSuccess)
                {
                    DeleteSourceFile(filePath, options.SecureDeleteOriginals);
                    retained = false;
                }

                return new FileOperationResult
                {
                    SourcePath = filePath,
                    OutputPath = encryptedPath,
                    BackupPath = backupPath,
                    Status = "Completed",
                    OriginalRetained = retained,
                    OutputVerified = options.VerifyAfterWrite,
                    Message = options.RemoveOriginalsAfterSuccess
                        ? options.SecureDeleteOriginals ? "Encrypted and securely removed original." : "Encrypted and removed original."
                        : "Encrypted and retained original."
                };
            }
            catch (Exception ex)
            {
                CleanupTemporaryFile(tempPath);
                throw new Exception($"Encryption failed: {ex.Message}");
            }
        }

        private FileOperationResult DecryptFileAdvanced(string filePath, string password, ProcessingRunOptions options)
        {
            string? backupPath = null;
            string finalPath = string.Empty;
            string tempPath = string.Empty;
            try
            {
                byte[] encryptedBytes = TryExtractStegoPayload(filePath) ?? File.ReadAllBytes(filePath);

                using var fs = new MemoryStream(encryptedBytes);
                byte version = (byte)fs.ReadByte();
                if (version != FORMAT_VERSION)
                {
                    throw new InvalidDataException("Unsupported file format version.");
                }

                byte[] salt = new byte[SALT_SIZE];
                byte[] iv = new byte[IV_SIZE];
                byte[] tag = new byte[TAG_SIZE];
                ReadExact(fs, salt, 0, SALT_SIZE);
                ReadExact(fs, iv, 0, IV_SIZE);
                ReadExact(fs, tag, 0, TAG_SIZE);

                byte[] ciphertext = new byte[fs.Length - 1 - SALT_SIZE - IV_SIZE - TAG_SIZE];
                ReadExact(fs, ciphertext, 0, ciphertext.Length);
                byte[] key = DeriveKeyArgon2(password, salt, options.KeyfileBytes);
                byte[] plaintext = new byte[ciphertext.Length];

                using (var aes = new AesGcm(key, TAG_SIZE))
                {
                    try
                    {
                        aes.Decrypt(iv, ciphertext, tag, plaintext);
                    }
                    catch (CryptographicException)
                    {
                        throw new UnauthorizedAccessException("Invalid password or corrupted file.");
                    }
                }

                int offset = 0;
                int metadataLength = BitConverter.ToInt32(plaintext, offset);
                offset += 4;
                byte[] metadataBytes = new byte[metadataLength];
                Buffer.BlockCopy(plaintext, offset, metadataBytes, 0, metadataLength);
                offset += metadataLength;
                FileMetadata metadata = DeserializeMetadata(metadataBytes);
                int paddingLength = BitConverter.ToInt32(plaintext, offset);
                offset += 4 + paddingLength;
                byte[] fileData = new byte[plaintext.Length - offset];
                Buffer.BlockCopy(plaintext, offset, fileData, 0, fileData.Length);
                if (metadata.IsCompressed)
                {
                    fileData = DecompressData(fileData);
                }

                if (metadata.ContentHash.Length > 0)
                {
                    EnsureHashMatch(metadata.ContentHash, fileData);
                }

                string? directory = Path.GetDirectoryName(filePath) ?? throw new InvalidOperationException("File directory is null.");
                string originalPath = Path.Combine(directory, metadata.OriginalFileName ?? "output");
                int counter = 1;
                finalPath = originalPath;
                while (File.Exists(finalPath))
                {
                    string name = Path.GetFileNameWithoutExtension(originalPath);
                    string ext = Path.GetExtension(originalPath);
                    finalPath = Path.Combine(directory, $"{name}_{counter}{ext}");
                    counter++;
                }
                tempPath = finalPath + ".tmp";

                if (!string.IsNullOrWhiteSpace(options.BackupFolderPath))
                {
                    backupPath = CreateBackupCopy(filePath, options.BackupFolderPath);
                }

                File.WriteAllBytes(tempPath, fileData);
                if (options.VerifyAfterWrite)
                {
                    VerifyWrittenFile(tempPath, fileData);
                }

                File.Move(tempPath, finalPath, overwrite: false);
                RestoreFileMetadata(finalPath, metadata);

                bool retained = true;
                if (options.RemoveOriginalsAfterSuccess)
                {
                    DeleteSourceFile(filePath, options.SecureDeleteOriginals);
                    retained = false;
                }

                return new FileOperationResult
                {
                    SourcePath = filePath,
                    OutputPath = finalPath,
                    BackupPath = backupPath,
                    Status = "Completed",
                    OriginalRetained = retained,
                    OutputVerified = options.VerifyAfterWrite,
                    Message = options.RemoveOriginalsAfterSuccess
                        ? options.SecureDeleteOriginals ? "Decrypted and securely removed source payload." : "Decrypted and removed source payload."
                        : "Decrypted and retained source payload."
                };
            }
            catch (Exception ex)
            {
                CleanupTemporaryFile(tempPath);
                throw new Exception($"Decryption failed: {ex.Message}");
            }
        }

        private static void ReadExact(MemoryStream fs, byte[] buffer, int offset, int count)
        {
            int readTotal = 0;
            while (readTotal < count)
            {
                int read = fs.Read(buffer, offset + readTotal, count - readTotal);
                if (read == 0) throw new EndOfStreamException();
                readTotal += read;
            }
        }

        private static void CleanupTemporaryFile(string? tempPath)
        {
            if (string.IsNullOrWhiteSpace(tempPath) || !File.Exists(tempPath))
            {
                return;
            }

            try
            {
                File.Delete(tempPath);
            }
            catch
            {
                // Ignore cleanup failures.
            }
        }

        private static void VerifyWrittenFile(string path, byte[] expectedBytes)
        {
            byte[] writtenBytes = File.ReadAllBytes(path);
            if (!writtenBytes.AsSpan().SequenceEqual(expectedBytes))
            {
                throw new IOException("Output verification failed after writing the file.");
            }
        }

        private static void RestoreFileMetadata(string path, FileMetadata metadata)
        {
            File.SetAttributes(path, System.IO.FileAttributes.Normal);

            if (metadata.CreationTime.Kind == DateTimeKind.Utc)
            {
                File.SetCreationTimeUtc(path, metadata.CreationTime);
            }
            else
            {
                File.SetCreationTime(path, metadata.CreationTime);
            }

            if (metadata.LastWriteTime.Kind == DateTimeKind.Utc)
            {
                File.SetLastWriteTimeUtc(path, metadata.LastWriteTime);
            }
            else
            {
                File.SetLastWriteTime(path, metadata.LastWriteTime);
            }

            if (metadata.LastAccessTime != default)
            {
                if (metadata.LastAccessTime.Kind == DateTimeKind.Utc)
                {
                    File.SetLastAccessTimeUtc(path, metadata.LastAccessTime);
                }
                else
                {
                    File.SetLastAccessTime(path, metadata.LastAccessTime);
                }
            }

            File.SetAttributes(path, metadata.OriginalAttributes == 0 ? System.IO.FileAttributes.Normal : metadata.OriginalAttributes);
        }

        private static string CreateBackupCopy(string sourcePath, string backupFolderPath)
        {
            Directory.CreateDirectory(backupFolderPath);
            string fileName = Path.GetFileNameWithoutExtension(sourcePath);
            string extension = Path.GetExtension(sourcePath);
            string destination = Path.Combine(
                backupFolderPath,
                $"{fileName}_{DateTime.Now:yyyyMMdd_HHmmss}{extension}");

            int counter = 1;
            while (File.Exists(destination))
            {
                destination = Path.Combine(
                    backupFolderPath,
                    $"{fileName}_{DateTime.Now:yyyyMMdd_HHmmss}_{counter}{extension}");
                counter++;
            }

            File.Copy(sourcePath, destination);
            return destination;
        }

        private static void DeleteSourceFile(string sourcePath, bool secureDelete)
        {
            if (secureDelete)
            {
                SecureDelete(sourcePath);
            }
            else
            {
                File.Delete(sourcePath);
            }
        }

        private void AppendHistory(string operation, ProcessingRunOptions options, List<FileOperationResult> results, bool cancelled)
        {
            var entry = new OperationHistoryEntry
            {
                Id = Guid.NewGuid().ToString("N"),
                TimestampUtc = DateTime.UtcNow,
                Operation = operation,
                ProfileName = options.ProfileName,
                Algorithm = options.Algorithm,
                Mode = options.Mode,
                KeySizeBits = options.KeySizeBits,
                UsedKeyfile = options.KeyfileBytes is { Length: > 0 },
                RemoveOriginalsAfterSuccess = options.RemoveOriginalsAfterSuccess,
                SecureDeleteOriginals = options.SecureDeleteOriginals,
                VerifyAfterWrite = options.VerifyAfterWrite,
                BackupFolderPath = options.BackupFolderPath,
                Cancelled = cancelled,
                SuccessCount = results.Count(result => string.Equals(result.Status, "Completed", StringComparison.OrdinalIgnoreCase)),
                FailureCount = results.Count(result => string.Equals(result.Status, "Failed", StringComparison.OrdinalIgnoreCase)),
                Results = results
            };

            _operationHistory.Insert(0, entry);
            while (_operationHistory.Count > MaxHistoryEntries)
            {
                _operationHistory.RemoveAt(_operationHistory.Count - 1);
            }

            SaveHistory();
            RefreshHistoryItems();
        }

        private sealed record PreflightIssue(PreflightSeverity Severity, string Message);

        private List<PreflightIssue> BuildPreflightIssues(bool encrypt, ProcessingRunOptions? options = null)
        {
            var issues = new List<PreflightIssue>();
            var allFiles = ExpandPathsToFiles(selectedPaths);

            if (allFiles.Count == 0)
            {
                issues.Add(new PreflightIssue(PreflightSeverity.Info, "Queue is empty."));
                return issues;
            }

            if (options != null && !string.IsNullOrWhiteSpace(options.BackupFolderPath))
            {
                try
                {
                    Directory.CreateDirectory(options.BackupFolderPath);
                }
                catch (Exception ex)
                {
                    issues.Add(new PreflightIssue(PreflightSeverity.Error, $"Backup folder is not available: {ex.Message}"));
                }
            }

            if (options != null && !string.IsNullOrWhiteSpace(options.KeyfilePath) && options.KeyfileBytes is null)
            {
                issues.Add(new PreflightIssue(PreflightSeverity.Error, "The selected keyfile could not be loaded."));
            }

            foreach (string filePath in allFiles)
            {
                if (!File.Exists(filePath))
                {
                    issues.Add(new PreflightIssue(PreflightSeverity.Error, $"Missing file: {filePath}"));
                    continue;
                }

                try
                {
                    using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                }
                catch (Exception ex)
                {
                    issues.Add(new PreflightIssue(PreflightSeverity.Error, $"Unable to read {Path.GetFileName(filePath)}: {ex.Message}"));
                    continue;
                }

                if (encrypt)
                {
                    if (filePath.EndsWith(ENCRYPTED_EXTENSION, StringComparison.OrdinalIgnoreCase) ||
                        TryExtractStegoPayload(filePath) != null)
                    {
                        issues.Add(new PreflightIssue(PreflightSeverity.Warning, $"{Path.GetFileName(filePath)} already looks encrypted."));
                    }
                }
                else if (!filePath.EndsWith(ENCRYPTED_EXTENSION, StringComparison.OrdinalIgnoreCase) &&
                         TryExtractStegoPayload(filePath) == null)
                {
                    issues.Add(new PreflightIssue(PreflightSeverity.Error, $"{Path.GetFileName(filePath)} does not look like a FileLocker payload."));
                }

                if (options != null)
                {
                    string predictedPath = encrypt
                        ? BuildOutputPath(filePath, options.ScrambleNames, options.UseSteganography)
                        : PredictDecryptedOutputPath(filePath);

                    if (File.Exists(predictedPath))
                    {
                        issues.Add(new PreflightIssue(PreflightSeverity.Warning, $"Output will be renamed because {Path.GetFileName(predictedPath)} already exists."));
                    }
                }
            }

            if (allFiles.Count > 1)
            {
                issues.Add(new PreflightIssue(PreflightSeverity.Info, $"Batch contains {allFiles.Count} file(s). You can cancel between items if needed."));
            }

            return issues;
        }

        private void DisplayPreflightIssues(List<PreflightIssue> issues)
        {
            _preflightItems.Clear();

            if (issues.Count == 0)
            {
                _preflightItems.Add(new PreflightIssueItem
                {
                    IconGlyph = "\uE73E",
                    SeverityText = "Ready",
                    Message = "No preflight issues detected."
                });
                PreflightSummaryText.Text = "Ready to run";
                return;
            }

            int errorCount = issues.Count(issue => issue.Severity == PreflightSeverity.Error);
            int warningCount = issues.Count(issue => issue.Severity == PreflightSeverity.Warning);
            PreflightSummaryText.Text = errorCount > 0
                ? $"{errorCount} error(s), {warningCount} warning(s)"
                : warningCount > 0
                    ? $"{warningCount} warning(s)"
                    : "Informational checks only";

            foreach (var issue in issues.Take(8))
            {
                _preflightItems.Add(new PreflightIssueItem
                {
                    IconGlyph = issue.Severity switch
                    {
                        PreflightSeverity.Error => "\uEA39",
                        PreflightSeverity.Warning => "\uE7BA",
                        _ => "\uE946"
                    },
                    SeverityText = issue.Severity.ToString(),
                    Message = issue.Message
                });
            }
        }

        private void RefreshPreflightPreview()
        {
            if (_isApplyingProfile)
            {
                return;
            }

            try
            {
                ProcessingRunOptions options = CaptureProcessingRunOptions();
                bool encrypt = !(GetComboContent(_operationModeCombo) ?? string.Empty)
                    .Contains("Hash", StringComparison.OrdinalIgnoreCase);
                DisplayPreflightIssues(BuildPreflightIssues(encrypt, options));
            }
            catch (Exception ex)
            {
                DisplayPreflightIssues(
                [
                    new PreflightIssue(PreflightSeverity.Error, ex.Message)
                ]);
            }
        }

        private static string PredictDecryptedOutputPath(string filePath)
        {
            string directory = Path.GetDirectoryName(filePath)
                ?? throw new InvalidOperationException("File directory is null.");

            string fileName = Path.GetFileNameWithoutExtension(filePath);
            if (filePath.EndsWith(".png", StringComparison.OrdinalIgnoreCase))
            {
                fileName = Path.GetFileNameWithoutExtension(fileName.Replace("_secure", string.Empty, StringComparison.OrdinalIgnoreCase));
            }

            return Path.Combine(directory, fileName);
        }

        private static string GenerateObfuscatedFilename(string originalPath)
        {
            string? directory = Path.GetDirectoryName(originalPath) ?? throw new InvalidOperationException("File directory is null.");
            string randomName = GenerateRandomString(16) + ENCRYPTED_EXTENSION;
            return Path.Combine(directory, randomName);
        }

        private static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);
            }
            return new string([.. random.Select(b => chars[b % chars.Length])]);
        }

        private static int GenerateRandomPaddingSize()
        {
            using var rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[4];
            rng.GetBytes(bytes);
            int random = BitConverter.ToInt32(bytes, 0);
            return MIN_PADDING_SIZE + (Math.Abs(random) % (MAX_PADDING_SIZE - MIN_PADDING_SIZE));
        }

        private static byte[] CompressData(byte[] data, out bool compressed)
        {
            using var output = new MemoryStream();
            using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            {
                gzip.Write(data, 0, data.Length);
            }

            byte[] compressedBytes = output.ToArray();
            compressed = compressedBytes.Length < data.Length - 16; // ensure compression was worthwhile
            return compressed ? compressedBytes : data;
        }

        private static byte[] DecompressData(byte[] compressedData)
        {
            using var input = new MemoryStream(compressedData);
            using var gzip = new GZipStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            gzip.CopyTo(output);
            return output.ToArray();
        }

        private static byte[] BuildEncryptedPayload(byte[] salt, byte[] iv, byte[] tag, byte[] ciphertext)
        {
            byte[] payload = new byte[1 + salt.Length + iv.Length + tag.Length + ciphertext.Length];
            int offset = 0;
            payload[offset++] = FORMAT_VERSION;
            Buffer.BlockCopy(salt, 0, payload, offset, salt.Length);
            offset += salt.Length;
            Buffer.BlockCopy(iv, 0, payload, offset, iv.Length);
            offset += iv.Length;
            Buffer.BlockCopy(tag, 0, payload, offset, tag.Length);
            offset += tag.Length;
            Buffer.BlockCopy(ciphertext, 0, payload, offset, ciphertext.Length);
            return payload;
        }

        private static string BuildOutputPath(string filePath, bool scrambleNames, bool useSteganography)
        {
            string? directory = Path.GetDirectoryName(filePath) ?? throw new InvalidOperationException("File directory is null.");
            string baseName = Path.GetFileName(filePath);

            if (useSteganography)
            {
                string name = scrambleNames ? GenerateRandomString(12) : Path.GetFileNameWithoutExtension(baseName) + "_secure";
                return Path.Combine(directory, name + ".png");
            }

            if (scrambleNames)
            {
                return GenerateObfuscatedFilename(filePath);
            }

            return Path.Combine(directory, baseName + ENCRYPTED_EXTENSION);
        }

        private static byte[] EmbedInPngContainer(byte[] payload)
        {
            int iendIndex = FindIendChunkIndex(StegoCarrierPng);
            if (iendIndex <= 0)
            {
                throw new InvalidDataException("Invalid PNG carrier for steganography mode.");
            }

            byte[] chunk = BuildCustomPngChunk(STEGO_CHUNK_TYPE, payload);
            byte[] result = new byte[StegoCarrierPng.Length + chunk.Length];
            Buffer.BlockCopy(StegoCarrierPng, 0, result, 0, iendIndex);
            Buffer.BlockCopy(chunk, 0, result, iendIndex, chunk.Length);
            Buffer.BlockCopy(StegoCarrierPng, iendIndex, result, iendIndex + chunk.Length, StegoCarrierPng.Length - iendIndex);
            return result;
        }

        private static byte[]? TryExtractStegoPayload(string filePath)
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            if (!IsPng(fileBytes))
            {
                return null;
            }

            int index = 8; // skip signature
            while (index + 8 <= fileBytes.Length)
            {
                int length = BinaryPrimitives.ReadInt32BigEndian(fileBytes.AsSpan(index, 4));
                string type = Encoding.ASCII.GetString(fileBytes, index + 4, 4);
                int dataStart = index + 8;
                if (length < 0 || dataStart + length + 4 > fileBytes.Length)
                {
                    break;
                }
                if (type == STEGO_CHUNK_TYPE)
                {
                    byte[] payload = new byte[length];
                    Buffer.BlockCopy(fileBytes, dataStart, payload, 0, length);
                    return payload;
                }
                index = dataStart + length + 4; // move past data and CRC
            }

            return null;
        }

        private static bool IsPng(ReadOnlySpan<byte> data)
        {
            byte[] signature = [137, 80, 78, 71, 13, 10, 26, 10];
            return data.Length >= signature.Length && data[..signature.Length].SequenceEqual(signature);
        }

        private static int FindIendChunkIndex(byte[] png)
        {
            int index = 8; // skip signature
            while (index + 8 <= png.Length)
            {
                int length = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(index, 4));
                string type = Encoding.ASCII.GetString(png, index + 4, 4);
                if (type == "IEND")
                {
                    return index;
                }

                index += 8 + length + 4;
            }

            return -1;
        }

        private static byte[] BuildCustomPngChunk(string type, byte[] data)
        {
            byte[] typeBytes = Encoding.ASCII.GetBytes(type);
            byte[] chunk = new byte[4 + 4 + data.Length + 4];
            BinaryPrimitives.WriteInt32BigEndian(chunk.AsSpan(0, 4), data.Length);
            Buffer.BlockCopy(typeBytes, 0, chunk, 4, 4);
            Buffer.BlockCopy(data, 0, chunk, 8, data.Length);

            byte[] crcInput = [.. typeBytes, .. data];
            uint crcValue = ComputeCrc32(crcInput);
            byte[] crcBytes = BitConverter.GetBytes(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(crcValue));
            Buffer.BlockCopy(crcBytes, 0, chunk, 8 + data.Length, 4);

            return chunk;
        }

        private static byte[] SerializeMetadata(FileMetadata metadata)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            writer.Write(metadata.OriginalFileName);
            writer.Write(metadata.OriginalSize);
            writer.Write(metadata.CreationTime.ToBinary());
            writer.Write(metadata.LastWriteTime.ToBinary());
            writer.Write(metadata.IsCompressed);
            writer.Write(metadata.IsSteganographyContainer);
            writer.Write(metadata.ContentHash.Length);
            writer.Write(metadata.ContentHash);
            writer.Write(metadata.Algorithm ?? string.Empty);
            writer.Write(metadata.Mode ?? string.Empty);
            writer.Write(metadata.KeySizeBits);
            writer.Write(metadata.CustomNote ?? string.Empty);
            writer.Write(metadata.MetadataLabel ?? string.Empty);
            writer.Write(metadata.LastAccessTime.ToBinary());
            writer.Write((int)metadata.OriginalAttributes);
            return stream.ToArray();
        }

        private static FileMetadata DeserializeMetadata(byte[] data)
        {
            using var stream = new MemoryStream(data);
            using var reader = new BinaryReader(stream);
            var metadata = new FileMetadata
            {
                OriginalFileName = reader.ReadString(),
                OriginalSize = reader.ReadInt64(),
                CreationTime = DateTime.FromBinary(reader.ReadInt64()),
                LastWriteTime = DateTime.FromBinary(reader.ReadInt64()),
                IsCompressed = reader.ReadBoolean()
            };

            if (stream.Position < stream.Length)
            {
                metadata.IsSteganographyContainer = reader.ReadBoolean();
            }

            if (stream.Position < stream.Length)
            {
                int hashLength = reader.ReadInt32();
                if (hashLength > 0 && hashLength <= stream.Length - stream.Position)
                {
                    metadata.ContentHash = reader.ReadBytes(hashLength);
                }
            }

            if (TryReadString(reader, stream, out string algorithm))
            {
                metadata.Algorithm = algorithm;
            }

            if (TryReadString(reader, stream, out string mode))
            {
                metadata.Mode = mode;
            }

            if (stream.Position + sizeof(int) <= stream.Length)
            {
                metadata.KeySizeBits = reader.ReadInt32();
            }

            if (TryReadString(reader, stream, out string note))
            {
                metadata.CustomNote = note;
            }

            if (TryReadString(reader, stream, out string label))
            {
                metadata.MetadataLabel = label;
            }

            if (stream.Position + sizeof(long) <= stream.Length)
            {
                metadata.LastAccessTime = DateTime.FromBinary(reader.ReadInt64());
            }

            if (stream.Position + sizeof(int) <= stream.Length)
            {
                metadata.OriginalAttributes = (System.IO.FileAttributes)reader.ReadInt32();
            }

            return metadata;
        }

        private static bool TryReadString(BinaryReader reader, Stream stream, out string value)
        {
            if (stream.Position < stream.Length)
            {
                value = reader.ReadString();
                return true;
            }

            value = string.Empty;
            return false;
        }

        private static byte[] GenerateRandomBytes(int size)
        {
            byte[] bytes = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        private static byte[] DeriveKeyArgon2(string password, byte[] salt, byte[]? keyfileBytes = null)
        {
            return DeriveKey(password, salt, keyfileBytes, KEY_SIZE);
        }

        private static byte[] DeriveKey(string password, byte[] salt, byte[]? keyfileBytes, int keySize)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] secret = keyfileBytes is { Length: > 0 }
                ? SHA256.HashData([.. passwordBytes, .. keyfileBytes])
                : passwordBytes;

            using var pbkdf2 = new Rfc2898DeriveBytes(secret, salt, 120000, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(keySize);
        }

        private static byte[] ComputeSha256(byte[] data)
        {
            return SHA256.HashData(data);
        }

        private static void EnsureHashMatch(byte[] expectedHash, byte[] data)
        {
            byte[] actualHash = ComputeSha256(data);
            if (!actualHash.SequenceEqual(expectedHash))
            {
                throw new UnauthorizedAccessException("File failed integrity validation after decryption.");
            }
        }

        private static void SecureDelete(string filePath)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                long fileSize = fileInfo.Length;
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write))
                {
                    byte[] randomData = GenerateRandomBytes(4096);
                    for (int pass = 0; pass < 3; pass++)
                    {
                        fs.Seek(0, SeekOrigin.Begin);
                        long written = 0;
                        while (written < fileSize)
                        {
                            int toWrite = (int)Math.Min(randomData.Length, fileSize - written);
                            fs.Write(randomData, 0, toWrite);
                            written += toWrite;
                        }
                        fs.Flush();
                        randomData = GenerateRandomBytes(4096);
                    }
                }
                File.Delete(filePath);
            }
            catch
            {
                try { File.Delete(filePath); } catch { }
            }
        }

        private static void ReadExact(FileStream fs, byte[] buffer, int offset, int count)
        {
            int readTotal = 0;
            while (readTotal < count)
            {
                int read = fs.Read(buffer, offset + readTotal, count - readTotal);
                if (read == 0) throw new EndOfStreamException();
                readTotal += read;
            }
        }

        private void SetUIEnabled(bool enabled)
        {
            _encryptButton.IsEnabled = enabled;
            _decryptButton.IsEnabled = enabled;
            _passwordBox.IsEnabled = enabled;
            _clearListButton.IsEnabled = enabled;
            _dropPanel.AllowDrop = enabled;
            BrowseKeyfileButton.IsEnabled = enabled;
            BrowseBackupFolderButton.IsEnabled = enabled;
            SaveProfileButton.IsEnabled = enabled;
            ProfileCombo.IsEnabled = enabled;
        }

        private void AnimateDropPanel(bool highlight)
        {
            _dropPanel.Background = highlight
                ? GetBrushResource("DropPanelActiveBrush")
                : GetBrushResource("DropPanelBrush");

            _dropPanel.BorderBrush = highlight
                ? GetBrushResource("AccentBrush")
                : GetBrushResource("DropPanelBorderBrush");
        }

        private static Brush GetBrushResource(string key)
        {
            if (Application.Current.Resources.TryGetValue(key, out object? resource) &&
                resource is Brush brush)
            {
                return brush;
            }

            return new SolidColorBrush(Microsoft.UI.Colors.Transparent);
        }

        private class FileMetadata
        {
            public string OriginalFileName { get; set; } = string.Empty;
            public long OriginalSize { get; set; }
            public DateTime CreationTime { get; set; }
            public DateTime LastWriteTime { get; set; }
            public DateTime LastAccessTime { get; set; }
            public System.IO.FileAttributes OriginalAttributes { get; set; } = System.IO.FileAttributes.Normal;
            public bool IsCompressed { get; set; }
            public bool IsSteganographyContainer { get; set; }
            public byte[] ContentHash { get; set; } = [];
            public string Algorithm { get; set; } = string.Empty;
            public string Mode { get; set; } = string.Empty;
            public int KeySizeBits { get; set; }
            public string CustomNote { get; set; } = string.Empty;
            public string MetadataLabel { get; set; } = string.Empty;
        }

        // --- Dialog Helpers ---
        private async Task ShowErrorDialogAsync(string message)
        {
            var dialog = new ContentDialog
            {
                Title = "Error",
                Content = message,
                PrimaryButtonText = "OK",
                XamlRoot = Content.XamlRoot
            };
            await dialog.ShowAsync();
        }

        private async Task ShowInfoDialogAsync(string message, string title)
        {
            var dialog = new ContentDialog
            {
                Title = title,
                Content = message,
                PrimaryButtonText = "OK",
                XamlRoot = Content.XamlRoot
            };
            await dialog.ShowAsync();
        }

        private async Task<bool> ShowConfirmDialogAsync(string message, string title)
        {
            var dialog = new ContentDialog
            {
                Title = title,
                Content = message,
                PrimaryButtonText = "Yes",
                SecondaryButtonText = "No",
                XamlRoot = Content.XamlRoot
            };
            var result = await dialog.ShowAsync();
            return result == ContentDialogResult.Primary;
        }

        private async Task<string?> PromptForTextAsync(string title, string prompt, string defaultValue)
        {
            var inputBox = new TextBox
            {
                Text = defaultValue,
                PlaceholderText = "Name"
            };

            var panel = new StackPanel
            {
                Spacing = 12
            };
            panel.Children.Add(new TextBlock { Text = prompt, TextWrapping = TextWrapping.Wrap });
            panel.Children.Add(inputBox);

            var dialog = new ContentDialog
            {
                Title = title,
                Content = panel,
                PrimaryButtonText = "Save",
                SecondaryButtonText = "Cancel",
                XamlRoot = Content.XamlRoot
            };

            var result = await dialog.ShowAsync();
            return result == ContentDialogResult.Primary ? inputBox.Text : null;
        }

        private async Task StartAutomaticUpdateCheckAsync()
        {
            if (_hasStartedAutomaticUpdateCheck)
            {
                return;
            }

            _hasStartedAutomaticUpdateCheck = true;

            if (!UpdateService.ShouldPerformAutomaticCheck(_updateSettings, DateTimeOffset.UtcNow))
            {
                SetAboutUpdateStatusText("Updates: automatic checks enabled");
                return;
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
            await CheckForUpdatesAsync(isManualCheck: false);
        }

        private async Task CheckForUpdatesAsync(bool isManualCheck)
        {
            if (_isCheckingForUpdates || _isDownloadingUpdate)
            {
                return;
            }

            try
            {
                _isCheckingForUpdates = true;
                SetAboutUpdateStatusText("Updates: checking...");

                UpdateCheckResult result = await UpdateService.CheckForUpdatesAsync(CancellationToken.None);
                _updateSettings.LastCheckedUtc = DateTimeOffset.UtcNow;
                UpdateService.SaveSettings(_updateSettings);

                if (!result.IsUpdateAvailable || result.Release == null)
                {
                    _updateSettings.SkippedVersion = null;
                    UpdateService.SaveSettings(_updateSettings);
                    SetAboutUpdateStatusText(result.StatusMessage);

                    if (isManualCheck)
                    {
                        await ShowInfoDialogAsync(result.StatusMessage, "Updates");
                    }

                    return;
                }

                if (string.Equals(_updateSettings.SkippedVersion, result.Release.DisplayVersion, StringComparison.OrdinalIgnoreCase))
                {
                    SetAboutUpdateStatusText($"Update available: {result.Release.DisplayVersion} (skipped)");
                    if (!isManualCheck)
                    {
                        return;
                    }
                }
                else
                {
                    SetAboutUpdateStatusText($"Update available: {result.Release.DisplayVersion}");
                }

                await PromptToInstallUpdateAsync(result.Release, isManualCheck);
            }
            catch (Exception ex)
            {
                SetAboutUpdateStatusText("Updates: check failed");
                if (isManualCheck)
                {
                    await ShowErrorDialogAsync($"Unable to check for updates:\n{ex.Message}");
                }
            }
            finally
            {
                _isCheckingForUpdates = false;
            }
        }

        private async Task PromptToInstallUpdateAsync(UpdateReleaseInfo release, bool isManualCheck)
        {
            var panel = new StackPanel
            {
                Spacing = 12,
                MaxWidth = 520
            };

            panel.Children.Add(new TextBlock
            {
                Text = $"FileLocker {release.DisplayVersion} is available. You are currently running {UpdateService.GetCurrentVersionLabel()}.",
                TextWrapping = TextWrapping.WrapWholeWords
            });

            panel.Children.Add(new TextBlock
            {
                Text = "Release notes",
                FontWeight = FontWeights.SemiBold
            });

            panel.Children.Add(new ScrollViewer
            {
                MaxHeight = 240,
                Content = new TextBlock
                {
                    Text = string.IsNullOrWhiteSpace(release.Notes)
                        ? "No release notes were provided for this release."
                        : release.Notes,
                    IsTextSelectionEnabled = true,
                    TextWrapping = TextWrapping.WrapWholeWords
                }
            });

            var dialog = new ContentDialog
            {
                Title = "Update Available",
                Content = panel,
                PrimaryButtonText = "Download && Install",
                SecondaryButtonText = "View Release",
                CloseButtonText = isManualCheck ? "Not Now" : "Skip This Version",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = Content.XamlRoot
            };

            ContentDialogResult result = await dialog.ShowAsync();

            if (result == ContentDialogResult.Primary)
            {
                await DownloadAndInstallUpdateAsync(release);
                return;
            }

            if (result == ContentDialogResult.Secondary)
            {
                OpenWithShell(release.HtmlUrl);
                return;
            }

            if (!isManualCheck)
            {
                _updateSettings.SkippedVersion = release.DisplayVersion;
                UpdateService.SaveSettings(_updateSettings);
                SetAboutUpdateStatusText($"Update available: {release.DisplayVersion} (skipped)");
            }
        }

        private async Task DownloadAndInstallUpdateAsync(UpdateReleaseInfo release)
        {
            try
            {
                _isDownloadingUpdate = true;
                SetAboutUpdateStatusText($"Updates: downloading {release.DisplayVersion}...");
                SetStatus($"Downloading FileLocker {release.DisplayVersion} update...");

                string installerPath = await UpdateService.DownloadInstallerAsync(release, CancellationToken.None);

                _updateSettings.SkippedVersion = null;
                UpdateService.SaveSettings(_updateSettings);

                SetAboutUpdateStatusText($"Updates: ready to install {release.DisplayVersion}");
                SetStatus($"Launching FileLocker {release.DisplayVersion} installer...");
                LaunchInstallerAndExit(installerPath);
            }
            catch (Exception ex)
            {
                SetAboutUpdateStatusText("Updates: download failed");
                await ShowErrorDialogAsync($"Unable to download the update:\n{ex.Message}");
            }
            finally
            {
                _isDownloadingUpdate = false;
            }
        }

        private void LaunchInstallerAndExit(string installerPath)
        {
            string escapedInstallerPath = installerPath.Replace("\"", "\"\"", StringComparison.Ordinal);

            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c timeout /t 2 /nobreak >nul & start \"\" \"{escapedInstallerPath}\"",
                CreateNoWindow = true,
                UseShellExecute = false
            });

            Close();
        }

        private void SetAboutUpdateStatusText(string text)
        {
            _aboutUpdateStatusText = text;
            AboutUpdateStatusMenuItem.Text = text;
        }

        private async void BrowseKeyfileButton_Click(object sender, RoutedEventArgs e)
        {
            var picker = new FileOpenPicker();
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");

            StorageFile? file = await picker.PickSingleFileAsync();
            if (file != null)
            {
                KeyfilePathBox.Text = file.Path;
                SetStatus($"Keyfile selected: {Path.GetFileName(file.Path)}");
            }
        }

        private async void BrowseBackupFolderButton_Click(object sender, RoutedEventArgs e)
        {
            var picker = new FolderPicker();
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
            picker.FileTypeFilter.Add("*");

            StorageFolder? folder = await picker.PickSingleFolderAsync();
            if (folder != null)
            {
                BackupFolderBox.Text = folder.Path;
                SetStatus($"Backup folder selected: {folder.Name}");
            }
        }

        private void KeyfilePathBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!_isUiReady) return;
            RefreshPreflightPreview();
        }

        private void BackupFolderBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!_isUiReady) return;
            RefreshPreflightPreview();
        }

        private void SafetyOption_Toggled(object sender, RoutedEventArgs e)
        {
            if (!_isUiReady)
            {
                return;
            }

            SecureDeleteOriginalsToggle.IsEnabled = RemoveOriginalsToggle.IsOn;
            if (!RemoveOriginalsToggle.IsOn)
            {
                SecureDeleteOriginalsToggle.IsOn = false;
            }

            RefreshPreflightPreview();
        }

        private void CancelRunButton_Click(object sender, RoutedEventArgs e)
        {
            if (_isProcessing)
            {
                _processingCancellation?.Cancel();
                SetStatus("Cancellation requested. The current item will finish before the queue stops.");
            }
        }

        private async void ExportMarkdownButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OperationHistoryEntry entry = GetSelectedHistoryEntry();
                string? path = await SaveReportWithPickerAsync(entry, "md", BuildMarkdownReport(entry));
                if (!string.IsNullOrWhiteSpace(path))
                {
                    await ShowInfoDialogAsync($"Markdown report saved to:\n{path}", "Report Exported");
                }
            }
            catch (Exception ex)
            {
                await ShowErrorDialogAsync($"Unable to export Markdown report: {ex.Message}");
            }
        }

        private async void ExportCsvButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OperationHistoryEntry entry = GetSelectedHistoryEntry();
                string? path = await SaveReportWithPickerAsync(entry, "csv", BuildCsvReport(entry));
                if (!string.IsNullOrWhiteSpace(path))
                {
                    await ShowInfoDialogAsync($"CSV report saved to:\n{path}", "Report Exported");
                }
            }
            catch (Exception ex)
            {
                await ShowErrorDialogAsync($"Unable to export CSV report: {ex.Message}");
            }
        }

        private OperationHistoryEntry GetSelectedHistoryEntry()
        {
            string? selectedId = (RecentJobsListView.SelectedItem as JobHistoryItem)?.Id
                ?? _jobHistoryItems.FirstOrDefault()?.Id;

            if (string.IsNullOrWhiteSpace(selectedId))
            {
                throw new InvalidOperationException("There is no job history to export yet.");
            }

            return _operationHistory.First(history => history.Id == selectedId);
        }

        private async Task<string?> SaveReportWithPickerAsync(OperationHistoryEntry entry, string format, string contents)
        {
            string safeOperation = entry.Operation.Replace(" ", "_", StringComparison.OrdinalIgnoreCase).ToLowerInvariant();
            string fileName = $"{safeOperation}_{entry.TimestampUtc:yyyyMMdd_HHmmss}.{format}";
            var picker = new FileSavePicker
            {
                SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
                SuggestedFileName = Path.GetFileNameWithoutExtension(fileName)
            };
            picker.FileTypeChoices.Add(
                string.Equals(format, "md", StringComparison.OrdinalIgnoreCase) ? "Markdown Report" : "CSV Report",
                [$".{format}"]);
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));

            StorageFile? file = await picker.PickSaveFileAsync();
            if (file == null)
            {
                return null;
            }

            File.WriteAllText(file.Path, contents);
            return file.Path;
        }

        private static string BuildMarkdownReport(OperationHistoryEntry entry)
        {
            var builder = new StringBuilder();
            builder.AppendLine($"# FileLocker {entry.Operation} Report");
            builder.AppendLine();
            builder.AppendLine($"- Timestamp: {entry.TimestampUtc.ToLocalTime():f}");
            builder.AppendLine($"- Profile: {entry.ProfileName}");
            builder.AppendLine($"- Algorithm: {entry.Algorithm} ({entry.KeySizeBits}-bit)");
            builder.AppendLine($"- Keyfile used: {(entry.UsedKeyfile ? "Yes" : "No")}");
            builder.AppendLine($"- Originals removed: {(entry.RemoveOriginalsAfterSuccess ? "Yes" : "No")}");
            builder.AppendLine($"- Secure delete: {(entry.SecureDeleteOriginals ? "Yes" : "No")}");
            builder.AppendLine($"- Verify after write: {(entry.VerifyAfterWrite ? "Yes" : "No")}");
            builder.AppendLine($"- Backup folder: {(string.IsNullOrWhiteSpace(entry.BackupFolderPath) ? "Not configured" : entry.BackupFolderPath)}");
            builder.AppendLine();
            builder.AppendLine("| Source | Output | Status | Message |");
            builder.AppendLine("| --- | --- | --- | --- |");

            foreach (var result in entry.Results)
            {
                builder.AppendLine($"| {EscapeMarkdown(result.SourcePath)} | {EscapeMarkdown(result.OutputPath ?? "-")} | {result.Status} | {EscapeMarkdown(result.Message ?? "-")} |");
            }

            return builder.ToString();
        }

        private static string BuildCsvReport(OperationHistoryEntry entry)
        {
            var builder = new StringBuilder();
            builder.AppendLine("SourcePath,OutputPath,Status,Message,BackupPath,OriginalRetained,OutputVerified");

            foreach (var result in entry.Results)
            {
                builder.AppendLine(string.Join(",",
                    EscapeCsv(result.SourcePath),
                    EscapeCsv(result.OutputPath ?? string.Empty),
                    EscapeCsv(result.Status),
                    EscapeCsv(result.Message ?? string.Empty),
                    EscapeCsv(result.BackupPath ?? string.Empty),
                    result.OriginalRetained ? "true" : "false",
                    result.OutputVerified ? "true" : "false"));
            }

            return builder.ToString();
        }

        private static string EscapeMarkdown(string text)
        {
            return text.Replace("|", "\\|", StringComparison.Ordinal);
        }

        private static string EscapeCsv(string text)
        {
            if (text.Contains(',') || text.Contains('"') || text.Contains('\n') || text.Contains('\r'))
            {
                return $"\"{text.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
            }

            return text;
        }

        private async void About_Click(object sender, RoutedEventArgs e)
        {
            UpdateAboutMenuInfo();
            FlyoutBase.ShowAttachedFlyout(AboutButton);
            await Task.CompletedTask;
        }

        private async void CheckForUpdatesMenuItem_Click(object sender, RoutedEventArgs e)
        {
            await CheckForUpdatesAsync(isManualCheck: true);
        }

        private void OpenGitHubMenuItem_Click(object sender, RoutedEventArgs e)
        {
            OpenWithShell(UpdateService.GitHubRepositoryUrl);
        }

        private void OpenReportsFolderMenuItem_Click(object sender, RoutedEventArgs e)
        {
            OpenWithShell(GetReportsDirectory());
        }

        private void OpenAppDataFolderMenuItem_Click(object sender, RoutedEventArgs e)
        {
            OpenWithShell(GetAppDataDirectory());
        }

        private static void OpenWithShell(string target)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = target,
                UseShellExecute = true
            });
        }

        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            // Minimize window
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            ShowWindow(hwnd, 2); // SW_MINIMIZE
        }

        private void MaximizeRestore_Click(object sender, RoutedEventArgs e)
        {
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            var placement = GetWindowPlacement(hwnd);
            if (placement.showCmd == 3) // SW_MAXIMIZE
            {
                ShowWindow(hwnd, 9); // SW_RESTORE
            }
            else
            {
                ShowWindow(hwnd, 3); // SW_MAXIMIZE
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        // P/Invoke for window controls
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool GetWindowPlacement(IntPtr hWnd, ref WINDOWPLACEMENT lpwndpl);

        private static WINDOWPLACEMENT GetWindowPlacement(IntPtr hwnd)
        {
            WINDOWPLACEMENT placement = new();
            placement.length = System.Runtime.InteropServices.Marshal.SizeOf(placement);
            GetWindowPlacement(hwnd, ref placement);
            return placement;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct WINDOWPLACEMENT
        {
            public int length;
            public int flags;
            public int showCmd;
            public System.Drawing.Point ptMinPosition;
            public System.Drawing.Point ptMaxPosition;
            public System.Drawing.Rectangle rcNormalPosition;
        }

        // Advanced options event handlers
        private void CompressModeToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleSwitch toggleSwitch)
            {
                IsCompressModeEnabled = toggleSwitch.IsOn;
            }

            if (!_isUiReady) return;
            RefreshPreflightPreview();
        }

        private void ScrambleNamesToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleSwitch toggleSwitch)
            {
                IsScrambleNamesEnabled = toggleSwitch.IsOn;
            }

            if (!_isUiReady) return;
            RefreshPreflightPreview();
        }

        private void SteganographyToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleSwitch toggleSwitch)
            {
                IsSteganographyEnabled = toggleSwitch.IsOn;
            }

            if (!_isUiReady) return;
            RefreshPreflightPreview();
        }
        private static List<string> ExpandPathsToFiles(IEnumerable<string> paths)
        {
            var allFiles = new List<string>();
            foreach (var path in paths)
            {
                if (File.Exists(path))
                {
                    allFiles.Add(path);
                }
                else if (Directory.Exists(path))
                {
                    try
                    {
                        allFiles.AddRange(Directory.GetFiles(path, "*", SearchOption.AllDirectories));
                    }
                    catch
                    {
                        // Optionally handle access exceptions or log
                    }
                }
            }
            return allFiles;
        }
        // At class level:
        private static readonly uint[] Crc32Table = CreateCrc32Table();

        private static uint[] CreateCrc32Table()
        {
            const uint Polynomial = 0xEDB88320u;
            var table = new uint[256];

            for (uint i = 0; i < table.Length; i++)
            {
                uint crc = i;
                for (int j = 0; j < 8; j++)
                {
                    if ((crc & 1) != 0)
                        crc = (crc >> 1) ^ Polynomial;
                    else
                        crc >>= 1;
                }
                table[i] = crc;
            }

            return table;
        }

        private static uint ComputeCrc32(byte[] data)
        {
            uint result = 0xFFFFFFFFu;
            foreach (byte b in data)
            {
                result = (result >> 8) ^ Crc32Table[(result ^ b) & 0xFF];
            }
            return ~result;
        }

        // Add this method to your MainWindow class to resolve CS0103 for InitializeComponent

    }
}
