using FileLocker;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;


namespace FileLockerWinUI
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
        private static readonly byte[] StegoCarrierPng = Convert.FromBase64String(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII=");

        private readonly List<string> selectedPaths = new();
        private readonly Updater _updater = new();
        private bool isDarkTheme = true;
        public ObservableCollection<string> FileList { get; set; } = new();
        public string StatusText { get; set; } = "Ready - Add files to begin";
        private TextBlock DropLabelControler;
        private AppWindow? _appWindow;
        private XamlRoot _xamlRoot;

        // UI element references (resolved after InitializeComponent)
        private ListView _fileListBox = null!;
        private Button _themeToggleButton = null!;
        private TextBlock _dropLabel = null!;
        private TextBlock _statusLabel = null!;
        private PasswordBox _passwordBox = null!;
        private ProgressBar _passwordStrengthBar = null!;
        private TextBlock _passwordStrengthText = null!;
        private Button _encryptButton = null!;
        private Button _decryptButton = null!;
        private Button _clearListButton = null!;
        private Border _dropPanel = null!;
        private ComboBox _operationModeCombo = null!;
        private ComboBox _algorithmCombo = null!;
        private ComboBox _keySizeCombo = null!;
        private StackPanel _hashHelperPanel = null!;
        private TextBox _hashInputBox = null!;
        private TextBox _hashOutputBox = null!;
        private TextBox _metadataNameBox = null!;
        private TextBox _metadataNotesBox = null!;
        private TextBox _metadataCreatedBox = null!;
        private TextBox _metadataModifiedBox = null!;
        private ToggleSwitch _metadataRandomizeToggle = null!;
        private TextBlock _metadataHelperText = null!;
        private TextBlock _algorithmHintText = null!;
        private Button _recommendedModeButton = null!;

        // Advanced options properties
        public bool IsCompressModeEnabled { get; set; } = true;
        public bool IsScrambleNamesEnabled { get; set; } = false;
        public bool IsSteganographyEnabled { get; set; } = false;
        private readonly Random _random = new();
        private readonly string[] _encryptionAlgorithms = new[] { "AES-GCM", "AES-CBC" };
        private readonly string[] _hashAlgorithms = new[] { "SHA-256", "SHA-512", "Base64" };

        private record struct PasswordStrengthResult(
            int Score,
            string Feedback,
            Windows.UI.Color BarColor);

        public MainWindow()
        {
            InitializeComponent();
            var root = Content as FrameworkElement ?? throw new InvalidOperationException("Window content not loaded.");

            var hWnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hWnd);
            var appWindow = AppWindow.GetFromWindowId(windowId);

            // Set minimum size
            if (appWindow != null)
            {
                // Ensure presenter and optional initial size/icon
                appWindow.SetPresenter(AppWindowPresenterKind.Default);
                appWindow.ResizeClient(new SizeInt32(600, 900)); // optional initial size
                appWindow.SetIcon(null); // ignore if you set an icon elsewhere

                // Enforce a minimum size by listening for size changes and resizing back when smaller.
                var minSize = new SizeInt32(600, 900);
                appWindow.Changed += (s, args) =>
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
                        // Swallow exceptions to avoid crashing the UI thread if resizing fails
                    }
                };
            }

            _fileListBox = GetElement<ListView>(root, nameof(FileListBox));
            _themeToggleButton = GetElement<Button>(root, nameof(ThemeToggleButton));
            _dropLabel = GetElement<TextBlock>(root, nameof(DropLabel));
            _statusLabel = GetElement<TextBlock>(root, nameof(StatusLabel));
            _passwordBox = GetElement<PasswordBox>(root, nameof(PasswordBox));
            _passwordStrengthBar = GetElement<ProgressBar>(root, nameof(PasswordStrengthBar));
            _passwordStrengthText = GetElement<TextBlock>(root, nameof(PasswordStrengthText));
            _encryptButton = GetElement<Button>(root, nameof(EncryptButton));
            _decryptButton = GetElement<Button>(root, nameof(DecryptButton));
            _clearListButton = GetElement<Button>(root, nameof(ClearListButton));
            _dropPanel = GetElement<Border>(root, nameof(DropPanel));
            _operationModeCombo = GetElement<ComboBox>(root, nameof(OperationModeCombo));
            _algorithmCombo = GetElement<ComboBox>(root, nameof(AlgorithmCombo));
            _keySizeCombo = GetElement<ComboBox>(root, nameof(KeySizeCombo));
            _hashHelperPanel = GetElement<StackPanel>(root, nameof(HashHelperPanel));
            _hashInputBox = GetElement<TextBox>(root, nameof(HashInputBox));
            _hashOutputBox = GetElement<TextBox>(root, nameof(HashOutputBox));
            _metadataNameBox = GetElement<TextBox>(root, nameof(MetadataNameBox));
            _metadataNotesBox = GetElement<TextBox>(root, nameof(MetadataNotesBox));
            _metadataCreatedBox = GetElement<TextBox>(root, nameof(MetadataCreatedBox));
            _metadataModifiedBox = GetElement<TextBox>(root, nameof(MetadataModifiedBox));
            _metadataRandomizeToggle = GetElement<ToggleSwitch>(root, nameof(MetadataRandomizeToggle));
            _metadataHelperText = GetElement<TextBlock>(root, nameof(MetadataHelperText));
            _algorithmHintText = GetElement<TextBlock>(root, nameof(AlgorithmHintText));
            _recommendedModeButton = GetElement<Button>(root, nameof(RecommendedModeButton));

            _xamlRoot = root.XamlRoot;
            _fileListBox.ItemsSource = FileList;
            isDarkTheme = true;
            _themeToggleButton.Content = "🌙";
            UpdateStatusLabel();
            ConfigureModeOptions();

            // Set window size to 600x800
            InitializeAppWindow();

            // Initialize DropLabel controller using the on-screen label so drag cues stay in sync
            DropLabelControler = _dropLabel;

        }

        private static TElement GetElement<TElement>(FrameworkElement root, string name) where TElement : class
        {
            return root.FindName(name) as TElement
                ?? throw new InvalidOperationException($"Unable to locate element '{name}'.");
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
                button.Content = isDarkTheme ? "🌙" : "☀️";

                if (Content is FrameworkElement root)
                {
                    root.RequestedTheme = isDarkTheme ? ElementTheme.Dark : ElementTheme.Light;
                }
            }
        }


        // --- Drag & Drop ---
        private void DropPanel_DragOver(object sender, DragEventArgs e)
        {
            if (e.DataView.Contains(StandardDataFormats.StorageItems))
            {
                e.AcceptedOperation = DataPackageOperation.Copy;
                AnimateDropPanel(true);
                DropLabelControler.Text = "🟢 Release to add files";
                DropLabelControler.FontWeight = FontWeights.Bold;
            }
        }

        private async void DropPanel_Drop(object sender, DragEventArgs e)
        {
            AnimateDropPanel(false);
            DropLabelControler.Text = "📁 Drag files here or click to browse";
            DropLabelControler.FontWeight = FontWeights.Normal;

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
                    AddFilesToList(files.ToArray());
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
            foreach (string path in paths)
            {
                if (!selectedPaths.Contains(path))
                {
                    selectedPaths.Add(path);
                    string displayName = Path.GetFileName(path);
                    if (Directory.Exists(path))
                        displayName += " (Folder)";
                    if (File.Exists(path))
                    {
                        var fileInfo = new FileInfo(path);
                        displayName += $" ({FormatFileSize(fileInfo.Length)})";
                    }
                    FileList.Add(displayName);
                }
            }
            UpdateStatusLabel();
        }

        private string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB" };
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
            FileList.Clear();
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
                SetStatus("Ready - No files selected");
            else
                SetStatus($"Ready - {selectedPaths.Count} item(s) selected");
        }

        private void OperationModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_algorithmHintText == null) return;
            ConfigureModeOptions();
        }

        private void AlgorithmCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_algorithmHintText == null) return;
            UpdateKeySizeInteractivity();
            UpdateAlgorithmHelper();
        }

        private void KeySizeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_algorithmHintText == null) return;
            UpdateAlgorithmHelper();
        }

        private void RecommendedModeButton_Click(object sender, RoutedEventArgs e)
        {
            SetComboSelection(_operationModeCombo, "Encrypt / Decrypt");
            ConfigureModeOptions();
            SetComboSelection(_algorithmCombo, "AES-GCM");
            SetComboSelection(_keySizeCombo, "256");
            UpdateAlgorithmHelper();
            SetStatus("Recommended mode applied: AES-256-GCM");
        }

        private void ConfigureModeOptions()
        {
            string mode = GetComboContent(_operationModeCombo) ?? "Encrypt / Decrypt";
            bool isHashMode = mode.Contains("Hash", StringComparison.OrdinalIgnoreCase);
            string? previousAlgorithm = GetComboContent(_algorithmCombo);

            PopulateComboWithValues(_algorithmCombo, isHashMode ? _hashAlgorithms : _encryptionAlgorithms, previousAlgorithm);
            PopulateKeySizes(isHashMode);
            _hashHelperPanel.Visibility = isHashMode ? Visibility.Visible : Visibility.Collapsed;
            _recommendedModeButton.Visibility = isHashMode ? Visibility.Collapsed : Visibility.Visible;
            UpdateKeySizeInteractivity();
            UpdateAlgorithmHelper();
        }

        private void PopulateComboWithValues(ComboBox comboBox, IEnumerable<string> values, string? preferredSelection)
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
            int[] sizes = isHashMode ? new[] { 256, 512 } : new[] { 128, 192, 256 };
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

        private PasswordStrengthResult CalculatePasswordStrength(string password)
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
            string[] commonPasswords = { "password", "123456", "qwerty", "letmein", "welcome", "admin" };
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
                string output = await Task.Run(() => RunHashOrEncode(input, algorithm, keySize));
                _hashOutputBox.Text = output;
                SetStatus($"Generated output using {algorithm} ({keySize}-bit)");
            }
            catch (Exception ex)
            {
                await ShowErrorDialogAsync($"Failed to generate output: {ex.Message}");
            }
        }

        private string RunHashOrEncode(string input, string algorithm, int keySize)
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

            return EncryptTextWithAes(inputBytes, algorithm, keySize);
        }

        private string EncryptTextWithAes(byte[] inputBytes, string algorithm, int keySize)
        {
            if (string.IsNullOrWhiteSpace(_passwordBox.Password))
            {
                throw new InvalidOperationException("Enter a password for AES-based helpers.");
            }

            byte[] salt = GenerateRandomBytes(16);
            int keySizeBytes = Math.Max(16, keySize / 8);
            byte[] key = new Rfc2898DeriveBytes(_passwordBox.Password, salt, 80000, HashAlgorithmName.SHA256).GetBytes(keySizeBytes);

            if (algorithm.Contains("GCM", StringComparison.OrdinalIgnoreCase))
            {
                return EncodeAesGcmPayload(inputBytes, key, salt, keySize);
            }

            return EncodeAesCbcPayload(inputBytes, key, salt, keySize);
        }

        private string EncodeAesGcmPayload(byte[] inputBytes, byte[] key, byte[] salt, int keySize)
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

        private string EncodeAesCbcPayload(byte[] inputBytes, byte[] key, byte[] salt, int keySize)
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = Math.Min(keySize, 256);
            aes.Key = key;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            byte[] ciphertext = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
            return EncodeLabeledPayload("AES-CBC", keySize, salt, aes.IV, Array.Empty<byte>(), ciphertext);
        }

        private string EncodeLabeledPayload(string label, int keySize, byte[] salt, byte[] iv, byte[] tag, byte[] ciphertext)
        {
            using var stream = new MemoryStream();
            WriteLengthPrefixed(stream, salt);
            WriteLengthPrefixed(stream, iv);
            WriteLengthPrefixed(stream, tag);
            WriteLengthPrefixed(stream, ciphertext);

            return $"{label} ({keySize}-bit): {Convert.ToBase64String(stream.ToArray())}";
        }

        private void WriteLengthPrefixed(Stream stream, byte[] data)
        {
            ushort length = (ushort)data.Length;
            stream.Write(BitConverter.GetBytes(length), 0, sizeof(ushort));
            stream.Write(data, 0, data.Length);
        }

        private void ApplyMetadataOverrides(FileMetadata metadata, string filePath)
        {
            metadata.MetadataLabel = string.IsNullOrWhiteSpace(_metadataNameBox.Text)
                ? metadata.OriginalFileName
                : _metadataNameBox.Text.Trim();
            metadata.OriginalFileName = metadata.MetadataLabel;
            metadata.CustomNote = _metadataNotesBox.Text?.Trim() ?? string.Empty;
            metadata.Algorithm = GetComboContent(_algorithmCombo) ?? "AES-GCM";
            metadata.Mode = GetComboContent(_operationModeCombo) ?? "Encrypt / Decrypt";
            metadata.KeySizeBits = ParseKeySizeSelection();

            if (_metadataRandomizeToggle.IsOn)
            {
                var (created, modified) = GenerateRandomizedDates();
                metadata.CreationTime = created;
                metadata.LastWriteTime = modified;
                _metadataHelperText.Text = "Metadata randomized for this session.";
            }
            else
            {
                metadata.CreationTime = ParseDateOrDefault(_metadataCreatedBox.Text, File.GetCreationTime(filePath));
                metadata.LastWriteTime = ParseDateOrDefault(_metadataModifiedBox.Text, File.GetLastWriteTime(filePath));
                _metadataHelperText.Text = "Overrides stored alongside encrypted payload for auditing.";
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
            if (_metadataRandomizeToggle.IsOn)
            {
                ApplyRandomizedMetadataFields();
            }
            else
            {
                _metadataHelperText.Text = "Manual metadata values will be used.";
            }
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
        }

        private string GenerateRandomAlias()
        {
            byte[] aliasBytes = GenerateRandomBytes(6);
            return $"meta-{Convert.ToHexString(aliasBytes).ToLowerInvariant()}";
        }

        private DateTime ParseDateOrDefault(string? input, DateTime fallback)
        {
            if (!string.IsNullOrWhiteSpace(input) &&
                DateTime.TryParse(input, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out DateTime parsed))
            {
                return parsed;
            }

            return fallback;
        }

        private string? GetComboContent(ComboBox comboBox)
        {
            if (comboBox.SelectedItem is ComboBoxItem item && item.Content is string text)
            {
                return text;
            }

            return comboBox.SelectedValue as string;
        }

        private void SetComboSelection(ComboBox comboBox, string content)
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
            PasswordBox.PasswordRevealMode = PasswordRevealMode.Visible;
        }

        private void ShowPasswordCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            PasswordBox.PasswordRevealMode = PasswordRevealMode.Peek;
        }

        private async Task ProcessFilesAsync(bool encrypt)
        {
            try
            {
                SetUIEnabled(false);

                // Capture password on UI thread before starting background tasks
                string password = _passwordBox.Password;

                var allFiles = ExpandPathsToFiles(selectedPaths);
                int processed = 0;

                foreach (string filePath in allFiles)
                {
                    try
                    {
                        if (encrypt)
                        {
                            await Task.Run(() => EncryptFileAdvanced(filePath, password));
                        }
                        else
                        {
                            await Task.Run(() => DecryptFileAdvanced(filePath, password));
                        }

                        processed++;
                        SetStatus($"Processed {processed}/{allFiles.Count} files...");
                    }
                    catch (Exception ex)
                    {
                        await ShowErrorDialogAsync($"Error processing {Path.GetFileName(filePath)}: {ex.Message}");
                    }
                }

                SetStatus($"Completed! Processed {processed} files.");

                // Clear the list after successful processing
                selectedPaths.Clear();
                FileList.Clear();
                UpdateStatusLabel();
            }
            catch (Exception ex)
            {
                await ShowErrorDialogAsync($"Error: {ex.Message}");
            }
            finally
            {
                SetUIEnabled(true);
            }
        }

        // --- Encryption/Decryption Logic ---
        private void EncryptFileAdvanced(string filePath, string password)
        {
            try
            {
                bool scrambleNames = IsScrambleNamesEnabled;
                bool useSteganography = IsSteganographyEnabled;
                byte[] salt = GenerateRandomBytes(SALT_SIZE);
                byte[] iv = GenerateRandomBytes(IV_SIZE);
                byte[] key = DeriveKeyArgon2(password, salt);
                byte[] fileData = File.ReadAllBytes(filePath);
                string originalFileName = Path.GetFileName(filePath) ?? string.Empty;

                FileMetadata metadata = new FileMetadata
                {
                    OriginalFileName = originalFileName,
                    OriginalSize = fileData.Length,
                    CreationTime = File.GetCreationTime(filePath),
                    LastWriteTime = File.GetLastWriteTime(filePath),
                    IsSteganographyContainer = useSteganography
                };

                ApplyMetadataOverrides(metadata, filePath);

                byte[] dataToEncrypt = fileData;
                if (IsCompressModeEnabled)
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
                string encryptedPath = BuildOutputPath(filePath, scrambleNames, useSteganography);
                byte[] outputBytes = useSteganography ? EmbedInPngContainer(payload) : payload;

                File.WriteAllBytes(encryptedPath, outputBytes);
                File.SetCreationTime(encryptedPath, new DateTime(2020, 1, 1));
                File.SetLastWriteTime(encryptedPath, new DateTime(2020, 1, 1));
                SecureDelete(filePath);
            }
            catch (Exception ex)
            {
                throw new Exception($"Encryption failed: {ex.Message}");
            }
        }

        private void DecryptFileAdvanced(string filePath, string password)
        {
            byte[] encryptedBytes = TryExtractStegoPayload(filePath) ?? File.ReadAllBytes(filePath);

            using (var fs = new MemoryStream(encryptedBytes))
            {
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
                byte[] key = DeriveKeyArgon2(password, salt);
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

                string? directory = Path.GetDirectoryName(filePath);
                if (directory == null) throw new InvalidOperationException("File directory is null.");
                string originalPath = Path.Combine(directory, metadata.OriginalFileName ?? "output");
                int counter = 1;
                string finalPath = originalPath;
                while (File.Exists(finalPath))
                {
                    string name = Path.GetFileNameWithoutExtension(originalPath);
                    string ext = Path.GetExtension(originalPath);
                    finalPath = Path.Combine(directory, $"{name}_{counter}{ext}");
                    counter++;
                }
                File.WriteAllBytes(finalPath, fileData);
                File.SetCreationTime(finalPath, metadata.CreationTime);
                File.SetLastWriteTime(finalPath, metadata.LastWriteTime);
            }

            SecureDelete(filePath);
        }

        private void ReadExact(MemoryStream fs, byte[] buffer, int offset, int count)
        {
            int readTotal = 0;
            while (readTotal < count)
            {
                int read = fs.Read(buffer, offset + readTotal, count - readTotal);
                if (read == 0) throw new EndOfStreamException();
                readTotal += read;
            }
        }

        private string GenerateObfuscatedFilename(string originalPath)
        {
            string? directory = Path.GetDirectoryName(originalPath);
            if (directory == null)
                throw new InvalidOperationException("File directory is null.");
            string randomName = GenerateRandomString(16) + ENCRYPTED_EXTENSION;
            return Path.Combine(directory, randomName);
        }

        private string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);
            }
            return new string(random.Select(b => chars[b % chars.Length]).ToArray());
        }

        private int GenerateRandomPaddingSize()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[4];
                rng.GetBytes(bytes);
                int random = BitConverter.ToInt32(bytes, 0);
                return MIN_PADDING_SIZE + (Math.Abs(random) % (MAX_PADDING_SIZE - MIN_PADDING_SIZE));
            }
        }

        private byte[] CompressData(byte[] data, out bool compressed)
        {
            using (var output = new MemoryStream())
            {
                using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
                {
                    gzip.Write(data, 0, data.Length);
                }

                byte[] compressedBytes = output.ToArray();
                compressed = compressedBytes.Length < data.Length - 16; // ensure compression was worthwhile
                return compressed ? compressedBytes : data;
            }
        }

        private byte[] DecompressData(byte[] compressedData)
        {
            using (var input = new MemoryStream(compressedData))
            using (var gzip = new GZipStream(input, CompressionMode.Decompress))
            using (var output = new MemoryStream())
            {
                gzip.CopyTo(output);
                return output.ToArray();
            }
        }

        private byte[] BuildEncryptedPayload(byte[] salt, byte[] iv, byte[] tag, byte[] ciphertext)
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

        private string BuildOutputPath(string filePath, bool scrambleNames, bool useSteganography)
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

        private byte[] EmbedInPngContainer(byte[] payload)
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

        private byte[]? TryExtractStegoPayload(string filePath)
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
            byte[] signature = { 137, 80, 78, 71, 13, 10, 26, 10 };
            return data.Length >= signature.Length && data.Slice(0, signature.Length).SequenceEqual(signature);
        }

        private int FindIendChunkIndex(byte[] png)
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

        private byte[] BuildCustomPngChunk(string type, byte[] data)
        {
            byte[] typeBytes = Encoding.ASCII.GetBytes(type);
            byte[] chunk = new byte[4 + 4 + data.Length + 4];
            BinaryPrimitives.WriteInt32BigEndian(chunk.AsSpan(0, 4), data.Length);
            Buffer.BlockCopy(typeBytes, 0, chunk, 4, 4);
            Buffer.BlockCopy(data, 0, chunk, 8, data.Length);

            byte[] crcInput = typeBytes.Concat(data).ToArray();
            uint crcValue = ComputeCrc32(crcInput);
            byte[] crcBytes = BitConverter.GetBytes(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(crcValue));
            Buffer.BlockCopy(crcBytes, 0, chunk, 8 + data.Length, 4);

            return chunk;
        }

        private byte[] SerializeMetadata(FileMetadata metadata)
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
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
                return stream.ToArray();
            }
        }

        private FileMetadata DeserializeMetadata(byte[] data)
        {
            using (var stream = new MemoryStream(data))
            using (var reader = new BinaryReader(stream))
            {
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

                return metadata;
            }
        }

        private bool TryReadString(BinaryReader reader, Stream stream, out string value)
        {
            if (stream.Position < stream.Length)
            {
                value = reader.ReadString();
                return true;
            }

            value = string.Empty;
            return false;
        }

        private byte[] GenerateRandomBytes(int size)
        {
            byte[] bytes = new byte[size];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        private byte[] DeriveKeyArgon2(string password, byte[] salt)
        {
            // Using PBKDF2 as Argon2 requires additional NuGet package
            // In production, consider using Argon2 for better security
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 120000, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(KEY_SIZE);
            }
        }

        private byte[] ComputeSha256(byte[] data)
        {
            return SHA256.HashData(data);
        }

        private void EnsureHashMatch(byte[] expectedHash, byte[] data)
        {
            byte[] actualHash = ComputeSha256(data);
            if (!actualHash.SequenceEqual(expectedHash))
            {
                throw new UnauthorizedAccessException("File failed integrity validation after decryption.");
            }
        }

        private void SecureDelete(string filePath)
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
        }

        private void AnimateDropPanel(bool highlight)
        {
            // Simple animation for drop panel
            var color = highlight ?
                new SolidColorBrush(Microsoft.UI.Colors.LightGreen) :
                new SolidColorBrush(Microsoft.UI.Colors.Transparent);
            _dropPanel.Background = color;
        }

        private class FileMetadata
        {
            public string OriginalFileName { get; set; } = string.Empty;
            public long OriginalSize { get; set; }
            public DateTime CreationTime { get; set; }
            public DateTime LastWriteTime { get; set; }
            public bool IsCompressed { get; set; }
            public bool IsSteganographyContainer { get; set; }
            public byte[] ContentHash { get; set; } = Array.Empty<byte>();
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

        // --- Window Controls ---
        private async void CheckUpdates_Click(object sender, RoutedEventArgs e)
        {
            await _updater.CheckForUpdatesAsync(this.Content.XamlRoot);
        }

        private async void About_Click(object sender, RoutedEventArgs e)
        {
            await ShowInfoDialogAsync(
                "FileLocker WinUI 3\nSecure file encryption with AES-256-GCM plus hashing & encoding helpers." +
                "\nGitHub: https://github.com/jeremyhayes/FileLocker" +
                "\nFeatures: drag-and-drop queuing, metadata controls, optional steganography." +
                "\n\n© 2025 Jeremy Hayes",
                "About FileLocker");
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

        private WINDOWPLACEMENT GetWindowPlacement(IntPtr hwnd)
        {
            WINDOWPLACEMENT placement = new WINDOWPLACEMENT();
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
        }

        private void ScrambleNamesToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleSwitch toggleSwitch)
            {
                IsScrambleNamesEnabled = toggleSwitch.IsOn;
            }
        }

        private void SteganographyToggle_Toggled(object sender, RoutedEventArgs e)
        {
            if (sender is ToggleSwitch toggleSwitch)
            {
                IsSteganographyEnabled = toggleSwitch.IsOn;
            }
        }
        private List<string> ExpandPathsToFiles(IEnumerable<string> paths)
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

        private uint ComputeCrc32(byte[] data)
        {
            uint result = 0xFFFFFFFFu;
            foreach (byte b in data)
            {
                result = (result >> 8) ^ Crc32Table[(result ^ b) & 0xFF];
            }
            return ~result;
        }
    }
}
