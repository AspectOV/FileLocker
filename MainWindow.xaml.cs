using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.ApplicationModel.DataTransfer;
using Microsoft.UI.Xaml.Media.Animation;
using WinRT.Interop;
using Microsoft.UI.Text;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace FileLocker
{
    /// <summary>
    /// An empty window that can be used on its own or navigated to within a Frame.
    /// </summary>
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

        private List<string> selectedPaths = new List<string>();
        private readonly Updater _updater = new Updater();
        private bool isDarkTheme = true;
        public ObservableCollection<string> FileList { get; set; } = new();
        public string StatusText { get; set; } = "Ready - Add files to begin";
        private TextBlock DropLabelControler;

        // Advanced options properties
        public bool IsCompressModeEnabled { get; set; } = true;
        public bool IsScrambleNamesEnabled { get; set; } = false;
        public bool IsSteganographyEnabled { get; set; } = false;

        private TextBox plainTextPasswordBox;

        public MainWindow()
        {
            InitializeComponent();
            _updater.SetXamlRoot(this.Content.XamlRoot); // Set XamlRoot for dialogs
            FileListBox.ItemsSource = FileList;
            isDarkTheme = true;
            ThemeToggleButton.Content = "☀️";
            UpdateStatusLabel();

            // Set window size to 600x800
            this.AppWindow.MoveAndResize(new Windows.Graphics.RectInt32(100, 100, 600, 800));

            // Initialize DropLabelControl
            DropLabelControler = new TextBlock
            {
                Text = "📁 Drag files here or click to browse",
                FontWeight = FontWeights.Normal
            };

            // Create the plain text password TextBox (hidden by default)
            plainTextPasswordBox = new TextBox
            {
                Width = PasswordBox.Width,
                Height = PasswordBox.Height,
                Visibility = Visibility.Collapsed,
                Margin = PasswordBox.Margin,
                VerticalAlignment = PasswordBox.VerticalAlignment,
                HorizontalAlignment = PasswordBox.HorizontalAlignment
            };

            // Insert after PasswordBox in the parent StackPanel
            var parent = PasswordBox.Parent as Panel;
            if (parent != null)
            {
                int idx = parent.Children.IndexOf(PasswordBox);
                parent.Children.Insert(idx + 1, plainTextPasswordBox);
            }
            plainTextPasswordBox.TextChanged += (s, e) => PasswordBox.Password = plainTextPasswordBox.Text;
        }

        private void ThemeToggleButton_Click(object sender, RoutedEventArgs e)
        {
            if (ThemeToggleButton is Button button)
            {
                isDarkTheme = !isDarkTheme;
                button.Content = isDarkTheme ? "🌙" : "☀️";
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
            StatusLabel.Text = text;
        }

        private void UpdateStatusLabel()
        {
            if (selectedPaths.Count == 0)
                SetStatus("Ready - No files selected");
            else
                SetStatus($"Ready - {selectedPaths.Count} item(s) selected");
        }

        // --- Password Section ---
        private void ShowPasswordCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            // Show plain text
            plainTextPasswordBox.Text = PasswordBox.Password;
            plainTextPasswordBox.Visibility = Visibility.Visible;
            PasswordBox.Visibility = Visibility.Collapsed;
        }

        private void ShowPasswordCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            // Hide plain text
            PasswordBox.Password = plainTextPasswordBox.Text;
            plainTextPasswordBox.Visibility = Visibility.Collapsed;
            PasswordBox.Visibility = Visibility.Visible;
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            // Sync with plain text box if it's visible
            if (plainTextPasswordBox.Visibility == Visibility.Visible)
            {
                plainTextPasswordBox.Text = PasswordBox.Password;
            }

            // Update password strength
            int strength = CalculatePasswordStrength(PasswordBox.Password);
            PasswordStrengthBar.Value = strength;
            
            if (strength < 30)
            {
                PasswordStrengthText.Text = "Weak";
                PasswordStrengthBar.Foreground = new SolidColorBrush(Microsoft.UI.Colors.Red);
            }
            else if (strength < 70)
            {
                PasswordStrengthText.Text = "Medium";
                PasswordStrengthBar.Foreground = new SolidColorBrush(Microsoft.UI.Colors.Orange);
            }
            else
            {
                PasswordStrengthText.Text = "Strong";
                PasswordStrengthBar.Foreground = new SolidColorBrush(Microsoft.UI.Colors.Green);
            }
        }

        private int CalculatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return 0;
            int score = 0;
            score += Math.Min(password.Length * 4, 25);
            bool hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
            foreach (char c in password)
            {
                if (char.IsLower(c)) hasLower = true;
                else if (char.IsUpper(c)) hasUpper = true;
                else if (char.IsDigit(c)) hasDigit = true;
                else hasSpecial = true;
            }
            if (hasLower) score += 5;
            if (hasUpper) score += 5;
            if (hasDigit) score += 5;
            if (hasSpecial) score += 10;
            if (hasLower && hasUpper) score += 10;
            if (hasDigit && hasSpecial) score += 10;
            if (password.Length < 8) score -= 15;
            if (password.Length < 6) score -= 25;
            if (password.All(char.IsLetter)) score -= 10;
            if (password.All(char.IsDigit)) score -= 15;
            string[] commonPasswords = { "password", "123456", "qwerty", "letmein" };
            if (commonPasswords.Contains(password.ToLower())) score = 5;
            return Math.Clamp(score, 0, 100);
        }

        // --- Encrypt/Decrypt ---
        private async void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateInput()) return;
            await ProcessFilesAsync(true);
        }

        private async void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateInput()) return;
            await ProcessFilesAsync(false);
        }

        private bool ValidateInput()
        {
            if (selectedPaths.Count == 0)
            {
                _ = ShowErrorDialogAsync("Please select files or folders to process.");
                return false;
            }
            if (string.IsNullOrWhiteSpace(PasswordBox.Password))
            {
                _ = ShowErrorDialogAsync("Please enter a password.");
                return false;
            }
            if (PasswordBox.Password.Length < 6)
            {
                _ = ShowConfirmDialogAsync("Password is very weak. Continue anyway?", "Weak Password");
                return false;
            }
            return true;
        }

        private async Task ProcessFilesAsync(bool encrypt)
        {
            try
            {
                SetUIEnabled(false);
                
                // Capture password on UI thread before starting background tasks
                string password = PasswordBox.Password;
                
                var allFiles = selectedPaths.ToList();
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
                bool isCompressed = IsCompressModeEnabled;
                bool scrambleNames = IsScrambleNamesEnabled;
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
                    IsCompressed = isCompressed
                };
                byte[] dataToEncrypt;
                if (isCompressed)
                {
                    dataToEncrypt = CompressData(fileData);
                }
                else
                {
                    dataToEncrypt = fileData;
                }
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
                string encryptedPath;
                if (scrambleNames)
                {
                    encryptedPath = GenerateObfuscatedFilename(filePath);
                }
                else
                {
                    string? directory = Path.GetDirectoryName(filePath);
                    if (directory == null) throw new InvalidOperationException("File directory is null.");
                    encryptedPath = Path.Combine(directory, originalFileName + ENCRYPTED_EXTENSION);
                }
                using (var fs = new FileStream(encryptedPath, FileMode.Create))
                {
                    fs.WriteByte(FORMAT_VERSION);
                    fs.Write(salt, 0, salt.Length);
                    fs.Write(iv, 0, iv.Length);
                    fs.Write(tag, 0, tag.Length);
                    fs.Write(ciphertext, 0, ciphertext.Length);
                }
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
            using (var fs = new FileStream(filePath, FileMode.Open))
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
            File.Delete(filePath);
        }

        private string GenerateObfuscatedFilename(string originalPath)
        {
            string directory = Path.GetDirectoryName(originalPath);
            if (directory == null) throw new InvalidOperationException("File directory is null.");
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

        private byte[] CompressData(byte[] data)
        {
            using (var output = new MemoryStream())
            {
                using (var gzip = new GZipStream(output, CompressionMode.Compress))
                {
                    gzip.Write(data, 0, data.Length);
                }
                return output.ToArray();
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
                return stream.ToArray();
            }
        }

        private FileMetadata DeserializeMetadata(byte[] data)
        {
            using (var stream = new MemoryStream(data))
            using (var reader = new BinaryReader(stream))
            {
                return new FileMetadata
                {
                    OriginalFileName = reader.ReadString(),
                    OriginalSize = reader.ReadInt64(),
                    CreationTime = DateTime.FromBinary(reader.ReadInt64()),
                    LastWriteTime = DateTime.FromBinary(reader.ReadInt64()),
                    IsCompressed = reader.ReadBoolean()
                };
            }
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
            EncryptButton.IsEnabled = enabled;
            DecryptButton.IsEnabled = enabled;
            PasswordBox.IsEnabled = enabled;
            ClearListButton.IsEnabled = enabled;
            DropPanel.AllowDrop = enabled;
        }

        private void AnimateDropPanel(bool highlight)
        {
            // Simple animation for drop panel
            var color = highlight ? 
                new SolidColorBrush(Microsoft.UI.Colors.LightGreen) : 
                new SolidColorBrush(Microsoft.UI.Colors.Transparent);
            DropPanel.Background = color;
        }

        private class FileMetadata
        {
            public string OriginalFileName { get; set; } = string.Empty;
            public long OriginalSize { get; set; }
            public DateTime CreationTime { get; set; }
            public DateTime LastWriteTime { get; set; }
            public bool IsCompressed { get; set; }
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
            _updater.SetXamlRoot(this.Content.XamlRoot); // Ensure XamlRoot is set before showing dialogs
            await _updater.CheckForUpdatesAsync();
        }

        private async void About_Click(object sender, RoutedEventArgs e)
        {
            await ShowInfoDialogAsync("FileLocker WinUI 3\nA secure file encryption tool using AES-256-GCM encryption.\n\n© 2025 Jeremy Hayes", "About FileLocker");
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
    }
}
