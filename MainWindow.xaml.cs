using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using System.Windows.Media.Animation;
using System.Windows.Media;
using System.Windows.Threading;

namespace FileLocker
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
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
        private Updater updater;
        private bool isDarkTheme = true;
        public System.Collections.ObjectModel.ObservableCollection<string> FileList { get; set; } = new();
        public string StatusText { get; set; } = "Ready - Add files to begin";
        private TextBox plainTextPasswordBox;

        public MainWindow()
        {
            InitializeComponent();
            updater = new Updater();
            DataContext = this;
            isDarkTheme = true;
            ApplyTheme();
            ThemeToggleButton.Content = "☀️";
            UpdateStatusLabel();

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
            isDarkTheme = !isDarkTheme;
            ApplyTheme();
            ThemeToggleButton.Content = isDarkTheme ? "🌙" : "☀️";
        }

        private void ApplyTheme()
        {
            var dict = Application.Current.Resources.MergedDictionaries.FirstOrDefault(x => x.Source != null && x.Source.OriginalString.Contains("Themes/Styles.xaml"));
            if (dict != null)
            {
                dict["BackgroundBrush"] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(isDarkTheme ? "#FF1E1E1E" : "#FFF9F9F9"));
                dict["ForegroundBrush"] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(isDarkTheme ? "#FFF3F3F3" : "#FF222222"));
                dict["AccentBrush"] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(isDarkTheme ? "#FF888EA8" : "#FF888EA8"));
                dict["PanelBrush"] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(isDarkTheme ? "#FF232323" : "#FFFFFFFF"));
                dict["ErrorBrush"] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(isDarkTheme ? "#FFCF6679" : "#FFB00020"));
                dict["SuccessBrush"] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(isDarkTheme ? "#FF27AE60" : "#FF2ECC71"));
            }
        }

        // --- Drag & Drop ---
        private void DropPanel_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                AnimateDropPanel(true);
                DropLabel.Text = "🟢 Release to add files";
                DropLabel.FontWeight = FontWeights.Bold;
            }
        }

        private void DropPanel_DragLeave(object sender, DragEventArgs e)
        {
            AnimateDropPanel(false);
            DropLabel.Text = "📁 Drag files here or click to browse";
            DropLabel.FontWeight = FontWeights.Normal;
        }

        private void DropPanel_Drop(object sender, DragEventArgs e)
        {
            AnimateDropPanel(false);
            DropLabel.Text = "📁 Drag files here or click to browse";
            DropLabel.FontWeight = FontWeights.Normal;

            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files != null && files.Length > 0)
                {
                    AddFilesToList(files);
                    SetStatus($"Added {files.Length} file(s)");
                }
            }
        }

        private void DropPanel_Click(object sender, MouseButtonEventArgs e)
        {
            BrowseFiles();
        }

        private void BrowseFiles()
        {
            var dialog = new OpenFileDialog
            {
                Multiselect = true,
                Filter = "All Files (*.*)|*.*|Documents (*.doc;*.docx;*.pdf)|*.doc;*.docx;*.pdf|Images (*.jpg;*.png;*.bmp)|*.jpg;*.png;*.bmp",
                Title = "Select Files to Encrypt/Decrypt",
                CheckFileExists = true,
                CheckPathExists = true
            };

            if (dialog.ShowDialog() == true)
            {
                AddFilesToList(dialog.FileNames);
                SetStatus($"Added {dialog.FileNames.Length} file(s)");
            }
        }

        // --- File List and Status Binding ---
        private void AddFilesToList(string[] paths)
        {
            foreach (string path in paths)
            {
                if (!selectedPaths.Contains(path))
                {
                    selectedPaths.Add(path);
                    string displayName = System.IO.Path.GetFileName(path);
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
            // Animate status label color for feedback
            var anim = new ColorAnimation((Color)ColorConverter.ConvertFromString("#FF888EA8"), TimeSpan.FromMilliseconds(200));
            var oldBrush = StatusLabel.Foreground as SolidColorBrush;
            SolidColorBrush brush;
            if (oldBrush == null || oldBrush.IsFrozen)
            {
                brush = new SolidColorBrush(oldBrush != null ? oldBrush.Color : (Color)ColorConverter.ConvertFromString("#FFF3F3F3"));
                StatusLabel.Foreground = brush;
            }
            else
            {
                brush = oldBrush;
            }
            brush.BeginAnimation(SolidColorBrush.ColorProperty, anim);
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
            if (ShowPasswordCheckBox.IsChecked == true)
            {
                plainTextPasswordBox.Text = PasswordBox.Password;
            }
            int strength = CalculatePasswordStrength(PasswordBox.Password);
            StrengthBar.Value = strength;
            if (strength < 30)
            {
                StrengthLabel.Text = "Weak Password";
                StrengthLabel.Foreground = System.Windows.Media.Brushes.Red;
            }
            else if (strength < 70)
            {
                StrengthLabel.Text = "Good Password";
                StrengthLabel.Foreground = System.Windows.Media.Brushes.Orange;
            }
            else
            {
                StrengthLabel.Text = "Strong Password!";
                StrengthLabel.Foreground = System.Windows.Media.Brushes.Green;
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
                MessageBox.Show("Please select files or folders to process.", "No Files Selected", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if (string.IsNullOrWhiteSpace(PasswordBox.Password))
            {
                MessageBox.Show("Please enter a password.", "Password Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if (PasswordBox.Password.Length < 6)
            {
                var result = MessageBox.Show("Password is very weak. Continue anyway?", "Weak Password", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result != MessageBoxResult.Yes) return false;
            }
            return true;
        }
        private async Task ProcessFilesAsync(bool encrypt)
        {
            SetUIEnabled(false);
            MainProgressBar.Visibility = Visibility.Visible;
            MainProgressBar.Value = 0;
            var allFiles = new List<string>();
            foreach (string path in selectedPaths)
            {
                if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                {
                    allFiles.AddRange(Directory.GetFiles(path, "*", SearchOption.AllDirectories));
                }
                else if (!string.IsNullOrEmpty(path) && File.Exists(path))
                {
                    allFiles.Add(path);
                }
            }
            MainProgressBar.Maximum = allFiles.Count;
            int processed = 0;
            int successful = 0;
            foreach (string filePath in allFiles)
            {
                try
                {
                    string fileName = System.IO.Path.GetFileName(filePath);
                    SetStatus($"Processing: {fileName}");
                    await Task.Delay(10); // Let UI update
                    if (encrypt)
                    {
                        if (!filePath.EndsWith(ENCRYPTED_EXTENSION))
                        {
                            await Task.Run(() => EncryptFileAdvanced(filePath, PasswordBox.Password));
                            successful++;
                        }
                    }
                    else
                    {
                        if (filePath.EndsWith(ENCRYPTED_EXTENSION))
                        {
                            await Task.Run(() => DecryptFileAdvanced(filePath, PasswordBox.Password));
                            successful++;
                        }
                    }
                }
                catch (Exception ex)
                {
                    string fileName = System.IO.Path.GetFileName(filePath);
                    MessageBox.Show($"Error processing {fileName}: {ex.Message}", "Processing Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                processed++;
                MainProgressBar.Value = processed;
            }
            MainProgressBar.Visibility = Visibility.Collapsed;
            SetUIEnabled(true);
            string operation = encrypt ? "encrypted" : "decrypted";
            SetStatus($"Complete: {successful} files {operation} successfully.");
            MessageBox.Show($"Operation completed successfully!\n{successful} files {operation}.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            if (successful > 0)
            {
                selectedPaths.Clear();
                FileList.Clear();
                UpdateStatusLabel();
            }
        }

        // --- Encryption/Decryption Logic ---
        private void EncryptFileAdvanced(string filePath, string password)
        {
            bool isCompressed = false;
            bool scrambleNames = false;
            Dispatcher.Invoke(() => {
                isCompressed = CompressionCheckBox.IsChecked == true;
                scrambleNames = ScrambleNamesCheckBox.IsChecked == true;
            });
            byte[] salt = GenerateRandomBytes(SALT_SIZE);
            byte[] iv = GenerateRandomBytes(IV_SIZE);
            byte[] key = DeriveKeyArgon2(password, salt);
            byte[] fileData = File.ReadAllBytes(filePath);
            string originalFileName = System.IO.Path.GetFileName(filePath) ?? string.Empty;
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
                string? directory = System.IO.Path.GetDirectoryName(filePath);
                if (directory == null) throw new InvalidOperationException("File directory is null.");
                encryptedPath = System.IO.Path.Combine(directory, originalFileName + ENCRYPTED_EXTENSION);
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
                string? directory = System.IO.Path.GetDirectoryName(filePath);
                if (directory == null) throw new InvalidOperationException("File directory is null.");
                string originalPath = System.IO.Path.Combine(directory, metadata.OriginalFileName ?? "output");
                int counter = 1;
                string finalPath = originalPath;
                while (File.Exists(finalPath))
                {
                    string name = System.IO.Path.GetFileNameWithoutExtension(originalPath);
                    string ext = System.IO.Path.GetExtension(originalPath);
                    finalPath = System.IO.Path.Combine(directory, $"{name}_{counter}{ext}");
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
            string directory = System.IO.Path.GetDirectoryName(originalPath);
            if (directory == null) throw new InvalidOperationException("File directory is null.");
            string randomName = GenerateRandomString(16) + ENCRYPTED_EXTENSION;
            return System.IO.Path.Combine(directory, randomName);
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
            CompressionCheckBox.IsEnabled = enabled;
            SteganographyCheckBox.IsEnabled = enabled;
            ScrambleNamesCheckBox.IsEnabled = enabled;
            DropPanel.AllowDrop = enabled;
        }
        private void AnimateDropPanel(bool highlight)
        {
            var color = (Color)ColorConverter.ConvertFromString(highlight ? (isDarkTheme ? "#FF232323" : "#E8F4FD") : (isDarkTheme ? "#FF232323" : "#FFFFFFFF"));
            var anim = new ColorAnimation(color, TimeSpan.FromMilliseconds(200));
            var oldBrush = DropPanel.Background as SolidColorBrush;
            SolidColorBrush brush;
            if (oldBrush == null || oldBrush.IsFrozen)
            {
                brush = new SolidColorBrush(oldBrush != null ? oldBrush.Color : color);
                DropPanel.Background = brush;
            }
            else
            {
                brush = oldBrush;
            }
            brush.BeginAnimation(SolidColorBrush.ColorProperty, anim);
        }
        private class FileMetadata
        {
            public string OriginalFileName { get; set; } = string.Empty;
            public long OriginalSize { get; set; }
            public DateTime CreationTime { get; set; }
            public DateTime LastWriteTime { get; set; }
            public bool IsCompressed { get; set; }
        }

        private async void CheckUpdates_Click(object sender, RoutedEventArgs e)
        {
            await updater.CheckForUpdatesAsync(false);
        }

        private void About_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("FileLocker WPF\nA secure file encryption tool using AES-256-GCM encryption.\n\n© 2025 Jeremy Hayes", "About FileLocker");
        }

        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }
        private void MaximizeRestore_Click(object sender, RoutedEventArgs e)
        {
            if (WindowState == WindowState.Maximized)
                WindowState = WindowState.Normal;
            else
                WindowState = WindowState.Maximized;
        }
        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void TopBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
            {
                try { DragMove(); } catch { }
            }
        }
    }
}