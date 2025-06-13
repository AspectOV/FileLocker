using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Linq;

namespace FileLocker
{
    public partial class MainForm : Form
    {
        private const string ENCRYPTED_EXTENSION = ".locked";
        private const int SALT_SIZE = 32;
        private const int IV_SIZE = 12; // GCM uses 12-byte IV
        private const int KEY_SIZE = 32;
        private const int TAG_SIZE = 16; // GCM authentication tag
        private const byte FORMAT_VERSION = 2; // Version for compatibility
        private const int MIN_PADDING_SIZE = 1024; // Minimum padding to hide file size
        private const int MAX_PADDING_SIZE = 8192; // Maximum padding

        private ProgressBar progressBar;
        private Label statusLabel;
        private TextBox passwordTextBox;
        private Button encryptButton;
        private Button decryptButton;
        private Panel dropPanel;
        private Label dropLabel;
        private ListBox fileListBox;
        private Button clearListButton;
        private CheckBox showPasswordCheckBox;
        private CheckBox compressionCheckBox;
        private CheckBox steganographyCheckBox;
        private CheckBox scrambleNamesCheckBox;
        private Label instructionLabel;
        private Label passwordLabel;
        private ProgressBar strengthBar;
        private Label strengthLabel;
        private List<string> selectedPaths = new List<string>();

        public MainForm()
        {
            InitializeComponent();
            SetupDragDrop();
            SetupPasswordStrengthCheck();
            SetupEventHandlers(); // Add missing event handlers
        }

        private void InitializeComponent()
        {
            // Define color scheme
            Color primaryColor = Color.FromArgb(0, 122, 204);  // Blue
            Color successColor = Color.FromArgb(46, 204, 113); // Green
            Color lightBg = Color.FromArgb(250, 250, 250);     // Off-white

            // Main form setup
            this.Text = "FileLocker - AES-256-GCM Encryption Tool";
            this.BackColor = lightBg;
            this.ClientSize = new Size(600, 800);  // Increased form size
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedSingle;

            // Create main container panel for perfect centering
            Panel mainPanel = new Panel
            {
                Size = new Size(550, 750),  // Increased panel size
                Location = new Point(
                    (this.ClientSize.Width - 550) / 2,
                    (this.ClientSize.Height - 750) / 2
                ),
                Anchor = AnchorStyles.None
            };

            // CENTERED Instruction label
            instructionLabel = new Label
            {
                Text = "Drag & drop files/folders or click to select",
                Size = new Size(530, 25),
                Location = new Point((mainPanel.Width - 530) / 2, 20),
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 10F, FontStyle.Bold)
            };

            // CENTERED Drop panel
            dropPanel = new Panel
            {
                Size = new Size(530, 120),  // Increased height
                Location = new Point((mainPanel.Width - 530) / 2, 50),
                BackColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                AllowDrop = true
            };

            dropLabel = new Label
            {
                Text = "📁 Drag files here or click to browse",
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 10F)
            };
            dropPanel.Controls.Add(dropLabel);

            // CENTERED File list
            fileListBox = new ListBox
            {
                Size = new Size(530, 180),  // Increased height
                Location = new Point((mainPanel.Width - 530) / 2, 180)
            };

            // CENTERED Clear button (aligned to list box)
            clearListButton = new Button
            {
                Text = "Clear All",
                Size = new Size(100, 30),  // Increased size
                Location = new Point(
                    (mainPanel.Width - 530) / 2 + 530 - 100,  // Right-align to list box
                    370
                )
            };

            // Password section - CENTERED
            passwordLabel = new Label
            {
                Text = "Encryption Password:",
                Size = new Size(530, 20),
                Location = new Point((mainPanel.Width - 530) / 2, 410),
                TextAlign = ContentAlignment.MiddleLeft
            };

            // Password box group - CENTERED
            Panel passwordPanel = new Panel
            {
                Size = new Size(530, 35),  // Increased height
                Location = new Point((mainPanel.Width - 530) / 2, 435)
            };

            passwordTextBox = new TextBox
            {
                Size = new Size(400, 30),  // Increased size
                Location = new Point(0, 0),
                UseSystemPasswordChar = true
            };

            showPasswordCheckBox = new CheckBox
            {
                Text = "Show Password",
                Size = new Size(120, 30),  // Increased size
                Location = new Point(410, 0)
            };
            passwordPanel.Controls.AddRange(new Control[] { passwordTextBox, showPasswordCheckBox });

            // CENTERED Strength indicator
            strengthLabel = new Label
            {
                Text = "Password Strength:",
                Size = new Size(530, 20),
                Location = new Point((mainPanel.Width - 530) / 2, 480),
                TextAlign = ContentAlignment.MiddleLeft
            };

            strengthBar = new ProgressBar
            {
                Size = new Size(530, 15),  // Increased height
                Location = new Point((mainPanel.Width - 530) / 2, 505)
            };

            // CENTERED Options panel
            Panel optionsPanel = new Panel
            {
                Size = new Size(530, 80),  // Increased height
                Location = new Point((mainPanel.Width - 530) / 2, 530)
            };

            compressionCheckBox = new CheckBox
            {
                Text = "Compress Files",
                Size = new Size(160, 30),  // Increased size
                Location = new Point(0, 0)
            };

            steganographyCheckBox = new CheckBox
            {
                Text = "Steganography Mode",
                Size = new Size(180, 30),  // Increased size
                Location = new Point(170, 0)
            };

            scrambleNamesCheckBox = new CheckBox
            {
                Text = "Scramble File Names",
                Size = new Size(160, 30),  // Increased size
                Location = new Point(0, 40)
            };

            optionsPanel.Controls.AddRange(new Control[] { compressionCheckBox, steganographyCheckBox, scrambleNamesCheckBox });

            // CENTERED Buttons (grouped)
            Panel buttonPanel = new Panel
            {
                Size = new Size(350, 50),  // Increased size
                Location = new Point((mainPanel.Width - 350) / 2, 620)
            };

            encryptButton = new Button
            {
                Text = "🔒 ENCRYPT",
                Size = new Size(160, 45),  // Increased size
                Location = new Point(0, 0),
                BackColor = successColor,
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 10F, FontStyle.Bold)  // Added bold font
            };

            decryptButton = new Button
            {
                Text = "🔓 DECRYPT",
                Size = new Size(160, 45),  // Increased size
                Location = new Point(190, 0),
                BackColor = primaryColor,
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 10F, FontStyle.Bold)  // Added bold font
            };
            buttonPanel.Controls.AddRange(new Control[] { encryptButton, decryptButton });

            // CENTERED Progress bar
            progressBar = new ProgressBar
            {
                Size = new Size(530, 25),  // Increased size
                Location = new Point((mainPanel.Width - 530) / 2, 680)
            };

            // CENTERED Status label
            statusLabel = new Label
            {
                Text = "Ready - Add files to begin",
                Size = new Size(530, 25),
                Location = new Point((mainPanel.Width - 530) / 2, 710),
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 9F)  // Added font
            };

            // Add all controls to main panel
            mainPanel.Controls.AddRange(new Control[] {
                instructionLabel, dropPanel, fileListBox, clearListButton,
                passwordLabel, passwordPanel, strengthLabel, strengthBar,
                optionsPanel, buttonPanel, progressBar, statusLabel
            });

            // Add main panel to form
            this.Controls.Add(mainPanel);
        }

        // FIX: Add missing event handlers setup
        private void SetupEventHandlers()
        {
            // Clear button event handler
            clearListButton.Click += ClearListButton_Click;

            // Show password checkbox event handler
            showPasswordCheckBox.CheckedChanged += ShowPasswordCheckBox_CheckedChanged;

            // Encrypt/Decrypt button event handlers
            encryptButton.Click += EncryptButton_Click;
            decryptButton.Click += DecryptButton_Click;
        }

        private void SetupDragDrop()
        {
            dropPanel.DragEnter += (s, e) =>
            {
                if (e.Data.GetDataPresent(DataFormats.FileDrop))
                {
                    e.Effect = DragDropEffects.Copy;
                    dropPanel.BackColor = Color.FromArgb(232, 244, 253);
                    dropLabel.Text = "🟢 Release to add files";
                    dropLabel.Font = new Font(dropLabel.Font, FontStyle.Bold);
                }
            };

            dropPanel.DragDrop += (s, e) =>
            {
                dropPanel.BackColor = Color.White;
                dropLabel.Text = "📁 Drag files here or click to browse";
                dropLabel.Font = new Font(dropLabel.Font, FontStyle.Regular);

                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files != null && files.Length > 0)
                {
                    AddFilesToList(files);
                    statusLabel.Text = $"Added {files.Length} file(s)";
                }
            };

            dropPanel.DragLeave += (s, e) =>
            {
                dropPanel.BackColor = Color.White;
                dropLabel.Text = "📁 Drag files here or click to browse";
                dropLabel.Font = new Font(dropLabel.Font, FontStyle.Regular);
            };

            dropLabel.Click += (s, e) => BrowseFiles();
            dropPanel.Click += (s, e) => BrowseFiles();
        }

        private void BrowseFiles()
        {
            using (var dialog = new OpenFileDialog())
            {
                dialog.Multiselect = true;
                dialog.Filter = "All Files (*.*)|*.*|" +
                              "Documents (*.doc;*.docx;*.pdf)|*.doc;*.docx;*.pdf|" +
                              "Images (*.jpg;*.png;*.bmp)|*.jpg;*.png;*.bmp";
                dialog.Title = "Select Files to Encrypt/Decrypt";
                dialog.CheckFileExists = true;
                dialog.CheckPathExists = true;

                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    AddFilesToList(dialog.FileNames);
                    statusLabel.Text = $"Added {dialog.FileNames.Length} file(s)";
                }
            }
        }

        private void SetupPasswordStrengthCheck()
        {
            passwordTextBox.TextChanged += (s, e) =>
            {
                int strength = CalculatePasswordStrength(passwordTextBox.Text);
                strengthBar.Value = strength;

                if (strength < 30)
                {
                    strengthBar.ForeColor = Color.Red;
                    strengthLabel.Text = "Weak Password";
                    strengthLabel.ForeColor = Color.Red;
                }
                else if (strength < 70)
                {
                    strengthBar.ForeColor = Color.Orange;
                    strengthLabel.Text = "Good Password";
                    strengthLabel.ForeColor = Color.Orange;
                }
                else
                {
                    strengthBar.ForeColor = Color.Green;
                    strengthLabel.Text = "Strong Password!";
                    strengthLabel.ForeColor = Color.Green;
                }
            };
        }

        private int CalculatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return 0;

            int score = 0;

            // Length score (max 25)
            score += Math.Min(password.Length * 4, 25);

            // Character variety (max 25)
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

            // Bonus for mixed case (max 10)
            if (hasLower && hasUpper) score += 10;

            // Bonus for numbers and special chars (max 10)
            if (hasDigit && hasSpecial) score += 10;

            // Deductions for poor patterns
            if (password.Length < 8) score -= 15;
            if (password.Length < 6) score -= 25;
            if (password.All(char.IsLetter)) score -= 10;
            if (password.All(char.IsDigit)) score -= 15;

            // Common password check (simplified)
            string[] commonPasswords = { "password", "123456", "qwerty", "letmein" };
            if (commonPasswords.Contains(password.ToLower())) score = 5;

            return Math.Clamp(score, 0, 100);
        }

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

                    // Show file size for individual files
                    if (File.Exists(path))
                    {
                        var fileInfo = new FileInfo(path);
                        displayName += $" ({FormatFileSize(fileInfo.Length)})";
                    }

                    fileListBox.Items.Add(displayName);
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

        private void ClearListButton_Click(object sender, EventArgs e)
        {
            selectedPaths.Clear();
            fileListBox.Items.Clear();
            UpdateStatusLabel();
        }

        private void ShowPasswordCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            passwordTextBox.UseSystemPasswordChar = !showPasswordCheckBox.Checked;
        }

        private async void EncryptButton_Click(object sender, EventArgs e)
        {
            if (!ValidateInput()) return;
            await ProcessFilesAsync(true);
        }

        private async void DecryptButton_Click(object sender, EventArgs e)
        {
            if (!ValidateInput()) return;
            await ProcessFilesAsync(false);
        }

        private bool ValidateInput()
        {
            if (selectedPaths.Count == 0)
            {
                MessageBox.Show("Please select files or folders to process.", "No Files Selected",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (string.IsNullOrWhiteSpace(passwordTextBox.Text))
            {
                MessageBox.Show("Please enter a password.", "Password Required",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }

            if (passwordTextBox.Text.Length < 6)
            {
                var result = MessageBox.Show("Password is very weak. Continue anyway?", "Weak Password",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (result != DialogResult.Yes) return false;
            }

            return true;
        }

        private async Task ProcessFilesAsync(bool encrypt)
        {
            SetUIEnabled(false);
            progressBar.Visible = true;
            progressBar.Value = 0;

            var allFiles = new List<string>();

            // Collect all files from paths
            foreach (string path in selectedPaths)
            {
                if (Directory.Exists(path))
                {
                    allFiles.AddRange(Directory.GetFiles(path, "*", SearchOption.AllDirectories));
                }
                else if (File.Exists(path))
                {
                    allFiles.Add(path);
                }
            }

            progressBar.Maximum = allFiles.Count;
            int processed = 0;
            int successful = 0;

            foreach (string filePath in allFiles)
            {
                try
                {
                    string fileName = Path.GetFileName(filePath);
                    statusLabel.Text = $"Processing: {fileName}";
                    Application.DoEvents();

                    if (encrypt)
                    {
                        if (!filePath.EndsWith(ENCRYPTED_EXTENSION))
                        {
                            await Task.Run(() => EncryptFileAdvanced(filePath, passwordTextBox.Text));
                            successful++;
                        }
                    }
                    else
                    {
                        if (filePath.EndsWith(ENCRYPTED_EXTENSION))
                        {
                            await Task.Run(() => DecryptFileAdvanced(filePath, passwordTextBox.Text));
                            successful++;
                        }
                    }
                }
                catch (Exception ex)
                {
                    string fileName = Path.GetFileName(filePath);
                    MessageBox.Show($"Error processing {fileName}: {ex.Message}",
                        "Processing Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }

                processed++;
                progressBar.Value = processed;
            }

            progressBar.Visible = false;
            SetUIEnabled(true);

            string operation = encrypt ? "encrypted" : "decrypted";
            statusLabel.Text = $"Complete: {successful} files {operation} successfully.";

            MessageBox.Show($"Operation completed successfully!\n{successful} files {operation}.",
                "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);

            // Clear the list after successful operation
            if (successful > 0)
            {
                selectedPaths.Clear();
                fileListBox.Items.Clear();
                UpdateStatusLabel();
            }
        }

        private void EncryptFileAdvanced(string filePath, string password)
        {
            // Generate cryptographic components
            byte[] salt = GenerateRandomBytes(SALT_SIZE);
            byte[] iv = GenerateRandomBytes(IV_SIZE);
            byte[] key = DeriveKeyArgon2(password, salt);

            // Read and optionally compress file
            byte[] fileData = File.ReadAllBytes(filePath);
            string originalFileName = Path.GetFileName(filePath);

            FileMetadata metadata = new FileMetadata
            {
                OriginalFileName = originalFileName,
                OriginalSize = fileData.Length,
                CreationTime = File.GetCreationTime(filePath),
                LastWriteTime = File.GetLastWriteTime(filePath),
                IsCompressed = compressionCheckBox.Checked
            };

            byte[] dataToEncrypt;
            if (compressionCheckBox.Checked)
            {
                dataToEncrypt = CompressData(fileData);
            }
            else
            {
                dataToEncrypt = fileData;
            }

            // Add random padding to hide file size
            byte[] padding = GenerateRandomBytes(GenerateRandomPaddingSize());
            byte[] metadataBytes = SerializeMetadata(metadata);

            // Combine: metadata_length(4) + metadata + padding_length(4) + padding + data
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

            // Encrypt using AES-GCM
            byte[] ciphertext = new byte[combined.Length];
            byte[] tag = new byte[TAG_SIZE];

            using (var aes = new AesGcm(key))
            {
                aes.Encrypt(iv, combined, ciphertext, tag);
            }

            // Generate output filename based on scramble setting
            string encryptedPath;
            if (scrambleNamesCheckBox.Checked)
            {
                encryptedPath = GenerateObfuscatedFilename(filePath);
            }
            else
            {
                string directory = Path.GetDirectoryName(filePath);
                encryptedPath = Path.Combine(directory, originalFileName + ENCRYPTED_EXTENSION);
            }

            // Write encrypted file: version(1) + salt(32) + iv(12) + tag(16) + ciphertext
            using (var fs = new FileStream(encryptedPath, FileMode.Create))
            {
                fs.WriteByte(FORMAT_VERSION);
                fs.Write(salt, 0, salt.Length);
                fs.Write(iv, 0, iv.Length);
                fs.Write(tag, 0, tag.Length);
                fs.Write(ciphertext, 0, ciphertext.Length);
            }

            // Set fake timestamp
            File.SetCreationTime(encryptedPath, new DateTime(2020, 1, 1));
            File.SetLastWriteTime(encryptedPath, new DateTime(2020, 1, 1));

            // Securely delete original
            SecureDelete(filePath);
        }

        private void DecryptFileAdvanced(string filePath, string password)
        {
            using (var fs = new FileStream(filePath, FileMode.Open))
            {
                // Read format version
                byte version = (byte)fs.ReadByte();
                if (version != FORMAT_VERSION)
                {
                    throw new InvalidDataException("Unsupported file format version.");
                }

                // Read cryptographic components
                byte[] salt = new byte[SALT_SIZE];
                byte[] iv = new byte[IV_SIZE];
                byte[] tag = new byte[TAG_SIZE];

                fs.Read(salt, 0, SALT_SIZE);
                fs.Read(iv, 0, IV_SIZE);
                fs.Read(tag, 0, TAG_SIZE);

                // Read ciphertext
                byte[] ciphertext = new byte[fs.Length - 1 - SALT_SIZE - IV_SIZE - TAG_SIZE];
                fs.Read(ciphertext, 0, ciphertext.Length);

                // Derive key and decrypt
                byte[] key = DeriveKeyArgon2(password, salt);
                byte[] plaintext = new byte[ciphertext.Length];

                using (var aes = new AesGcm(key))
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

                // Parse decrypted data
                int offset = 0;
                int metadataLength = BitConverter.ToInt32(plaintext, offset);
                offset += 4;

                byte[] metadataBytes = new byte[metadataLength];
                Buffer.BlockCopy(plaintext, offset, metadataBytes, 0, metadataLength);
                offset += metadataLength;

                FileMetadata metadata = DeserializeMetadata(metadataBytes);

                int paddingLength = BitConverter.ToInt32(plaintext, offset);
                offset += 4 + paddingLength; // Skip padding

                byte[] fileData = new byte[plaintext.Length - offset];
                Buffer.BlockCopy(plaintext, offset, fileData, 0, fileData.Length);

                // Decompress if needed
                if (metadata.IsCompressed)
                {
                    fileData = DecompressData(fileData);
                }

                // Restore original filename and write file
                string directory = Path.GetDirectoryName(filePath);
                string originalPath = Path.Combine(directory, metadata.OriginalFileName);

                // Handle duplicate names
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

                // Restore timestamps
                File.SetCreationTime(finalPath, metadata.CreationTime);
                File.SetLastWriteTime(finalPath, metadata.LastWriteTime);
            }

            // Delete encrypted file
            File.Delete(filePath);
        }

        private string GenerateObfuscatedFilename(string originalPath)
        {
            string directory = Path.GetDirectoryName(originalPath);
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

                // Overwrite with random data multiple times
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write))
                {
                    byte[] randomData = GenerateRandomBytes(4096);

                    for (int pass = 0; pass < 3; pass++) // 3-pass overwrite
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
                        randomData = GenerateRandomBytes(4096); // New random data each pass
                    }
                }

                File.Delete(filePath);
            }
            catch
            {
                // Fallback to regular deletion
                try { File.Delete(filePath); } catch { }
            }
        }

        private void SetUIEnabled(bool enabled)
        {
            encryptButton.Enabled = enabled;
            decryptButton.Enabled = enabled;
            passwordTextBox.Enabled = enabled;
            clearListButton.Enabled = enabled;
            compressionCheckBox.Enabled = enabled;
            steganographyCheckBox.Enabled = enabled;
            scrambleNamesCheckBox.Enabled = enabled;
            dropPanel.AllowDrop = enabled;
        }

        private void UpdateStatusLabel()
        {
            if (selectedPaths.Count == 0)
                statusLabel.Text = "Ready - No files selected";
            else
                statusLabel.Text = $"Ready - {selectedPaths.Count} item(s) selected";
        }
        private class FileMetadata
        {
            public string OriginalFileName { get; set; }
            public long OriginalSize { get; set; }
            public DateTime CreationTime { get; set; }
            public DateTime LastWriteTime { get; set; }
            public bool IsCompressed { get; set; }
        }
    }
}

