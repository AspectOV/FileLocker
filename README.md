# FileLocker

FileLocker is a free, local-first Windows desktop security app built with WinUI 3 and the Windows App SDK. It focuses on practical file protection workflows: encrypt files, decrypt FileLocker payloads, generate hashes, manage local history, and run helper security tools without sending files to a cloud service.

Current app version: **1.0.5.2**

## What FileLocker Does

- Encrypt files and folders with the current FileLocker payload format.
- Decrypt supported FileLocker encrypted outputs, including `.locked` files.
- Generate and verify file hashes with SHA-256 as the recommended default.
- Track recent local activity when history is enabled.
- Show dashboard stats for protected files, last operation, security status, and compression impact.
- Provide helper pages for Encode Text, Metadata Scrambler, and Secure Delete.
- Keep core file work local to the device.

## Current App Pages

The main app shell currently includes:

1. Dashboard
2. Encrypt Files
3. Decrypt Files
4. Hash Files
5. Encode Text
6. Metadata Scrambler
7. Secure Delete
8. Settings
9. About

Dashboard is the default startup page for normal launches. Explorer or context-menu launches can still queue files into the existing workflow.

## Encryption And Decryption

FileLocker uses **AES-256-GCM** as the default and recommended encryption mode. The app is designed around authenticated encryption and the existing FileLocker payload format. Compatibility options may appear in the UI only as disabled or advanced notes unless the underlying format support is implemented safely.

Encrypted files use the project-specific `.locked` extension for normal FileLocker outputs. Decrypt Files validates selected encrypted files and handles unsupported files as a safe UI state instead of treating every file as decryptable.

Important security behavior:

- Passwords are not stored in settings, history, queues, or recent files.
- Passwords are not logged.
- FileLocker cannot recover forgotten or incorrect passwords.
- Wrong passwords and corrupted payloads fail safely.
- Source files are not deleted unless the matching delete-after-success option is explicitly enabled and the operation succeeds.

## Compression And Storage Impact

Compression is optional and is measured separately from encryption overhead.

The Dashboard **Storage Impact** card reports compression savings using:

```text
original input size before compression - compressed payload size before encryption
```

This avoids the misleading older behavior of comparing the original file size to the final encrypted output. Encrypted output can be larger because encryption adds metadata and authentication overhead, even when compression helped.

The UI now reports:

- saved space when compression reduced the payload,
- no savings when compression had no benefit,
- increased size when compression made the payload larger.

## Hash Files

The Hash Files page is for integrity checks and comparison workflows.

- SHA-256 is the recommended/default algorithm.
- SHA-512 is available for stronger digest length when supported by the app.
- Hash output is displayed for copying, saving, and verification.
- Expected hash comparison normalizes common whitespace/case issues before reporting match or mismatch.

Hashing is not encryption. It verifies integrity; it does not hide file contents.

## Settings And Privacy

Settings are grouped around appearance, security, file handling, privacy, updates, and about/support details.

Local-first behavior:

- File operations run on the local machine.
- Activity history is local and can be disabled or cleared.
- Update checks contact GitHub Releases, but file contents are not uploaded.
- Temporary/update files are stored under the user's local app data folder, not beside the installed executable.

## Updates

FileLocker uses GitHub Releases for update checks.

The updater expects:

- a release on `jeremymhayes/FileLocker`,
- a version tag such as `v1.0.5.2`,
- an installer asset named like `FileLocker-Setup-1.0.5.2.exe`.

The app is not currently code signed. That means Windows may show SmartScreen or publisher warnings for installers. The updater still supports the unsigned installer flow by validating release/download information and installer digest data where available, instead of requiring an Authenticode signature before a user can update.

Manual update checks are available from the app's help/update controls.

## Install

The recommended public install path is the NSIS installer from GitHub Releases:

```text
FileLocker-Setup-<version>.exe
```

Run the installer normally. On unsigned builds, Windows may ask for extra confirmation.

## Build From Source

### Requirements

- Windows 10 or Windows 11
- .NET SDK matching `global.json`
- Visual Studio 2022 recommended for WinUI development
- NSIS for installer builds, or `makensis.exe` available on PATH

### Build the app

```powershell
dotnet build .\FileLocker\FileLocker.csproj -c Release
```

### Run tests

```powershell
dotnet test .\FileLocker.Tests\FileLocker.Tests.csproj
```

### Build the NSIS installer

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Build-Installer.ps1 -Configuration Release
```

The installer workflow stages a fresh unpackaged WinUI publish output before NSIS packages it.

## Project Layout

```text
FileLocker/
├── FileLocker.slnx
├── README.md
├── global.json
├── installer/
├── scripts/
├── artifacts/
├── FileLocker/
└── FileLocker.Tests/
```

Key files:

- `FileLocker/FileLocker.csproj`
- `FileLocker/MainWindow.xaml`
- `FileLocker/MainWindow.Navigation.cs`
- `FileLocker/MainWindow.EncryptFiles.cs`
- `FileLocker/MainWindow.DecryptFiles.cs`
- `FileLocker/MainWindow.HashFiles.cs`
- `FileLocker/MainWindow.Workflows.cs`
- `FileLocker/OperationHistoryModels.cs`
- `FileLocker/UpdateService.cs`
- `installer/FileLocker.nsi`
- `scripts/Build-Installer.ps1`

## Current Distribution Model

FileLocker is currently distributed as an **unpackaged WinUI app with an NSIS installer**.

Legacy MSIX/AppInstaller files may still exist in the repo, but the active release path is NSIS plus GitHub Releases. Generated installer binaries should not be committed to source control.

## Security Notes

FileLocker is a local file security tool, not a password recovery product.

- Keep encryption passwords somewhere safe.
- Test decrypting important files before deleting originals.
- Keep backups for critical data.
- Do not assume compression will always reduce file size.
- Treat Secure Delete and delete-after-success options as destructive.

## License

See the repository license file or the in-app About page for license details.
