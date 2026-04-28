<p align="center">
  <img src="assets/FileLocker_Wordmark.png" alt="FileLocker wordmark" width="1672" height="100"/>
</p>

# FileLocker

FileLocker is a Windows desktop app for encrypting, decrypting, validating, and managing local files with a WinUI 3 interface.

It is built for people who want a practical encryption tool that feels approachable without hiding the safety controls that matter.

Current app version: `1.0.5.2`

Latest public release tag: [`v1.0.5.2`](https://github.com/AspectOV/FileLocker/releases/tag/v1.0.5.2)

## Highlights

- Modern WinUI 3 desktop app for Windows 10/11.
- Drag-and-drop queue for files and folders.
- AES-GCM and AES-CBC encryption workflows.
- PBKDF2-SHA256 based key derivation.
- Beginner, Intermediate, and Advanced experience modes.
- Built-in profiles for safer defaults.
- Optional keyfile support.
- Verification, backup, and cleanup controls.
- Custom encrypt output destinations.
- Markdown and CSV report export.
- NSIS installer distribution.
- Automatic update checks through GitHub Releases.
- Help menu shortcuts for the installed app folder and updater download cache.

## Current Release

### FileLocker 1.0.5.2

This is a follow-up release focused on updater testing, supportability, and release metadata consistency.

What changed:

- Added quick Help menu actions to open the installed app folder.
- Added quick Help menu actions to open the updater download cache folder.
- Improved update troubleshooting by making install and download locations easier to inspect.
- Refreshed release metadata and versioning to `1.0.5.2`.
- Updated documentation to match the current app, installer, and release process.

Release asset:

```text
FileLocker-Setup-1.0.5.2.exe
sha256: 5d07105c584631b40344fc3f03b6d915efe00f5d800d938511399566ced967bc
```

## Core Features

### Encryption and Decryption

- Encrypt files with AES-GCM or AES-CBC.
- Decrypt FileLocker payloads back to their original file names and extensions.
- Optional compression before encryption.
- Optional filename scrambling.
- Optional PNG container mode for less obvious encrypted output.
- Save encrypted output next to source files or to a custom folder.

### Safety and Recovery

- Temporary-file write flow to reduce partial-write risk.
- Optional post-write verification.
- Optional backup copy creation before destructive actions.
- Optional original-file removal after success.
- Optional secure delete when removing originals.
- Preflight validation before queued work starts.
- Failed queue items remain visible and include clearer details.

### Profiles and Key Material

- Built-in security profiles.
- Save reusable custom profiles.
- Optional keyfile support in addition to password-based encryption.
- Password strength feedback in the UI.
- Built-in help for terms such as Verify Only, Rotate Access, Keyfile, and Recovery key.

### Queue and Reporting

- Drag-and-drop queue.
- Recursive folder handling.
- Duplicate skipping.
- Queue metrics for file count, root selections, and total size.
- Structured queue item details.
- Recent job history.
- Markdown and CSV report export through save pickers.

## Built-In Profiles

| Profile          | Purpose                                                                    |
| ---------------- | -------------------------------------------------------------------------- |
| Recommended      | Balanced default with AES-GCM, verification, and non-destructive behavior. |
| Private Archive  | Better privacy defaults with scrambled names and randomized metadata.      |
| Fast Local Lock  | Faster local protection with compression disabled.                         |
| Transfer Copy    | Verified encrypted output with source removal after success.               |
| Shred After Lock | Aggressive cleanup path with secure delete after success.                  |
| Stealth PNG      | Wraps encrypted output in a PNG container.                                 |

## Security Notes

FileLocker currently uses:

- AES-GCM.
- AES-CBC.
- PBKDF2-SHA256 for key derivation.

Some older internal naming still references Argon2 from earlier experiments, but the current implementation is PBKDF2-SHA256.

## Requirements

### End Users

- Windows 10 or Windows 11.
- x64 system for the current NSIS installer.

### Development

- Visual Studio 2022 recommended.
- .NET SDK matching `global.json`.

## Install

The recommended way to install FileLocker is from GitHub Releases.

Download the latest installer asset:

```text
FileLocker-Setup-1.0.5.2.exe
```

Run the installer and launch the app normally from the Start menu.

## Automatic Updates

FileLocker checks GitHub Releases for updates.

The updater expects:

- a published GitHub Release on `AspectOV/FileLocker`;
- a release tag like `v1.0.5.2`;
- an uploaded installer asset named `FileLocker-Setup-1.0.5.2.exe`.

When a newer release is found, the app can:

- show the release notes;
- download the installer;
- verify the published SHA-256 digest when GitHub provides one;
- close FileLocker and launch the new installer.

The Help menu can open the installed app folder and updater download cache folder so you can confirm the installed build and inspect the downloaded installer.

## Build From Source

1. Clone the repository.

```powershell
git clone https://github.com/jeremymhayes/FileLocker.git
cd FileLocker
```

2. Build the app.

```powershell
dotnet build .\FileLocker\FileLocker.csproj -c Release
```

3. Publish the unpackaged app.

```powershell
dotnet publish .\FileLocker\FileLocker.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=false /p:PublishTrimmed=false
```

4. Build the NSIS installer.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Build-Installer.ps1
```

Installer output:

```text
artifacts\nsis\FileLocker-Setup-1.0.5.2.exe
```

## Release Workflow

For a new public release:

1. Update the version values in `FileLocker.csproj`.
2. Build a fresh installer with `Build-Installer.ps1`.
3. Create a GitHub Release with a matching tag such as `v1.0.5.2`.
4. Upload the generated installer asset, such as `FileLocker-Setup-1.0.5.2.exe`.
5. Confirm the updater can read the tag and installer asset from the release.

## Project Layout

```text
FileLocker/
├── FileLocker.slnx
├── README.md
├── global.json
├── installer/
├── scripts/
└── FileLocker/
    ├── App.xaml
    ├── App.xaml.cs
    ├── MainWindow.xaml
    ├── MainWindow.xaml.cs
    ├── UpdateService.cs
    ├── FileLocker.csproj
    ├── app.manifest
    ├── Assets/
    ├── Themes/
    └── Properties/
```

## Notes

- Legacy MSIX/AppInstaller files are still present in the repository for reference, but the current distribution path is unpackaged plus NSIS.
- App data is stored under the user profile, not beside the installed executable.
- Reports are exported through a save picker so the user chooses the destination.
- The advanced warning banner can be dismissed and restored.
- Custom encrypt output selection is intended to make batch workflows more flexible without changing the default same-folder behavior.

## Repository Files

- `FileLocker.csproj`
- `FileLocker.nsi`
- `Build-Installer.ps1`
- `FEATURE_IMPROVEMENTS.md`

## Summary

FileLocker is a Windows-focused file protection app with guided workflows, reusable profiles, safer output handling, report export, NSIS-based distribution, and GitHub Releases update support through the current `1.0.5.2` release.
