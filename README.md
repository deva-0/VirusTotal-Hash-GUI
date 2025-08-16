# VirusTotal Hash GUI

A simple Windows GUI tool to calculate file hashes and check them on VirusTotal without uploading your files.

## What it does

- Calculates SHA256/SHA1/MD5 hashes of any file
- Generates VirusTotal links to check if the file is malicious
- No upload needed - your files stay on your computer
- Drag & drop support for quick checking

## Installation

Just download `VirusTotal-Hash-GUI.ps1` and run it. 

If Windows blocks it, either:
- Right-click → Properties → Unblock
- Or run PowerShell as admin and type: `Set-ExecutionPolicy RemoteSigned`

## Usage

1. **Run the script** - Double-click or right-click → "Run with PowerShell"
2. **Select a file** - Browse or drag & drop
3. **Click "Calculate Hash"**
4. **Click "Open in VirusTotal"** to check if it's malware

That's it. The tool will open VirusTotal in your browser with the file's reputation info.

## Why use this?

Sometimes you want to check if a file is malicious without uploading it (maybe it contains sensitive data). This tool calculates the file's "fingerprint" (hash) locally and checks if that fingerprint is known to VirusTotal.

## Requirements

- Windows 7 or newer
- PowerShell 5.0+ (comes with Windows 10/11)

## Quick tips

- SHA256 is the default and recommended
- Large files take longer (1GB ≈ 5 seconds)
- You can drag files directly onto the window
- The hash is just a fingerprint - no file content is shared

## Troubleshooting

**"Cannot be loaded" error?**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**File access denied?**
- Make sure the file isn't open in another program

**VirusTotal doesn't recognize the hash?**
- This means the file hasn't been scanned before
- You'll need to upload it manually if you want it analyzed

## License

MIT - Use it however you want.

---

*Note: This is a third-party tool. VirusTotal is a Google service with its own terms.*
