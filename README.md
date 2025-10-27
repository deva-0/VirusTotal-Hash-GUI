# VirusTotal Hash GUI

A powerful Windows GUI tool to calculate file hashes and check them on VirusTotal without uploading your files.

## What it does

- Calculates SHA256/SHA1/MD5 hashes of any file
- **NEW: Calculate all hash types at once** for comprehensive analysis
- Generates VirusTotal links to check if the file is malicious
- **NEW: Real-time progress bar** for large file hash calculations
- **NEW: Hash verification** - compare calculated hashes against known values
- **NEW: Export functionality** - save results to TXT, CSV, or JSON
- No upload needed - your files stay on your computer
- Drag & drop support for quick checking
- **NEW: Keyboard shortcuts** for faster workflow
- **NEW: Auto-calculate option** for instant results

## Installation

Just download `VirusTotal-Hash-GUI.ps1` and run it. 

If Windows blocks it, either:
- Right-click → Properties → Unblock
- Or run PowerShell as admin and type: `Set-ExecutionPolicy RemoteSigned`

## Usage

### Basic Usage
1. **Run the script** - Double-click or right-click → "Run with PowerShell"
2. **Select a file** - Browse or drag & drop
3. **Click "Calculate All"** to get all hash types at once
4. **Click "Open in VirusTotal"** to check if it's malware

### Advanced Features

**Calculate All Hashes**
- Click "Calculate All" to generate SHA256, SHA1, and MD5 in one go
- Progress bar shows real-time calculation progress
- All hashes displayed simultaneously for easy reference

**Hash Verification**
- Calculate the hash of a file
- Paste an expected hash value in the verification field
- Click "Verify" to confirm the file matches the expected hash
- Great for validating downloads or checking file integrity

**Export Results**
- After calculating hashes, click "Export..."
- Choose format: Text, CSV, or JSON
- Results include file info, all hashes, and VirusTotal URL
- Perfect for documentation or audit trails

**Auto-Calculate Mode**
- Enable "Auto-calculate" checkbox
- Hashes are automatically calculated when you select a file
- Speeds up workflow when checking multiple files

**Keyboard Shortcuts**
- `Ctrl+O` - Browse for file
- `F5` or `Ctrl+H` - Calculate selected hash
- `Ctrl+Shift+H` - Calculate all hashes
- `Ctrl+E` - Export results
- `Ctrl+V` - Open VirusTotal

## Why use this?

Sometimes you want to check if a file is malicious without uploading it (maybe it contains sensitive data). This tool calculates the file's "fingerprint" (hash) locally and checks if that fingerprint is known to VirusTotal.

## Requirements

- Windows 7 or newer
- PowerShell 5.0+ (comes with Windows 10/11)

## Quick tips

- **Use "Calculate All"** for the most comprehensive results
- SHA256 is the default and most secure hash algorithm
- Large files show a progress bar during calculation
- You can drag files directly onto the window
- The hash is just a fingerprint - no file content is shared
- Enable auto-calculate for batch checking multiple files
- Use hash verification to confirm file integrity
- Export results for record-keeping or sharing with your team

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

## What's New in v3.0

- **Multi-hash calculation**: Calculate SHA256, SHA1, and MD5 simultaneously
- **Progress bar**: Visual feedback during hash calculation with percentage
- **Hash verification**: Compare calculated hashes against expected values
- **Export functionality**: Save results to TXT, CSV, or JSON formats
- **Auto-calculate mode**: Automatically calculate hashes when selecting files
- **Keyboard shortcuts**: Speed up your workflow with hotkeys
- **Enhanced UI**: Larger window with better organization
- **Tooltips**: Hover help for all controls
- **Copy all hashes**: Copy all hash values at once
- **Better status messages**: More informative feedback throughout

## Features Comparison

| Feature | v2.0 | v3.0 |
|---------|------|------|
| Single hash calculation | ✓ | ✓ |
| Multi-hash calculation | ✗ | ✓ |
| Progress bar | ✗ | ✓ |
| Hash verification | ✗ | ✓ |
| Export to file | ✗ | ✓ |
| Auto-calculate | ✗ | ✓ |
| Keyboard shortcuts | ✗ | ✓ |
| Tooltips | ✗ | ✓ |

## License

MIT - Use it however you want.

---

*Note: This is a third-party tool. VirusTotal is a Google service with its own terms.*
