#Requires -Version 5.0
<#
.SYNOPSIS
    VirusTotal Hash Calculator with GUI
.DESCRIPTION
    A PowerShell GUI application for calculating file hashes and generating VirusTotal URLs.
    Supports SHA256, SHA1, and MD5 algorithms with drag-and-drop functionality.
.AUTHOR
    deva
.VERSION
    2.0
#>


Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Script-wide variables
$script:CurrentFile = $null
$script:CurrentHash = $null

#region Helper Functions

function Write-StatusMessage {
    <#
    .SYNOPSIS
        Updates the status label with a message and color
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [System.Drawing.Color]$Color = [System.Drawing.Color]::Black
    )
    
    $script:StatusLabel.Text = $Message
    $script:StatusLabel.ForeColor = $Color
    $script:MainForm.Refresh()
}

function Get-FormattedFileSize {
    <#
    .SYNOPSIS
        Formats file size in human-readable format
    #>
    param(
        [Parameter(Mandatory=$true)]
        [long]$Bytes
    )
    
    switch ($Bytes) {
        {$_ -gt 1TB} { return "{0:N2} TB" -f ($Bytes / 1TB) }
        {$_ -gt 1GB} { return "{0:N2} GB" -f ($Bytes / 1GB) }
        {$_ -gt 1MB} { return "{0:N2} MB" -f ($Bytes / 1MB) }
        {$_ -gt 1KB} { return "{0:N2} KB" -f ($Bytes / 1KB) }
        default { return "$Bytes bytes" }
    }
}

function Test-FileAccess {
    <#
    .SYNOPSIS
        Checks if file can be accessed for reading
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $fileStream.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Copy-ToClipboard {
    <#
    .SYNOPSIS
        Copies text to clipboard with error handling
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Text,
        
        [Parameter(Mandatory=$true)]
        [string]$ItemType
    )
    
    try {
        [System.Windows.Forms.Clipboard]::SetText($Text)
        Write-StatusMessage -Message "$ItemType copied to clipboard!" -Color Green
        return $true
    }
    catch {
        Write-StatusMessage -Message "Failed to copy $ItemType to clipboard" -Color Red
        return $false
    }
}

#endregion

#region File Operations

function Set-SelectedFile {
    <#
    .SYNOPSIS
        Sets the selected file and updates UI accordingly
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
        Write-StatusMessage -Message "File not found: $FilePath" -Color Red
        return $false
    }
    
    if (-not (Test-FileAccess -FilePath $FilePath)) {
        Write-StatusMessage -Message "Cannot access file. It may be in use or protected." -Color Red
        return $false
    }
    
    $script:CurrentFile = $FilePath
    $script:FilePathTextBox.Text = $FilePath
    $script:CalculateButton.Enabled = $true
    
    Update-FileInformation -FilePath $FilePath
    Clear-HashResults
    Write-StatusMessage -Message "File selected. Ready to calculate hash."
    
    return $true
}

function Update-FileInformation {
    <#
    .SYNOPSIS
        Updates the file information display
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        $fileInfo = Get-Item -Path $FilePath -ErrorAction Stop
        $fileSize = Get-FormattedFileSize -Bytes $fileInfo.Length
        
        $infoText = @"
File Name: $($fileInfo.Name)
File Size: $fileSize ($("{0:N0}" -f $fileInfo.Length) bytes)
Created: $($fileInfo.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"))
Modified: $($fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"))
Attributes: $($fileInfo.Attributes)
Full Path: $($fileInfo.FullName)
"@
        $script:FileInfoTextBox.Text = $infoText
    }
    catch {
        $script:FileInfoTextBox.Text = "Unable to retrieve file information: $_"
    }
}

function Clear-HashResults {
    <#
    .SYNOPSIS
        Clears hash calculation results
    #>
    $script:HashTextBox.Clear()
    $script:URLTextBox.Clear()
    $script:CopyHashButton.Enabled = $false
    $script:CopyURLButton.Enabled = $false
    $script:OpenURLButton.Enabled = $false
    $script:CurrentHash = $null
}

function Calculate-FileHash {
    <#
    .SYNOPSIS
        Calculates the hash of the selected file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("SHA256", "SHA1", "MD5")]
        [string]$Algorithm
    )
    
    Write-StatusMessage -Message "Calculating $Algorithm hash..."
    
    try {
        # Check file size for warning
        $fileInfo = Get-Item -Path $FilePath
        if ($fileInfo.Length -gt 1GB) {
            Write-StatusMessage -Message "Large file detected. This may take a moment..." -Color Blue
        }
        
        # Calculate hash
        $hashResult = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop
        $script:CurrentHash = $hashResult.Hash
        
        # Update UI
        $script:HashTextBox.Text = $hashResult.Hash
        $vtUrl = "https://www.virustotal.com/gui/file/$($hashResult.Hash.ToLower())"
        $script:URLTextBox.Text = $vtUrl
        
        # Enable action buttons
        $script:CopyHashButton.Enabled = $true
        $script:CopyURLButton.Enabled = $true
        $script:OpenURLButton.Enabled = $true
        
        Write-StatusMessage -Message "$Algorithm hash calculated successfully!" -Color Green
        return $true
    }
    catch {
        $errorMessage = "Error calculating hash: $($_.Exception.Message)"
        Write-StatusMessage -Message $errorMessage -Color Red
        [System.Windows.Forms.MessageBox]::Show(
            $errorMessage,
            "Hash Calculation Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return $false
    }
}

#endregion

#region Event Handlers

function Invoke-BrowseFile {
    <#
    .SYNOPSIS
        Opens file dialog for file selection
    #>
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = "Select file to hash"
    $openFileDialog.Filter = "All Files (*.*)|*.*|Executable Files (*.exe)|*.exe|DLL Files (*.dll)|*.dll|Archive Files (*.zip;*.rar;*.7z)|*.zip;*.rar;*.7z"
    $openFileDialog.FilterIndex = 1
    $openFileDialog.RestoreDirectory = $true
    
    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Set-SelectedFile -FilePath $openFileDialog.FileName | Out-Null
    }
}

function Invoke-CalculateHash {
    <#
    .SYNOPSIS
        Initiates hash calculation for selected file
    #>
    if ([string]::IsNullOrWhiteSpace($script:CurrentFile)) {
        Write-StatusMessage -Message "No file selected" -Color Red
        return
    }
    
    if (-not (Test-Path -Path $script:CurrentFile)) {
        Write-StatusMessage -Message "Selected file no longer exists" -Color Red
        Clear-HashResults
        return
    }
    
    $algorithm = $script:AlgorithmComboBox.SelectedItem.ToString()
    Calculate-FileHash -FilePath $script:CurrentFile -Algorithm $algorithm | Out-Null
}

function Invoke-OpenVirusTotal {
    <#
    .SYNOPSIS
        Opens VirusTotal URL in default browser
    #>
    if (-not [string]::IsNullOrWhiteSpace($script:URLTextBox.Text)) {
        try {
            Start-Process $script:URLTextBox.Text
            Write-StatusMessage -Message "Opening VirusTotal in browser..." -Color Blue
        }
        catch {
            Write-StatusMessage -Message "Failed to open browser" -Color Red
        }
    }
}

function Handle-DragEnter {
    <#
    .SYNOPSIS
        Handles drag enter event
    #>
    param($Sender, $Event)
    
    if ($Event.Data.GetDataPresent([Windows.Forms.DataFormats]::FileDrop)) {
        $Event.Effect = [Windows.Forms.DragDropEffects]::Copy
    }
    else {
        $Event.Effect = [Windows.Forms.DragDropEffects]::None
    }
}

function Handle-DragDrop {
    <#
    .SYNOPSIS
        Handles drag drop event
    #>
    param($Sender, $Event)
    
    $files = $Event.Data.GetData([Windows.Forms.DataFormats]::FileDrop)
    if ($files -and $files.Count -gt 0) {
        if ($files.Count -gt 1) {
            Write-StatusMessage -Message "Multiple files detected. Using first file only." -Color Orange
        }
        Set-SelectedFile -FilePath $files[0] | Out-Null
    }
}

#endregion

#region UI Creation Functions

function New-Label {
    <#
    .SYNOPSIS
        Creates a new label control
    #>
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 80,
        [int]$Height = 20
    )
    
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point($X, $Y)
    $label.Size = New-Object System.Drawing.Size($Width, $Height)
    $label.Text = $Text
    return $label
}

function New-TextBox {
    <#
    .SYNOPSIS
        Creates a new textbox control
    #>
    param(
        [int]$X,
        [int]$Y,
        [int]$Width,
        [int]$Height = 20,
        [bool]$ReadOnly = $true,
        [bool]$Multiline = $false,
        [System.Drawing.Font]$Font = $null
    )
    
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point($X, $Y)
    $textBox.Size = New-Object System.Drawing.Size($Width, $Height)
    $textBox.ReadOnly = $ReadOnly
    $textBox.Multiline = $Multiline
    
    if ($Font) {
        $textBox.Font = $Font
    }
    
    if ($Multiline) {
        $textBox.ScrollBars = "Vertical"
    }
    
    return $textBox
}

function New-Button {
    <#
    .SYNOPSIS
        Creates a new button control
    #>
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 75,
        [int]$Height = 23,
        [scriptblock]$ClickAction = $null,
        [bool]$Enabled = $true
    )
    
    $button = New-Object System.Windows.Forms.Button
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size($Width, $Height)
    $button.Text = $Text
    $button.Enabled = $Enabled
    
    if ($ClickAction) {
        $button.Add_Click($ClickAction)
    }
    
    return $button
}

function Initialize-MainForm {
    <#
    .SYNOPSIS
        Creates and configures the main form
    #>
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "VirusTotal Hash Calculator v2.0"
    $form.Size = New-Object System.Drawing.Size(620, 440)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.Icon = [System.Drawing.SystemIcons]::Shield
    
    # Enable drag and drop
    $form.AllowDrop = $true
    $form.Add_DragEnter({ Handle-DragEnter -Sender $args[0] -Event $args[1] })
    $form.Add_DragDrop({ Handle-DragDrop -Sender $args[0] -Event $args[1] })
    
    return $form
}

function Initialize-UIControls {
    <#
    .SYNOPSIS
        Creates all UI controls and adds them to the form
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.Form]$Form
    )
    
    # File selection section
    $Form.Controls.Add((New-Label -Text "File Path:" -X 10 -Y 20))
    
    $script:FilePathTextBox = New-TextBox -X 90 -Y 20 -Width 400
    $Form.Controls.Add($script:FilePathTextBox)
    
    $script:BrowseButton = New-Button -Text "Browse..." -X 500 -Y 18 -ClickAction { Invoke-BrowseFile }
    $Form.Controls.Add($script:BrowseButton)
    
    # Algorithm selection section
    $Form.Controls.Add((New-Label -Text "Algorithm:" -X 10 -Y 60))
    
    $script:AlgorithmComboBox = New-Object System.Windows.Forms.ComboBox
    $script:AlgorithmComboBox.Location = New-Object System.Drawing.Point(90, 60)
    $script:AlgorithmComboBox.Size = New-Object System.Drawing.Size(150, 20)
    $script:AlgorithmComboBox.DropDownStyle = "DropDownList"
    $script:AlgorithmComboBox.Items.AddRange(@("SHA256", "SHA1", "MD5"))
    $script:AlgorithmComboBox.SelectedIndex = 0
    $Form.Controls.Add($script:AlgorithmComboBox)
    
    $script:CalculateButton = New-Button -Text "Calculate Hash" -X 250 -Y 58 -Width 100 `
        -ClickAction { Invoke-CalculateHash } -Enabled $false
    $Form.Controls.Add($script:CalculateButton)
    
    # Hash result section
    $Form.Controls.Add((New-Label -Text "Hash:" -X 10 -Y 100))
    
    $script:HashTextBox = New-TextBox -X 90 -Y 100 -Width 400 `
        -Font (New-Object System.Drawing.Font("Consolas", 9))
    $Form.Controls.Add($script:HashTextBox)
    
    $script:CopyHashButton = New-Button -Text "Copy" -X 500 -Y 98 `
        -ClickAction { Copy-ToClipboard -Text $script:HashTextBox.Text -ItemType "Hash" } `
        -Enabled $false
    $Form.Controls.Add($script:CopyHashButton)
    
    # URL section
    $Form.Controls.Add((New-Label -Text "VT URL:" -X 10 -Y 140))
    
    $script:URLTextBox = New-TextBox -X 90 -Y 140 -Width 400
    $Form.Controls.Add($script:URLTextBox)
    
    $script:CopyURLButton = New-Button -Text "Copy" -X 500 -Y 138 `
        -ClickAction { Copy-ToClipboard -Text $script:URLTextBox.Text -ItemType "URL" } `
        -Enabled $false
    $Form.Controls.Add($script:CopyURLButton)
    
    # Open URL button
    $script:OpenURLButton = New-Button -Text "Open in VirusTotal" -X 225 -Y 180 -Width 150 -Height 30 `
        -ClickAction { Invoke-OpenVirusTotal } -Enabled $false
    $script:OpenURLButton.BackColor = [System.Drawing.Color]::LightBlue
    $Form.Controls.Add($script:OpenURLButton)
    
    # File information group box
    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Location = New-Object System.Drawing.Point(10, 230)
    $groupBox.Size = New-Object System.Drawing.Size(585, 120)
    $groupBox.Text = "File Information"
    $Form.Controls.Add($groupBox)
    
    $script:FileInfoTextBox = New-TextBox -X 10 -Y 20 -Width 565 -Height 90 -Multiline $true `
        -Font (New-Object System.Drawing.Font("Consolas", 8))
    $groupBox.Controls.Add($script:FileInfoTextBox)
    
    # Status label
    $script:StatusLabel = New-Label -Text "Ready. Select a file or drag and drop to begin." `
        -X 10 -Y 360 -Width 585 -Height 20
    $Form.Controls.Add($script:StatusLabel)
}

#endregion

#region Main Execution

function Start-HashCalculatorGUI {
    <#
    .SYNOPSIS
        Main entry point for the application
    #>
    
    # Create main form
    $script:MainForm = Initialize-MainForm
    
    # Initialize all UI controls
    Initialize-UIControls -Form $script:MainForm
    
    # Check for command-line file argument
    if ($args -and $args.Count -gt 0) {
        $filePath = $args[0]
        if (Test-Path -Path $filePath -PathType Leaf) {
            Set-SelectedFile -FilePath $filePath | Out-Null
        }
    }
    
    # Show the form
    $script:MainForm.ShowDialog() | Out-Null
    
    # Cleanup
    $script:MainForm.Dispose()
}

# Start the application
Start-HashCalculatorGUI

#endregion