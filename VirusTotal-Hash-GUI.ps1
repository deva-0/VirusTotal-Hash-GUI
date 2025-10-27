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
    3.0
#>


Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Script-wide variables
$script:CurrentFile = $null
$script:CurrentHash = $null
$script:AllHashes = @{}
$script:AutoCalculate = $false

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
    $script:CalculateAllButton.Enabled = $true

    Update-FileInformation -FilePath $FilePath
    Clear-HashResults
    Write-StatusMessage -Message "File selected. Ready to calculate hash."

    # Auto-calculate if enabled
    if ($script:AutoCalculate -and $script:AutoCalcCheckbox.Checked) {
        Invoke-CalculateAllHashes
    }

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
    $script:AllHashesTextBox.Clear()
    $script:VerifyHashTextBox.Clear()
    $script:VerifyResultLabel.Text = ""
    $script:CopyHashButton.Enabled = $false
    $script:CopyURLButton.Enabled = $false
    $script:OpenURLButton.Enabled = $false
    $script:CopyAllHashesButton.Enabled = $false
    $script:ExportButton.Enabled = $false
    $script:CurrentHash = $null
    $script:AllHashes.Clear()
}

function Calculate-FileHashWithProgress {
    <#
    .SYNOPSIS
        Calculates the hash of a file with progress updates
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [ValidateSet("SHA256", "SHA1", "MD5")]
        [string]$Algorithm
    )

    try {
        $fileInfo = Get-Item -Path $FilePath -ErrorAction Stop
        $fileStream = [System.IO.File]::OpenRead($FilePath)

        $hasher = switch ($Algorithm) {
            "SHA256" { [System.Security.Cryptography.SHA256]::Create() }
            "SHA1" { [System.Security.Cryptography.SHA1]::Create() }
            "MD5" { [System.Security.Cryptography.MD5]::Create() }
        }

        $buffer = New-Object byte[] 4096
        $totalBytes = $fileStream.Length
        $bytesRead = 0
        $totalRead = 0

        while (($bytesRead = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $hasher.TransformBlock($buffer, 0, $bytesRead, $null, 0) | Out-Null
            $totalRead += $bytesRead

            # Update progress every 1MB or for small files
            if ($totalRead % 1MB -eq 0 -or $totalRead -eq $totalBytes) {
                $percent = [math]::Min(100, [int](($totalRead / $totalBytes) * 100))
                $script:ProgressBar.Value = $percent
                $script:MainForm.Refresh()
            }
        }

        $hasher.TransformFinalBlock($buffer, 0, 0) | Out-Null
        $hash = [System.BitConverter]::ToString($hasher.Hash) -replace '-', ''

        $fileStream.Close()
        $hasher.Dispose()

        return $hash
    }
    catch {
        if ($fileStream) { $fileStream.Close() }
        if ($hasher) { $hasher.Dispose() }
        throw
    }
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
    $script:ProgressBar.Value = 0
    $script:ProgressBar.Visible = $true

    try {
        # Check file size for warning
        $fileInfo = Get-Item -Path $FilePath
        if ($fileInfo.Length -gt 1GB) {
            Write-StatusMessage -Message "Large file detected. This may take a moment..." -Color Blue
        }

        # Calculate hash with progress
        $hash = Calculate-FileHashWithProgress -FilePath $FilePath -Algorithm $Algorithm
        $script:CurrentHash = $hash

        # Update UI
        $script:HashTextBox.Text = $hash
        $vtUrl = "https://www.virustotal.com/gui/file/$($hash.ToLower())"
        $script:URLTextBox.Text = $vtUrl

        # Enable action buttons
        $script:CopyHashButton.Enabled = $true
        $script:CopyURLButton.Enabled = $true
        $script:OpenURLButton.Enabled = $true

        $script:ProgressBar.Value = 100
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
    finally {
        # Hide progress bar after a short delay
        Start-Sleep -Milliseconds 500
        $script:ProgressBar.Visible = $false
        $script:ProgressBar.Value = 0
    }
}

function Calculate-AllHashes {
    <#
    .SYNOPSIS
        Calculates all hash types for the selected file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    Write-StatusMessage -Message "Calculating all hashes..."
    $script:ProgressBar.Value = 0
    $script:ProgressBar.Visible = $true
    $script:AllHashes.Clear()

    try {
        $algorithms = @("SHA256", "SHA1", "MD5")
        $completed = 0

        foreach ($algorithm in $algorithms) {
            $hash = Calculate-FileHashWithProgress -FilePath $FilePath -Algorithm $algorithm
            $script:AllHashes[$algorithm] = $hash

            $completed++
            $script:ProgressBar.Value = [int](($completed / $algorithms.Count) * 100)
        }

        # Update display with SHA256 by default
        $script:CurrentHash = $script:AllHashes["SHA256"]
        $script:HashTextBox.Text = $script:AllHashes["SHA256"]
        $vtUrl = "https://www.virustotal.com/gui/file/$($script:AllHashes["SHA256"].ToLower())"
        $script:URLTextBox.Text = $vtUrl

        # Show all hashes in info panel
        $hashInfo = @"
SHA256: $($script:AllHashes["SHA256"])
SHA1:   $($script:AllHashes["SHA1"])
MD5:    $($script:AllHashes["MD5"])
"@
        $script:AllHashesTextBox.Text = $hashInfo

        # Enable buttons
        $script:CopyHashButton.Enabled = $true
        $script:CopyURLButton.Enabled = $true
        $script:OpenURLButton.Enabled = $true
        $script:CopyAllHashesButton.Enabled = $true
        $script:ExportButton.Enabled = $true

        Write-StatusMessage -Message "All hashes calculated successfully!" -Color Green
        return $true
    }
    catch {
        $errorMessage = "Error calculating hashes: $($_.Exception.Message)"
        Write-StatusMessage -Message $errorMessage -Color Red
        return $false
    }
    finally {
        Start-Sleep -Milliseconds 500
        $script:ProgressBar.Visible = $false
        $script:ProgressBar.Value = 0
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

function Invoke-CalculateAllHashes {
    <#
    .SYNOPSIS
        Initiates calculation of all hash types for selected file
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

    Calculate-AllHashes -FilePath $script:CurrentFile | Out-Null
}

function Invoke-VerifyHash {
    <#
    .SYNOPSIS
        Verifies the calculated hash against a user-provided hash
    #>
    if ([string]::IsNullOrWhiteSpace($script:CurrentHash)) {
        Write-StatusMessage -Message "No hash calculated yet" -Color Red
        return
    }

    $providedHash = $script:VerifyHashTextBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($providedHash)) {
        Write-StatusMessage -Message "Please enter a hash to verify" -Color Red
        return
    }

    # Remove any spaces or dashes from both hashes for comparison
    $calculatedHash = $script:CurrentHash -replace '[-\s]', ''
    $providedHash = $providedHash -replace '[-\s]', ''

    if ($calculatedHash -eq $providedHash) {
        $script:VerifyResultLabel.Text = "MATCH: Hash verification successful!"
        $script:VerifyResultLabel.ForeColor = [System.Drawing.Color]::Green
        Write-StatusMessage -Message "Hash verification: MATCH" -Color Green
    }
    else {
        $script:VerifyResultLabel.Text = "NO MATCH: Hashes do not match!"
        $script:VerifyResultLabel.ForeColor = [System.Drawing.Color]::Red
        Write-StatusMessage -Message "Hash verification: NO MATCH" -Color Red
    }
}

function Invoke-ExportResults {
    <#
    .SYNOPSIS
        Exports hash results to a file
    #>
    if ($script:AllHashes.Count -eq 0) {
        Write-StatusMessage -Message "No hashes to export. Calculate hashes first." -Color Red
        return
    }

    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Title = "Export Hash Results"
    $saveFileDialog.Filter = "Text File (*.txt)|*.txt|CSV File (*.csv)|*.csv|JSON File (*.json)|*.json|All Files (*.*)|*.*"
    $saveFileDialog.FilterIndex = 1
    $saveFileDialog.DefaultExt = "txt"
    $saveFileDialog.FileName = "hash_results_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $fileInfo = Get-Item -Path $script:CurrentFile
            $extension = [System.IO.Path]::GetExtension($saveFileDialog.FileName).ToLower()

            switch ($extension) {
                ".json" {
                    $exportData = @{
                        FileName = $fileInfo.Name
                        FilePath = $fileInfo.FullName
                        FileSize = $fileInfo.Length
                        DateScanned = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Hashes = $script:AllHashes
                        VirusTotalURL = $script:URLTextBox.Text
                    }
                    $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $saveFileDialog.FileName -Encoding UTF8
                }
                ".csv" {
                    $csvContent = "Algorithm,Hash`n"
                    foreach ($algo in $script:AllHashes.Keys) {
                        $csvContent += "$algo,$($script:AllHashes[$algo])`n"
                    }
                    $csvContent | Out-File -FilePath $saveFileDialog.FileName -Encoding UTF8
                }
                default {
                    $textContent = @"
VirusTotal Hash Calculator - Export Report
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
==============================================

File Information:
-----------------
File Name: $($fileInfo.Name)
File Path: $($fileInfo.FullName)
File Size: $(Get-FormattedFileSize -Bytes $fileInfo.Length) ($("{0:N0}" -f $fileInfo.Length) bytes)
Modified:  $($fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"))

Hash Values:
------------
SHA256: $($script:AllHashes["SHA256"])
SHA1:   $($script:AllHashes["SHA1"])
MD5:    $($script:AllHashes["MD5"])

VirusTotal URL:
---------------
$($script:URLTextBox.Text)
"@
                    $textContent | Out-File -FilePath $saveFileDialog.FileName -Encoding UTF8
                }
            }

            Write-StatusMessage -Message "Results exported successfully!" -Color Green
            [System.Windows.Forms.MessageBox]::Show(
                "Hash results exported to:`n$($saveFileDialog.FileName)",
                "Export Successful",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
        catch {
            Write-StatusMessage -Message "Export failed: $($_.Exception.Message)" -Color Red
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to export results:`n$($_.Exception.Message)",
                "Export Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
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
    $form.Text = "VirusTotal Hash Calculator v3.0"
    $form.Size = New-Object System.Drawing.Size(650, 650)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.Icon = [System.Drawing.SystemIcons]::Shield
    $form.KeyPreview = $true

    # Enable drag and drop
    $form.AllowDrop = $true
    $form.Add_DragEnter({ Handle-DragEnter -Sender $args[0] -Event $args[1] })
    $form.Add_DragDrop({ Handle-DragDrop -Sender $args[0] -Event $args[1] })

    # Add keyboard shortcuts
    $form.Add_KeyDown({
        param($sender, $e)

        # Ctrl+O - Open file
        if ($e.Control -and $e.KeyCode -eq 'O') {
            Invoke-BrowseFile
            $e.Handled = $true
        }
        # Ctrl+H or F5 - Calculate hash
        elseif (($e.Control -and $e.KeyCode -eq 'H') -or $e.KeyCode -eq 'F5') {
            if ($script:CalculateButton.Enabled) {
                Invoke-CalculateHash
            }
            $e.Handled = $true
        }
        # Ctrl+Shift+H - Calculate all hashes
        elseif ($e.Control -and $e.Shift -and $e.KeyCode -eq 'H') {
            if ($script:CalculateAllButton.Enabled) {
                Invoke-CalculateAllHashes
            }
            $e.Handled = $true
        }
        # Ctrl+E - Export
        elseif ($e.Control -and $e.KeyCode -eq 'E') {
            if ($script:ExportButton.Enabled) {
                Invoke-ExportResults
            }
            $e.Handled = $true
        }
        # Ctrl+V - Open VirusTotal
        elseif ($e.Control -and $e.KeyCode -eq 'V') {
            if ($script:OpenURLButton.Enabled) {
                Invoke-OpenVirusTotal
            }
            $e.Handled = $true
        }
    })

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

    $tooltip = New-Object System.Windows.Forms.ToolTip
    $tooltip.AutoPopDelay = 5000
    $tooltip.InitialDelay = 500
    $tooltip.ReshowDelay = 100

    # File selection section
    $Form.Controls.Add((New-Label -Text "File Path:" -X 10 -Y 20))

    $script:FilePathTextBox = New-TextBox -X 90 -Y 20 -Width 400
    $Form.Controls.Add($script:FilePathTextBox)
    $tooltip.SetToolTip($script:FilePathTextBox, "Path to the file to hash (Ctrl+O to browse)")

    $script:BrowseButton = New-Button -Text "Browse..." -X 500 -Y 18 -ClickAction { Invoke-BrowseFile }
    $Form.Controls.Add($script:BrowseButton)
    $tooltip.SetToolTip($script:BrowseButton, "Browse for a file (Ctrl+O)")

    # Algorithm and options section
    $Form.Controls.Add((New-Label -Text "Algorithm:" -X 10 -Y 60))

    $script:AlgorithmComboBox = New-Object System.Windows.Forms.ComboBox
    $script:AlgorithmComboBox.Location = New-Object System.Drawing.Point(90, 60)
    $script:AlgorithmComboBox.Size = New-Object System.Drawing.Size(120, 20)
    $script:AlgorithmComboBox.DropDownStyle = "DropDownList"
    $script:AlgorithmComboBox.Items.AddRange(@("SHA256", "SHA1", "MD5"))
    $script:AlgorithmComboBox.SelectedIndex = 0
    $Form.Controls.Add($script:AlgorithmComboBox)
    $tooltip.SetToolTip($script:AlgorithmComboBox, "Select hash algorithm")

    $script:CalculateButton = New-Button -Text "Calculate" -X 220 -Y 58 -Width 80 `
        -ClickAction { Invoke-CalculateHash } -Enabled $false
    $Form.Controls.Add($script:CalculateButton)
    $tooltip.SetToolTip($script:CalculateButton, "Calculate selected hash (F5 or Ctrl+H)")

    $script:CalculateAllButton = New-Button -Text "Calculate All" -X 310 -Y 58 -Width 100 `
        -ClickAction { Invoke-CalculateAllHashes } -Enabled $false
    $script:CalculateAllButton.BackColor = [System.Drawing.Color]::LightGreen
    $Form.Controls.Add($script:CalculateAllButton)
    $tooltip.SetToolTip($script:CalculateAllButton, "Calculate all hash types (Ctrl+Shift+H)")

    $script:AutoCalcCheckbox = New-Object System.Windows.Forms.CheckBox
    $script:AutoCalcCheckbox.Location = New-Object System.Drawing.Point(420, 60)
    $script:AutoCalcCheckbox.Size = New-Object System.Drawing.Size(150, 20)
    $script:AutoCalcCheckbox.Text = "Auto-calculate"
    $script:AutoCalcCheckbox.Add_CheckedChanged({ $script:AutoCalculate = $script:AutoCalcCheckbox.Checked })
    $Form.Controls.Add($script:AutoCalcCheckbox)
    $tooltip.SetToolTip($script:AutoCalcCheckbox, "Automatically calculate all hashes when file is selected")

    # Progress bar
    $script:ProgressBar = New-Object System.Windows.Forms.ProgressBar
    $script:ProgressBar.Location = New-Object System.Drawing.Point(10, 90)
    $script:ProgressBar.Size = New-Object System.Drawing.Size(610, 20)
    $script:ProgressBar.Visible = $false
    $script:ProgressBar.Style = "Continuous"
    $Form.Controls.Add($script:ProgressBar)

    # Hash result section
    $Form.Controls.Add((New-Label -Text "Hash:" -X 10 -Y 120))

    $script:HashTextBox = New-TextBox -X 90 -Y 120 -Width 450 `
        -Font (New-Object System.Drawing.Font("Consolas", 9))
    $Form.Controls.Add($script:HashTextBox)
    $tooltip.SetToolTip($script:HashTextBox, "Calculated hash value")

    $script:CopyHashButton = New-Button -Text "Copy" -X 550 -Y 118 `
        -ClickAction { Copy-ToClipboard -Text $script:HashTextBox.Text -ItemType "Hash" } `
        -Enabled $false
    $Form.Controls.Add($script:CopyHashButton)
    $tooltip.SetToolTip($script:CopyHashButton, "Copy hash to clipboard")

    # URL section
    $Form.Controls.Add((New-Label -Text "VT URL:" -X 10 -Y 150))

    $script:URLTextBox = New-TextBox -X 90 -Y 150 -Width 450
    $Form.Controls.Add($script:URLTextBox)
    $tooltip.SetToolTip($script:URLTextBox, "VirusTotal URL for this hash")

    $script:CopyURLButton = New-Button -Text "Copy" -X 550 -Y 148 `
        -ClickAction { Copy-ToClipboard -Text $script:URLTextBox.Text -ItemType "URL" } `
        -Enabled $false
    $Form.Controls.Add($script:CopyURLButton)
    $tooltip.SetToolTip($script:CopyURLButton, "Copy URL to clipboard")

    # All hashes display
    $allHashesGroupBox = New-Object System.Windows.Forms.GroupBox
    $allHashesGroupBox.Location = New-Object System.Drawing.Point(10, 180)
    $allHashesGroupBox.Size = New-Object System.Drawing.Size(410, 90)
    $allHashesGroupBox.Text = "All Hash Values"
    $Form.Controls.Add($allHashesGroupBox)

    $script:AllHashesTextBox = New-TextBox -X 10 -Y 20 -Width 390 -Height 60 -Multiline $true `
        -Font (New-Object System.Drawing.Font("Consolas", 8))
    $allHashesGroupBox.Controls.Add($script:AllHashesTextBox)
    $tooltip.SetToolTip($script:AllHashesTextBox, "All calculated hash values")

    $script:CopyAllHashesButton = New-Button -Text "Copy All" -X 430 -Y 205 -Width 80 `
        -ClickAction { Copy-ToClipboard -Text $script:AllHashesTextBox.Text -ItemType "All hashes" } `
        -Enabled $false
    $Form.Controls.Add($script:CopyAllHashesButton)
    $tooltip.SetToolTip($script:CopyAllHashesButton, "Copy all hashes to clipboard")

    $script:ExportButton = New-Button -Text "Export..." -X 520 -Y 205 -Width 80 `
        -ClickAction { Invoke-ExportResults } -Enabled $false
    $Form.Controls.Add($script:ExportButton)
    $tooltip.SetToolTip($script:ExportButton, "Export results to file (Ctrl+E)")

    # Hash verification section
    $verifyGroupBox = New-Object System.Windows.Forms.GroupBox
    $verifyGroupBox.Location = New-Object System.Drawing.Point(10, 280)
    $verifyGroupBox.Size = New-Object System.Drawing.Size(610, 80)
    $verifyGroupBox.Text = "Hash Verification"
    $Form.Controls.Add($verifyGroupBox)

    $verifyLabel = New-Label -Text "Expected:" -X 10 -Y 25 -Width 70
    $verifyGroupBox.Controls.Add($verifyLabel)

    $script:VerifyHashTextBox = New-Object System.Windows.Forms.TextBox
    $script:VerifyHashTextBox.Location = New-Object System.Drawing.Point(80, 23)
    $script:VerifyHashTextBox.Size = New-Object System.Drawing.Size(420, 20)
    $script:VerifyHashTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $verifyGroupBox.Controls.Add($script:VerifyHashTextBox)
    $tooltip.SetToolTip($script:VerifyHashTextBox, "Paste expected hash to verify against calculated hash")

    $verifyButton = New-Button -Text "Verify" -X 510 -Y 21 -Width 80 -ClickAction { Invoke-VerifyHash }
    $verifyGroupBox.Controls.Add($verifyButton)
    $tooltip.SetToolTip($verifyButton, "Verify hash matches expected value")

    $script:VerifyResultLabel = New-Label -Text "" -X 10 -Y 50 -Width 590 -Height 20
    $script:VerifyResultLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
    $verifyGroupBox.Controls.Add($script:VerifyResultLabel)

    # Open VirusTotal button
    $script:OpenURLButton = New-Button -Text "Open in VirusTotal" -X 210 -Y 370 -Width 200 -Height 35 `
        -ClickAction { Invoke-OpenVirusTotal } -Enabled $false
    $script:OpenURLButton.BackColor = [System.Drawing.Color]::LightBlue
    $script:OpenURLButton.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 10, [System.Drawing.FontStyle]::Bold)
    $Form.Controls.Add($script:OpenURLButton)
    $tooltip.SetToolTip($script:OpenURLButton, "Open VirusTotal page in browser (Ctrl+V)")

    # File information group box
    $fileInfoGroupBox = New-Object System.Windows.Forms.GroupBox
    $fileInfoGroupBox.Location = New-Object System.Drawing.Point(10, 415)
    $fileInfoGroupBox.Size = New-Object System.Drawing.Size(610, 130)
    $fileInfoGroupBox.Text = "File Information"
    $Form.Controls.Add($fileInfoGroupBox)

    $script:FileInfoTextBox = New-TextBox -X 10 -Y 20 -Width 590 -Height 100 -Multiline $true `
        -Font (New-Object System.Drawing.Font("Consolas", 8))
    $fileInfoGroupBox.Controls.Add($script:FileInfoTextBox)

    # Status label
    $script:StatusLabel = New-Label -Text "Ready. Select a file or drag and drop to begin. Press F1 for shortcuts." `
        -X 10 -Y 555 -Width 610 -Height 20
    $Form.Controls.Add($script:StatusLabel)

    # Keyboard shortcuts info
    $shortcutsLabel = New-Label -Text "Shortcuts: Ctrl+O=Browse | F5=Calculate | Ctrl+Shift+H=All | Ctrl+E=Export | Ctrl+V=Open VT" `
        -X 10 -Y 575 -Width 610 -Height 20
    $shortcutsLabel.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 7.5)
    $shortcutsLabel.ForeColor = [System.Drawing.Color]::Gray
    $Form.Controls.Add($shortcutsLabel)
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