<#
.SYNOPSIS
    Comprehensive Google Chrome Update Manager

.DESCRIPTION
    This script manages the complete Chrome update process including:
    - Getting current Chrome version
    - Uninstalling current version
    - Downloading latest Chrome version
    - Installing new version
    - Comparing before/after versions
    - Comprehensive error handling and logging

.PARAMETER LogPath
    Path for log file output. Defaults to temp directory.

.PARAMETER WhatIf
    Shows what would be done without actually performing the update.

.EXAMPLE
    .\ChromeUpdateManager.ps1
    
.EXAMPLE
    .\ChromeUpdateManager.ps1 -LogPath "C:\Logs\ChromeUpdate.log" -MaxLogSizeMB 10 -WhatIf
    
.EXAMPLE
    .\ChromeUpdateManager.ps1 -MaxLogSizeMB 2
    
.EXAMPLE
    .\ChromeUpdateManager.ps1 -Quiet
    
.EXAMPLE
    Invoke-Command -ComputerName SERVER01 -ScriptBlock { .\ChromeUpdateManager.ps1 -Quiet }

.NOTES
    - Requires administrative privileges for uninstall/install operations
    - Creates detailed logs of all operations with automatic size management
    - Supports -WhatIf for preview mode
    - Use -Quiet for remote execution with minimal output
    - Fault-resistant: defaults to installing latest version if detection fails
    - Single-line summary output format: COMPUTER | STATUS | VERSION_CHANGE | DURATION
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(HelpMessage = 'Path for log file output')]
    [string] $LogPath = "$env:TEMP\ChromeUpdate.log",
    
    [Parameter(HelpMessage = 'Maximum log file size in MB before rotation')]
    [int] $MaxLogSizeMB = 5,
    
    [Parameter(HelpMessage = 'Suppress all console output for remote execution')]
    [switch] $Quiet
)

#region Classes and Data Structures

class ChromeUpdateResult {
    [string] $Operation
    [bool] $Success
    [string] $Message
    [string] $Details
    [datetime] $Timestamp
    
    ChromeUpdateResult([string] $Operation, [bool] $Success, [string] $Message, [string] $Details) {
        $this.Operation = $Operation
        $this.Success = $Success
        $this.Message = $Message
        $this.Details = $Details
        $this.Timestamp = Get-Date
    }
}

class ChromeVersionInfo {
    [string] $Version
    [string] $InstallPath
    [bool] $IsInstalled
    [datetime] $DetectionTime
    
    ChromeVersionInfo([string] $Version, [string] $InstallPath, [bool] $IsInstalled) {
        $this.Version = $Version
        $this.InstallPath = $InstallPath
        $this.IsInstalled = $IsInstalled
        $this.DetectionTime = Get-Date
    }
}

class ChromeUpdateSession {
    [ChromeVersionInfo] $InitialVersion
    [ChromeVersionInfo] $FinalVersion
    [System.Collections.Generic.List[ChromeUpdateResult]] $Results
    [datetime] $StartTime
    [datetime] $EndTime
    [bool] $OverallSuccess
    
    ChromeUpdateSession() {
        $this.Results = [System.Collections.Generic.List[ChromeUpdateResult]]::new()
        $this.StartTime = Get-Date
        $this.OverallSuccess = $true
    }
    
    [void] AddResult([ChromeUpdateResult] $Result) {
        $this.Results.Add($Result)
        if (-not $Result.Success) {
            $this.OverallSuccess = $false
        }
    }
    
    [void] Complete() {
        $this.EndTime = Get-Date
    }
}

#endregion

#region Helper Functions

function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string] $Level = 'Info',
        
        [Parameter()]
        [string] $LogPath = $script:LogPath,
        
        [Parameter()]
        [int] $MaxLogSizeMB = $script:MaxLogSizeMB,
        
        [Parameter()]
        [switch] $Quiet = $script:Quiet
    )
    
    $timeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timeStamp] [$Level] $Message"
    
    # Write to console with appropriate color (unless -Quiet is specified)
    if (-not $Quiet) {
        switch ($Level) {
            'Info' { Write-Host $logEntry -ForegroundColor Cyan }
            'Warning' { Write-Warning $logEntry }
            'Error' { Write-Error $logEntry }
            'Success' { Write-Host $logEntry -ForegroundColor Green }
        }
    }

    if($LogPath -eq "")
    {
        $LogPath = "$env:TEMP\ChromeUpdate.log"
    }

    if($MaxLogSizeMB -eq 0)
    {
        $MaxLogSizeMB = 5
    }
    
    # Write to log file with size management
    try {
        # Check if log file exists and its size
        if (Test-Path $LogPath) {
            $logFile = Get-Item $LogPath
            $logSizeBytes = $logFile.Length
            $maxSizeBytes = $MaxLogSizeMB * 1024 * 1024
            
            # If log file exceeds max size, create a backup and start fresh
            if ($logSizeBytes -gt $maxSizeBytes) {
                try {
                    # Create a backup of the current log with timestamp
                    $backupPath = $LogPath -replace '\.log$', "_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                    Move-Item -Path $LogPath -Destination $backupPath -Force
                    
                    # Start new log file with rotation message
                    $rotationMessage = "[$timeStamp] [INFO] === LOG ROTATED === Previous log archived to: $backupPath (Size: $([math]::Round($logSizeBytes/1MB, 2)) MB)"
                    Set-Content -Path $LogPath -Value $rotationMessage -ErrorAction Stop
                    
                    if (-not $Quiet) { Write-Host "Log file rotated. Previous log archived to: $backupPath" -ForegroundColor Yellow }
                } catch {
                    # If backup fails, just truncate the current log
                    $truncateMessage = "[$timeStamp] [WARNING] === LOG TRUNCATED === Previous log content removed due to size limit ($MaxLogSizeMB MB exceeded)"
                    Set-Content -Path $LogPath -Value $truncateMessage -ErrorAction Stop
                    if (-not $Quiet) { Write-Host "Log file truncated due to size limit." -ForegroundColor Yellow }
                }
            }
        }
        
        # Append the new log entry
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction Stop
        
    } catch {
        Write-Warning "Failed to write to log file: $_"
    }
}

function Test-AdministrativePrivileges {
    [CmdletBinding()]
    param()
    
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-LogMessage "Error checking administrative privileges: $_" -Level Error
        return $false
    }
}

function Clear-OldLogBackups {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $LogPath = $script:LogPath,
        
        [Parameter()]
        [int] $MaxBackupsToKeep = 10
    )
    
    try {
        $logDirectory = [System.IO.Path]::GetDirectoryName($LogPath)
        $logFileName = [System.IO.Path]::GetFileNameWithoutExtension($LogPath)
        
        # Find all backup log files
        $backupPattern = "$logFileName" + "_backup_*.log"
        $backupFiles = Get-ChildItem -Path $logDirectory -Filter $backupPattern -ErrorAction SilentlyContinue | 
                       Sort-Object CreationTime -Descending
        
        # If we have more backups than the limit, remove the oldest ones
        if ($backupFiles.Count -gt $MaxBackupsToKeep) {
            $filesToRemove = $backupFiles | Select-Object -Skip $MaxBackupsToKeep
            foreach ($file in $filesToRemove) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-LogMessage "Removed old log backup: $($file.Name)" -Level Info
                } catch {
                    Write-LogMessage "Warning: Could not remove old log backup $($file.Name): $_" -Level Warning
                }
            }
        }
        
        # Also remove backup files older than 30 days regardless of count
        $cutoffDate = (Get-Date).AddDays(-30)
        $oldBackups = $backupFiles | Where-Object { $_.CreationTime -lt $cutoffDate }
        foreach ($file in $oldBackups) {
            try {
                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                Write-LogMessage "Removed old log backup (>30 days): $($file.Name)" -Level Info
            } catch {
                Write-LogMessage "Warning: Could not remove old log backup $($file.Name): $_" -Level Warning
            }
        }
        
    } catch {
        Write-LogMessage "Error during log backup cleanup: $_" -Level Warning
    }
}

#endregion

#region Chrome Detection Functions

function Get-ChromeVersionFromRegistry {
    [CmdletBinding()]
    param()
    
    # Check for EXE-based installations (standard Chrome installer)
    $exeRegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome'
    )
    
    foreach ($path in $exeRegistryPaths) {
        try {
            if (Test-Path $path) {
                $versionValue = Get-ItemProperty -Path $path -Name 'DisplayVersion' -ErrorAction Stop
                if ($versionValue -and $versionValue.DisplayVersion) {
                    Write-LogMessage "Found Chrome version in registry (EXE install): $($versionValue.DisplayVersion)" -Level Info
                    return $versionValue.DisplayVersion
                }
            }
        } catch {
            Write-LogMessage "Error reading registry path ${path}: $_" -Level Warning
        }
    }
    
    # Check for MSI-based installations (enterprise Chrome)
    $msiRegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    
    foreach ($basePath in $msiRegistryPaths) {
        try {
            if (Test-Path $basePath) {
                $uninstallKeys = Get-ChildItem -Path $basePath -ErrorAction Stop
                foreach ($key in $uninstallKeys) {
                    try {
                        $properties = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
                        if ($properties.DisplayName -like '*Google Chrome*' -or 
                            $properties.DisplayName -like '*Chrome*') {
                            if ($properties.DisplayVersion) {
                                Write-LogMessage "Found Chrome version in registry (MSI install): $($properties.DisplayVersion) under $($key.PSChildName)" -Level Info
                                return $properties.DisplayVersion
                            }
                        }
                    } catch {
                        # Skip individual key errors
                        continue
                    }
                }
            }
        } catch {
            Write-LogMessage "Error reading MSI registry path ${basePath}: $_" -Level Warning
        }
    }
    
    return $null
}

function Get-ChromeVersionFromWmi {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage "Checking WMI Win32_Product for Chrome installations..." -Level Info
        
        # Query WMI for Chrome products (common for MSI installations)
        $chromeProducts = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Google Chrome%' OR Name LIKE '%Chrome%'" -ErrorAction Stop
        
        foreach ($product in $chromeProducts) {
            if ($product.Version) {
                Write-LogMessage "Found Chrome version in WMI: $($product.Version) - $($product.Name)" -Level Info
                return $product.Version
            }
        }
    } catch {
        Write-LogMessage "Error querying WMI for Chrome: $_" -Level Warning
    }
    
    return $null
}

function Get-ChromeVersionFromFileSystem {
    [CmdletBinding()]
    param()
    
    $chromePaths = @(
        "${env:ProgramFiles}\Google\Chrome\Application",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application"
    )
    
    $versionRegex = '^\d+(\.\d+)+$'
    
    foreach ($basePath in $chromePaths) {
        try {
            if (Test-Path $basePath) {
                $versionDirs = Get-ChildItem -Path $basePath -Directory -ErrorAction Stop | 
                               Where-Object { $_.Name -match $versionRegex } |
                               Sort-Object { [version]$_.Name } -Descending
                
                if ($versionDirs) {
                    $latestVersion = $versionDirs[0].Name
                    Write-LogMessage "Found Chrome version in filesystem: $latestVersion" -Level Info
                    return $latestVersion
                }
            }
        } catch {
            Write-LogMessage "Error reading Chrome path ${basePath}: $_" -Level Warning
        }
    }
    
    return $null
}

function Get-CurrentChromeVersion {
    [CmdletBinding()]
    param()
    
    Write-LogMessage "Detecting current Chrome version..." -Level Info
    
    # Try registry first (most reliable for both EXE and MSI)
    $version = Get-ChromeVersionFromRegistry
    
    # Fall back to WMI if registry fails (good for MSI installations)
    if (-not $version) {
        $version = Get-ChromeVersionFromWmi
    }
    
    # Fall back to filesystem if both registry and WMI fail
    if (-not $version) {
        $version = Get-ChromeVersionFromFileSystem
    }
    
    # Determine install path
    $installPath = $null
    $isInstalled = $false
    
    if ($version) {
        $possiblePaths = @(
            "${env:ProgramFiles}\Google\Chrome\Application",
            "${env:ProgramFiles(x86)}\Google\Chrome\Application"
        )
        
        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                $installPath = $path
                $isInstalled = $true
                break
            }
        }
    }
    
    return [ChromeVersionInfo]::new($version, $installPath, $isInstalled)
}

#endregion

#region Chrome Uninstall Functions

function Get-ChromeUninstallString {
    [CmdletBinding()]
    param()
    
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome'
    )
    
    foreach ($path in $uninstallPaths) {
        try {
            if (Test-Path $path) {
                $uninstallInfo = Get-ItemProperty -Path $path -ErrorAction Stop
                if ($uninstallInfo.UninstallString) {
                    Write-LogMessage "Found Chrome uninstall string: $($uninstallInfo.UninstallString)" -Level Info
                    return $uninstallInfo.UninstallString
                }
            }
        } catch {
            Write-LogMessage "Error reading uninstall registry path ${path}: $_" -Level Warning
        }
    }
    
    return $null
}

function Invoke-ChromeUninstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ChromeUpdateSession] $Session
    )
    
    Write-LogMessage "Starting Chrome uninstall process..." -Level Info
    
    try {
        # Get uninstall string from registry
        $uninstallString = Get-ChromeUninstallString
        
        if (-not $uninstallString) {
            $result = [ChromeUpdateResult]::new('Uninstall', $false, 'Chrome uninstall string not found', 'Unable to locate Chrome uninstall information in registry')
            $Session.AddResult($result)
            return $result
        }
        
        if ($PSCmdlet.ShouldProcess("Chrome Browser", "Uninstall")) {
            # Parse uninstall string - it typically contains the full command with --uninstall
            if ($uninstallString -match '^"?([^"]+)"?\s*(.*)$') {
                $uninstallCommand = $matches[1]
                $existingArgs = $matches[2]
            } else {
                $uninstallCommand = $uninstallString.Trim('"')
                $existingArgs = ""
            }
            
            # Add silent flags for unattended operation
            $silentArgs = @(
                '--uninstall'
                '--force-uninstall'
                '--system-level'
                '--do-not-launch-chrome'
            )
            
            # Combine existing args with silent args, avoiding duplicates
            $allArgs = @()
            if ($existingArgs) {
                $allArgs += $existingArgs.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
            }
            
            foreach ($arg in $silentArgs) {
                if ($allArgs -notcontains $arg) {
                    $allArgs += $arg
                }
            }
            
            Write-LogMessage "Executing uninstall command: `"$uninstallCommand`" $($allArgs -join ' ')" -Level Info
            
            # Execute uninstall with silent flags
            $process = Start-Process -FilePath $uninstallCommand -ArgumentList $allArgs -Wait -PassThru
            
            Write-LogMessage "Uninstall process completed with exit code: $($process.ExitCode)" -Level Info
            
            # Wait a moment for cleanup operations to complete
            Start-Sleep -Seconds 5
            
            # Verify uninstall was successful by checking if Chrome is still installed
            # This is more reliable than just checking exit codes
            $postUninstallVersion = Get-CurrentChromeVersion
            
            if (-not $postUninstallVersion.IsInstalled) {
                # Chrome is no longer installed - uninstall was successful
                $exitCodeMessage = switch ($process.ExitCode) {
                    0 { "Success (clean exit)" }
                    19 { "Success (likely reboot required or partial cleanup)" }
                    default { "Success (non-standard exit code but Chrome removed)" }
                }
                
                $result = [ChromeUpdateResult]::new('Uninstall', $true, 'Chrome uninstalled successfully', "Exit code: $($process.ExitCode) - $exitCodeMessage")
                $Session.AddResult($result)
                Write-LogMessage "Chrome uninstalled successfully (verified by absence of installation)" -Level Success
                return $result
            } else {
                # Chrome is still installed - uninstall failed
                $result = [ChromeUpdateResult]::new('Uninstall', $false, 'Chrome uninstall verification failed', "Chrome appears to still be installed after uninstall process. Exit code: $($process.ExitCode)")
                $Session.AddResult($result)
                Write-LogMessage "Chrome uninstall failed - Chrome still detected after uninstall attempt" -Level Error
                return $result
            }
        } else {
            $result = [ChromeUpdateResult]::new('Uninstall', $true, 'Chrome uninstall skipped (WhatIf)', 'Would execute: ' + $uninstallString)
            $Session.AddResult($result)
            return $result
        }
    } catch {
        $result = [ChromeUpdateResult]::new('Uninstall', $false, 'Chrome uninstall error', $_.Exception.Message)
        $Session.AddResult($result)
        Write-LogMessage "Chrome uninstall error: $_" -Level Error
        return $result
    }
}

#endregion

#region Chrome Download and Install Functions

function Get-ChromeVersionFromMsi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $MsiPath
    )
    
    try {
        if (-not (Test-Path $MsiPath)) {
            Write-LogMessage "MSI file not found: $MsiPath" -Level Error
            return $null
        }
        
        # Use Shell.Application COM object to get extended file properties
        $shell = New-Object -ComObject Shell.Application
        $folder = $shell.Namespace((Get-Item $MsiPath).DirectoryName)
        $file = $folder.ParseName((Get-Item $MsiPath).Name)
        
        # Get Comments property (index 24 based on your output)
        $comments = $folder.GetDetailsOf($file, 24)
        
        if ($comments) {
            Write-LogMessage "MSI Comments field: $comments" -Level Info
            
            # Extract version using regex - matches version pattern at start of comments
            # Pattern: digits.digits.digits.digits (Chrome version format)
            if ($comments -match '^\s*(\d+\.\d+\.\d+\.\d+)') {
                $version = $matches[1]
                Write-LogMessage "Extracted MSI version: $version" -Level Info
                return $version
            } else {
                Write-LogMessage "Could not extract version from comments: $comments" -Level Warning
                return $null
            }
        } else {
            Write-LogMessage "No comments field found in MSI properties" -Level Warning
            return $null
        }
    } catch {
        Write-LogMessage "Error reading MSI properties: $_" -Level Error
        return $null
    } finally {
        # Clean up COM objects
        if ($shell) {
            try {
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
            } catch {
                # Ignore cleanup errors
            }
        }
    }
}

function Test-ChromeVersionComparison {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $CurrentVersion,
        
        [Parameter(Mandatory)]
        [string] $MsiVersion
    )
    
    try {
        # Convert to version objects for proper comparison
        $currentVer = [version]$CurrentVersion
        $msiVer = [version]$MsiVersion
        
        $comparison = $msiVer.CompareTo($currentVer)
        
        Write-LogMessage "Version comparison: Current=$CurrentVersion, MSI=$MsiVersion" -Level Info
        
        switch ($comparison) {
            1 { 
                Write-LogMessage "MSI version is newer - upgrade recommended" -Level Info
                return 'Upgrade'
            }
            0 { 
                Write-LogMessage "MSI version is same as current - no update needed" -Level Info
                return 'SameVersion'
            }
            -1 { 
                Write-LogMessage "MSI version is older - downgrade would occur" -Level Warning
                return 'Downgrade'
            }
        }
    } catch {
        Write-LogMessage "Error comparing versions: $_" -Level Error
        return 'ComparisonError'
    }
}

function Invoke-ChromeDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ChromeUpdateSession] $Session
    )
    
    Write-LogMessage "Starting Chrome download process..." -Level Info
    
    try {
        $tempDir = $env:TEMP
        $chromeInstaller = "ChromeInstaller_$(Get-Date -Format 'yyyyMMdd_HHmmss').msi"
        $installerPath = Join-Path $tempDir $chromeInstaller
        
        # Google Chrome latest version download URL (MSI installer for enterprise deployment)
        $chromeDownloadUrl = 'https://dl.google.com/chrome/install/googlechromestandaloneenterprise64.msi'
        
        if ($PSCmdlet.ShouldProcess("Chrome Installer", "Download")) {
            Write-LogMessage "Downloading Chrome installer from: $chromeDownloadUrl" -Level Info
            Write-LogMessage "Saving to: $installerPath" -Level Info
            
            # Download with progress
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($chromeDownloadUrl, $installerPath)
            
            # Verify download
            if (Test-Path $installerPath) {
                $fileSize = (Get-Item $installerPath).Length
                $result = [ChromeUpdateResult]::new('Download', $true, 'Chrome installer downloaded successfully', "File size: $fileSize bytes, Path: $installerPath")
                $Session.AddResult($result)
                Write-LogMessage "Chrome installer downloaded successfully ($fileSize bytes)" -Level Success
                return $result
            } else {
                $result = [ChromeUpdateResult]::new('Download', $false, 'Chrome download verification failed', 'Downloaded file not found')
                $Session.AddResult($result)
                return $result
            }
        } else {
            $result = [ChromeUpdateResult]::new('Download', $true, 'Chrome download skipped (WhatIf)', "Would download from: $chromeDownloadUrl")
            $Session.AddResult($result)
            return $result
        }
    } catch {
        $result = [ChromeUpdateResult]::new('Download', $false, 'Chrome download error', $_.Exception.Message)
        $Session.AddResult($result)
        Write-LogMessage "Chrome download error: $_" -Level Error
        return $result
    }
}

function Invoke-ChromeInstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ChromeUpdateSession] $Session
    )
    
    Write-LogMessage "Starting Chrome installation process..." -Level Info
    
    try {
        # Find the downloaded installer
        $tempDir = $env:TEMP
        $installerFiles = Get-ChildItem -Path $tempDir -Filter "ChromeInstaller_*.msi" | Sort-Object CreationTime -Descending
        
        if (-not $installerFiles) {
            $result = [ChromeUpdateResult]::new('Install', $false, 'Chrome installer not found', 'No installer file found in temp directory')
            $Session.AddResult($result)
            return $result
        }
        
        $installerPath = $installerFiles[0].FullName
        
        if ($PSCmdlet.ShouldProcess("Chrome Browser", "Install")) {
            Write-LogMessage "Installing Chrome from: $installerPath" -Level Info
            
            # Install with silent flags
            $installArgs = '/i', $installerPath, '/quiet', '/norestart'
            $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
            
            if ($process.ExitCode -eq 0) {
                # Wait for installation to complete
                Start-Sleep -Seconds 5
                
                # Verify installation
                $postInstallVersion = Get-CurrentChromeVersion
                
                if ($postInstallVersion.IsInstalled) {
                    $result = [ChromeUpdateResult]::new('Install', $true, 'Chrome installed successfully', "New version: $($postInstallVersion.Version)")
                    $Session.AddResult($result)
                    Write-LogMessage "Chrome installed successfully - Version: $($postInstallVersion.Version)" -Level Success
                    
                    # Clean up installer
                    try {
                        Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
                        Write-LogMessage "Installer file cleaned up: $installerPath" -Level Info
                    } catch {
                        Write-LogMessage "Warning: Could not clean up installer file: $_" -Level Warning
                    }
                    
                    return $result
                } else {
                    $result = [ChromeUpdateResult]::new('Install', $false, 'Chrome installation verification failed', 'Chrome not detected after installation')
                    $Session.AddResult($result)
                    return $result
                }
            } else {
                $result = [ChromeUpdateResult]::new('Install', $false, 'Chrome installation failed', "Exit code: $($process.ExitCode)")
                $Session.AddResult($result)
                return $result
            }
        } else {
            $result = [ChromeUpdateResult]::new('Install', $true, 'Chrome installation skipped (WhatIf)', "Would install from: $installerPath")
            $Session.AddResult($result)
            return $result
        }
    } catch {
        $result = [ChromeUpdateResult]::new('Install', $false, 'Chrome installation error', $_.Exception.Message)
        $Session.AddResult($result)
        Write-LogMessage "Chrome installation error: $_" -Level Error
        return $result
    }
}

#endregion

#region Reporting Functions

function Show-ChromeUpdateSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ChromeUpdateSession] $Session,
        
        [Parameter()]
        [switch] $Quiet = $script:Quiet
    )
    
    if ($Quiet) {
        return  # No console output in quiet mode
    }
    
    # Create single line summary for remote execution
    $computerName = $env:COMPUTERNAME
    $statusText = if ($Session.OverallSuccess) { 'SUCCESS' } else { 'FAILED' }
    $statusColor = if ($Session.OverallSuccess) { 'Green' } else { 'Red' }
    
    # Get version change info
    $initialVersion = if ($Session.InitialVersion.IsInstalled) { $Session.InitialVersion.Version } else { 'None' }
    $finalVersion = if ($Session.FinalVersion.IsInstalled) { $Session.FinalVersion.Version } else { 'None' }
    
    # Determine change type
    $changeType = 'Unknown'
    if ($Session.InitialVersion.IsInstalled -and $Session.FinalVersion.IsInstalled) {
        try {
            $initialVer = [version]$Session.InitialVersion.Version
            $finalVer = [version]$Session.FinalVersion.Version
            $comparison = $finalVer.CompareTo($initialVer)
            
            switch ($comparison) {
                1 { $changeType = 'UPGRADED' }
                0 { $changeType = 'NO CHANGE' }
                -1 { $changeType = 'DOWNGRADED' }
            }
        } catch {
            $changeType = 'VERSION ERROR'
        }
    } elseif (-not $Session.InitialVersion.IsInstalled -and $Session.FinalVersion.IsInstalled) {
        $changeType = 'INSTALLED'
    } elseif ($Session.InitialVersion.IsInstalled -and -not $Session.FinalVersion.IsInstalled) {
        $changeType = 'REMOVED'
    }
    
    # Duration
    $duration = $Session.EndTime - $Session.StartTime
    $durationText = "$($duration.TotalMinutes.ToString('F1'))min"
    
    # Create single line summary
    $summary = "$computerName | $statusText | $initialVersion -> $finalVersion | $changeType | $durationText"
    
    Write-Host $summary -ForegroundColor $statusColor
    
    # Show detailed summary only if -Verbose is specified
    if ($VerbosePreference -eq 'Continue') {
        Write-Host "`n" -NoNewline
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "                           CHROME UPDATE SUMMARY                               " -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        
        # Overall Status
        Write-Host "Overall Status: " -NoNewline -ForegroundColor White
        Write-Host $statusText -ForegroundColor $statusColor
        
        # Timing Information
        Write-Host "Duration: " -NoNewline -ForegroundColor White
        Write-Host "$($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor Cyan
        
        # Version Comparison
        Write-Host "`nVersion Information:" -ForegroundColor Yellow
        Write-Host "  Initial Version: " -NoNewline -ForegroundColor White
        Write-Host $initialVersion -ForegroundColor Cyan
        
        Write-Host "  Final Version:   " -NoNewline -ForegroundColor White
        Write-Host $finalVersion -ForegroundColor Green
        
        Write-Host "  Change Status:   " -NoNewline -ForegroundColor White
        $changeColor = switch ($changeType) {
            'UPGRADED' { 'Green' }
            'NO CHANGE' { 'Yellow' }
            'DOWNGRADED' { 'Red' }
            'INSTALLED' { 'Green' }
            'REMOVED' { 'Red' }
            default { 'Yellow' }
        }
        Write-Host $changeType -ForegroundColor $changeColor
        
        # Operation Results
        Write-Host "`nOperation Results:" -ForegroundColor Yellow
        foreach ($result in $Session.Results) {
            $resultColor = if ($result.Success) { 'Green' } else { 'Red' }
            $resultSymbol = if ($result.Success) { '✓' } else { '✗' }
            
            Write-Host "  $resultSymbol " -NoNewline -ForegroundColor $resultColor
            Write-Host "$($result.Operation): " -NoNewline -ForegroundColor White
            Write-Host "$($result.Message)" -ForegroundColor $resultColor
            
            if ($result.Details -and $VerbosePreference -eq 'Continue') {
                Write-Host "    Details: $($result.Details)" -ForegroundColor Gray
            }
        }
        
        Write-Host "`nLog File: " -NoNewline -ForegroundColor White
        Write-Host "$LogPath" -ForegroundColor Cyan
        
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    }
}

#endregion

#region Main Execution

function Start-ChromeUpdateProcess {
    [CmdletBinding()]
    param()
    
    # Initialize update session
    $session = [ChromeUpdateSession]::new()
    
    Write-LogMessage "Starting Chrome Update Manager" -Level Info
    Write-LogMessage "Log file: $LogPath (Max size: $MaxLogSizeMB MB)" -Level Info
    
    # Clean up old log backups
    Clear-OldLogBackups -LogPath $LogPath
    
    # Check administrative privileges
    if (-not (Test-AdministrativePrivileges)) {
        Write-LogMessage "WARNING: Script is not running with administrative privileges. Some operations may fail." -Level Warning
    }
    
    try {
        # Step 1: Get current Chrome version (fault-resistant)
        Write-LogMessage "Step 1: Getting current Chrome version..." -Level Info
        try {
            $session.InitialVersion = Get-CurrentChromeVersion
            
            if ($session.InitialVersion.IsInstalled) {
                Write-LogMessage "Current Chrome version detected: $($session.InitialVersion.Version)" -Level Success
                $result = [ChromeUpdateResult]::new('VersionDetection', $true, 'Current version detected', $session.InitialVersion.Version)
                $session.AddResult($result)
            } else {
                Write-LogMessage "Chrome is not currently installed" -Level Warning
                $result = [ChromeUpdateResult]::new('VersionDetection', $true, 'Chrome not installed', 'No existing installation found')
                $session.AddResult($result)
            }
        } catch {
            Write-LogMessage "Error detecting Chrome version: $_ - Defaulting to fresh installation" -Level Warning
            $session.InitialVersion = [ChromeVersionInfo]::new('Unknown', '', $false)
            $result = [ChromeUpdateResult]::new('VersionDetection', $false, 'Version detection failed', 'Proceeding with fresh installation')
            $session.AddResult($result)
        }
        
        # Step 2: Download latest Chrome version first
        Write-LogMessage "Step 2: Downloading latest Chrome version..." -Level Info
        $downloadResult = Invoke-ChromeDownload -Session $session
        
        if (-not $downloadResult.Success) {
            Write-LogMessage "Download failed. Aborting update process." -Level Error
            $session.Complete()
            Show-ChromeUpdateSummary -Session $session
            return $session
        }
        
        # Step 2.5: Check if update is actually needed
        Write-LogMessage "Step 2.5: Checking if update is needed..." -Level Info
        
        # Find the downloaded installer
        $tempDir = $env:TEMP
        $installerFiles = Get-ChildItem -Path $tempDir -Filter "ChromeInstaller_*.msi" | Sort-Object CreationTime -Descending
        
        if ($installerFiles) {
            $installerPath = $installerFiles[0].FullName
            
            try {
                $msiVersion = Get-ChromeVersionFromMsi -MsiPath $installerPath
                
                if ($msiVersion -and $session.InitialVersion.IsInstalled -and $session.InitialVersion.Version -ne 'Unknown') {
                    $versionComparison = Test-ChromeVersionComparison -CurrentVersion $session.InitialVersion.Version -MsiVersion $msiVersion
                    
                    switch ($versionComparison) {
                        'SameVersion' {
                            Write-LogMessage "Chrome is already at the latest version ($msiVersion). No update needed." -Level Success
                            $result = [ChromeUpdateResult]::new('VersionCheck', $true, 'No update needed', "Current version ($($session.InitialVersion.Version)) matches MSI version ($msiVersion)")
                            $session.AddResult($result)
                            
                            # Set final version to current version since no update was needed
                            $session.FinalVersion = $session.InitialVersion
                            
                            # Clean up downloaded installer
                            try {
                                Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
                                Write-LogMessage "Cleaned up unnecessary installer file: $installerPath" -Level Info
                            } catch {
                                Write-LogMessage "Warning: Could not clean up installer file: $_" -Level Warning
                            }
                            
                            $session.Complete()
                            Show-ChromeUpdateSummary -Session $session
                            return $session
                        }
                        'Downgrade' {
                            Write-LogMessage "WARNING: Downloaded MSI version ($msiVersion) is older than current version ($($session.InitialVersion.Version))" -Level Warning
                            $result = [ChromeUpdateResult]::new('VersionCheck', $true, 'Downgrade detected', "MSI version ($msiVersion) is older than current ($($session.InitialVersion.Version))")
                            $session.AddResult($result)
                            # Continue with installation - user might want to downgrade
                        }
                        'Upgrade' {
                            Write-LogMessage "Update needed: Current version ($($session.InitialVersion.Version)) -> MSI version ($msiVersion)" -Level Info
                            $result = [ChromeUpdateResult]::new('VersionCheck', $true, 'Upgrade available', "Current: $($session.InitialVersion.Version) -> New: $msiVersion")
                            $session.AddResult($result)
                            # Continue with installation
                        }
                        default {
                            Write-LogMessage "Version comparison inconclusive. Proceeding with installation." -Level Warning
                            $result = [ChromeUpdateResult]::new('VersionCheck', $false, 'Version comparison failed', 'Proceeding with installation')
                            $session.AddResult($result)
                            # Continue with installation
                        }
                    }
                } else {
                    Write-LogMessage "Could not determine MSI version or no reliable current version. Proceeding with installation." -Level Warning
                    $result = [ChromeUpdateResult]::new('VersionCheck', $false, 'Version check skipped', 'Unable to determine versions for comparison - defaulting to install')
                    $session.AddResult($result)
                }
            } catch {
                Write-LogMessage "Error during version check: $_ - Proceeding with installation." -Level Warning
                $result = [ChromeUpdateResult]::new('VersionCheck', $false, 'Version check error', 'Proceeding with installation due to error')
                $session.AddResult($result)
            }
        } else {
            Write-LogMessage "Downloaded installer not found. Proceeding with installation attempt." -Level Warning
            $result = [ChromeUpdateResult]::new('VersionCheck', $false, 'Installer not found', 'Cannot perform version check')
            $session.AddResult($result)
        }
        
        # Step 3: Try install-over first (more reliable than uninstall + install)
        Write-LogMessage "Step 3: Attempting install-over (installing over existing version)..." -Level Info
        $installResult = Invoke-ChromeInstall -Session $session
        
        if (-not $installResult.Success -and $session.InitialVersion.IsInstalled -and $session.InitialVersion.Version -ne 'Unknown') {
            Write-LogMessage "Install-over failed. Attempting uninstall + install approach..." -Level Warning
            
            # Step 3b: Uninstall current version
            Write-LogMessage "Step 3b: Uninstalling current Chrome version..." -Level Info
            $uninstallResult = Invoke-ChromeUninstall -Session $session
            
            # Step 3c: Retry installation after uninstall (continue even if uninstall partially failed)
            Write-LogMessage "Step 3c: Retrying installation after uninstall..." -Level Info
            $installResult = Invoke-ChromeInstall -Session $session
            
            if (-not $installResult.Success) {
                Write-LogMessage "Installation failed even after uninstall. Continuing to verification..." -Level Warning
                # Don't abort - continue to verification step to see if Chrome is installed
            }
        } elseif (-not $installResult.Success) {
            Write-LogMessage "Installation failed. Continuing to verification..." -Level Warning
            # Don't abort - continue to verification step to see if Chrome is installed
        }
        
        # Step 4: Get final Chrome version (fault-resistant)
        Write-LogMessage "Step 4: Verifying new Chrome version..." -Level Info
        try {
            $session.FinalVersion = Get-CurrentChromeVersion
            
            if ($session.FinalVersion.IsInstalled) {
                Write-LogMessage "New Chrome version confirmed: $($session.FinalVersion.Version)" -Level Success
                $result = [ChromeUpdateResult]::new('FinalVerification', $true, 'New version confirmed', $session.FinalVersion.Version)
                $session.AddResult($result)
            } else {
                Write-LogMessage "Chrome installation could not be verified - may need manual verification" -Level Warning
                $result = [ChromeUpdateResult]::new('FinalVerification', $false, 'Installation verification failed', 'Chrome not detected after installation')
                $session.AddResult($result)
                # Set a default final version to prevent null reference errors
                $session.FinalVersion = [ChromeVersionInfo]::new('Unknown', '', $false)
            }
        } catch {
            Write-LogMessage "Error during final verification: $_ - Process completed with unknown status" -Level Warning
            $result = [ChromeUpdateResult]::new('FinalVerification', $false, 'Verification error', 'Error during final verification')
            $session.AddResult($result)
            # Set a default final version to prevent null reference errors
            $session.FinalVersion = [ChromeVersionInfo]::new('Unknown', '', $false)
        }
        
        # Complete session
        $session.Complete()
        Write-LogMessage "Chrome update process completed" -Level Success
        
        # Step 5: Show update summary
        Show-ChromeUpdateSummary -Session $session
        
        return $session
        
    } catch {
        Write-LogMessage "Critical error in Chrome update process: $_" -Level Error
        $result = [ChromeUpdateResult]::new('CriticalError', $false, 'Critical error occurred', $_.Exception.Message)
        $session.AddResult($result)
        $session.Complete()
        Show-ChromeUpdateSummary -Session $session
        return $session
    }
}

#endregion

# Main execution
if (-not $Quiet) {
    Write-Host "Chrome Update Manager Starting..." -ForegroundColor Green
    Write-Host "Log file: $LogPath" -ForegroundColor Cyan
}

if ($PSCmdlet.ShouldProcess("Chrome Browser", "Complete Update Process")) {
    $updateSession = Start-ChromeUpdateProcess
    
    # Exit with appropriate code
    if ($updateSession.OverallSuccess) {
        if (-not $Quiet) { Write-Host "Chrome update completed successfully!" -ForegroundColor Green }
        #exit 0
    } else {
        if (-not $Quiet) { Write-Host "Chrome update failed. Check log for details." -ForegroundColor Red }
        #exit 1
    }
} else {
    if (-not $Quiet) { Write-Host "WhatIf mode - showing what would be done:" -ForegroundColor Yellow }
    $updateSession = Start-ChromeUpdateProcess
} 