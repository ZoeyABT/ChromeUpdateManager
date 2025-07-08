# Chrome Update Manager

A comprehensive PowerShell script for automated Google Chrome browser update management in Windows environments. Designed for enterprise deployment with remote execution capabilities, fault tolerance, and detailed logging.

## 🚀 Features

- **Automated Chrome Updates**: Complete update workflow from detection to installation
- **Remote Execution Ready**: Optimized for PowerShell Remoting across multiple computers
- **Fault Tolerant**: Defaults to fresh installation when version detection fails
- **Smart Version Comparison**: Skips unnecessary updates when Chrome is already current
- **Flexible Output Modes**: Single-line summary, detailed verbose output, or completely silent execution
- **Comprehensive Logging**: Automatic log rotation with size management
- **Multiple Installation Methods**: Install-over existing version or uninstall/reinstall approach
- **Enterprise MSI Support**: Downloads and installs Chrome Enterprise MSI packages

## 📋 Requirements

- **Windows Operating System**
- **PowerShell 5.1 or later**
- **Administrative privileges** (for uninstall/install operations)
- **Internet connectivity** (for downloading Chrome installer)

## 🛠️ Installation

1. **Download the script:**
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ZoeyABT/ChromeUpdateManager/main/ChromeUpdateManager.ps1" -OutFile "ChromeUpdateManager.ps1"
   ```

2. **Set execution policy** (if needed):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Run the script:**
   ```powershell
   .\ChromeUpdateManager.ps1
   ```

## 📖 Usage

### Basic Usage

```powershell
# Standard execution with normal output
.\ChromeUpdateManager.ps1

# Silent execution (no console output)
.\ChromeUpdateManager.ps1 -Quiet

# Detailed verbose output
.\ChromeUpdateManager.ps1 -Verbose

# Preview mode (shows what would be done without executing)
.\ChromeUpdateManager.ps1 -WhatIf
```

### Advanced Usage

```powershell
# Custom log file location and size limit
.\ChromeUpdateManager.ps1 -LogPath "C:\Logs\ChromeUpdate.log" -MaxLogSizeMB 10

# Combine parameters for remote execution
.\ChromeUpdateManager.ps1 -Quiet -LogPath "C:\Temp\Chrome.log" -MaxLogSizeMB 2
```

### Remote Execution

```powershell
# Single remote computer
Invoke-Command -ComputerName SERVER01 -ScriptBlock { 
    .\ChromeUpdateManager.ps1 -Quiet 
}

# Multiple computers with results
$computers = @('PC1', 'PC2', 'PC3', 'PC4')
Invoke-Command -ComputerName $computers -ScriptBlock { 
    .\ChromeUpdateManager.ps1 -Quiet 
} | Select-Object PSComputerName, @{N='Result';E={$_.ToString()}}

# Scheduled task execution
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\ChromeUpdateManager.ps1 -Quiet"
$trigger = New-ScheduledTaskTrigger -Daily -At 3:00AM
Register-ScheduledTask -TaskName "ChromeUpdate" -Action $action -Trigger $trigger
```

## 📊 Output Formats

### Normal Mode (Single Line Summary)
```
DESKTOP-ABC123 | SUCCESS | 138.0.7204.99 -> 138.0.7204.101 | UPGRADED | 2.3min
```

### Quiet Mode
```
(No console output - all logging to file only)
```

### Verbose Mode
```
DESKTOP-ABC123 | SUCCESS | 138.0.7204.99 -> 138.0.7204.101 | UPGRADED | 2.3min

═══════════════════════════════════════════════════════════════════════════════
                           CHROME UPDATE SUMMARY                               
═══════════════════════════════════════════════════════════════════════════════
Overall Status: SUCCESS
Duration: 2.31 minutes

Version Information:
  Initial Version: 138.0.7204.99
  Final Version: 138.0.7204.101
  Change Status: UPGRADED

Operation Results:
  ✓ VersionDetection: Current version detected
  ✓ Download: Chrome installer downloaded successfully
  ✓ VersionCheck: Upgrade available
  ✓ Install: Chrome installed successfully
  ✓ FinalVerification: New version confirmed

Log File: C:\Users\username\AppData\Local\Temp\ChromeUpdate.log
═══════════════════════════════════════════════════════════════════════════════
```

## 🔧 Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `LogPath` | String | `$env:TEMP\ChromeUpdate.log` | Path for log file output |
| `MaxLogSizeMB` | Int | `5` | Maximum log file size in MB before rotation |
| `Quiet` | Switch | `False` | Suppress all console output for remote execution |
| `WhatIf` | Switch | `False` | Preview mode - shows what would be done |
| `Verbose` | Switch | `False` | Enable detailed console output |

## 📝 Logging

The script implements intelligent logging with automatic size management:

- **Default Location**: `%TEMP%\ChromeUpdate.log`
- **Size Management**: Automatically rotates when exceeding size limit (default 5MB)
- **Backup Strategy**: Keeps up to 10 most recent backup files
- **Cleanup**: Removes backups older than 30 days
- **Format**: `[YYYY-MM-DD HH:MM:SS] [LEVEL] Message`

## 🛡️ Error Handling & Fault Tolerance

The script is designed to be fault-tolerant and will attempt to complete the Chrome update even when individual steps fail:

- **Version Detection Fails**: Defaults to fresh installation
- **Download Issues**: Comprehensive error reporting with retry logic
- **Install-Over Fails**: Automatically tries uninstall + install approach
- **Uninstall Fails**: Continues with installation attempt
- **Verification Fails**: Completes with warning rather than complete failure

## 🔄 Update Process Flow

1. **Version Detection**: Detect currently installed Chrome version
2. **Download**: Download latest Chrome Enterprise MSI
3. **Version Comparison**: Compare current vs. available version
4. **Smart Skip**: Skip installation if already up-to-date
5. **Installation**: Install-over existing version or uninstall/reinstall
6. **Verification**: Confirm successful installation
7. **Reporting**: Generate summary and detailed logs

## 📅 Automation Examples

### Daily Scheduled Task
```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\ChromeUpdateManager.ps1 -Quiet"
$trigger = New-ScheduledTaskTrigger -Daily -At 3:00AM
$principal = New-ScheduledTaskPrincipal -UserID "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "Daily Chrome Update" -Action $action -Trigger $trigger -Principal $principal
```

### Group Policy Deployment
```powershell
# Create startup script via Group Policy
# Computer Configuration > Policies > Windows Settings > Scripts > Startup
# Add: PowerShell.exe -File \\server\share\ChromeUpdateManager.ps1 -Quiet
```

### Configuration Manager (SCCM) Package
```powershell
# Create package with command line:
# PowerShell.exe -ExecutionPolicy Bypass -File ChromeUpdateManager.ps1 -Quiet
```

## 🔍 Troubleshooting

### Common Issues

1. **"Access Denied" Errors**
   - Ensure script is run with administrative privileges
   - Check antivirus software is not blocking execution

2. **Download Failures**
   - Verify internet connectivity
   - Check firewall/proxy settings
   - Ensure access to `dl.google.com`

3. **Installation Failures**
   - Chrome may be in use - close all Chrome instances
   - Try running with `-WhatIf` first to preview actions
   - Check Windows Installer service is running

4. **Version Detection Issues**
   - Script will default to fresh installation
   - Check registry permissions for Chrome entries
   - Verify WMI service is functioning

### Log Analysis
```powershell
# View recent log entries
Get-Content "$env:TEMP\ChromeUpdate.log" | Select-Object -Last 50

# Search for errors
Get-Content "$env:TEMP\ChromeUpdate.log" | Select-String -Pattern "ERROR"

# Filter by today's entries
Get-Content "$env:TEMP\ChromeUpdate.log" | Select-String -Pattern (Get-Date -Format "yyyy-MM-dd")
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Google Chrome Enterprise team for MSI distribution
- PowerShell community for best practices
- Enterprise IT professionals for feedback and testing

## 📞 Support

For issues, questions, or contributions:
- **GitHub Issues**: [Create an issue](https://github.com/ZoeyABT/ChromeUpdateManager/issues)
- **Documentation**: This README and inline script comments
- **Enterprise Support**: Suitable for enterprise environments with comprehensive logging

---

**Note**: This script is designed for Windows environments and requires administrative privileges for Chrome installation/uninstallation operations. Always test in a non-production environment first. 