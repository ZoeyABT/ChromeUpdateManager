<#
.SYNOPSIS
    Azure Automation Runbook for Chrome Update Management across VMs

.DESCRIPTION
    This runbook executes Chrome Update Manager on Azure VMs matching a name pattern.
    It sets up run commands sequentially, then monitors until completion and returns results.

.PARAMETER vmNamePattern
    Pattern to match VM names (case-insensitive substring match)

.PARAMETER timeoutMinutes
    Maximum time to wait for all VMs to complete (default: 30 minutes)

.NOTES
    - Requires System Managed Identity with appropriate permissions
    - Uses PowerShell 7.2 runbook capabilities
    - Returns structured results with one row per VM
#>

param(
    [Parameter(Mandatory = $true)]
    [string] $vmNamePattern,
    
    [Parameter(Mandatory = $false)]
    [int] $timeoutMinutes = 30
)

#region Classes and Data Structures

class VmExecutionResult {
    [string] $VmName
    [string] $ResourceGroup
    [string] $Status
    [string] $ChromeResult
    [string] $ErrorDetails
    [datetime] $StartTime
    [datetime] $EndTime
    [int] $DurationMinutes
    
    VmExecutionResult([string] $VmName, [string] $ResourceGroup) {
        $this.VmName = $VmName
        $this.ResourceGroup = $ResourceGroup
        $this.Status = 'Pending'
        $this.ChromeResult = ''
        $this.ErrorDetails = ''
        $this.StartTime = Get-Date
        $this.EndTime = [datetime]::MinValue
        $this.DurationMinutes = 0
    }
    
    [void] SetCompleted([string] $ChromeResult) {
        $this.Status = 'Completed'
        $this.ChromeResult = $ChromeResult
        $this.EndTime = Get-Date
        $this.DurationMinutes = [math]::Round(($this.EndTime - $this.StartTime).TotalMinutes, 1)
    }
    
    [void] SetFailed([string] $ErrorDetails) {
        $this.Status = 'Failed'
        $this.ErrorDetails = $ErrorDetails
        $this.EndTime = Get-Date
        $this.DurationMinutes = [math]::Round(($this.EndTime - $this.StartTime).TotalMinutes, 1)
    }
    
    [void] SetTimedOut() {
        $this.Status = 'TimedOut'
        $this.ErrorDetails = 'Operation timed out'
        $this.EndTime = Get-Date
        $this.DurationMinutes = [math]::Round(($this.EndTime - $this.StartTime).TotalMinutes, 1)
    }
}

#endregion

#region Helper Functions

function Write-RunbookOutput {
    param(
        [Parameter(Mandatory)]
        [string] $Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string] $Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Output $logEntry
}

function Get-TargetVms {
    param(
        [Parameter(Mandatory)]
        [string] $NamePattern
    )
    
    try {
        Write-RunbookOutput "Searching for VMs matching pattern: '$NamePattern'" -Level Info
        
        $vms = Get-AzVm | Where-Object { ($_.Name.ToLower()).Contains($NamePattern.ToLower()) }
        
        if ($vms.Count -eq 0) {
            Write-RunbookOutput "No VMs found matching pattern: '$NamePattern'" -Level Warning
            return @()
        }
        
        Write-RunbookOutput "Found $($vms.Count) VMs matching pattern" -Level Success
        foreach ($vm in $vms) {
            Write-RunbookOutput "  - $($vm.Name) (Resource Group: $($vm.ResourceGroupName))" -Level Info
        }
        
        return $vms
    }
    catch {
        Write-RunbookOutput "Error searching for VMs: $($_.Exception.Message)" -Level Error
        throw $_
    }
}

function Initialize-RunCommand {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VM,
        
        [Parameter(Mandatory)]
        [string] $RunCommandName
    )
    
    try {
        # Clean up any existing run commands with the same name
        $existingCommands = Get-AzVMRunCommand -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -ErrorAction SilentlyContinue
        if ($existingCommands) {
            foreach ($command in $existingCommands) {
                if ($command.Name -eq $RunCommandName) {
                    Write-RunbookOutput "Cleaning up existing run command '$RunCommandName' on $($VM.Name)" -Level Info
                    Remove-AzVMRunCommand -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -RunCommandName $RunCommandName -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2  # Brief pause to ensure cleanup
                }
            }
        }
        
        # Define the Chrome Update Manager script block
        $runCommandPayload = {
            try {
                $script = (Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/ChromeUpdateManager/refs/heads/main/ChromeUpdateManager.ps1" -UseBasicParsing).Content
                & ([ScriptBlock]::Create($script))
            }
            catch {
                Write-Output "ERROR: Failed to download or execute Chrome Update Manager: $($_.Exception.Message)"
            }
        }
        
        # Set up the run command
        Write-RunbookOutput "Setting up run command on $($VM.Name)" -Level Info
        Set-AzVMRunCommand -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -RunCommandName $RunCommandName -Location $VM.Location -SourceScript $runCommandPayload -NoWait
        
        return $true
    }
    catch {
        Write-RunbookOutput "Failed to set up run command on $($VM.Name): $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Get-RunCommandResult {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Azure.Commands.Compute.Models.PSVirtualMachine] $VM,
        
        [Parameter(Mandatory)]
        [string] $RunCommandName
    )
    
    try {
        $runCommand = Get-AzVMRunCommand -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -RunCommandName $RunCommandName -Expand InstanceView -ErrorAction SilentlyContinue
        
        if (-not $runCommand) {
            return @{
                Status = 'NotFound'
                Output = ''
                Error = 'Run command not found'
            }
        }
        
        $executionState = $runCommand.InstanceView.ExecutionState
        $executionMessage = $runCommand.InstanceView.ExecutionMessage
        
        # Get output from the run command
        $stdout = ''
        $stderr = ''
        
        if ($runCommand.InstanceView.Output) {
            $stdout = $runCommand.InstanceView.Output | ForEach-Object { $_.Message } | Out-String
        }
        
        if ($runCommand.InstanceView.Error) {
            $stderr = $runCommand.InstanceView.Error | ForEach-Object { $_.Message } | Out-String
        }
        
        return @{
            Status = $executionState
            Output = $stdout.Trim()
            Error = $stderr.Trim()
            Message = $executionMessage
        }
    }
    catch {
        return @{
            Status = 'Error'
            Output = ''
            Error = $_.Exception.Message
        }
    }
}

function Wait-ForAllRunCommands {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[VmExecutionResult]] $Results,
        
        [Parameter(Mandatory)]
        [string] $RunCommandName,
        
        [Parameter(Mandatory)]
        [int] $TimeoutMinutes
    )
    
    $timeout = (Get-Date).AddMinutes($TimeoutMinutes)
    $pollingInterval = 30  # seconds
    
    Write-RunbookOutput "Monitoring run commands with $TimeoutMinutes minute timeout" -Level Info
    
    while ((Get-Date) -lt $timeout) {
        $pendingCount = ($Results | Where-Object { $_.Status -eq 'Pending' }).Count
        
        if ($pendingCount -eq 0) {
            Write-RunbookOutput "All run commands completed" -Level Success
            break
        }
        
        Write-RunbookOutput "Checking status... ($pendingCount VMs still pending)" -Level Info
        
        # Check each pending VM
        foreach ($result in $Results | Where-Object { $_.Status -eq 'Pending' }) {
            try {
                $vm = Get-AzVm -ResourceGroupName $result.ResourceGroup -Name $result.VmName -ErrorAction SilentlyContinue
                if (-not $vm) {
                    $result.SetFailed("VM not found")
                    continue
                }
                
                $commandResult = Get-RunCommandResult -VM $vm -RunCommandName $RunCommandName
                
                switch ($commandResult.Status) {
                    'Succeeded' {
                        # Parse the Chrome Update Manager output
                        $chromeOutput = $commandResult.Output
                        
                        # Look for Chrome result line pattern (computer name | status | version info | change | duration)
                        $chromeResultLine = ($chromeOutput -split "`n" | Where-Object { $_ -match "^\s*.*\s*\|\s*(SUCCESS|FAILED)\s*\|.*\|.*\|.*min\s*$" })[0]
                        
                        if ($chromeResultLine) {
                            $result.SetCompleted($chromeResultLine.Trim())
                        } else {
                            # Fall back to looking for any line that looks like Chrome output
                            $fallbackLine = ($chromeOutput -split "`n" | Where-Object { $_ -match "^\s*\w+.*\|.*\|.*\|.*\|.*" })[0]
                            if ($fallbackLine) {
                                $result.SetCompleted($fallbackLine.Trim())
                            } else {
                                $result.SetCompleted("Completed - Output: $($chromeOutput.Substring(0, [math]::Min(100, $chromeOutput.Length)))")
                            }
                        }
                        
                        # Clean up the run command
                        Remove-AzVMRunCommand -ResourceGroupName $result.ResourceGroup -VMName $result.VmName -RunCommandName $RunCommandName -ErrorAction SilentlyContinue
                    }
                    'Failed' {
                        $errorMsg = if ($commandResult.Error) { $commandResult.Error } else { $commandResult.Message }
                        $result.SetFailed($errorMsg.Substring(0, [math]::Min(200, $errorMsg.Length)))
                        
                        # Clean up the run command
                        Remove-AzVMRunCommand -ResourceGroupName $result.ResourceGroup -VMName $result.VmName -RunCommandName $RunCommandName -ErrorAction SilentlyContinue
                    }
                    'Running' {
                        # Still running, continue monitoring
                        continue
                    }
                    default {
                        # Still pending or unknown state
                        continue
                    }
                }
            }
            catch {
                $result.SetFailed("Error checking status: $($_.Exception.Message)")
            }
        }
        
        # Wait before next check
        if ($pendingCount -gt 0) {
            Start-Sleep -Seconds $pollingInterval
        }
    }
    
    # Handle any remaining timeouts
    foreach ($result in $Results | Where-Object { $_.Status -eq 'Pending' }) {
        $result.SetTimedOut()
        # Clean up timed out run commands
        try {
            Remove-AzVMRunCommand -ResourceGroupName $result.ResourceGroup -VMName $result.VmName -RunCommandName $RunCommandName -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore cleanup errors for timed out commands
        }
    }
}

#endregion

#region Main Execution

function Start-ChromeUpdateRunbook {
    param(
        [Parameter(Mandatory)]
        [string] $VmNamePattern,
        
        [Parameter(Mandatory)]
        [int] $TimeoutMinutes
    )
    
    $startTime = Get-Date
    Write-RunbookOutput "Starting Chrome Update Runbook" -Level Info
    Write-RunbookOutput "VM Name Pattern: '$VmNamePattern'" -Level Info
    Write-RunbookOutput "Timeout: $TimeoutMinutes minutes" -Level Info
    
    try {
        # Step 1: Connect to Azure
        Write-RunbookOutput "Connecting to Azure using System Managed Identity" -Level Info
        try {
            Connect-AzAccount -Identity | Out-Null
            Write-RunbookOutput "Successfully connected to Azure" -Level Success
        }
        catch {
            Write-RunbookOutput "Failed to connect to Azure: $($_.Exception.Message)" -Level Error
            throw $_
        }
        
        # Step 2: Get target VMs
        $vms = Get-TargetVms -NamePattern $VmNamePattern
        
        if ($vms.Count -eq 0) {
            Write-RunbookOutput "No VMs found. Exiting." -Level Warning
            return @()
        }
        
        # Step 3: Initialize results tracking
        $results = [System.Collections.Generic.List[VmExecutionResult]]::new()
        foreach ($vm in $vms) {
            $results.Add([VmExecutionResult]::new($vm.Name, $vm.ResourceGroupName))
        }
        
        $runCommandName = "ChromeUpdate$(Get-Date -Format 'yyyyMMddHHmmss')"
        
        # Step 4: Set up run commands sequentially
        Write-RunbookOutput "Setting up run commands on all VMs" -Level Info
        foreach ($vm in $vms) {
            $result = $results | Where-Object { $_.VmName -eq $vm.Name }
            
            $setupSuccess = Initialize-RunCommand -VM $vm -RunCommandName $runCommandName
            
            if (-not $setupSuccess) {
                $result.SetFailed("Failed to initialize run command")
            }
            
            # Brief pause between setups to avoid overwhelming Azure
            Start-Sleep -Seconds 2
        }
        
        # Step 5: Monitor until completion
        Wait-ForAllRunCommands -Results $results -RunCommandName $runCommandName -TimeoutMinutes $TimeoutMinutes
        
        # Step 6: Generate summary
        $totalDuration = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)
        $successCount = ($results | Where-Object { $_.Status -eq 'Completed' }).Count
        $failedCount = ($results | Where-Object { $_.Status -eq 'Failed' }).Count
        $timedOutCount = ($results | Where-Object { $_.Status -eq 'TimedOut' }).Count
        
        Write-RunbookOutput "Runbook completed in $totalDuration minutes" -Level Success
        Write-RunbookOutput "Results: $successCount successful, $failedCount failed, $timedOutCount timed out" -Level Info
        
        return $results
    }
    catch {
        Write-RunbookOutput "Critical error in runbook execution: $($_.Exception.Message)" -Level Error
        throw $_
    }
}

#endregion

# Main execution
try {
    $results = Start-ChromeUpdateRunbook -VmNamePattern $vmNamePattern -TimeoutMinutes $timeoutMinutes
    
    # Format and output results
    if ($results.Count -gt 0) {
        Write-Output ""
        Write-Output "=== CHROME UPDATE RESULTS ==="
        Write-Output ""
        
        # Output results in a clean table format
        $results | Sort-Object VmName | ForEach-Object {
            $statusIcon = switch ($_.Status) {
                'Completed' { '✓' }
                'Failed' { '✗' }
                'TimedOut' { '⏱' }
                default { '?' }
            }
            
            if ($_.Status -eq 'Completed') {
                Write-Output "$statusIcon $($_.VmName): $($_.ChromeResult)"
            } else {
                Write-Output "$statusIcon $($_.VmName): $($_.Status) - $($_.ErrorDetails)"
            }
        }
        
        Write-Output ""
        Write-Output "=== SUMMARY ==="
        $successCount = ($results | Where-Object { $_.Status -eq 'Completed' }).Count
        $failedCount = ($results | Where-Object { $_.Status -eq 'Failed' }).Count
        $timedOutCount = ($results | Where-Object { $_.Status -eq 'TimedOut' }).Count
        
        Write-Output "Total VMs: $($results.Count)"
        Write-Output "Successful: $successCount"
        Write-Output "Failed: $failedCount"
        Write-Output "Timed Out: $timedOutCount"
        
        # Return structured results for further processing if needed
        return $results
    }
}
catch {
    Write-Output "RUNBOOK FAILED: $($_.Exception.Message)"
    throw $_
}