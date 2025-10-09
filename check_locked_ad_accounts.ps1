# ================================================================================
# CheckMK Local Check Script: Domain Account Monitoring
# ================================================================================
#
# Purpose:     Monitors domain user accounts for locked and disabled status
#              and reports them to CheckMK as individual services or summary check
#
# Author:      FELLNER Mario (mario.fellner@outlook.at)
# Created:     2025-09-17
# Version:     3.2
# Last Modified: 2025-10-09
#
# Description: This script searches for locked and disabled domain accounts in 
#              Active Directory and creates CheckMK local checks. It supports both 
#              individual checks per account and a summary check. The script tracks 
#              lock/unlock/disabled events in a log file and ensures resolved accounts 
#              get OK status.
#
#              NEW: Can discover domain accounts used locally on the system
#              (Services, Scheduled Tasks, IIS App Pools) and check their status.
#
# Installation: Copy this script to C:\ProgramData\checkmk\agent\local\
#              and ensure it has .ps1 extension for PowerShell execution
#
# ================================================================================
# CHANGE LOG
# ================================================================================
#
# Version 3.2 (2025-10-09)
# - Changed service name from "LockedUser" to "DomainAccount" for better accuracy
# - Service name now correctly represents both locked and disabled account monitoring
# - Updated script title and description to reflect domain account monitoring
# - Updated all references in code and comments
#
# Version 3.1 (2025-10-09)
# - Added support for monitoring disabled accounts (not just locked)
# - New configuration option: $checkDisabledAccounts
# - Enhanced status messages to differentiate between LOCKED and DISABLED
# - Improved debug output showing LockedOut status explicitly
# - Updated log entries with specific issue types (LOCKED/DISABLED/RESOLVED)
# - Added CMK_VERSION identifier for CheckMK agent plugin tracking
#
# Version 3.0 (2025-10-09)
# - Added Local System Discovery Mode
# - New feature: Scan Windows Services for domain accounts
# - New feature: Scan Scheduled Tasks for domain accounts
# - New feature: Scan IIS Application Pools for domain accounts
# - Enhanced logging with source information (where account is used)
# - Enhanced CheckMK output shows local usage context
# - Added $useLocalSystemDiscovery switch to toggle between modes
# - Added individual switches for each discovery source type
#
# Version 2.9 (2025-09-17) - Final Version of AD Search Mode
# - Professional code structure with header and documentation
# - Added ActiveDirectory module availability check
# - Enhanced error handling with CheckMK-compliant output
# - Automatic domain detection and DN substitution
# - Configuration section clearly separated from code
# - Added installation path documentation
#
# Version 2.0 (2025-09-17)
# - Added individual check mode per locked user
# - Added UPN (UserPrincipalName) support instead of SamAccountName
# - Added lock/unlock event logging
# - Unlocked users now receive OK status instead of disappearing
# - Added history tracking for previously locked users
#
# Version 1.0 (2025-09-17)
# - Initial release
# - Basic locked user detection in AD
# - Summary check mode
# - Support for OU-based search and Security Group filtering
#
# ================================================================================
# PREREQUISITES
# ================================================================================
#
# - PowerShell ActiveDirectory module must be installed
# - Script must run with sufficient AD permissions to query user accounts
# - CheckMK agent must be installed and configured
# - Write permissions to C:\ProgramData\checkmk\agent\log directory
# - For IIS discovery: WebAdministration module (if checking IIS App Pools)
#
# Installation of AD module (if not present):
# Windows Server: Install-WindowsFeature -Name RSAT-AD-PowerShell
# Windows Client: Install RSAT tools from Microsoft
#
# ================================================================================
# CONFIGURATION VARIABLES - MODIFY AS NEEDED
# ================================================================================

# CheckMK Version Identifier
$CMK_VERSION = "2.4.0p12"

# Discovery Mode: Choose how to find accounts to monitor
$useLocalSystemDiscovery = $true  # $true = scan local system for domain accounts, $false = use AD search

# Allowlist: Users to exclude from monitoring (even if locked)
$allowList = @("")

# === AD SEARCH MODE CONFIGURATION (when $useLocalSystemDiscovery = $false) ===
# Search scope: Choose ONE of the following options (leave others empty):
# Option 1: Search in specific OU (will be automatically updated with current domain)
$UserSearchBase = "OU=Service Accounts"  # Domain DN will be added automatically
# Option 2: Search members of a security group
$SecurityGroup = ""  # Example: "CN=MonitoredUsers,OU=Groups" or just "MonitoredUsers"
# Option 3: Leave both empty to search entire Active Directory

# === LOCAL SYSTEM DISCOVERY CONFIGURATION (when $useLocalSystemDiscovery = $true) ===
$checkWindowsServices = $true      # Check Windows Services for domain accounts
$checkScheduledTasks = $true       # Check Scheduled Tasks for domain accounts
$checkIISAppPools = $true          # Check IIS Application Pools for domain accounts
$checkDisabledAccounts = $true     # Also monitor disabled accounts (not just locked ones)
$debugMode = $false                # Enable debug output to see discovered accounts

# Thresholds for summary mode (ignored in individual mode)
$warn = 2    # Warning threshold: number of locked accounts
$crit = 5    # Critical threshold: number of locked accounts

# Check mode: Individual checks per user vs single summary check
$individualChecks = $true  # $true = individual checks per user, $false = single summary check

# Log file for tracking lock/unlock events
$logFile = "C:\ProgramData\checkmk\agent\log\domain_account_monitoring.log"

# ================================================================================
# PROGRAM CODE - DO NOT MODIFY BELOW THIS LINE
# ================================================================================

# Check if ActiveDirectory module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Output "<<<local>>>"
    Write-Output "2 'ActiveDirectory Module' - ActiveDirectory PowerShell module is not installed. Please install RSAT-AD-PowerShell feature."
    exit 1
}

# Import the Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Output "<<<local>>>"
    Write-Output "2 'ActiveDirectory Module' - Failed to import ActiveDirectory module: $($_.Exception.Message)"
    exit 1
}

# Get current domain automatically
try {
    $currentDomain = Get-ADDomain
    $domainDN = $currentDomain.DistinguishedName
    $domainNetBIOS = $currentDomain.NetBIOSName
} catch {
    Write-Output "<<<local>>>"
    Write-Output "2 'AD Domain Access' - Failed to get current domain information: $($_.Exception.Message)"
    exit 1
}

# Function to discover domain accounts used locally on the system
function Get-LocalSystemDomainAccounts {
    $discoveredAccounts = @()
    
    # Check Windows Services
    if ($checkWindowsServices) {
        try {
            # Get ALL services regardless of running state
            $services = Get-WmiObject Win32_Service | Where-Object { 
                $_.StartName -and 
                $_.StartName -notmatch "^(LocalSystem|NT AUTHORITY|SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$" -and
                $_.StartName -match "\\"
            }
            
            foreach ($service in $services) {
                $accountName = $service.StartName
                if ($accountName -match "^(.+?)\\(.+)$") {
                    $domain = $matches[1]
                    $username = $matches[2]
                    
                    # Only add if it's a domain account from our domain
                    if ($domain -eq $domainNetBIOS -or $domain -eq $currentDomain.DNSRoot) {
                        $serviceState = $service.State
                        $serviceStatus = $service.Status
                        $discoveredAccounts += [PSCustomObject]@{
                            Username = $username
                            Source = "Windows Service"
                            SourceName = $service.Name
                            DisplayName = $service.DisplayName
                            State = $serviceState
                            Status = $serviceStatus
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Failed to query Windows Services: $($_.Exception.Message)"
        }
    }
    
    # Check Scheduled Tasks
    if ($checkScheduledTasks) {
        try {
            # Get ALL scheduled tasks regardless of enabled/disabled state
            $tasks = Get-ScheduledTask | Where-Object { 
                $_.Principal.UserId -and 
                $_.Principal.UserId -match "\\" -and
                $_.Principal.UserId -notmatch "^(SYSTEM|BUILTIN|NT AUTHORITY)"
            }
            
            foreach ($task in $tasks) {
                $accountName = $task.Principal.UserId
                if ($accountName -match "^(.+?)\\(.+)$") {
                    $domain = $matches[1]
                    $username = $matches[2]
                    
                    if ($domain -eq $domainNetBIOS -or $domain -eq $currentDomain.DNSRoot) {
                        $taskState = $task.State
                        $discoveredAccounts += [PSCustomObject]@{
                            Username = $username
                            Source = "Scheduled Task"
                            SourceName = $task.TaskName
                            DisplayName = $task.TaskPath + $task.TaskName
                            State = $taskState
                            Status = $taskState
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Failed to query Scheduled Tasks: $($_.Exception.Message)"
        }
    }
    
    # Check IIS Application Pools
    if ($checkIISAppPools) {
        try {
            # Check if WebAdministration module is available
            if (Get-Module -ListAvailable -Name WebAdministration) {
                Import-Module WebAdministration -ErrorAction Stop
                
                # Verify IIS drive is available before querying
                if (Test-Path IIS:\AppPools -ErrorAction SilentlyContinue) {
                    # Get ALL app pools regardless of running state
                    $appPools = Get-ChildItem IIS:\AppPools -ErrorAction Stop | Where-Object {
                        $_.processModel.userName -and 
                        $_.processModel.userName -match "\\"
                    }
                    
                    foreach ($pool in $appPools) {
                        $accountName = $pool.processModel.userName
                        if ($accountName -match "^(.+?)\\(.+)$") {
                            $domain = $matches[1]
                            $username = $matches[2]
                            
                            if ($domain -eq $domainNetBIOS -or $domain -eq $currentDomain.DNSRoot) {
                                $poolState = $pool.State
                                $discoveredAccounts += [PSCustomObject]@{
                                    Username = $username
                                    Source = "IIS App Pool"
                                    SourceName = $pool.Name
                                    DisplayName = $pool.Name
                                    State = $poolState
                                    Status = $poolState
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            # Silently skip IIS if not available or accessible
            Write-Verbose "IIS Application Pools not available: $($_.Exception.Message)"
        }
    }
    
    return $discoveredAccounts
}

# Get users to check based on discovery mode
try {
    if ($useLocalSystemDiscovery) {
        # Local System Discovery Mode
        $discoveredAccounts = Get-LocalSystemDomainAccounts
        
        # Debug output
        if ($debugMode) {
            Write-Output "<<<local>>>"
            Write-Output "0 'Account Discovery Debug' - Found $($discoveredAccounts.Count) domain accounts in use locally"
            foreach ($acc in $discoveredAccounts) {
                Write-Output "0 'Discovery: $($acc.Username)' - $($acc.Source): $($acc.SourceName) [$($acc.State)]"
            }
        }
        
        $uniqueUsernames = $discoveredAccounts | Select-Object -ExpandProperty Username -Unique
        
        # Query AD for these specific users and check if they're locked
        $lockedUsers = @()
        $allQueriedUsers = @()  # Track all users we checked
        
        foreach ($username in $uniqueUsernames) {
            try {
                $user = Get-ADUser -Identity $username -Properties LastLogonDate, PasswordExpired, LockedOut, UserPrincipalName, Enabled -ErrorAction Stop
                $allQueriedUsers += $user
                
                # Check if user has issues (locked OR disabled if configured)
                $hasIssue = $false
                if ($user.LockedOut) {
                    $hasIssue = $true
                }
                if ($checkDisabledAccounts -and -not $user.Enabled) {
                    $hasIssue = $true
                }
                
                if ($hasIssue) {
                    # Add source information to the user object
                    $user | Add-Member -NotePropertyName "LocalSources" -NotePropertyValue ($discoveredAccounts | Where-Object { $_.Username -eq $username }) -Force
                    $lockedUsers += $user
                }
            } catch {
                if ($debugMode) {
                    Write-Output "0 'AD Query Failed' - Failed to query AD for user '$username': $($_.Exception.Message)"
                }
            }
        }
        
        # Debug: Show what we found
        if ($debugMode -and $allQueriedUsers.Count -gt 0) {
            $issueCount = $lockedUsers.Count
            Write-Output "0 'AD Query Summary' - Queried $($allQueriedUsers.Count) users, found $issueCount with issues (locked or disabled)"
            foreach ($u in $allQueriedUsers) {
                $lockStatus = if ($u.LockedOut) { "LOCKED" } elseif (-not $u.Enabled) { "DISABLED" } else { "OK" }
                Write-Output "0 'User Status: $($u.SamAccountName)' - Status: $lockStatus, Enabled: $($u.Enabled), LockedOut: $($u.LockedOut)"
            }
        }
    } else {
        # Original AD Search Mode
        # Update UserSearchBase with actual domain DN if using OU search
        if ($UserSearchBase -and $UserSearchBase -notmatch "DC=") {
            $UserSearchBase = "$UserSearchBase,$domainDN"
        }
        
        if ($SecurityGroup) {
            # Get users from security group and check if they are locked
            $groupMembers = Get-ADGroupMember -Identity $SecurityGroup -Recursive | Where-Object {$_.objectClass -eq "user"}
            $lockedUsers = @()
            
            foreach ($member in $groupMembers) {
                $user = Get-ADUser -Identity $member.SamAccountName -Properties LastLogonDate, PasswordExpired, LockedOut, UserPrincipalName -ErrorAction SilentlyContinue
                if ($user -and $user.LockedOut -and $user.Enabled) {
                    $lockedUsers += $user
                }
            }
        } elseif ($UserSearchBase) {
            $lockedUsers = Search-ADAccount -LockedOut -SearchBase $UserSearchBase -UsersOnly | 
                Where-Object {$_.Enabled -eq $True} | 
                Get-ADUser -Properties LastLogonDate, PasswordExpired, LockedOut, UserPrincipalName
        } else {
            $lockedUsers = Search-ADAccount -LockedOut -UsersOnly | 
                Where-Object {$_.Enabled -eq $True} | 
                Get-ADUser -Properties LastLogonDate, PasswordExpired, LockedOut, UserPrincipalName
        }
    }
} catch {
    Write-Output "<<<local>>>"
    Write-Output "2 'AD Query Error' - Failed to query Active Directory: $($_.Exception.Message)"
    exit 1
}

# Filter out users in allowlist
$filteredLockedUsers = $lockedUsers | Where-Object { $allowList -notcontains $_.SamAccountName }

# Create log directory if it doesn't exist
$logDir = Split-Path $logFile -Parent
if (!(Test-Path $logDir)) {
    try {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    } catch {
        Write-Warning "Could not create log directory: $logDir"
    }
}

# Read previously locked users from log file
$previouslyLockedUsers = @()
if (Test-Path $logFile) {
    try {
        $logContent = Get-Content $logFile | Where-Object { $_ -match "LOCKED|UNLOCKED" }
        $previouslyLockedUsers = $logContent | ForEach-Object {
            if ($_ -match "User '([^']+)'") { $matches[1] }
        } | Sort-Object -Unique
    } catch {
        Write-Warning "Could not read log file: $logFile"
    }
}

# Get current locked user names (UPN or SamAccountName)
$currentLockedUserNames = @()
foreach ($user in $filteredLockedUsers) {
    $upn = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { $user.SamAccountName }
    $currentLockedUserNames += $upn
}

# Log changes (new locks and unlocks)
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Check for newly locked users
foreach ($userName in $currentLockedUserNames) {
    if ($previouslyLockedUsers -notcontains $userName) {
        try {
            $user = $filteredLockedUsers | Where-Object { 
                $upn = if ($_.UserPrincipalName) { $_.UserPrincipalName } else { $_.SamAccountName }
                $upn -eq $userName 
            }
            
            # Determine the issue type
            $issueType = if ($user.LockedOut) { "LOCKED" } elseif (-not $user.Enabled) { "DISABLED" } else { "ISSUE" }
            $logEntry = "$timestamp [$issueType] User '$userName' - Account is $($issueType.ToLower())"
            
            if ($useLocalSystemDiscovery -and $user.LocalSources) {
                $sources = ($user.LocalSources | ForEach-Object { 
                    "$($_.Source): $($_.SourceName) [$($_.State)]" 
                }) -join ", "
                $logEntry += " | Used by: $sources"
            }
            Add-Content -Path $logFile -Value $logEntry
        } catch {
            Write-Warning "Could not write to log file: $logFile"
        }
    }
}

# Check for newly unlocked users
foreach ($userName in $previouslyLockedUsers) {
    if ($currentLockedUserNames -notcontains $userName) {
        try {
            Add-Content -Path $logFile -Value "$timestamp [RESOLVED] User '$userName' - Account issue resolved (unlocked or re-enabled)"
        } catch {
            Write-Warning "Could not write to log file: $logFile"
        }
    }
}

# Get all users we need to report on (current + previously locked)
$allUsersToCheck = ($currentLockedUserNames + $previouslyLockedUsers) | Sort-Object -Unique

# Generate CheckMK output
Write-Output "<<<local>>>"

# Output discovery mode status only in debug mode
if ($debugMode) {
    if ($useLocalSystemDiscovery) {
        Write-Output "0 'Discovery Mode' - Local System Discovery Mode is ACTIVE"
    } else {
        Write-Output "0 'Discovery Mode' - AD Search Mode is ACTIVE"
    }
}

if ($individualChecks) {
    # Create individual checks for each user (current and previously locked)
    foreach ($userName in $allUsersToCheck) {
        # Find user in current locked users
        $currentUser = $filteredLockedUsers | Where-Object { 
            $upn = if ($_.UserPrincipalName) { $_.UserPrincipalName } else { $_.SamAccountName }
            $upn -eq $userName 
        }
        
        if ($currentUser) {
            # User is currently locked or disabled
            $lastLogon = if ($currentUser.LastLogonDate) { $currentUser.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            $passwordExpired = if ($currentUser.PasswordExpired) { "Yes" } else { "No" }
            
            # Determine status and message based on account state
            $statuscode = 2
            if ($currentUser.LockedOut) {
                $statustext = "User '$userName' is LOCKED OUT | LastLogon: $lastLogon | PasswordExpired: $passwordExpired"
            } elseif (-not $currentUser.Enabled) {
                $statustext = "User '$userName' is DISABLED | LastLogon: $lastLogon | PasswordExpired: $passwordExpired"
            }
            
            # Add local source information if in discovery mode
            if ($useLocalSystemDiscovery -and $currentUser.LocalSources) {
                $sourceDetails = ($currentUser.LocalSources | ForEach-Object { 
                    "$($_.Source): $($_.DisplayName) [$($_.State)]" 
                }) -join ", "
                $statustext += " | Used by: $sourceDetails"
            }
            
            Write-Output "$statuscode 'DomainAccount $userName' last_logon_days_ago=0;password_expired=$([int]$currentUser.PasswordExpired) $statustext"
        } else {
            # User was previously locked/disabled but is now OK
            $statuscode = 0
            $statustext = "User '$userName' is now OK (was previously locked or disabled)"
            
            Write-Output "$statuscode 'DomainAccount $userName' last_logon_days_ago=0;password_expired=0 $statustext"
        }
    }
} else {
    # Original summary approach
    $lockedAccountsString = ""
    foreach ($user in $filteredLockedUsers) {
        $upn = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { $user.SamAccountName }
        $lockedAccountsString += "$upn, "
    }
    
    if ($lockedAccountsString -ne "") {
        # Remove the trailing comma and space
        $lockedAccountsString = $lockedAccountsString.TrimEnd(", ")
    }
    
    # Count the number of locked accounts
    $lockedAccountsCount = $filteredLockedUsers.Count
    
    if ($lockedAccountsCount -eq 0) {
        $statuscode = 0
        $statustext = "There are no locked or disabled accounts present in Active Directory."
    } else {
        if ($lockedAccountsCount -gt $crit) {
            $statuscode = 2
        } elseif ($lockedAccountsCount -gt $warn) {
            $statuscode = 1
        } else {
            $statuscode = 0
        }
        $statustext = "There are currently $lockedAccountsCount domain accounts with issues: $lockedAccountsString"
    }
    
    Write-Output "$statuscode DomainAccounts account_issues=$lockedAccountsCount $statustext"
}
