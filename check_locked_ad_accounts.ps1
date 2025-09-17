# ================================================================================
# CheckMK Local Check Script: Locked User Monitoring
# ================================================================================
#
# Purpose:     Monitors locked user accounts in Active Directory and reports them
#              to CheckMK as individual services or summary check
#
# Author:      FELLNER Mario
# Created:     2025-09-17
# Version:     1.0
#
# Description: This script searches for locked user accounts in Active Directory
#              and creates CheckMK local checks. It supports both individual checks
#              per locked user and a summary check. The script tracks lock/unlock
#              events in a log file and ensures unlocked users get OK status.
#
# Installation: Copy this script to C:\ProgramData\checkmk\agent\local\
#              and ensure it has .ps1 extension for PowerShell execution
#
# ================================================================================
# PREREQUISITES
# ================================================================================
#
# - PowerShell ActiveDirectory module must be installed
# - Script must run with sufficient AD permissions to query user accounts
# - CheckMK agent must be installed and configured
# - Write permissions to C:\ProgramData\checkmk\agent\log directory
#
# Installation of AD module (if not present):
# Windows Server: Install-WindowsFeature -Name RSAT-AD-PowerShell
# Windows Client: Install RSAT tools from Microsoft
#
# ================================================================================
# CONFIGURATION VARIABLES - MODIFY AS NEEDED
# ================================================================================

# Allowlist: Users to exclude from monitoring (even if locked)
$allowList = @("")

# Search scope: Choose ONE of the following options (leave others empty):
# Option 1: Search in specific OU (will be automatically updated with current domain)
$UserSearchBase = "OU=Service Accounts"  # Domain DN will be added automatically
# Option 2: Search members of a security group
$SecurityGroup = ""  # Example: "CN=MonitoredUsers,OU=Groups" or just "MonitoredUsers"
# Option 3: Leave both empty to search entire Active Directory

# Thresholds for summary mode (ignored in individual mode)
$warn = 2    # Warning threshold: number of locked accounts
$crit = 5    # Critical threshold: number of locked accounts

# Check mode: Individual checks per user vs single summary check
$individualChecks = $true  # $true = individual checks per user, $false = single summary check

# Log file for tracking lock/unlock events
$logFile = "C:\ProgramData\checkmk\agent\log\locked_users_history.log"

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
} catch {
    Write-Output "<<<local>>>"
    Write-Output "2 'AD Domain Access' - Failed to get current domain information: $($_.Exception.Message)"
    exit 1
}

# Update UserSearchBase with actual domain DN if using OU search
if ($UserSearchBase -and $UserSearchBase -notmatch "DC=") {
    $UserSearchBase = "$UserSearchBase,$domainDN"
}

# Get locked users with additional properties
try {
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
            Add-Content -Path $logFile -Value "$timestamp [LOCKED] User '$userName' was locked out"
        } catch {
            Write-Warning "Could not write to log file: $logFile"
        }
    }
}

# Check for newly unlocked users
foreach ($userName in $previouslyLockedUsers) {
    if ($currentLockedUserNames -notcontains $userName) {
        try {
            Add-Content -Path $logFile -Value "$timestamp [UNLOCKED] User '$userName' was unlocked"
        } catch {
            Write-Warning "Could not write to log file: $logFile"
        }
    }
}

# Get all users we need to report on (current + previously locked)
$allUsersToCheck = ($currentLockedUserNames + $previouslyLockedUsers) | Sort-Object -Unique

# Generate CheckMK output
Write-Output "<<<local>>>"

if ($individualChecks) {
    # Create individual checks for each user (current and previously locked)
    foreach ($userName in $allUsersToCheck) {
        # Find user in current locked users
        $currentUser = $filteredLockedUsers | Where-Object { 
            $upn = if ($_.UserPrincipalName) { $_.UserPrincipalName } else { $_.SamAccountName }
            $upn -eq $userName 
        }
        
        if ($currentUser) {
            # User is currently locked
            $lastLogon = if ($currentUser.LastLogonDate) { $currentUser.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            $passwordExpired = if ($currentUser.PasswordExpired) { "Yes" } else { "No" }
            
            $statuscode = 2
            $statustext = "User '$userName' is locked out | LastLogon: $lastLogon | PasswordExpired: $passwordExpired"
            
            Write-Output "$statuscode 'LockedUser $userName' last_logon_days_ago=0;password_expired=$([int]$currentUser.PasswordExpired) $statustext"
        } else {
            # User was previously locked but is now unlocked
            $statuscode = 0
            $statustext = "User '$userName' was unlocked (previously locked)"
            
            Write-Output "$statuscode 'LockedUser $userName' last_logon_days_ago=0;password_expired=0 $statustext"
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
        $statustext = "There are no locked accounts present in Active Directory."
    } else {
        if ($lockedAccountsCount -gt $crit) {
            $statuscode = 2
        } elseif ($lockedAccountsCount -gt $warn) {
            $statuscode = 1
        } else {
            $statuscode = 0
        }
        $statustext = "There are currently $lockedAccountsCount locked accounts: $lockedAccountsString"
    }
    
    Write-Output "$statuscode LockedUsers locked_count=$lockedAccountsCount $statustext"
}
