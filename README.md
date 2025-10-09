# CheckMK Local Check: Domain Account Monitoring

A PowerShell-based CheckMK local check script that monitors Active Directory domain accounts for locked and disabled status, with optional local system discovery to identify where accounts are being used.

## 🎯 Features

- **Dual Operation Modes**
  - **Local System Discovery Mode**: Scans local system for domain accounts used in Windows Services, Scheduled Tasks, and IIS Application Pools
  - **AD Search Mode**: Traditional OU or Security Group-based monitoring
  
- **Comprehensive Account Monitoring**
  - Detects locked accounts
  - Detects disabled accounts
  - Tracks LastLogonDate and PasswordExpired status
  - Historical tracking with automatic OK status for resolved issues

- **Context-Aware Reporting**
  - Shows where accounts are used (Service names, Task names, App Pool names)
  - Displays service/task/pool state (Running, Stopped, Disabled, etc.)
  - Multi-usage support: One account used in multiple places = single consolidated check

- **Flexible Check Modes**
  - Individual checks per account
  - Summary check with aggregated statistics
  - Configurable warning and critical thresholds

## 📋 Prerequisites

- **PowerShell ActiveDirectory Module**
  - Windows Server: `Install-WindowsFeature -Name RSAT-AD-PowerShell`
  - Windows Client: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`

- **CheckMK Agent** installed and configured

- **Permissions**: Account running the script must have read access to Active Directory

- **Optional**: WebAdministration module for IIS Application Pool monitoring

## 🚀 Installation

1. Copy the script to your CheckMK agent's local directory:
   ```
   C:\ProgramData\checkmk\agent\local\check_domain_accounts.ps1
   ```

2. Ensure the script has `.ps1` extension for PowerShell execution

3. Configure the variables in the script (see Configuration section)

4. Test the script manually:
   ```powershell
   C:\ProgramData\checkmk\agent\local\check_domain_accounts.ps1
   ```

5. Discover services in CheckMK

## ⚙️ Configuration

Edit the configuration section in the script:

### Basic Settings

```powershell
# CheckMK Version
$CMK_VERSION = "2.4.0p12"

# Discovery Mode
$useLocalSystemDiscovery = $true  # true = local scan, false = AD search

# Allowlist (accounts to exclude)
$allowList = @("")
```

### Local System Discovery Mode

```powershell
$checkWindowsServices = $true    # Scan Windows Services
$checkScheduledTasks = $true     # Scan Scheduled Tasks
$checkIISAppPools = $true        # Scan IIS Application Pools
$checkDisabledAccounts = $true   # Monitor disabled accounts
$debugMode = $false              # Enable debug output
```

### AD Search Mode

```powershell
# Option 1: Search in specific OU
$UserSearchBase = "OU=Service Accounts"

# Option 2: Search in Security Group
$SecurityGroup = "MonitoredAccounts"

# Option 3: Leave both empty for domain-wide search
```

### Check Behavior

```powershell
$warn = 2                        # Warning threshold (summary mode)
$crit = 5                        # Critical threshold (summary mode)
$individualChecks = $true        # true = per-account checks, false = summary
```

## 📊 Output Examples

### Local Discovery Mode - Individual Check

```
CRIT - DomainAccount svc_account@domain.com
User 'svc_account@domain.com' is DISABLED
LastLogon: 2025-08-13 13:33:06
PasswordExpired: No
Used by: Windows Service: SQL Server Agent (Instance) [Stopped]
```

### Multiple Usage Example

```
CRIT - DomainAccount svc_backup@domain.com
User 'svc_backup@domain.com' is LOCKED OUT
LastLogon: 2025-10-09 10:15:30
PasswordExpired: No
Used by: Windows Service: BackupService [Running], 
         Windows Service: BackupScheduler [Stopped], 
         Scheduled Task: \Backup\DailyBackup [Ready]
```

### Summary Mode

```
WARN - DomainAccounts
There are currently 2 domain accounts with issues: 
svc_backup@domain.com, svc_reports@domain.com
```

### Resolved Account

```
OK - DomainAccount svc_test@domain.com
User 'svc_test@domain.com' is now OK (was previously locked or disabled)
```

## 📝 Logging

The script maintains a detailed log file at:
```
C:\ProgramData\checkmk\agent\log\domain_account_monitoring.log
```

### Log Entry Examples

```
2025-10-09 14:30:15 [LOCKED] User 'svc_backup@domain.com' - Account is locked | Used by: Windows Service: BackupService [Running]
2025-10-09 15:45:22 [DISABLED] User 'svc_reports@domain.com' - Account is disabled | Used by: Scheduled Task: \Reports\DailyReport [Ready]
2025-10-09 16:10:33 [RESOLVED] User 'svc_backup@domain.com' - Account issue resolved (unlocked or re-enabled)
```

## 🔍 Troubleshooting

### Enable Debug Mode

Set `$debugMode = $true` in the configuration section to see detailed discovery information:

```powershell
$debugMode = $true
```

This will show:
- Number of accounts discovered
- Each discovered account with source and state
- AD query results
- Lock/Disable status for each account

### Common Issues

**Issue**: "ActiveDirectory PowerShell module is not installed"
- **Solution**: Install RSAT-AD-PowerShell (see Prerequisites)

**Issue**: No accounts discovered in Local Discovery Mode
- **Check**: Are there Windows Services/Tasks using domain accounts?
- **Check**: Are the accounts from the correct domain?
- **Enable**: Debug mode to see what's being scanned

**Issue**: "Cannot find drive IIS"
- **Info**: This is normal if IIS is not installed
- **Action**: The script will skip IIS scanning automatically

## 🔄 Operation Modes Comparison

| Feature | Local Discovery Mode | AD Search Mode |
|---------|---------------------|----------------|
| **Scope** | Accounts used locally | Accounts in OU/Group |
| **Context** | Shows where account is used | No usage context |
| **Best For** | Server monitoring | Central account management |
| **Discovery** | Automatic | Manual configuration |
| **Coverage** | Only local usage | All accounts in scope |

## 📦 Version History

### Version 3.2 (2025-10-09)
- Changed service name from "LockedUser" to "DomainAccount"
- Updated all descriptions and documentation
- Renamed log file to domain_account_monitoring.log

### Version 3.1 (2025-10-09)
- Added disabled account monitoring
- Enhanced status differentiation (LOCKED vs DISABLED)
- Added CMK_VERSION tracking

### Version 3.0 (2025-10-09)
- Added Local System Discovery Mode
- Windows Services scanning
- Scheduled Tasks scanning
- IIS Application Pools scanning
- Context-aware reporting

### Version 2.9 (2025-09-17)
- Professional code structure
- Module validation
- Enhanced error handling

### Version 2.0 (2025-09-17)
- Individual check mode
- UPN support
- Event logging
- OK status for resolved accounts

### Version 1.0 (2025-09-17)
- Initial release
- Basic locked account detection
- OU and Security Group support

## 👨‍💻 Author

**FELLNER Mario (mario.fellner@outlook.at)**

## 📄 License

This script is provided as-is for use with CheckMK monitoring systems.

## 🤝 Contributing

Feedback and contributions are welcome! Please ensure any modifications maintain compatibility with CheckMK local check format.

## ⚠️ Important Notes

- The script requires domain access to query account status
- Local System Discovery Mode requires RSAT-AD-PowerShell even when scanning locally
- Service names remain constant even when account status changes (by design)
- Historical tracking ensures accounts don't disappear from monitoring when resolved
- One account used in multiple services/tasks = one consolidated CheckMK service

## 🔗 Related Documentation

- [CheckMK Local Checks Documentation](https://docs.checkmk.com/latest/en/localchecks.html)
- [Active Directory PowerShell Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/)
- [CheckMK Agent Windows](https://docs.checkmk.com/latest/en/agent_windows.html)
