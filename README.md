# check_locked_ad_accounts
Monitors locked user accounts in Active Directory and reports them to CheckMK as individual services or summary check

This script searches for locked user accounts in Active Directory and creates CheckMK local checks. It supports both individual checks per locked user and a summary check. The script tracks lock/unlock events in a log file and ensures unlocked users get OK status.
