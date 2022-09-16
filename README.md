# CyberArkDsc

A [PowerShell DSC](https://docs.microsoft.com/en-us/powershell/dsc/overview?view=dsc-1.1) module for CyberArk's [Privileged Access Manager](https://www.cyberark.com/products/privileged-access-manager/) objects (Accounts, Safes, Platforms, etc.).

It currently contains the following resources:

- CYA_Account
- CYA_Safe
- CYA_SafeMember

## Installation

Ensure the [psPAS](https://github.com/pspete/psPAS) module and the `CyberArkDsc` folder is in a location listed under `$env:PSModulePath` that the `SYSTEM` account can access. Example: `C:\Program Files\WindowsPowerShell\Modules\`

## Resources

### CYA_Account

```powershell
CYA_Account [String] #ResourceName
{
    Address = [string]
    AuthenticationType = [string]
    Credential = [PSCredential]
    Ensure = [string]{ Absent | Present }
    PlatformId = [string]
    PvwaUrl = [string]
    SafeName = [string]
    SkipCertificateCheck = [bool]
    UserName = [string]
    [DependsOn = [string[]]]
    [LogonAccount = [HashTable]]
    [Name = [string]]
    [Password = [PSCredential]]
    [PsDscRunAsCredential = [PSCredential]]
    [ReconcileAccount = [HashTable]]
}
```

### CYA_Safe

```powershell
CYA_Safe [String] #ResourceName
{
    AuthenticationType = [string]
    Credential = [PSCredential]
    Ensure = [string]{ Absent | Present }
    PvwaUrl = [string]
    SafeName = [string]
    [DependsOn = [string[]]]
    [Description = [string]]
    [ManagingCPM = [string]]
    [NumberOfDaysRetention = [string]]
    [NumberOfVersionsRetention = [string]]
    [PsDscRunAsCredential = [PSCredential]]
    [SkipCertificateCheck = [bool]]
}
```

### CYA_SafeMember

```powershell
CYA_SafeMember [String] #ResourceName
{
    AuthenticationType = [string]
    Credential = [PSCredential]
    Ensure = [string]{ Absent | Present }
    MemberName = [string]
    PvwaUrl = [string]
    SafeName = [string]
    SearchIn = [string]
    [AccessWithoutConfirmation = [bool]]
    [AddAccounts = [bool]]
    [BackupSafe = [bool]]
    [CreateFolders = [bool]]
    [DeleteAccounts = [bool]]
    [DeleteFolders = [bool]]
    [DependsOn = [string[]]]
    [InitiateCPMAccountManagementOperations = [bool]]
    [ListAccounts = [bool]]
    [ManageSafe = [bool]]
    [ManageSafeMembers = [bool]]
    [MembershipExpirationDate = [DateTime]]
    [MoveAccountsAndFolders = [bool]]
    [PsDscRunAsCredential = [PSCredential]]
    [RenameAccounts = [bool]]
    [requestsAuthorizationLevel1 = [bool]]
    [requestsAuthorizationLevel2 = [bool]]
    [RetrieveAccounts = [bool]]
    [SkipCertificateCheck = [bool]]
    [SpecifyNextAccountContent = [bool]]
    [UnlockAccounts = [bool]]
    [UpdateAccountContent = [bool]]
    [UpdateAccountProperties = [bool]]
    [UseAccounts = [bool]]
    [ViewAuditLog = [bool]]
    [ViewSafeMembers = [bool]]
}
```
