enum Ensure {
    Absent
    Present
}

function Get-SafeMember {
    param (
        [String]$SafeName,
        [String]$MemberName,

        [String]$PvwaUrl,
        [String]$AuthenticationType,
        [pscredential]$Credential,
        [bool] $SkipCertificateCheck
    )

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $CurrentState = [CYA_SafeMember]::new()

    try {
        $ResourceExists = Get-PASSafeMember -SafeName $SafeName -MemberName $MemberName -ErrorAction SilentlyContinue

        $CurrentState.Ensure = [Ensure]::Present
        $CurrentState.SafeName = $ResourceExists.SafeName
        $CurrentState.MemberName = $ResourceExists.UserName
        $CurrentState.UseAccounts = $ResourceExists.Permissions.useAccounts
        $CurrentState.RetrieveAccounts = $ResourceExists.Permissions.retrieveAccounts
        $CurrentState.ListAccounts = $ResourceExists.Permissions.listAccounts
        $CurrentState.AddAccounts = $ResourceExists.Permissions.addAccounts
        $CurrentState.UpdateAccountContent = $ResourceExists.Permissions.updateAccountContent
        $CurrentState.UpdateAccountProperties = $ResourceExists.Permissions.updateAccountProperties
        $CurrentState.InitiateCPMAccountManagementOperations = $ResourceExists.Permissions.initiateCPMAccountManagementOperations
        $CurrentState.SpecifyNextAccountContent = $ResourceExists.Permissions.specifyNextAccountContent
        $CurrentState.RenameAccounts = $ResourceExists.Permissions.renameAccounts
        $CurrentState.DeleteAccounts = $ResourceExists.Permissions.deleteAccounts
        $CurrentState.UnlockAccounts = $ResourceExists.Permissions.unlockAccounts
        $CurrentState.ManageSafe = $ResourceExists.Permissions.manageSafe
        $CurrentState.ManageSafeMembers = $ResourceExists.Permissions.manageSafeMembers
        $CurrentState.BackupSafe = $ResourceExists.Permissions.backupSafe
        $CurrentState.ViewAuditLog = $ResourceExists.Permissions.viewAuditLog
        $CurrentState.ViewSafeMembers = $ResourceExists.Permissions.viewSafeMembers
        $CurrentState.AccessWithoutConfirmation = $ResourceExists.Permissions.accessWithoutConfirmation
        $CurrentState.CreateFolders = $ResourceExists.Permissions.createFolders
        $CurrentState.DeleteFolders = $ResourceExists.Permissions.deleteFolders
        $CurrentState.MoveAccountsandFolders = $ResourceExists.Permissions.moveAccountsandFolders
        $CurrentState.RequestsAuthorizationLevel1 = $ResourceExists.Permissions.requestsAuthorizationLevel1
        $CurrentState.RequestsAuthorizationLevel2 = $ResourceExists.Permissions.requestsAuthorizationLevel2
    } catch {
        $CurrentState.Ensure = [Ensure]::Absent
    }

    return $CurrentState
}

function Set-SafeMember {
    param (
        [Ensure]$Ensure,

        [string]$SafeName,

        [string]$MemberName,

        [string]$SearchIn,

        [datetime]$MembershipExpirationDate,

        [boolean]$UseAccounts,

        [boolean]$RetrieveAccounts,

        [boolean]$ListAccounts,

        [boolean]$AddAccounts,

        [boolean]$UpdateAccountContent,

        [boolean]$UpdateAccountProperties,

        [boolean]$InitiateCPMAccountManagementOperations,

        [boolean]$SpecifyNextAccountContent,

        [boolean]$RenameAccounts,

        [boolean]$DeleteAccounts,

        [boolean]$UnlockAccounts,

        [boolean]$ManageSafe,

        [boolean]$ManageSafeMembers,

        [boolean]$BackupSafe,

        [boolean]$ViewAuditLog,

        [boolean]$ViewSafeMembers,

        [boolean]$requestsAuthorizationLevel1,

        [boolean]$requestsAuthorizationLevel2,

        [boolean]$AccessWithoutConfirmation,

        [boolean]$CreateFolders,

        [boolean]$DeleteFolders,

        [boolean]$MoveAccountsAndFolders,

        [parameter(Mandatory = $true)]
        [String] $PvwaUrl,

        [parameter(Mandatory = $true)]
        [String] $AuthenticationType,

        [parameter(Mandatory = $true)]
        [pscredential] $Credential,

        [bool] $SkipCertificateCheck
    )

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $TestSafeMemberParameters = @{
        Ensure                                 = $Ensure

        SafeName                               = $SafeName
        MemberName                             = $MemberName
        UseAccounts                            = $UseAccounts
        RetrieveAccounts                       = $RetrieveAccounts
        ListAccounts                           = $ListAccounts
        AddAccounts                            = $AddAccounts
        UpdateAccountContent                   = $UpdateAccountContent
        UpdateAccountProperties                = $UpdateAccountProperties
        InitiateCPMAccountManagementOperations = $InitiateCPMAccountManagementOperations
        SpecifyNextAccountContent              = $SpecifyNextAccountContent
        RenameAccounts                         = $RenameAccounts
        DeleteAccounts                         = $DeleteAccounts
        UnlockAccounts                         = $UnlockAccounts
        ManageSafe                             = $ManageSafe
        ManageSafeMembers                      = $ManageSafeMembers
        BackupSafe                             = $BackupSafe
        ViewAuditLog                           = $ViewAuditLog
        ViewSafeMembers                        = $ViewSafeMembers
        requestsAuthorizationLevel1            = $requestsAuthorizationLevel1
        requestsAuthorizationLevel2            = $requestsAuthorizationLevel2
        AccessWithoutConfirmation              = $AccessWithoutConfirmation
        CreateFolders                          = $CreateFolders
        DeleteFolders                          = $DeleteFolders
        MoveAccountsAndFolders                 = $MoveAccountsAndFolders

        PvwaUrl                                = $PvwaUrl
        AuthenticationType                     = $AuthenticationType
        Credential                             = $Credential
        SkipCertificateCheck                   = $SkipCertificateCheck
    }

    if ($MembershipExpirationDate) {
        $TestSafeMemberParameters.Add('MembershipExpirationDate', $MembershipExpirationDate)
    }

    $DesiredState = Test-SafeMember @TestSafeMemberParameters

    if ($DesiredState -eq $false) {

        if ($Ensure -eq [Ensure]::Present) {
            Add-PASSafeMember -SafeName $SafeName -MemberName $MemberName -UseAccounts $UseAccounts -RetrieveAccounts $RetrieveAccounts -ListAccounts $ListAccounts -AddAccounts $AddAccounts -UpdateAccountContent $UpdateAccountContent -UpdateAccountProperties $UpdateAccountProperties -InitiateCPMAccountManagementOperations $InitiateCPMAccountManagementOperations -SpecifyNextAccountContent $SpecifyNextAccountContent -RenameAccounts $RenameAccounts -DeleteAccounts $DeleteAccounts -UnlockAccounts $UnlockAccounts -ManageSafe $ManageSafe -ManageSafeMembers $ManageSafeMembers -BackupSafe $BackupSafe -ViewAuditLog $ViewAuditLog -ViewSafeMembers $ViewSafeMembers -requestsAuthorizationLevel1 $requestsAuthorizationLevel1 -requestsAuthorizationLevel2 $requestsAuthorizationLevel2 -AccessWithoutConfirmation $AccessWithoutConfirmation -CreateFolders $CreateFolders -DeleteFolders $DeleteFolders -MoveAccountsAndFolders $MoveAccountsAndFolders
        }

        if ($Ensure -eq [Ensure]::Absent) {
            Get-PASSafeMember -SafeName $SafeName -MemberName $MemberName | Remove-PASSafeMember
        }

    }
}


function Test-SafeMember {
    param (
        [Ensure]$Ensure,

        [string]$SafeName,

        [string]$MemberName,

        [datetime]$MembershipExpirationDate,

        [boolean]$UseAccounts,

        [boolean]$RetrieveAccounts,

        [boolean]$ListAccounts,

        [boolean]$AddAccounts,

        [boolean]$UpdateAccountContent,

        [boolean]$UpdateAccountProperties,

        [boolean]$InitiateCPMAccountManagementOperations,

        [boolean]$SpecifyNextAccountContent,

        [boolean]$RenameAccounts,

        [boolean]$DeleteAccounts,

        [boolean]$UnlockAccounts,

        [boolean]$ManageSafe,

        [boolean]$ManageSafeMembers,

        [boolean]$BackupSafe,

        [boolean]$ViewAuditLog,

        [boolean]$ViewSafeMembers,

        [boolean]$requestsAuthorizationLevel1,

        [boolean]$requestsAuthorizationLevel2,

        [boolean]$AccessWithoutConfirmation,

        [boolean]$CreateFolders,

        [boolean]$DeleteFolders,

        [boolean]$MoveAccountsAndFolders,

        [parameter(Mandatory = $true)]
        [String] $PvwaUrl,

        [parameter(Mandatory = $true)]
        [String] $AuthenticationType,

        [parameter(Mandatory = $true)]
        [pscredential] $Credential,

        [bool] $SkipCertificateCheck
    )

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $DesiredState = $false

    try {
        $ResourceExists = Get-PASSafeMember -SafeName $SafeName -MemberName $MemberName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Permissions | Where-Object { $_.UseAccounts -eq $UseAccounts -and $_.RetrieveAccounts -eq $RetrieveAccounts -and $_.ListAccounts -eq $ListAccounts -and $_.AddAccounts -eq $AddAccounts -and $_.UpdateAccountContent -eq $UpdateAccountContent -and $_.UpdateAccountProperties -eq $UpdateAccountProperties -and $_.InitiateCPMAccountManagementOperations -eq $InitiateCPMAccountManagementOperations -and $_.SpecifyNextAccountContent -eq $SpecifyNextAccountContent -and $_.RenameAccounts -eq $RenameAccounts -and $_.DeleteAccounts -eq $DeleteAccounts -and $_.UnlockAccounts -eq $UnlockAccounts -and $_.ManageSafe -eq $ManageSafe -and $_.ManageSafeMembers -eq $ManageSafeMembers -and $_.BackupSafe -eq $BackupSafe -and $_.ViewAuditLog -eq $ViewAuditLog -and $_.ViewSafeMembers -eq $ViewSafeMembers -and $_.requestsAuthorizationLevel1 -eq $requestsAuthorizationLevel1 -and $_.requestsAuthorizationLevel2 -eq $requestsAuthorizationLevel2 -and $_.AccessWithoutConfirmation -eq $AccessWithoutConfirmation -and $_.CreateFolders -eq $CreateFolders -and $_.DeleteFolders -eq $DeleteFolders -and $_.MoveAccountsAndFolders -eq $MoveAccountsAndFolders }
    } catch {
        $ResourceExists = $null
    }

    if ($Ensure -eq [Ensure]::Present -and $null -ne $ResourceExists) {
        $DesiredState = $true
    }

    if ($Ensure -eq [Ensure]::Absent -and $null -eq $ResourceExists) {
        $DesiredState = $true
    }

    $DesiredState
}

[DscResource()]
class CYA_SafeMember {
    [DscProperty(Mandatory)]
    [Ensure]$Ensure

    [DscProperty(Key)]
    [string]$SafeName

    [DscProperty(Key)]
    [string]$MemberName

    [DscProperty()]
    [String]$SearchIn = $null

    [DscProperty()]
    [datetime]$MembershipExpirationDate

    [DscProperty()]
    [boolean]$UseAccounts = $false

    [DscProperty()]
    [boolean]$RetrieveAccounts = $false

    [DscProperty()]
    [boolean]$ListAccounts = $false

    [DscProperty()]
    [boolean]$AddAccounts = $false

    [DscProperty()]
    [boolean]$UpdateAccountContent = $false

    [DscProperty()]
    [boolean]$UpdateAccountProperties = $false

    [DscProperty()]
    [boolean]$InitiateCPMAccountManagementOperations = $false

    [DscProperty()]
    [boolean]$SpecifyNextAccountContent = $false

    [DscProperty()]
    [boolean]$RenameAccounts = $false

    [DscProperty()]
    [boolean]$DeleteAccounts = $false

    [DscProperty()]
    [boolean]$UnlockAccounts = $false

    [DscProperty()]
    [boolean]$ManageSafe = $false

    [DscProperty()]
    [boolean]$ManageSafeMembers = $false

    [DscProperty()]
    [boolean]$BackupSafe = $false

    [DscProperty()]
    [boolean]$ViewAuditLog = $false

    [DscProperty()]
    [boolean]$ViewSafeMembers = $false

    [DscProperty()]
    [boolean]$requestsAuthorizationLevel1 = $false

    [DscProperty()]
    [boolean]$requestsAuthorizationLevel2 = $false

    [DscProperty()]
    [boolean]$AccessWithoutConfirmation = $false

    [DscProperty()]
    [boolean]$CreateFolders = $false

    [DscProperty()]
    [boolean]$DeleteFolders = $false

    [DscProperty()]
    [boolean]$MoveAccountsAndFolders = $false

    [DscProperty(Mandatory)]
    [string]$PvwaUrl

    [DscProperty(Mandatory)]
    [string]$AuthenticationType

    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty()]
    [bool]$SkipCertificateCheck

    [CYA_SafeMember] Get() {
        $Get = Get-SafeMember -SafeName $this.SafeName -MemberName $this.MemberName -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck $this.SkipCertificateCheck
        return $Get
    }

    [void] Set() {
        $SetSafeMemberParameters = @{
            Ensure                                 = $this.Ensure

            SafeName                               = $this.SafeName
            MemberName                             = $this.MemberName
            UseAccounts                            = $this.UseAccounts
            RetrieveAccounts                       = $this.RetrieveAccounts
            ListAccounts                           = $this.ListAccounts
            AddAccounts                            = $this.AddAccounts
            UpdateAccountContent                   = $this.UpdateAccountContent
            UpdateAccountProperties                = $this.UpdateAccountProperties
            InitiateCPMAccountManagementOperations = $this.InitiateCPMAccountManagementOperations
            SpecifyNextAccountContent              = $this.SpecifyNextAccountContent
            RenameAccounts                         = $this.RenameAccounts
            DeleteAccounts                         = $this.DeleteAccounts
            UnlockAccounts                         = $this.UnlockAccounts
            ManageSafe                             = $this.ManageSafe
            ManageSafeMembers                      = $this.ManageSafeMembers
            BackupSafe                             = $this.BackupSafe
            ViewAuditLog                           = $this.ViewAuditLog
            ViewSafeMembers                        = $this.ViewSafeMembers
            requestsAuthorizationLevel1            = $this.requestsAuthorizationLevel1
            requestsAuthorizationLevel2            = $this.requestsAuthorizationLevel2
            AccessWithoutConfirmation              = $this.AccessWithoutConfirmation
            CreateFolders                          = $this.CreateFolders
            DeleteFolders                          = $this.DeleteFolders
            MoveAccountsAndFolders                 = $this.MoveAccountsAndFolders

            PvwaUrl                                = $this.PvwaUrl
            AuthenticationType                     = $this.AuthenticationType
            Credential                             = $this.Credential
            SkipCertificateCheck                   = $this.SkipCertificateCheck
        }

        if ($this.MembershipExpirationDate) {
            $SetSafeMemberParameters.Add('MembershipExpirationDate', $this.MembershipExpirationDate)
        }
        if ($this.SearchIn) {
            $SetSafeMemberParameters.Add('SearchIn', $this.SearchIn)
        }

        Set-SafeMember @SetSafeMemberParameters
    }

    [bool] Test() {
        $TestSafeMemberParameters = @{
            Ensure                                 = $this.Ensure

            SafeName                               = $this.SafeName
            MemberName                             = $this.MemberName
            UseAccounts                            = $this.UseAccounts
            RetrieveAccounts                       = $this.RetrieveAccounts
            ListAccounts                           = $this.ListAccounts
            AddAccounts                            = $this.AddAccounts
            UpdateAccountContent                   = $this.UpdateAccountContent
            UpdateAccountProperties                = $this.UpdateAccountProperties
            InitiateCPMAccountManagementOperations = $this.InitiateCPMAccountManagementOperations
            SpecifyNextAccountContent              = $this.SpecifyNextAccountContent
            RenameAccounts                         = $this.RenameAccounts
            DeleteAccounts                         = $this.DeleteAccounts
            UnlockAccounts                         = $this.UnlockAccounts
            ManageSafe                             = $this.ManageSafe
            ManageSafeMembers                      = $this.ManageSafeMembers
            BackupSafe                             = $this.BackupSafe
            ViewAuditLog                           = $this.ViewAuditLog
            ViewSafeMembers                        = $this.ViewSafeMembers
            requestsAuthorizationLevel1            = $this.requestsAuthorizationLevel1
            requestsAuthorizationLevel2            = $this.requestsAuthorizationLevel2
            AccessWithoutConfirmation              = $this.AccessWithoutConfirmation
            CreateFolders                          = $this.CreateFolders
            DeleteFolders                          = $this.DeleteFolders
            MoveAccountsAndFolders                 = $this.MoveAccountsAndFolders

            PvwaUrl                                = $this.PvwaUrl
            AuthenticationType                     = $this.AuthenticationType
            Credential                             = $this.Credential
            SkipCertificateCheck                   = $this.SkipCertificateCheck
        }

        if ($this.MembershipExpirationDate) {
            $TestSafeMemberParameters.Add('MembershipExpirationDate', $this.MembershipExpirationDate)
        }

        $Test = Test-SafeMember @TestSafeMemberParameters
        return $Test
    }
}