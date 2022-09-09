enum Ensure {
    Absent
    Present
}



function Get-SafeMember {
    param (
        [Ensure]$Ensure,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$SafeName,

        [String]$MemberName,

        [parameter(Mandatory = $true)]
        [String] $PvwaUrl,

        [parameter(Mandatory = $true)]
        [String] $AuthenticationType,

        [parameter(Mandatory = $true)]
        [pscredential] $Credential,

        [bool] $SkipCertificateCheck
    )

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    try {
        $ResourceExists = Get-PASSafeMember -SafeName $SafeName -MemberName $MemberName -ErrorAction SilentlyContinue
        $EnsureReturn = [Ensure]::Present
    } catch {
        $EnsureReturn = [Ensure]::Absent
    } finally {

        @{
            Ensure                                 = $EnsureReturn
            SafeName                               = $ResourceExists.SafeName
            MemberName                             = $ResourceExists.UserName
            UseAccounts                            = $ResourceExists.Permissions.useAccounts
            RetrieveAccounts                       = $ResourceExists.Permissions.retrieveAccounts
            ListAccounts                           = $ResourceExists.Permissions.listAccounts
            AddAccounts                            = $ResourceExists.Permissions.addAccounts
            UpdateAccountContent                   = $ResourceExists.Permissions.updateAccountContent
            UpdateAccountProperties                = $ResourceExists.Permissions.updateAccountProperties
            InitiateCPMAccountManagementOperations = $ResourceExists.Permissions.initiateCPMAccountManagementOperations
            SpecifyNextAccountContent              = $ResourceExists.Permissions.specifyNextAccountContent
            RenameAccounts                         = $ResourceExists.Permissions.renameAccounts
            DeleteAccounts                         = $ResourceExists.Permissions.deleteAccounts
            UnlockAccounts                         = $ResourceExists.Permissions.unlockAccounts
            ManageSafe                             = $ResourceExists.Permissions.manageSafe
            ManageSafeMembers                      = $ResourceExists.Permissions.manageSafeMembers
            BackupSafe                             = $ResourceExists.Permissions.backupSafe
            ViewAuditLog                           = $ResourceExists.Permissions.viewAuditLog
            ViewSafeMembers                        = $ResourceExists.Permissions.viewSafeMembers
            AccessWithoutConfirmation              = $ResourceExists.Permissions.accessWithoutConfirmation
            CreateFolders                          = $ResourceExists.Permissions.createFolders
            DeleteFolders                          = $ResourceExists.Permissions.deleteFolders
            MoveAccountsandFolders                 = $ResourceExists.Permissions.moveAccountsandFolders
            RequestsAuthorizationLevel1            = $ResourceExists.Permissions.requestsAuthorizationLevel1
            RequestsAuthorizationLevel2            = $ResourceExists.Permissions.requestsAuthorizationLevel2
        }
    }

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
        $Get = Get-SafeMember -Ensure $this.Ensure -SafeName $this.SafeName -MemberName $this.MemberName -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck $this.SkipCertificateCheck
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