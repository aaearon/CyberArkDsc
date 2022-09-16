enum Ensure {
    Absent
    Present
}

function Get-LinkedAccounts {
    param(
        $AccountId
    )

    $PASSession = Get-PASSession

    Add-Type @'
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
'@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    $RestRequest = @{
        Method      = 'Get'
        Uri         = "$($PASSession.BaseUri)/api/ExtendedAccounts/$AccountId/LinkedAccounts"
        WebSession  = $PASSession.WebSession
        ContentType = 'application/json'
    }

    $Accounts = @()

    $Response = Invoke-RestMethod @RestRequest | Select-Object -ExpandProperty LinkedAccounts

    foreach ($LinkedAccount in $Response) {
        if (-not [string]::isNullOrEmpty($LinkedAccount.Descriptor)) {
            $LinkedAccountUserName = $LinkedAccount.Descriptor.Split('-')[1]
            $LinkedAccountAddress = $LinkedAccount.Descriptor.Split('-')[2]
            $LinkedAccountObject = Get-PASAccount -search "$LinkedAccountUserName $LinkedAccountAddress" | Where-Object { $_.UserName -eq $LinkedAccountUserName -and $_.Address -eq $LinkedAccountAddress }

            $Accounts += @{
                Name   = $LinkedAccountObject.Name
                Safe   = $LinkedAccountObject.SafeName
                Folder = 'root'
                Type   = $LinkedAccount.Name
            }
        }
    }
    return $Accounts
}

function Get-Account {
    param (
        [String]$UserName,
        [String]$Address,
        [String]$PlatformId,
        [String]$SafeName,
        [String]$Name,
        [hashtable]$ReconcileAccount,
        [hashtable]$LogonAccount,

        [String] $PvwaUrl,
        [String] $AuthenticationType,
        [pscredential] $Credential,
        [bool] $SkipCertificateCheck
    )

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $ResourceExists = Get-PASAccount -search "$UserName $Address" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address }

    $CurrentState = [CYA_Account]::new()

    if ($ResourceExists) {
        $CurrentState.Ensure = [Ensure]::Present

        $LinkedAccounts = Get-LinkedAccounts -AccountId $ResourceExists.Id
        foreach ($LinkedAccount in $LinkedAccounts) {
            $CurrentState.$($LinkedAccount.Type) = $LinkedAccount
            $CurrentState.$($LinkedAccount.Type).Remove('Type') | Out-Null
        }

        $CurrentState.UserName = $ResourceExists.UserName
        $CurrentState.Address = $ResourceExists.Address
        $CurrentState.PlatformId = $ResourceExists.PlatformId
        $CurrentState.SafeName = $ResourceExists.SafeName
        $CurrentState.Name = $ResourceExists.Name
        $CurrentState.platformAccountProperties = $ResourceExists.PlatformAccountProperties
        $CurrentState.Id = $ResourceExists.Id
    } else {
        $CurrentState.Ensure = [Ensure]::Absent
    }

    return $CurrentState
}

function Set-Account {
    param (
        [Ensure]$Ensure,

        [String]$UserName,
        [String]$Address,
        [String]$PlatformId,
        [String]$SafeName,
        [String]$Name,
        [hashtable]$ReconcileAccount,
        [hashtable]$LogonAccount,

        [String] $PvwaUrl,
        [String] $AuthenticationType,
        [pscredential] $Credential,
        [bool] $SkipCertificateCheck
    )

    $Properties = Get-AccountPropertiesFromPSBoundParameters $PSBoundParameters

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    switch ($Ensure) {

        'Absent' {
            Get-PASAccount -safeName $SafeName -search "$UserName $Address" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address } | Remove-PASAccount
        }

        # TODO: Refactor all of this as it's ugly.
        'Present' {
            $Account = Get-Account -UserName $UserName -Address $Address -PvwaUrl $PvwaUrl -AuthenticationType $AuthenticationType -Credential $Credential -SkipCertificateCheck:$SkipCertificateCheck

            if ([string]::isNullOrEmpty($Account.Id)) {
                # Remove linked accounts as they need to be added after the account is created.
                $Properties.Remove('ReconcileAccount') | Out-Null
                $Properties.Remove('LogonAccount') | Out-Null

                $ResultingAccount = Add-PASAccount @Properties

                if ($PSBoundParameters.ContainsKey('LogonAccount')) {
                    $ResultingAccount | Set-PASLinkedAccount -safe $LogonAccount.Safe -folder $LogonAccount.Folder -name $LogonAccount.Name -extraPasswordIndex 1
                }

                if ($PSBoundParameters.ContainsKey('ReconcileAccount')) {
                    $ResultingAccount | Set-PASLinkedAccount -safe $ReconcileAccount.Safe -folder $ReconcileAccount.Folder -name $ReconcileAccount.Name -extraPasswordIndex 3
                }
            } else {
                $Properties.Remove('ReconcileAccount') | Out-Null
                $Properties.Remove('LogonAccount') | Out-Null

                if ($null -ne $LogonAccount) {
                    Set-PASLinkedAccount -AccountID $Account.Id -safe $LogonAccount.Safe -folder $LogonAccount.Folder -name $LogonAccount.Name -extraPasswordIndex 1
                }

                if ($null -ne $ReconcileAccount) {
                    Set-PASLinkedAccount -AccountID $Account.Id -safe $ReconcileAccount.Safe -folder $ReconcileAccount.Folder -name $ReconcileAccount.Name -extraPasswordIndex 3
                }

                $Actions = @()

                foreach ($Property in $Properties.GetEnumerator()) {
                    if ($ResourceExists.$($Property.Name) -ne $Property.Value) {
                        $Actions += @{
                            op    = 'replace'
                            path  = "/$($Property.Name)"
                            value = $Property.Value
                        }
                    }
                }
                if ($Actions.Count -gt 0) {
                    Set-PASAccount -ID $Account.ID -operations $Actions
                }
            }
        }
    }
}



function Test-Account {
    param (
        [Ensure]$Ensure,
        [String]$UserName,
        [String]$Address,
        [String]$PlatformId,
        [String]$SafeName,
        [String]$Name,
        [hashtable]$ReconcileAccount,
        [hashtable]$LogonAccount,

        [String] $PvwaUrl,
        [String] $AuthenticationType,
        [pscredential] $Credential,
        [bool] $SkipCertificateCheck
    )

    $DesiredState = $true

    $Properties = Get-AccountPropertiesFromPSBoundParameters $PSBoundParameters

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $CurrentState = Get-Account @Properties

    switch ($Ensure) {
        'Absent' {
            if ($CurrentState.Ensure -ne 'Absent') {
                $DesiredState = $false
            }
        }
        'Present' {
            if ($CurrentState.Ensure -ne 'Present') {
                $DesiredState = $false
                break
            } else {
                foreach ($Property in $Properties.GetEnumerator()) {
                    if ($Property.Name -eq 'ReconcileAccount' -or $Property.Name -eq 'LogonAccount') {
                        foreach ($LinkedAccountProperty in $Property.Value.GetEnumerator()) {
                            if ($CurrentState.$($Property.Name).$($LinkedAccountProperty.Name) -ne $LinkedAccountProperty.Value) {
                                $DesiredState = $false
                                break
                            }
                        }

                    } else {
                        if ($CurrentState.$($Property.Name) -ne $Property.Value) {
                            $DesiredState = $false
                            break
                        }
                    }
                }
            }

        }
    }

    return $DesiredState
}

[DscResource()]
class CYA_Account {
    [DscProperty(Mandatory)]
    [Ensure]$Ensure

    [DscProperty(Key)]
    [string]$UserName

    [DscProperty(Key)]
    [string]$Address

    [DscProperty(Mandatory)]
    [string]$PlatformId

    [DscProperty(Mandatory)]
    [string]$SafeName

    [DscProperty()]
    [string]$Name

    [DscProperty(NotConfigurable)]
    [string]$Id

    [DscProperty(NotConfigurable)]
    [string]$PlatformAccountProperties

    [DscProperty()]
    [System.Collections.Hashtable]$ReconcileAccount

    [DscProperty()]
    [System.Collections.Hashtable]$LogonAccount

    [DscProperty(Mandatory)]
    [string]$PvwaUrl

    [DscProperty(Mandatory)]
    [string]$AuthenticationType

    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [bool]$SkipCertificateCheck

    [CYA_Account] Get() {
        $Get = Get-Account -UserName $this.UserName -Address $this.Address -PlatformId $this.PlatformId -SafeName $this.SafeName -ReconcileAccount $this.ReconcileAccount -LogonAccount $this.LogonAccount -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck:$this.SkipCertificateCheck
        return $Get
    }

    [void] Set() {
        Set-Account -Ensure $this.Ensure -UserName $this.UserName -Address $this.Address -PlatformId $this.PlatformId -SafeName $this.SafeName -Name $this.Name -ReconcileAccount $this.ReconcileAccount -LogonAccount $this.LogonAccount -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck:$this.SkipCertificateCheck
    }

    [bool] Test() {
        $Test = Test-Account -Ensure $this.Ensure -UserName $this.UserName -Address $this.Address -PlatformId $this.PlatformId -SafeName $this.SafeName -ReconcileAccount $this.ReconcileAccount -LogonAccount $this.LogonAccount -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck:$this.SkipCertificateCheck
        return $Test
    }
}

