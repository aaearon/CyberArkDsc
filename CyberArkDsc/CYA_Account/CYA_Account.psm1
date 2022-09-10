enum Ensure {
    Absent
    Exactly
    Present
}

function Get-Account {
    param (
        [String]$UserName,
        [String]$Address,
        [String]$PlatformId,
        [String]$SafeName,
        [String]$Name,

        [String] $PvwaUrl,
        [String] $AuthenticationType,
        [pscredential] $Credential,
        [bool] $SkipCertificateCheck
    )

    $CurrentState = [CYA_Account]::new()

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    # $Properties = $PSBoundParameters
    # $Properties.Remove("PvwaUrl")
    # $Properties.Remove("AuthenticationType")
    # $Properties.Remove("Credential")
    # $Properties.Remove("SkipCertificateCheck")

    $ResourceExists = Get-PASAccount -search "$UserName $Address" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address }

    if ($ResourceExists) {
        if ($ResourceExists | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address -and $_.PlatformId -eq $PlatformId -and $_.Safe -eq $SafeName -and $_.Name -eq $Name }) {
            $CurrentState.Ensure = [Ensure]::Exactly
        }
        else {
            $CurrentState.Ensure = [Ensure]::Present
        }
        $CurrentState.UserName = $ResourceExists.UserName
        $CurrentState.Address = $ResourceExists.Address
        $CurrentState.PlatformId = $ResourceExists.PlatformId
        $CurrentState.SafeName = $ResourceExists.SafeName
        $CurrentState.Name = $ResourceExists.Name
        $CurrentState.platformAccountProperties = $ResourceExists.PlatformAccountProperties
        $CurrentState.Id = $ResourceExists.Id
    } else {
        $CurrentState = [Ensure]::Absent
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

        [String] $PvwaUrl,
        [String] $AuthenticationType,
        [pscredential] $Credential,
        [bool] $SkipCertificateCheck
    )

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $AccountExists = Test-Account -Ensure $Ensure -UserName $UserName -Address $Address -PlatformId $PlatformId -SafeName $SafeName -PvwaUrl $PvwaUrl -AuthenticationType $AuthenticationType -Credential $Credential -SkipCertificateCheck:$SkipCertificateCheck

    switch ($Ensure) {
        'Absent' {
            if ($AccountExists) {
                Get-PASAccount -safeName $SafeName -search "$UserName $Address" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address } | Remove-PASAccount
            }
        }
        'Exactly' {
            $Account = Get-PASAccount -search "$UserName $Address" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address }

            $Actions = @()

            if ( (-not [string]::IsNullOrEmpty($PlatformId)) -and $Account.PlatformId -ne $PlatformId ) {
                $Action = @{
                    op    = 'replace'
                    path  = '/platformId'
                    value = $PlatformId
                }

                $Actions += $Action
            }

            if ( (-not [string]::IsNullOrEmpty($Name)) -and $Account.Name -ne $Name ) {
                $Action = @{
                    op    = 'replace'
                    path  = '/name'
                    value = $name
                }

                $Actions += $Action
            }

            if ($Actions.Count -gt 0) {
                $Account | Set-PASAccount -operations $Actions
            }
        }
        'Present' {
            if (-not $AccountExists) {
                $NewAccountProperties = @{
                    UserName   = $UserName
                    Address    = $Address
                    PlatformId = $PlatformId
                    SafeName   = $SafeName
                }
                if ($Name) { $NewAccountProperties.Add('Name', $Name) }

                Add-PASAccount @NewAccountProperties
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

        [String] $PvwaUrl,
        [String] $AuthenticationType,
        [pscredential] $Credential,
        [bool] $SkipCertificateCheck
    )

    $DesiredState = $false

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $Properties = $PSBoundParameters
    $Properties.Remove("Ensure")
    $Properties.Remove("PvwaUrl")
    $Properties.Remove("AuthenticationType")
    $Properties.Remove("Credential")
    $Properties.Remove("SkipCertificateCheck")

    $CurrentState = Get-Account @Properties

    switch ($Ensure) {

        'Absent' {
            if ($CurrentState.Ensure -eq [Ensure]::Absent) {
                $DesiredState = $true
            }
        }

        'Exactly' {
            if ($CurrentState.Ensure -eq [Ensure]::Exactly) {
                $DesiredState = $true
            }
        }

        'Present' {
            if ($CurrentState.Ensure -eq [Ensure]::Present) {
                $DesiredState = $true
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

    [DscProperty(Mandatory)]
    [string]$PvwaUrl

    [DscProperty(Mandatory)]
    [string]$AuthenticationType

    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty(Mandatory)]
    [bool]$SkipCertificateCheck

    [CYA_Account] Get() {
        $Get = Get-Account -UserName $this.UserName -Address $this.Address -PlatformId $this.PlatformId -SafeName $this.SafeName -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck:$this.SkipCertificateCheck
        return $Get
    }

    [void] Set() {
        Set-Account -Ensure $this.Ensure -UserName $this.UserName -Address $this.Address -PlatformId $this.PlatformId -SafeName $this.SafeName -Name $this.Name -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck:$this.SkipCertificateCheck
    }

    [bool] Test() {
        $Test = Test-Account -Ensure $this.Ensure -UserName $this.UserName -Address $this.Address -PlatformId $this.PlatformId -SafeName $this.SafeName -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck:$this.SkipCertificateCheck
        return $Test
    }
}

