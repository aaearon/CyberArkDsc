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

    $Properties = @{} + $PSBoundParameters
    $Properties.Remove("PvwaUrl") | Out-Null
    $Properties.Remove("AuthenticationType") | Out-Null
    $Properties.Remove("Credential") | Out-Null
    $Properties.Remove("SkipCertificateCheck") | Out-Null
    $Properties.Remove("Ensure") | Out-Null

    $ResourceExists = Get-PASAccount -search "$UserName $Address" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address }

    if ($ResourceExists) {
        foreach ($Property in $Properties.GetEnumerator()) {

            if ($ResourceExists.$($Property.Name) -ne $Property.Value) {
                $CurrentState.Ensure = [Ensure]::Present
                break
            } else {
                $CurrentState.Ensure = [Ensure]::Exactly
            }
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

    $DesiredState = Test-Account -Ensure $Ensure -UserName $UserName -Address $Address -PlatformId $PlatformId -SafeName $SafeName -PvwaUrl $PvwaUrl -AuthenticationType $AuthenticationType -Credential $Credential -SkipCertificateCheck:$SkipCertificateCheck

    if (-not $DesiredState) {

        switch ($Ensure) {

            'Absent' {
                    Get-PASAccount -safeName $SafeName -search "$UserName $Address" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address } | Remove-PASAccount
                }

            'Exactly' {
                $Properties = @{} + $PSBoundParameters
                $Properties.Remove("PvwaUrl") | Out-Null
                $Properties.Remove("AuthenticationType") | Out-Null
                $Properties.Remove("Credential") | Out-Null
                $Properties.Remove("SkipCertificateCheck") | Out-Null
                $Properties.Remove("Ensure") | Out-Null

                $Account = Get-Account -UserName $UserName -Address $Address -PvwaUrl $PvwaUrl -AuthenticationType $AuthenticationType -Credential $Credential -SkipCertificateCheck:$SkipCertificateCheck

                $Actions = @()

                foreach ($Property in $Properties.GetEnumerator()) {
                    if ($ResourceExists.$($Property.Name) -ne $Property.Value) {
                        $Actions += @{
                            op    = 'replace'
                            path  = '/platformId'
                            value = $PlatformId
                        }
                }
            }


            if ($Actions.Count -gt 0) {
                Set-PASAccount -ID $Account.ID -operations $Actions
            }
        }

            'Present' {
                if (-not $DesiredState) {
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

    $Properties = @{} + $PSBoundParameters
    $Properties.Remove("Ensure") | Out-Null
    $Properties.Remove("PvwaUrl") | Out-Null
    $Properties.Remove("AuthenticationType") | Out-Null
    $Properties.Remove("Credential") | Out-Null
    $Properties.Remove("SkipCertificateCheck") | Out-Null

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
            if ($CurrentState.Ensure -ne [Ensure]::Absent) {
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

