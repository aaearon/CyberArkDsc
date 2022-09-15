enum Ensure {
    Absent
    Present
}

function Get-Safe {
    param (
        [String]$SafeName,
        [String]$ManagingCPM,
        [String]$NumberOfDaysRetention,
        [String]$NumberOfVersionsRetention,
        [String]$Description,

        [String]$PvwaUrl,
        [String]$AuthenticationType,
        [pscredential]$Credential,
        [bool]$SkipCertificateCheck
    )

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $CurrentState = [CYA_Safe]::new()

    try {
        $ResourceExists = Get-PASSafe -SafeName $SafeName -ErrorAction SilentlyContinue | Select-Object -Property *

        $CurrentState.Ensure = [Ensure]::Present
        $CurrentState.SafeName = $ResourceExists.SafeName
        $CurrentState.ManagingCPM = $ResourceExists.ManagingCPM
        $CurrentState.NumberOfDaysRetention = $ResourceExists.NumberOfDaysRetention
        $CurrentState.NumberOfVersionsRetention = $ResourceExists.NumberOfVersionsRetention
        $CurrentState.Description = $ResourceExists.Description
        $CurrentState.SafeNumber = $ResourceExists.SafeNumber
    } catch {
        $CurrentState.Ensure = [Ensure]::Absent
    }

    return $CurrentState
}

function Set-Safe {
    param (
        [Ensure]$Ensure,

        [String]$SafeName,
        [String]$ManagingCPM,
        [String]$NumberOfDaysRetention,
        [String]$NumberOfVersionsRetention,
        [String]$Description,

        [String]$PvwaUrl,
        [String]$AuthenticationType,
        [pscredential]$Credential,
        [bool]$SkipCertificateCheck
    )

    $Properties = Get-AccountPropertiesFromPSBoundParameters $PSBoundParameters

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    switch ($Ensure) {

        'Absent' {
            Remove-PASSafe -SafeName $SafeName
        }

        'Present' {
            $Safe = Get-Safe -SafeName $SafeName -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

            if ([string]::isNullOrEmpty($Safe.SafeNumber)) {
                Add-PASSafe @Properties
            } else {
                Set-PASSafe @Properties
            }
        }
    }
}

function Test-Safe {
    param (
        [Ensure]$Ensure,
        [String]$SafeName,
        [String]$ManagingCPM,
        [String]$NumberOfDaysRetention,
        [String]$NumberOfVersionsRetention,
        [String]$Description,

        [String]$PvwaUrl,
        [String]$AuthenticationType,
        [pscredential]$Credential,
        [bool]$SkipCertificateCheck
    )

    $DesiredState = $true

    $Properties = Get-AccountPropertiesFromPSBoundParameters $PSBoundParameters

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $CurrentState = Get-Safe @Properties

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
                    if ($CurrentState.$($Property.Name) -ne $Property.Value) {
                        $DesiredState = $false
                        break
                    }
                }
            }
        }
    }

    return $DesiredState
}

[DscResource()]
class CYA_Safe {
    [DscProperty(Mandatory)]
    [Ensure]$Ensure

    [DscProperty(Key)]
    [string]$SafeName

    [DscProperty()]
    [string]$ManagingCPM

    [DscProperty()]
    [String]$NumberOfDaysRetention

    [DscProperty()]
    [String]$NumberOfVersionsRetention

    [DscProperty()]
    [string]$Description

    [DscProperty(NotConfigurable)]
    [string]$SafeNumber

    [DscProperty(Mandatory)]
    [string]$PvwaUrl

    [DscProperty(Mandatory)]
    [string]$AuthenticationType

    [DscProperty(Mandatory)]
    [pscredential]$Credential

    [DscProperty()]
    [bool]$SkipCertificateCheck

    [CYA_Safe] Get() {
        $Get = Get-Safe -SafeName $this.SafeName -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck $this.SkipCertificateCheck
        return $Get
    }

    [void] Set() {
        Set-Safe -Ensure $this.Ensure -SafeName $this.SafeName -ManagingCPM $this.ManagingCPM -NumberOfDaysRetention $this.NumberOfDaysRetention -NumberOfVersionsRetention $this.NumberOfVersionsRetention -Description $this.Description -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck $this.SkipCertificateCheck
    }

    [bool] Test() {
        $Test = Test-Safe -Ensure $this.Ensure -SafeName $this.SafeName -ManagingCPM $this.ManagingCPM -NumberOfDaysRetention $this.NumberOfDaysRetention -NumberOfVersionsRetention $this.NumberOfVersionsRetention -Description $this.Description -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck $this.SkipCertificateCheck
        return $Test
    }
}
