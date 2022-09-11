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

        [String] $PvwaUrl,
        [String] $AuthenticationType,
        [pscredential] $Credential,
        [bool] $SkipCertificateCheck
    )

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $CurrentState = [CYA_Safe]::new()

    try {
        $ResourceExists = Get-PASSafe -SafeName $SafeName -ErrorAction SilentlyContinue | Select-Object -Property *

        $CurrentState.Ensure                    = [Ensure]::Present
        $CurrentState.SafeName                  = $ResourceExists.SafeName
        $CurrentState.ManagingCPM               = $ResourceExists.ManagingCPM
        $CurrentState.NumberOfDaysRetention     = $ResourceExists.NumberOfDaysRetention
        $CurrentState.NumberOfVersionsRetention = $ResourceExists.NumberOfVersionsRetention
        $CurrentState.Description               = $ResourceExists.Description
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

        [String] $PvwaUrl,
        [String] $AuthenticationType,
        [pscredential] $Credential,
        [bool] $SkipCertificateCheck
    )

    $Properties = Get-AccountPropertiesFromPSBoundParameters $PSBoundParameters

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $DesiredState = Test-Safe @Properties

    if ($DesiredState -eq $false) {

        switch ($Ensure) {

            'Absent' {
                Remove-PASSafe -SafeName $SafeName
            }

            'Present' {
                Add-PASSafe @Properties
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

    $isDesiredState = $false

    $Properties = Get-AccountPropertiesFromPSBoundParameters $PSBoundParameters

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $CurrentState = Get-Safe @Properties

    switch ($Ensure) {
        'Absent' {
            if ($CurrentState.Ensure -eq [Ensure]::Absent) {
                $isDesiredState = $true
            }
        }
        'Present' {
            if ($CurrentState.Ensure -ne [Ensure]::Absent) {
                $isDesiredState = $true
            }
        }
    }

    return $isDesiredState
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
        $SetSafeParameters = @{
            Ensure               = $this.Ensure
            SafeName             = $this.SafeName
            ManagingCPM          = $this.ManagingCPM
            Description          = $this.Description
            PvwaUrl              = $this.PvwaUrl
            AuthenticationType   = $this.AuthenticationType
            Credential           = $this.Credential
            SkipCertificateCheck = $this.SkipCertificateCheck
        }
        if ($this.NumberOfDaysRetention) { $SetSafeParameters.Add('NumberOfDaysRetention', $this.NumberOfDaysRetention) }
        if ($this.NumberOfVersionsRetention) { $SetSafeParameters.Add('NumberOfVersionsRetention', $this.NumberOfVersionsRetention) }

        Set-Safe @SetSafeParameters
    }

    [bool] Test() {
        $TestSafeParameters = @{
            Ensure               = $this.Ensure
            SafeName             = $this.SafeName
            ManagingCPM          = $this.ManagingCPM
            Description          = $this.Description
            PvwaUrl              = $this.PvwaUrl
            AuthenticationType   = $this.AuthenticationType
            Credential           = $this.Credential
            SkipCertificateCheck = $this.SkipCertificateCheck
        }
        if ($this.NumberOfDaysRetention) { $TestSafeParameters.Add('NumberOfDaysRetention', $this.NumberOfDaysRetention) }
        if ($this.NumberOfVersionsRetention) { $TestSafeParameters.Add('NumberOfVersionsRetention', $this.NumberOfVersionsRetention) }

        $Test = Test-Safe @TestSafeParameters
        return $Test
    }
}

