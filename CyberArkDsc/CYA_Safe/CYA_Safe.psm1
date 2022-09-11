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

    $ResourceExists = Get-PASSafe -SafeName $SafeName -ErrorAction SilentlyContinue | Select-Object -Property *

    $CurrentState = [CYA_Safe]::new()

    if ($ResourceExists) {
        $CurrentState.Ensure                    = [Ensure]::Present
        $CurrentState.SafeName                  = $ResourceExists.SafeName
        $CurrentState.ManagingCPM               = $ResourceExists.ManagingCPM
        $CurrentState.NumberOfDaysRetention     = $ResourceExists.NumberOfDaysRetention
        $CurrentState.NumberOfVersionsRetention = $ResourceExists.NumberOfVersionsRetention
        $CurrentState.Description               = $ResourceExists.Description
    } else {
        $CurrentState.Ensure = [Ensure]::Absent
    }

    return $CurrentState
}

function Set-Safe {
    param (
        [Ensure]$Ensure,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$SafeName,

        [String]$ManagingCPM,

        [String]$NumberOfDaysRetention,

        [String]$NumberOfVersionsRetention,

        [String]$Description,

        [parameter(Mandatory = $true)]
        [String] $PvwaUrl,

        [parameter(Mandatory = $true)]
        [String] $AuthenticationType,

        [parameter(Mandatory = $true)]
        [pscredential] $Credential,

        [bool] $SkipCertificateCheck
    )

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    $TestSafeParameters = @{
        Ensure               = $Ensure
        SafeName             = $SafeName
        ManagingCPM          = $ManagingCPM
        Description          = $Description

        PvwaUrl              = $PvwaUrl
        AuthenticationType   = $AuthenticationType
        Credential           = $Credential
        SkipCertificateCheck = $SkipCertificateCheck
    }

    if ($NumberOfDaysRetention) {
        $TestSafeParameters.Add('NumberOfDaysRetention', $NumberOfDaysRetention)
    }
    if ($NumberOfVersionsRetention) {
        $TestSafeParameters.Add('NumberOfVersionsRetention', $NumberOfVersionsRetention)
    }

    $DesiredState = Test-Safe @TestSafeParameters

    if ($DesiredState -eq $false) {

        if ($Ensure -eq [Ensure]::Present) {

            $NewResourceProperties = @{
                SafeName = $SafeName
            }
            if ($ManagingCPM) { $NewResourceProperties.Add('ManagingCPM', $ManagingCPM) }
            if ($Description) { $NewResourceProperties.Add('Description', $Description) }
            if ($NumberOfDaysRetention) { $NewResourceProperties.Add('NumberOfDaysRetention', $NumberOfDaysRetention) }
            if ($NumberOfVersionsRetention) { $NewResourceProperties.Add('NumberOfVersionsRetention', $NumberOfVersionsRetention) }

            Add-PASSafe @NewResourceProperties
        }

        if ($Ensure -eq [Ensure]::Present) {
            Get-PASSafe -SafeName $SafeName | Remove-PASSafe
        }

        Close-PASSession -ErrorAction SilentlyContinue
    }
}


function Test-Safe {
    param (
        [Ensure]$Ensure,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$SafeName,

        [String]$ManagingCPM,

        [String]$NumberOfDaysRetention,

        [String]$NumberOfVersionsRetention,

        [String]$Description,

        [parameter(Mandatory = $true)]
        [String] $PvwaUrl,

        [parameter(Mandatory = $true)]
        [String] $AuthenticationType,

        [parameter(Mandatory = $true)]
        [pscredential] $Credential,

        [bool] $SkipCertificateCheck
    )

    $DesiredState = $false

    Get-CyberArkSession -PvwaUrl $PvwaUrl -Credential $Credential -AuthenticationType $AuthenticationType -SkipCertificateCheck $SkipCertificateCheck

    try {

        $ResourceExists = Get-PASSafe -SafeName $SafeName -ErrorAction SilentlyContinue | Where-Object { $_.ManagingCPM -eq $ManagingCPM -and $_.Description -eq $Description }

        if ($NumberOfDaysRetention) {
            $ResourceExists = $ResourceExists | Where-Object { $_.NumberOfDaysRetention -eq $NumberOfDaysRetention }
        }
        if ($NumberOfVersionsRetention) {
            $ResourceExists = $ResourceExists | Where-Object { $_.NumberOfVersionsRetention -eq $NumberOfVersionsRetention }
        }

    } catch {
        $ResourceExists = $null
    }

    if ($Ensure -eq [Ensure]::Present -and $null -ne $ResourceExists) {
        $DesiredState = $true
    }

    if ($Ensure -eq [Ensure]::Absent -and $null -eq $ResourceExists) {
        $DesiredState = $true
    }

    Close-PASSession -ErrorAction SilentlyContinue

    $DesiredState
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
        $Get = Get-Safe -SafeName $this.SafeName -ManagingCPM $this.ManagingCPM -NumberOfDaysRetention $this.NumberOfDaysRetention -NumberOfVersionsRetention $this.NumberOfVersionsRetention -Description $this.Description -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck $this.SkipCertificateCheck
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

