enum Ensure {
    Absent
    Present
}

function Get-SafeMember {
    param (
        [ValidateSet('Present', 'Absent')]
        [string]$Ensure = 'Present',

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

    $EnsureReturn = 'Absent'

    $SessionParameters = @{
        BaseUri           = $PvwaUrl
        Credential        = $Credential
        Type              = $AuthenticationType
        concurrentSession = $true
    }
    if ($SkipCertificateCheck) { $SessionParameters.Add('SkipCertificateCheck', $true) }

    New-PASSession @SessionParameters

    $ResourceExists = Get-PASSafe -SafeName $SafeName -ErrorAction SilentlyContinue

    if ($ResourceExists) {
        $EnsureReturn = 'Present'
    }

    Close-PASSession -ErrorAction SilentlyContinue

    @{
        Ensure                    = $EnsureReturn
        SafeName                  = $ResourceExists.SafeName
        ManagingCPM               = $ResourceExists.ManagingCPM
        NumberOfDaysRetention     = $ResourceExists.NumberOfDaysRetention
        NumberOfVersionsRetention = $ResourceExists.NumberOfVersionsRetention
        Description               = $ResourceExists.Description
    }
    }

function Set-SafeMember {
    param (

        [ValidateSet('Present', 'Absent')]
        [string]$Ensure = 'Present',

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

    $SessionParameters = @{
        BaseUri           = $PvwaUrl
        Credential        = $Credential
        Type              = $AuthenticationType
        concurrentSession = $true
    }
    if ($SkipCertificateCheck) { $SessionParameters.Add('SkipCertificateCheck', $true) }

    New-PASSession @SessionParameters

    $TestSafeParameters = @{
        Ensure = $Ensure
        SafeName = $SafeName
        ManagingCPM = $ManagingCPM
        Description = $Description

        PvwaUrl = $PvwaUrl
        AuthenticationType = $AuthenticationType
        Credential = $Credential
        SkipCertificateCheck = $SkipCertificateCheck
    }

    if ($NumberOfDaysRetention) {
        $TestSafeParameters.Add('NumberOfDaysRetention', $NumberOfDaysRetention)
    }
    if ($NumberOfVersionsRetention) {
        $TestSafeParameters.Add('NumberOfVersionsRetention', $NumberOfVersionsRetention)
    }

    $DesiredState = Test-SafeMember @TestSafeParameters

    if ($DesiredState -eq $false) {

        if ($Ensure -eq 'Present') {

            $NewResourceProperties = @{
                SafeName = $SafeName
            }
            if ($ManagingCPM) { $NewResourceProperties.Add('ManagingCPM', $ManagingCPM) }
            if ($Description) { $NewResourceProperties.Add('Description', $Description) }
            if ($NumberOfDaysRetention) { $NewResourceProperties.Add('NumberOfDaysRetention', $NumberOfDaysRetention) }
            if ($NumberOfVersionsRetention) { $NewResourceProperties.Add('NumberOfVersionsRetention', $NumberOfVersionsRetention) }

            Add-PASSafe @NewResourceProperties
        }

        if ($Ensure -eq 'Absent') {
            Get-PASSafe -SafeName $SafeName | Remove-PASSafe
        }

        Close-PASSession -ErrorAction SilentlyContinue
    }
}


function Test-SafeMember {
    param (
        [ValidateSet('Present', 'Absent')]
        [string]$Ensure = 'Present',

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

    $SessionParameters = @{
        BaseUri           = $PvwaUrl
        Credential        = $Credential
        Type              = $AuthenticationType
        concurrentSession = $true
    }
    if ($SkipCertificateCheck) { $SessionParameters.Add('SkipCertificateCheck', $true) }

    New-PASSession @SessionParameters

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

    if ($Ensure -eq 'Present' -and $null -ne $ResourceExists) {
        $DesiredState = $true
    }

    if ($Ensure -eq 'Absent' -and $null -eq $ResourceExists) {
        $DesiredState = $true
    }

    Close-PASSession -ErrorAction SilentlyContinue

    $DesiredState
}

[DscResource()]
class CYA_SafeMember {
    [DscProperty(Mandatory)]
    [Ensure]$Ensure

    [DscProperty(Key)]
    [string]$SafeName

    [DscProperty(Key)]
    [string]$SafeMember

    [DscProperty()]
    [String]$SearchIn

    [DscProperty()]
    [datetime]$MembershipExpirationDate

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

    [CYA_SafeMember] Get() {
        $Get = Get-SafeMember -Ensure $this.Ensure -SafeName $this.SafeName -ManagingCPM $this.ManagingCPM -NumberOfDaysRetention $this.NumberOfDaysRetention -NumberOfVersionsRetention $this.NumberOfVersionsRetention -Description $this.Description -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck $this.SkipCertificateCheck
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

        Set-SafeMember @SetSafeParameters
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

        $Test = Test-SafeMember @TestSafeParameters
        return $Test
    }
}

