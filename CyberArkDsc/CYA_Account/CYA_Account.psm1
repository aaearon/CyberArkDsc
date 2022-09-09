enum Ensure {
    Absent
    Present
}

function Get-Account {
    param (
        [Ensure]$Ensure = 'Present',

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$UserName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Address,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$PlatformId,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$SafeName,

        [parameter(Mandatory = $false)]
        [String]$Name,

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

    $ResourceExists = Get-PASAccount -safeName $SafeName -search "$UserName $Address $PlatformId" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address -and $_.PlatformId -eq $PlatformId }

    if ($ResourceExists) {
        $EnsureReturn = 'Present'
    }

    Close-PASSession -ErrorAction SilentlyContinue

    @{
        Ensure                    = $EnsureReturn
        UserName                  = $AccountExists.UserName
        Address                   = $AccountExists.Address
        PlatformId                = $AccountExists.PlatformId
        SafeName                  = $AccountExists.SafeName
        Name                      = $AccountExists.Name
        PlatformAccountProperties = $AccountExists.PlatformAccountProperties
        Id                        = $AccountExists.Id
    }

}

function Set-Account {
    param (
        [Ensure]$Ensure = 'Present',

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$UserName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Address,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$PlatformId,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$SafeName,

        [parameter(Mandatory = $false)]
        [String]$Name,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $PvwaUrl,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $AuthenticationType,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
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

    $DesiredState = Test-Account -Ensure $Ensure -UserName $UserName -Address $Address -PlatformId $PlatformId -SafeName $SafeName -PvwaUrl $PvwaUrl -AuthenticationType $AuthenticationType -Credential $Credential -SkipCertificateCheck:$SkipCertificateCheck

    if ($DesiredState -eq $false) {

        if ($Ensure -eq 'Present') {

            $NewAccountProperties = @{
                UserName   = $UserName
                Address    = $Address
                PlatformId = $PlatformId
                SafeName   = $SafeName
            }
            if ($Name) { $NewAccountProperties.Add('Name', $Name) }

            Add-PASAccount @NewAccountProperties
        }

        if ($Ensure -eq 'Absent') {
            Get-PASAccount -safeName $SafeName -search "$UserName $Address $PlatformId" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address -and $_.PlatformId -eq $PlatformId } | Remove-PASAccount
        }

        Close-PASSession -ErrorAction SilentlyContinue
    }
}


function Test-Account {
    param (
        [Ensure]$Ensure = 'Present',

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$UserName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Address,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$PlatformId,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$SafeName,

        [parameter(Mandatory = $false)]
        [String]$Name,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $PvwaUrl,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $AuthenticationType,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
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

    $ResourceExists = Get-PASAccount -safeName $SafeName -search "$UserName $Address $PlatformId" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address -and $_.PlatformId -eq $PlatformId }

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
class CYA_Account {
    [DscProperty(Mandatory)]
    [Ensure]$Ensure

    [DscProperty(Key)]
    [string]$UserName

    [DscProperty(Key)]
    [string]$Address

    [DscProperty(Key)]
    [string]$PlatformId

    [DscProperty(Key)]
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
        $Get = Get-Account -Ensure $this.Ensure -UserName $this.UserName -Address $this.Address -PlatformId $this.PlatformId -SafeName $this.SafeName -PvwaUrl $this.PvwaUrl -AuthenticationType $this.AuthenticationType -Credential $this.Credential -SkipCertificateCheck:$this.SkipCertificateCheck
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

