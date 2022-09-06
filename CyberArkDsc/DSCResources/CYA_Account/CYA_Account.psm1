function Get-TargetResource {
    param (
        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

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

    $AccountExists = Get-PASAccount -safeName $SafeName -search "$UserName $Address $PlatformId" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address -and $_.PlatformId -eq $PlatformId }

    if ($AccountExists) {
        $EnsureReturn = 'Present'
    }

    Close-PASSession

    @{
        Ensure                    = $EnsureReturn
        UserName                  = $UserName
        Address                   = $Address
        PlatformId                = $PlatformId
        SafeName                  = $SafeName
        Name                      = $AccountExists.Name
        PlatformAccountProperties = $AccountExists.PlatformAccountProperties
        Id                        = $AccountExists.Id
    }

}

function Set-TargetResource {
    param (
        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

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

    if ($Ensure -eq 'Present') {

        $AccountExists = Test-TargetResource -UserName $UserName -Address $Address -PlatformId $PlatformId -SafeName $SafeName -PvwaUrl $PvwaUrl -AuthenticationType $AuthenticationType -Credential $Credential -SkipCertificateCheck:$SkipCertificateCheck

        if ($AccountExists -eq $false) {
            $NewAccountProperties = @{
                UserName = $UserName
                Address  = $Address
                PlatformId = $PlatformId
                SafeName = $SafeName
            }
            if ($Name) { $NewAccountProperties.Add('Name', $Name) }

            New-PASAccount @NewAccountProperties
        }
    }
}

function Test-TargetResource {
    param (
        [ensure]$ensure = 'Present',

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

    $AccountExists = $false

    $SessionParameters = @{
        BaseUri           = $PvwaUrl
        Credential        = $Credential
        Type              = $AuthenticationType
        concurrentSession = $true
    }
    if ($SkipCertificateCheck) { $SessionParameters.Add('SkipCertificateCheck', $true) }

    New-PASSession @SessionParameters

    $Account = Get-PASAccount -safeName $SafeName -search "$UserName $Address $PlatformId" | Where-Object { $_.UserName -eq $UserName -and $_.Address -eq $Address -and $_.PlatformId -eq $PlatformId }

    if ($Account) {
        $AccountExists = $true
    }

    $AccountExists
}