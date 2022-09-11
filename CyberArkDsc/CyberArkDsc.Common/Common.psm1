function Get-CyberArkSession {
    param (
        $PvwaUrl,
        $AuthenticationType,
        [pscredential] $Credential,
        $SkipCertificateCheck
    )

    try {
        Get-PASServer | Out-Null
    } catch {

        $SessionParameters = @{
            BaseUri           = $PvwaUrl
            Credential        = $Credential
            Type              = $AuthenticationType
            concurrentSession = $true
        }
        if ($SkipCertificateCheck) { $SessionParameters.Add('SkipCertificateCheck', $SkipCertificateCheck) }

        New-PASSession @SessionParameters
    }
}

function Get-AccountPropertiesFromPSBoundParameters {
    param (
        $Parameters
    )

    $Properties = @{} + $Parameters
    $Properties.Remove("PvwaUrl") | Out-Null
    $Properties.Remove("AuthenticationType") | Out-Null
    $Properties.Remove("Credential") | Out-Null
    $Properties.Remove("SkipCertificateCheck") | Out-Null
    $Properties.Remove("Ensure") | Out-Null

    # https://stackoverflow.com/a/54138232
    ($Properties.GetEnumerator() | Where-Object { -not $_.Value }) | ForEach-Object { $Properties.Remove($_.Name) | Out-Null}

    return $Properties
}