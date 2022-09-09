function Get-CyberArkSession {
    param (
        $PvwaUrl,
        $AuthenticationType,
        $Credential,
        $SkipCertificateCheck
    )

    try {
        Get-PASSuser
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