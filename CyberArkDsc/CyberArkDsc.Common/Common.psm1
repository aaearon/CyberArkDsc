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