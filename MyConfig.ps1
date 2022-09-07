# Only for testing as I am tired of the Get-Credential prompt
$VaultUserName = 'allison'
$VaultPassword = 'Password!'
$VaultCredential = New-Object System.Management.Automation.PSCredential($VaultUserName, (ConvertTo-SecureString $VaultPassword -AsPlainText -Force))

Configuration MyConfig {
    param(
        [pscredential]$Credential
    )

    Import-DSCResource -ModuleName CyberArkDsc

    Node localhost {

        CYA_Account 'windowsAdmin04' {
            Ensure               = 'Present'
            UserName             = 'windowsAdmin04'
            Address              = 'iosharp.dev'
            PlatformId           = 'ioSHARPWindowsDomainAccount'
            SafeName             = 'Windows'

            PvwaUrl              = 'https://192.168.137.101'
            AuthenticationType   = 'LDAP'
            SkipCertificateCheck = $true
            Credential           = $VaultCredential
        }

        CYA_Account 'windowsAdmin05' {
            Ensure               = 'Present'
            UserName             = 'windowsAdmin05'
            Address              = 'iosharp.dev'
            PlatformId           = 'ioSHARPWindowsDomainAccount'
            SafeName             = 'Windows'

            PvwaUrl              = 'https://192.168.137.101'
            AuthenticationType   = 'LDAP'
            SkipCertificateCheck = $true
            Credential           = $VaultCredential
        }

        CYA_Safe 'Switches' {
            Ensure                = 'Present'
            SafeName              = 'Switches'
            ManagingCPM           = 'PasswordManager'
            Description           = 'Switches Safe'
            NumberOfDaysRetention = '1'

            PvwaUrl               = 'https://192.168.137.101'
            AuthenticationType    = 'LDAP'
            SkipCertificateCheck  = $true
            Credential            = $VaultCredential
        }
    }
}

# Enables the password to be saved in plaintext in the MOF file
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName                    = 'localhost'
            PsDscAllowPlainTextPassword = $true
        }
    )
}

# $Credential = Get-Credential -Message 'Enter the username and password for the Vault user'
# MyConfig -ConfigurationData $ConfigurationData -Credential $Credential

MyConfig -ConfigurationData $ConfigurationData