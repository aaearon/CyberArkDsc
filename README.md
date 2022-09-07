# CyberArkDsc

A [PowerShell DSC](https://docs.microsoft.com/en-us/powershell/dsc/overview?view=dsc-1.1) module for CyberArk's [Privileged Access Manager](https://www.cyberark.com/products/privileged-access-manager/) objects (Accounts, Safes, Platforms, etc.).

## Usage

1. Ensure [psPAS](https://github.com/pspete/psPAS) and the `CyberArkDsc` folder is in a location that the `SYSTEM` account can access. Example: `C:\Windows\System32\WindowsPowerShell\v1.0\Modules\`

1. Update the `MyConfig.ps1` Configuration with the appropriate values.

1. Compile the Configuration.

   ```powershell
   . .\MyConfig.ps1
   ```

1. Test the Configuration with `Test-DscConfiguration`

   ```powershell
   Test-DscConfiguration -Path .\MyConfig -Verbose
   ```

1. Apply the Configuration with `Start-DscConfiguration`

   ```powershell
   Start-DscConfiguration -Path .\MyConfig -Verbose
   ```
