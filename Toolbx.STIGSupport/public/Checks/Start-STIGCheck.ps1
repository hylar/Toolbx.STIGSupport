
function Start-STIGCheck {

    [CmdletBinding()]
    param (

        # Specify the Host name to be used for the STIG check. By Default it grabs the local computer name using the $ENV:ComputerName variable.
        [Parameter()]
        $HostName = $env:COMPUTERNAME,

        # Specify the path to the STIG Checklist to populate.
        [Parameter(Mandatory=$true)]
        [ValidateScript( {Test-Path -Path $_})]
        $CKL,

        # Select the STIG check to perform.
        [Parameter(Mandatory=$true)]
        [ValidateSet(
            "MS_DotNet_Framework_4-0"
        )]
        $STIG
    )

    # Import STIG Checklist
    $CKLData = Import-StigCKL -Path $CKL

    # Get Host Data.
    Get-ChildItem ".\$STIG"
    # Complet PreChecks. This will run the script in the folder called prechecks.ps1.

}