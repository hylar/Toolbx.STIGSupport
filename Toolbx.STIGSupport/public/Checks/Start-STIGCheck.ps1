
function Start-STIGCheck {

    [CmdletBinding()]
    param (

        # Specify the Host name to be used for the STIG check. By Default it grabs the local computer name using the $ENV:ComputerName variable.
        [Parameter()]
        $HostName = $env:COMPUTERNAME,

        # Specify the path to the STIG Checklist to populate.
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path -Path $_ })]
        $CKL,

        # Select the STIG check to perform.
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "MS_DotNet_Framework_4-0"
        )]
        $STIG
    )

    # Start Metrics
    $StartTime = Get-Date

    # Import STIG Checklist
    $CKLData = Import-Checklist -Path $CKL

    # Get Host Data.

    # Run pre.check.ps1 if it exists.
    $PreCheck = $null
    if (Test-Path "$PSScriptRoot\$STIG\pre.check.ps1") {

        Write-Verbose "Running $STIG Pre Check"
        $PreCheck = . "$PSScriptRoot\$STIG\pre.check.ps1"
        Write-Verbose $PreCheck
    }

    # Run VulnID Checks
    $Checks = Get-ChildItem -Path $PSScriptRoot\$STIG -Filter "*.ps1" -File | Where-Object {$_.Name -ne "pre.check.ps1" -and $_.Name -ne "post.check.ps1"}

    $checks | ForEach-Object {

        Write-Verbose "Running $STIG Check - $($($_.Name).split(".")[0])"

        # Perform Check

        # Update Checklist

    }


    # Save Checklist

    # Output How long it took
    Write-Verbose "$STIG Check Took $(((Get-Date) - $StartTime).TotalSeconds) seconds to complete"

}