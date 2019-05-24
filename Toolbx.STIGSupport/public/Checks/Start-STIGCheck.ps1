
function Start-STIGCheck {

    [CmdletBinding()]
    param (

        # Specify the path to the STIG Checklist to populate.
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path -Path $_ })]
        $Checklist,

        # Select the STIG check to perform.
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "Windows_Server_2016_V1R9",
            "MS_DotNet_Framework_4-0"
        )]
        $STIG
    )

    If ($PSBoundParameters['Debug']) { $DebugPreference = 'Continue' }

    # Start Metrics
    $StartTime = Get-Date

    # Import STIG Checklist
    $CKL = Import-Checklist -Path $Checklist

    # Set Host Data.
    Set-ChecklistHostData -Checklist $CKL

    # Run pre.check.ps1 if it exists.
    $PreCheck = $null
    if (Test-Path "$PSScriptRoot\$STIG\pre.check.ps1") {
        Write-Verbose "[$($MyInvocation.MyCommand)] Running $STIG Pre Check"
        $PreCheck = . "$PSScriptRoot\$STIG\pre.check.ps1"
    }

    # Run VulnID Checks
    $Checks = Get-ChildItem -Path $PSScriptRoot\$STIG -Filter "*.ps1" -File | Where-Object { $_.Name -ne "pre.check.ps1" -and $_.Name -ne "post.check.ps1" }

    $checks | ForEach-Object {

        Try {

            Write-Verbose "[$($MyInvocation.MyCommand)] Running $STIG Check - $($($_.Name).split(".")[0])"
            Write-Debug "[$($MyInvocation.MyCommand)] Script Path: $PSScriptRoot\$STIG\$($_.Name)"

            # Perform Check
            $check = . "$PSScriptRoot\$STIG\$($_.Name)" $PreCheck

            # Lookup
            #TODO: Create function Grab predefined data points.
            # Pull apart the fqdn to get the short domain name.

            # Update Checklist
            Set-VulnIDFinding -Checklist $CKL -VulnID $check.VulnID -RuleID $check.RuleID -Details $check.Details -Comments $check.Comments -Status $check.Status

        }
        Catch {
            Write-Error $_
        }

    }

    # Save Checklist
    Export-Checklist -Checklist $CKL -Path $Checklist

    # Output How long it took
    Write-Verbose "[$($MyInvocation.MyCommand)] $STIG Check Took $(((Get-Date) - $StartTime).TotalSeconds) seconds to complete"

}