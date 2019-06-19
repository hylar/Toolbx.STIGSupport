
function Start-STIGCheck {

    [CmdletBinding()]
    param (

        # Specify the path to the STIG Checklist to populate.
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path -Path $_ })]
        $Checklist,

        # Specify the path to the SCAP Benchmark to import.
        [Parameter()]
        [ValidateScript( { Test-Path -Path $_ })]
        $SCAPBenchmark,

        # Select the STIG check to perform.
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            "MS_DotNet_Framework_4-0",
            "MS_IE11",
            "Windows_Server_2012_DC",
            "Windows_Server_2012_MS",
            "Windows_Server_2016",
            "Windows_10"
        )]
        $STIG,

        # Specify the Default Findings Result for checks that passed.
        [Parameter()]
        [string]
        $PassedSCAPFinding = "Vulnerability Closed by Automated Benchmark/SCAP Check.",

        # Specify the Default Findings Result for checks that passed.
        [Parameter()]
        [string]
        $FailedSCAPFinding = "Vulnerability Opened by Automated Benchmark/SCAP Check."
    )

    If ($PSBoundParameters['Debug']) { $DebugPreference = 'Continue' }

    # Start Metrics
    $StartTime = Get-Date

    # Import STIG Checklist
    $CKL = Import-Checklist -Path $Checklist

    # Import SCAP Results if provided
    if ($SCAPBenchmark) {

        Write-Verbose "[$($MyInvocation.MyCommand)] Importing SCAP Results"

        $SCAP = Get-SCAPResults -XccdfPath $SCAPBenchmark
    }

    # Set Host Data.
    Set-ChecklistHostData -Checklist $CKL

    # Run pre.check.ps1 if it exists.
    $PreCheck = $null
    if (Test-Path "$PSScriptRoot\$STIG\pre.check.ps1") {
        Write-Verbose "[$($MyInvocation.MyCommand)] Running $STIG Pre Check"
        $PreCheck = . "$PSScriptRoot\$STIG\pre.check.ps1"
    }

    # View default findings and update checklist.

    # Run VulnID Checks
    $Checks = Get-ChildItem -Path $PSScriptRoot\$STIG -Filter "*.ps1" -File | Where-Object { $_.Name -ne "pre.check.ps1" -and $_.Name -ne "post.check.ps1" }

    $checks | ForEach-Object {

        Try {

            Write-Verbose "[$($MyInvocation.MyCommand)] Running $STIG Check - $($($_.Name).split(".")[0])"

            Write-Debug "[$($MyInvocation.MyCommand)] Script Path: $PSScriptRoot\$STIG\$($_.Name)"

            # Perform Check
            $check = . "$PSScriptRoot\$STIG\$($_.Name)" $PreCheck

            # Check SCAP Benchmark if provided.
            if ($SCAPBenchmark) {

                Write-Verbose "[$($MyInvocation.MyCommand)] retrieving Rule ID for '$($check.VulnID)'"

                $ruleID = Get-FindingAttribute -Checklist $ckl -VulnID $check.VulnID  -Attribute "Rule_ID"

                Write-Verbose "[$($MyInvocation.MyCommand)] Searching SCAP Benchmark for '$($check.VulnID)' [$ruleID]  status"

                if ($SCAP.RuleID -contains $ruleID) {

                    Write-Verbose "[$($MyInvocation.MyCommand)] Found SCAP data for '$($check.VulnID)' [$ruleID]"

                    # See if the check passed or failed and update check.
                    $scapResult = $($SCAP | Where-Object { $_.RuleID -eq $ruleID }).Result

                    Write-Verbose "[$($MyInvocation.MyCommand)] Found SCAP Check '$($ruleID)' with a result of '$scapResult'"

                    # if the scap result and check both pass
                    if ($scapResult -eq "pass" -and $check.Status -eq "NotAFinding") {

                        # Update Checklist
                        Set-ChecklistItem -Checklist $CKL -VulnID $check.VulnID -Details $PassedSCAPFinding -Status "NotAFinding" -Comments $check.Comments

                    }
                    elseif ($scapResult -eq "fail" -and $check.Status -eq "NotAFinding") {
                        # if scap result failed but the check passes
                        $comment = "SCAP found this as a fail but the automated check found it as Not a Finding. Review comments and update status."

                        # Update Checklist
                        Set-ChecklistItem -Checklist $CKL -VulnID $check.VulnID -Details $comment -Status "Open" -Comments $check.Comments

                    }
                    elseif ($scapResult -eq "pass" -and $check.Status -eq "Open") {
                        # if scap result passed but the check failed
                        $comment = "SCAP found this as a pass but the automated check found it as a Finding. Review comments and update status."

                        # Update Checklist
                        Set-ChecklistItem -Checklist $CKL -VulnID $check.VulnID -Details $comment -Status "Open" -Comments $check.Comments

                    }
                    elseif ($scapResult -eq "fail" -and $check.Status -eq "Open") {

                        # Update Checklist
                        Set-ChecklistItem -Checklist $CKL -VulnID $check.VulnID -Details $FailedSCAPFinding -Status "Open" -Comments $check.Comments

                    }
                    else {

                        Write-Verbose "[$($MyInvocation.MyCommand)] Unkown Selection SCAP:'$scapResult' Check: '$($check.Status)'"
                        #TODO: Need review incase were missing an option
                        #Set-ChecklistItem -Checklist $CKL -VulnID $check.VulnID -Comments $check.Comments

                    }

                    # Clear Entry from benchmark
                    $SCAP = $SCAP | Where-Object { $_.RuleID -ne $ruleID }

                }
                else {

                    Write-Verbose "[$($MyInvocation.MyCommand)] No SCAP Checks for '$($check.VulnID)'"

                    # Update Checklist
                    Set-ChecklistItem -Checklist $CKL -VulnID $check.VulnID -Details $FailedSCAPFinding -Status $check.Status -Comments $check.Comments

                }

            }
            else {

                # Update Checklist
                Set-ChecklistItem -Checklist $CKL @check

            }



        }
        Catch {
            Write-Error $_
        }

    }

    # Check remaining SCAP Entries and update checklist
    if ($SCAPBenchmark) {

        Write-Verbose "[$($MyInvocation.MyCommand)] Updating Checklist with Remaining SCAP Findings that didnt have an automated check."

        $SCAP | ForEach-Object {

            #TODO: Add a check to see if the ruleid has alread been updated, if so we need to add some safty logic so we dont overwrite the findings.
            if ($_.result -eq "pass") {

                Write-Verbose "[$($MyInvocation.MyCommand)] Updating $($_.RuleID) [Pass]"

                # Update Checklist
                Set-ChecklistItem -Checklist $CKL -RuleID $_.RuleID -Details $PassedSCAPFinding -Status "NotAFinding"

            }
            else {

                Write-Verbose "[$($MyInvocation.MyCommand)] Updating $($_.RuleID) [Open]"

                # Update Checklist
                Set-ChecklistItem -Checklist $CKL -RuleID $_.RuleID -Details $FailedSCAPFinding -Status "Open"

            }

        }

    }

    # Save Checklist
    Write-Verbose "[$($MyInvocation.MyCommand)] Saving Updated Checklist"

    Export-Checklist -Checklist $CKL -Path $Checklist

    # Output How long it took
    Write-Verbose "[$($MyInvocation.MyCommand)] $STIG Check Took $(((Get-Date) - $StartTime).TotalSeconds) seconds to complete"

}