
#Merge-SCAPToChecklist -ChecklistPath "C:\Temp\U_MS_IE11_STIG_V1R17.ckl" -ScapPath "C:\Temp\SCAP_XCCDF-Results_IE_11_STIG-001.013.xml"
function Merge-SCAPToChecklist {

    [CmdletBinding()]
    param (

        # Specify the Path to the STIG Checklist.
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path -Path $_ })]
        [string]
        $ChecklistPath,

        # Specify the Path to the SCAP XCCDF file.
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path -Path $_ })]
        [string]
        $ScapPath,

        # Specify the Default Findings Result for checks that passed.
        [Parameter()]
        [string]
        $PassedFinding = "Vulnerability Closed by Automated Benchmark/SCAP Check.",

        # Specify the Default Findings Result for checks that passed.
        [Parameter()]
        [string]
        $FailedFinding = "Vulnerability Opened by Automated Benchmark/SCAP Check."

        #TODO: Add Parameter to copy host data over to checklist. This will require an update to the Set-CheclistHostData function.
    )

    $scapResults = Get-SCAPResults -XccdfPath $ScapPath
    $checklist = Import-Checklist -Path $ChecklistPath

    $scapResults | ForEach-Object {

        if ($_.result -eq "pass") {

            # Update Checklist
            Set-VulnIDFinding -Checklist $checklist -RuleID $_.RuleID -Details $PassedFinding -Status "NotAFinding"
        }
        else {

            # Update Checklist
            Set-VulnIDFinding -Checklist $checklist -RuleID $_.RuleID -Details $FailedFinding -Status "Open"

        }

    }

    Export-Checklist -Checklist $checklist -Path $ChecklistPath

}