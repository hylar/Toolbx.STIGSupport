Function Start-STIGViewer {

    <#
        .SYNOPSIS
            Launch new instance of DISA STIG Viewer

        .DESCRIPTION
             Launch new instance of DISA STIG Viewer

        .EXAMPLE
            PS C:\> Start-STIGViewer

        .OUTPUTS
            None

        .NOTES
            None
    #>

    [CmdletBinding()]
    param()

    Try {

        Start-Process -FilePath .\Toolbx.STIGSupport\tools\STIGViewer-2.9.jar

    }
    Catch {

        $PSCmdlet.ThrowTerminatingError( $_ )

    }

}