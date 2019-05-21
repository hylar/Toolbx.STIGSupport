Function Start-STIGViewer {

    [CmdletBinding()]
    param()

    Try {
        Start-Process -FilePath .\Toolbx.STIGSupport\tools\STIGViewer-2.9.jar
    }
    Catch {
        $PSCmdlet.ThrowTerminatingError( $_ )
    }

}