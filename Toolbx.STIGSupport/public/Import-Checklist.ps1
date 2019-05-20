Function Import-Checklist {

    Param(
        [Parameter(Mandatory = $true)]
        [ValidateScript( {Test-Path -Path $_})]
        [string]
        $Path
    )

    return [XML](Get-Content -Path $Path)

}
