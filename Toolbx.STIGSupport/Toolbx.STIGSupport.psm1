# Temporary - is replaced by BuildPSM1 Task

$functionFolders = @('public', 'private')
ForEach ($folder in $functionFolders) {
    $folderPath = Join-Path -Path "$PSScriptRoot" -ChildPath $folder
    If (Test-Path -Path $folderPath) {

        Write-Verbose -Message "Importing from $folder"

        $functions = Get-ChildItem -Path $folderPath -Filter '*.ps1' -Exclude "*.check.ps1" -Recurse

        ForEach ($function in $functions) {
            Write-Verbose -Message "  Importing $($function.BaseName)"
            . $($function.FullName)
        }
    }
}
$publicFunctions = (Get-ChildItem -Path "$PSScriptRoot\public" -Filter '*.ps1' -Recurse).BaseName
Export-ModuleMember -Function $publicFunctions