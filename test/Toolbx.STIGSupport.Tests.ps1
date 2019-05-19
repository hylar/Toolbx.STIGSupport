$ModuleManifestName = 'Toolbx.STIGSupport'
$ModuleManifestPath = "$PSScriptRoot\..\$ModuleManifestName\$ModuleManifestName.psd1"

Describe 'Module Manifest Tests' {
    It 'Passes Test-ModuleManifest' {
        Test-ModuleManifest -Path $ModuleManifestPath | Should Not BeNullOrEmpty
        $? | Should Be $true
    }
}
