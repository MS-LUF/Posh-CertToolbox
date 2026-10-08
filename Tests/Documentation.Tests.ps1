BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '../Posh-CertToolbox.psd1') -Force
}

Describe 'Comment-based help' -Tag Unit {
    InModuleScope 'Posh-CertToolbox' {
        BeforeAll {
            # Every function, public and private - not just exported cmdlets: a broken private
            # function's help is still a real regression (Get-Help on it silently returns
            # nothing useful).
            $script:allFunctionNames = Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public'), (Join-Path $script:ModuleRoot 'Private') `
                -Filter '*.ps1' -Recurse -File |
                ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) } |
                Sort-Object -Unique
        }

        It 'has at least the expected number of functions to check (sanity check on discovery itself)' {
            # Guards against this test silently checking nothing if the Get-ChildItem above ever
            # stops finding files - a real minimum, not a moving target.
            $script:allFunctionNames.Count | Should -BeGreaterOrEqual 31
        }

        It 'every function is defined in a file of the same name' {
            $missing = $script:allFunctionNames | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) }
            $missing | Should -BeNullOrEmpty
        }

        It 'every function''s comment-based help block is actually recognized by PowerShell' {
            # A help line that starts (after leading whitespace) with a literal "." - a prose
            # line wrapping right before a dot-prefixed term - is misparsed as an unknown help
            # keyword, which silently breaks recognition of the entire block. Get-Help then
            # shows a bare syntax line, with no error.
            $broken = foreach ($name in $script:allFunctionNames) {
                $command = Get-Command -Name $name -ErrorAction SilentlyContinue
                if (-not $command) { continue }
                $helpContent = $command.ScriptBlock.Ast.GetHelpContent()
                if (-not $helpContent -or -not $helpContent.Synopsis) { $name }
            }
            $broken | Should -BeNullOrEmpty -Because "these functions' comment-based help failed to parse - check for a wrapped line starting with a literal '.': $($broken -join ', ')"
        }
    }
}

Describe 'Internal design documents' -Tag Unit {
    It 'are not referenced from any file other than themselves' {
        # The two design documents are for people working on this repository. Code, help text,
        # the manifest and user documentation must stand on their own without pointing at them.
        # The names are assembled here so that this file does not match its own search.
        $internalNames = @(('Archi' + 'tecture.md'), ('CLAU' + 'DE.md'))
        $root = Join-Path $PSScriptRoot '..'

        $offenders = Get-ChildItem -Path $root -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1', '*.ps1xml', '*.json', '*.md', '*.xml', '*.txt' |
            Where-Object { $_.FullName -notmatch '[\\/](\.git|Sources)[\\/]' -and $internalNames -notcontains $_.Name } |
            Where-Object {
                $content = [System.IO.File]::ReadAllText($_.FullName)
                @($internalNames | Where-Object { $content.IndexOf($_, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count -gt 0
            } |
            ForEach-Object { $_.FullName.Substring((Resolve-Path $root).Path.Length).TrimStart('\', '/') }

        $offenders | Should -BeNullOrEmpty -Because "these files mention an internal design document: $($offenders -join ', ')"
    }
}

Describe 'Generated help files' -Tag Unit {
    BeforeAll {
        $script:repoRoot = Join-Path $PSScriptRoot '..'
        $script:publicNames = Get-ChildItem -Path (Join-Path $script:repoRoot 'Public') -Filter '*.ps1' -File |
            ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }
    }

    It 'has a page for every public cmdlet, with no placeholder left in it' {
        foreach ($name in $script:publicNames) {
            $page = Join-Path $script:repoRoot "Docs/$name.md"
            $page | Should -Exist
            [System.IO.File]::ReadAllText($page) | Should -Not -Match '\{\{'
        }
    }

    It 'documents every parameter of every public cmdlet in its page' {
        # Catches a parameter added to a cmdlet without regenerating the help.
        $common = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        $module = Import-Module (Join-Path $script:repoRoot 'Posh-CertToolbox.psd1') -Force -PassThru
        foreach ($name in $script:publicNames) {
            $content = [System.IO.File]::ReadAllText((Join-Path $script:repoRoot "Docs/$name.md"))
            $missing = $module.ExportedFunctions[$name].Parameters.Keys |
                Where-Object { $common -notcontains $_ -and $content -notmatch "(?m)^### -$_\s*$" }
            $missing | Should -BeNullOrEmpty -Because "Docs/$name.md lacks these parameters: $($missing -join ', ')"
        }
    }

    It 'has an external help entry for every public cmdlet' {
        $xml = [xml][System.IO.File]::ReadAllText((Join-Path $script:repoRoot 'en-US/Posh-CertToolbox-help.xml'))
        $documented = @($xml.helpItems.command | ForEach-Object { $_.details.name })

        ($documented | Sort-Object) -join ',' | Should -Be (($script:publicNames | Sort-Object) -join ',')
    }

    It 'has a module page whose help version matches the manifest' {
        $version = (Import-PowerShellDataFile (Join-Path $script:repoRoot 'Posh-CertToolbox.psd1')).ModuleVersion
        $page = [System.IO.File]::ReadAllText((Join-Path $script:repoRoot 'Docs/Posh-CertToolbox.md'))

        $page | Should -Match "(?m)^Help Version: $([regex]::Escape($version))\.0\s*$"
        $page | Should -Not -Match '\{\{'
    }
}

Describe 'Module manifest' -Tag Unit {
    It 'exports exactly the functions defined under Public' {
        $manifestPath = Join-Path $PSScriptRoot '../Posh-CertToolbox.psd1'
        $publicNames = Get-ChildItem -Path (Join-Path $PSScriptRoot '../Public') -Filter '*.ps1' -File |
            ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) } | Sort-Object
        $exported = (Import-Module $manifestPath -Force -PassThru).ExportedFunctions.Keys | Sort-Object

        ($exported -join ',') | Should -Be ($publicNames -join ',')
    }
}
