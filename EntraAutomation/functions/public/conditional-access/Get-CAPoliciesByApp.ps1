<#
.SYNOPSIS
Return Conditional Access policies that include or exclude an application
whose display-name matches a given pattern (wildcards allowed).

.DESCRIPTION
Searches IncludeApps, ExcludeApps, or both (-Scope).
Match is case-insensitive and supports PowerShell wildcards.
Accepts the configuration object from Get-CAPConfiguration
via pipeline or -Config parameter.
Outputs PolicyId, DisplayName, State, Scope (Include / Exclude),
and the array of app names.

.PARAMETER App
App display-name or wildcard pattern.

.PARAMETER Scope
'Include', 'Exclude', or 'Both' (default).

.PARAMETER Config
The object produced by Get-CAPolicyConfiguration. Accepts pipeline input.

.EXAMPLE
$cfg | Get-CAPoliciesByApp -AppPattern "Sharepoint"

.EXAMPLE
$cfg | Get-CAPoliciesByApp -AppPattern "Microsoft*" -Scope Exclude
#>
function Get-CAPoliciesByApp {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AppPattern,

        [ValidateSet('Include', 'Exclude', 'Both')]
        [string]$Scope = 'Both',

        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject]$Config
    )

    $pattern = $AppPattern.Trim()

    $Config.Policies |
    Where-Object {
        $incHit = $_.IncludeApps | Where-Object { $_.DisplayName -like $pattern }
        $excHit = $_.ExcludeApps | Where-Object { $_.DisplayName -like $pattern }

        switch ($Scope) {
            'Include' { $incHit }
            'Exclude' { $excHit }
            default { $incHit -or $excHit }
        }
    } |
    Select-Object PolicyId, DisplayName, State,
    @{Name = 'Scope'; Expression = {
            @(
                if ($_.IncludeApps.DisplayName -like $pattern) { 'Include' }
                if ($_.ExcludeApps.DisplayName -like $pattern) { 'Exclude' }
            ) -join ', '
        }
    },
    @{Name = 'MatchedApps'; Expression = {
            @($_.IncludeApps) + @($_.ExcludeApps) |
            Where-Object { $_.DisplayName -like $pattern } |
            Select-Object -Expand DisplayName
        }
    }
}
