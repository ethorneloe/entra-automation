<#
.SYNOPSIS
Return Conditional Access policies that include or exclude a group
whose display-name matches a given pattern (wildcards allowed).

.DESCRIPTION
Searches IncludeGroups, ExcludeGroups, or both (-Scope).
Match is case-insensitive and supports PowerShell wildcards.
Accepts the configuration object from Get-CAPolicyConfiguration
via pipeline or -Config parameter.
Outputs PolicyId, DisplayName, State, Scope (Include / Exclude),
and the array of group names.

.PARAMETER Group
Group display-name or wildcard pattern, e.g. "BreakGlass Accounts", "HR*".

.PARAMETER Scope
'Include', 'Exclude', or 'Both' (default).

.PARAMETER Config
The object produced by Get-CAPolicyConfiguration. Accepts pipeline input.

.EXAMPLE
$cfg | Get-CAPoliciesByGroup -GroupPattern "BreakGlass Accounts"

.EXAMPLE
$cfg | Get-CAPoliciesByGroup -GroupPattern "HR*" -Scope Exclude
#>
function Get-CAPoliciesByGroup {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupPattern,

        [ValidateSet('Include', 'Exclude', 'Both')]
        [string]$Scope = 'Both',

        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject]$Config
    )

    $pattern = $GroupPattern.Trim()

    $Config.Policies |
    Where-Object {
        $incHit = $_.IncludeGroups | Where-Object { $_.DisplayName -like $pattern }
        $excHit = $_.ExcludeGroups | Where-Object { $_.DisplayName -like $pattern }

        switch ($Scope) {
            'Include' { $incHit }
            'Exclude' { $excHit }
            default { $incHit -or $excHit }
        }
    } |
    Select-Object PolicyId, DisplayName, State,
    @{Name = 'Scope'; Expression = {
            @(
                if ($_.IncludeGroups.DisplayName -like $pattern) { 'Include' }
                if ($_.ExcludeGroups.DisplayName -like $pattern) { 'Exclude' }
            ) -join ', '
        }
    },
    @{Name = 'MatchedGroups'; Expression = {
            @($_.IncludeGroups) + @($_.ExcludeGroups) |
            Where-Object { $_.DisplayName -like $pattern } |
            Select-Object -Expand DisplayName
        }
    }
}
