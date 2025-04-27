<#
.SYNOPSIS
Return Conditional Access policies that include or exclude a group
whose display-name matches a given pattern (wildcards allowed).

.DESCRIPTION
Searches IncludeGroups, ExcludeGroups, or both (-Scope).
Match is case-insensitive and supports PowerShell wildcards.
Accepts the configuration object from Get-ConditionalAccessConfiguration
via pipeline or -Config parameter.
Outputs PolicyId, DisplayName, State, Scope (Include / Exclude),
and the array of group names.

.PARAMETER Group
Group display-name or wildcard pattern, e.g. "BreakGlass Accounts", "HR*".

.PARAMETER Scope
'Include', 'Exclude', or 'Both' (default).

.PARAMETER Config
The configuration object (must expose .Policies). Accepts pipeline input.

.EXAMPLE
$cfg | Find-CAPoliciesByGroup -GroupPattern "BreakGlass Accounts"

.EXAMPLE
$cfg | Find-CAPoliciesByGroup -GroupPattern "HR*" -Scope Exclude
#>
function Find-CAPoliciesByGroup {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupPattern,

        [ValidateSet('Include', 'Exclude', 'Both')]
        [string]$Scope = 'Both',

        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject]$Config
    )

    process {
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
        @{N = 'Scope'; E = {
                @(
                    if ($_.IncludeGroups.DisplayName -like $pattern) { 'Include' }
                    if ($_.ExcludeGroups.DisplayName -like $pattern) { 'Exclude' }
                ) -join ', '
            }
        },
        @{N = 'MatchedGroups'; E = {
                    ($_.IncludeGroups + $_.ExcludeGroups |
                Where-Object { $_.DisplayName -like $pattern } |
                Select-Object -Expand DisplayName)
            }
        }
    }
}
