<#
.SYNOPSIS
Find Conditional Access policies that reference a given country
(via any Named Location) in their Include / Exclude scopes.

.PARAMETER Country
English country name (case-insensitive).

.PARAMETER Scope
'Include', 'Exclude' or 'Both' (default).

.PARAMETER Config
The object produced by Get-ConditionalAccessConfiguration
(must contain .Policies and .NamedLocations).
Accepts pipeline input.

.EXAMPLE
$cfg | Find-CAPoliciesByCountry -Country Brazil

.EXAMPLE
$cfg | Find-CAPoliciesByCountry Japan -Scope Exclude
#>
function Find-CAPoliciesByRoleName {
    param(
        [Parameter(Mandatory)]
        [string]$RolePattern,

        [ValidateSet('Include', 'Exclude', 'Both')]
        [string]$Scope = 'Both',

        [Parameter(ValueFromPipeline, Mandatory = $true)]
        [psobject]$Config
    )

    $Config.Policies | Where-Object {
        $in = ($_.IncludeRoles | Where-Object { $_.DisplayName -like $RolePattern }).Count
        $ex = ($_.ExcludeRoles | Where-Object { $_.DisplayName -like $RolePattern }).Count
        switch ($Scope) {
            'Include' { $in }
            'Exclude' { $ex }
            'Both' { $in -or $ex }
        }
    } | Select-Object PolicyId, DisplayName, State,
    @{Name = 'Scope'; Expression = { @(
                if ($_.IncludeRoles.DisplayName -like $RolePattern) { 'Include' }
                if ($_.ExcludeRoles.DisplayName -like $RolePattern) { 'Exclude' }
            ) -join ', ' }
    },
    @{Name = 'MatchedRoles'; Expression = {
                ($_.IncludeRoles + $_.ExcludeRoles |
            Where-Object { $_.DisplayName -like $RolePattern } |
            Select-Object -ExpandProperty DisplayName)
        }
    }
}
