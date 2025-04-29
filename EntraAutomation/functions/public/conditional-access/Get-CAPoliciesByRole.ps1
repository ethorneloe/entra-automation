<#
.SYNOPSIS
Find Conditional Access policies that reference a given role
in their Include / Exclude scopes.

.PARAMETER RolePattern
Entra Role name (case-insensitive).

.PARAMETER Scope
'Include', 'Exclude' or 'Both' (default).

.PARAMETER Config
The object produced by Get-CAPolicyConfiguration. Accepts pipeline input.

.EXAMPLE
$cfg | Find-CAPoliciesByRole -Role "Global Reader"

.EXAMPLE
$cfg | Find-CAPoliciesByRole -RolePattern "Global*" -Scope Exclude
#>
function Get-CAPoliciesByRole {
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
            @($_.IncludeRoles) + @($_.ExcludeRoles) |
            Where-Object { $_.DisplayName -like $RolePattern } |
            Select-Object -ExpandProperty DisplayName
        }
    }
}
