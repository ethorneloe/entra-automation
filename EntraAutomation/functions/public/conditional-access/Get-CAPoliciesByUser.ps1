<#
.SYNOPSIS
Return Conditional Access policies that include or exclude a group
whose display-name matches a given pattern (wildcards allowed).

.DESCRIPTION
Searches IncludeUsers, ExcludeUsers, or both (-Scope).
Match is case-insensitive and supports PowerShell wildcards.
Accepts the configuration object from Get-CAPolicyConfiguration
via pipeline or -Config parameter.
Outputs PolicyId, DisplayName, State, Scope (Include / Exclude),
and the array of User UPNs.

.PARAMETER User
User UPN or wildcard pattern, e.g. "John.Smith@domain.com", "*admin*".

.PARAMETER Scope
'Include', 'Exclude', or 'Both' (default).

.PARAMETER Config
The object produced by Get-CAPolicyConfiguration. Accepts pipeline input.

.EXAMPLE
$cfg | Get-CAPoliciesByUser -UserPattern "John.Smith@domain.com"

.EXAMPLE
$cfg | Get-CAPoliciesByUser -UserPattern "*admin*" -Scope Exclude
#>
function Get-CAPoliciesByUser {

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
        $incHit = $_.IncludeUsers | Where-Object { $_.DisplayName -like $pattern }
        $excHit = $_.ExcludeUsers | Where-Object { $_.DisplayName -like $pattern }

        switch ($Scope) {
            'Include' { $incHit }
            'Exclude' { $excHit }
            default { $incHit -or $excHit }
        }
    } |
    Select-Object PolicyId, DisplayName, State,
    @{Name = 'Scope'; Expression = {
            @(
                if ($_.IncludeUsers.DisplayName -like $pattern) { 'Include' }
                if ($_.ExcludeUsers.DisplayName -like $pattern) { 'Exclude' }
            ) -join ', '
        }
    },
    @{Name = 'MatchedGroups'; Expression = {
            @($_.IncludeUsers) + @($_.ExcludeUsers) |
            Where-Object { $_.DisplayName -like $pattern } |
            Select-Object -Expand DisplayName
        }
    }
}
