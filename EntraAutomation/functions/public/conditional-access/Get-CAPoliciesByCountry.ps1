<#
.SYNOPSIS
Find Conditional Access policies that reference a given country
(via any Named Location) in their Include / Exclude scopes.

.PARAMETER CountryPattern
English country name (case-insensitive).

.PARAMETER Scope
'Include', 'Exclude' or 'Both' (default).

.PARAMETER Config
The object produced by Get-CAPolicyConfiguration
(must contain .Policies and .NamedLocations).
Accepts pipeline input.

.EXAMPLE
$cfg | Find-CAPoliciesByCountry -CountryPattern "Brazil"
.EXAMPLE
$cfg | Find-CAPoliciesByCountry -CountryPattern "United*" -Scope Exclude
#>
function Get-CAPoliciesByCountry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CountryPattern,

        [ValidateSet('Include', 'Exclude', 'Both')]
        [string]$Scope = 'Both',

        [Parameter(ValueFromPipeline, Mandatory = $true)]
        [psobject]$Config
    )

    process {
        # Find matching countries
        $countries = ($script:CountryCodeLookup.GetEnumerator() |
            Where-Object { $_.Value -like $CountryPattern })

        # Get the country codes
        $codes = $countries.Key
        if (-not $codes) { throw "Country '$CountryPattern' not recognized." }

        # Named locations that reference the country codes
        $matchedLocations = $Config.NamedLocations |
        Where-Object { $_.Countries.Code | Where-Object { $codes -contains $_ } } |
        Select-Object Id, Countries

        if (-not $matchedLocations) { return }   # nothing references this country

        # Policies that reference those named locations
        $Config.Policies | Where-Object {
            (($Scope -in 'Include', 'Both') -and
            ($_.IncludeLocations.Id | Where-Object { $matchedLocations.Id -contains $_ })) -or
            (($Scope -in 'Exclude', 'Both') -and
            ($_.ExcludeLocations.Id | Where-Object { $matchedLocations.Id -contains $_ }))
        } | Select-Object PolicyId, DisplayName, State,
        @{Name = 'Scope'; Expression = {
                @(
                    if ($_.IncludeLocations.Id | Where-Object { $matchedLocations.Id -contains $_ }) { 'Include' }
                    if ($_.ExcludeLocations.Id | Where-Object { $matchedLocations.Id -contains $_ }) { 'Exclude' }
                ) -join ','
            }
        },
        @{Name = 'NamedLocations'; Expression = {
                @($_.IncludeLocations) + @($_.ExcludeLocations) |
                Where-Object { $matchedLocations.Id -contains $_.Id }
            }
        },
        @{Name = 'MatchedCountries'; Expression = {
                # Grab the named-location objects referenced by this policy
                $locs = @($_.IncludeLocations) + @($_.ExcludeLocations)
                $matchedLocations |
                Where-Object { $locs.Id -eq $_.Id } | Select-Object -ExpandProperty Countries | Where-Object { $_.Code -in $codes }
            }
        }
    }
}
