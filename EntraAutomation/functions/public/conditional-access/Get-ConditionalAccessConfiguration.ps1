<#
.SYNOPSIS
    Retrieve Conditional Access policies, named locations, and Terms of Use agreements as PowerShell objects.

.DESCRIPTION
    Connects to Microsoft Graph to fetch all Conditional Access policies, named locations, and Terms of Use agreements.
    Resolves GUIDs for users, groups, applications, roles, locations, and ToU policies into human-readable names using in-memory caches.
    Supports interactive, certificate-based, system-assigned MI, or user-assigned MI authentication, and can reuse an existing Graph session.
    Returns a single object containing 'Policies', 'NamedLocations', and 'TermsOfUseAgreements'.

.EXAMPLE
    # Interactive connection
    Get-ConditionalAccessConfiguration

.NOTES
    Make sure to run Connect-MgGraph and connect with appropriate scopes.
    This function makes use of the CountryCodeLookup data file in this module("$PSScriptRoot\data\CountryCodeLookup.ps1") to resolve country codes to names.
#>
function Get-ConditionalAccessConfiguration {
    [CmdletBinding()]
    param (
        [switch]$UseExistingGraphSession
    )

    Try {
        #---------------------------------------------------------------------
        # 1. Import required modules
        #---------------------------------------------------------------------
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        Import-Module Microsoft.Graph.Groups -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

        #---------------------------------------------------------------------
        # 2. Connect to Graph if required
        #---------------------------------------------------------------------
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Connect-MgGraph -Scopes 'Policy.Read.All', 'Directory.Read.All', 'Agreement.Read.All', 'CrossTenantInformation.ReadBasic.All' -NoWelcome -ErrorAction Stop
        }

        #---------------------------------------------------------------------
        # 3. Fetch data
        #---------------------------------------------------------------------
        $policies = Get-MgIdentityConditionalAccessPolicy -All
        $namedLocs = @(Get-MgIdentityConditionalAccessNamedLocation -All)
        $touAgreements = @(Get-MgIdentityGovernanceTermsOfUseAgreement -All)

        #---------------------------------------------------------------------
        # 4. Initialize caches
        #---------------------------------------------------------------------
        # Note that the country lookup used for named locations is a global variable
        # defined in the data portion of this module.
        $userCache = @{}
        $groupCache = @{}
        $appCache = @{}
        $roleCache = @{}
        $touCache = @{}

        foreach ($tou in $touAgreements) {
            $touCache[$tou.Id] = $tou.DisplayName
        }

        #---------------------------------------------------------------------
        # 5. Resolver function for IDs and tokens
        #---------------------------------------------------------------------
        function Resolve-Entity {
            param(
                [string]$Id,
                [ValidateSet('User', 'Group', 'App', 'Role', 'Location', 'TermsOfUse', 'Tenant')] [string]$Type
            )

            if (-not $Id) {
                return $null
            }

            switch ($Id) {
                'All' { return 'All' }
                'None' { return 'None' }
                'GuestsOrExternalUsers' { return 'GuestsOrExternalUsers' }
                'AllTrusted' { return 'AllTrusted' }
                'Office365' { 'Office365' }
            }

            switch ($Type) {
                'User' {
                    if (-not $userCache.ContainsKey($Id)) {
                        $u = Get-MgUser -UserId $Id -ErrorAction SilentlyContinue
                        $userCache[$Id] = if ($u) { $u.UserPrincipalName } else { "UnknownUser($Id)" }
                    }
                    return [PSCustomObject]@{ Id = $Id; UserPrincipalName = $userCache[$Id] }
                }
                'Group' {
                    if (-not $groupCache.ContainsKey($Id)) {
                        $g = Get-MgGroup -GroupId $Id -ErrorAction SilentlyContinue
                        $groupCache[$Id] = if ($g) { $g.DisplayName } else { "UnknownGroup($Id)" }
                    }
                    return [PSCustomObject]@{ Id = $Id; DisplayName = $groupCache[$Id] }
                }
                'App' {
                    if (-not $appCache.ContainsKey($Id)) {
                        $sp = Get-MgServicePrincipal -Filter "appId eq '$Id'" -ErrorAction SilentlyContinue
                        $appCache[$Id] = if ($sp) { $sp.DisplayName } else { "UnknownApp($Id)" }
                    }
                    return [PSCustomObject]@{ Id = $Id; DisplayName = $appCache[$Id] }
                }
                'Role' {
                    if (-not $roleCache.ContainsKey($Id)) {
                        $rt = Get-MgDirectoryRoleTemplate -Filter "id eq '$Id'" -ErrorAction SilentlyContinue
                        $roleCache[$Id] = if ($rt) { $rt.DisplayName } else { "UnknownRole($Id)" }
                    }
                    return [PSCustomObject]@{ Id = $Id; DisplayName = $roleCache[$Id] }
                }
                'TermsOfUse' {
                    return [PSCustomObject]@{ Id = $Id; DisplayName = $touCache[$Id] -or "UnknownToU($Id)" }
                }
                'Tenant' {
                    Try {
                        return (Find-MgTenantRelationshipTenantInformationByTenantId -TenantId $Id).DisplayName
                    }
                    catch {
                        return "UnknownTenant($Id)"
                    }

                }
            }
        }

        #---------------------------------------------------------------------
        # 6. Build named location objects with IP ranges and Geo details
        #---------------------------------------------------------------------
        $namedLocationObjects = $namedLocs | ForEach-Object {

            # Convert the country codes to an array of objects holding the code and the country name.
            $countryCodes = $_.AdditionalProperties.countriesAndRegions
            $countries = foreach ($code in $countryCodes) {
                [pscustomobject]@{
                    Code = $code
                    Name = $script:CountryCodeLookup[$code]
                }
            }

            [PSCustomObject]@{
                Id                                = $_.Id
                CreatedDateTime                   = $_.CreatedDateTime
                ModifiedDateTime                  = $_.ModifiedDateTime
                DisplayName                       = $_.DisplayName
                IsTrusted                         = $_.AdditionalProperties.isTrusted
                IpRanges                          = $_.AdditionalProperties.ipRanges.cidrAddress
                Countries                         = $countries
                IncludeUnknownCountriesAndRegions = $_.AdditionalProperties.includeUnknownCountriesAndRegions
                CountryLookupMethod               = if ($_.AdditionalProperties.countryLookupMethod) { $_.AdditionalProperties.countryLookupMethod } else { $null }
            }
        }

        # ------------------------------------------------------------------
        # 7. Build policy objects
        # ------------------------------------------------------------------
        Write-Verbose 'Building policy objects…'
        $policyObjects = $policies | ForEach-Object {
            $p = $_
            [PSCustomObject]@{
                DisplayName                                 = $p.DisplayName
                PolicyId                                    = $p.Id
                State                                       = $p.State
                Created                                     = $p.CreatedDateTime
                Modified                                    = $p.ModifiedDateTime

                # ----- applications ------------------------------------------------------------
                # Based on https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0
                IncludeApps                                 = $p.Conditions.Applications.IncludeApplications | ForEach-Object { Resolve-Entity $_ 'App' }
                ExcludeApps                                 = $p.Conditions.Applications.ExcludeApplications | ForEach-Object { Resolve-Entity $_ 'App' }
                IncludeUserActions                          = $p.Conditions.Applications.IncludeUserActions
                ApplicationFilter                           = $p.Conditions.Applications.applicationFilter

                # ----- authenticationFlows ------------------------------------------------------------
                AuthenticationFlows                         = $p.Conditions.AuthenticationFlows

                # ----- clientApplications ------------------------------------------------------------
                ExcludeServicePrincipals                    = $p.Conditions.ClientApplications.excludeServicePrincipals
                IncludeServicePrincipals                    = $p.Conditions.ClientApplications.includeServicePrincipals
                ServicePrincipalFilterMode                  = $p.Conditions.ClientApplications.servicePrincipalFilter.mode
                ServicePrincipalFilterRule                  = $p.Conditions.ClientApplications.servicePrincipalFilter.rule

                # ----- clientAppTypes ------------------------------------------------------------
                ClientAppTypes                              = $p.Conditions.ClientAppTypes

                # ----- devices ------------------------------------------------------------
                DeviceFilterMode                            = $p.Conditions.Devices.DeviceFilter.Mode
                DeviceFilterRule                            = $p.Conditions.Devices.DeviceFilter.Rule

                # ----- locations ---------------------------------------------------------------
                IncludeLocations                            = $namedLocationObjects | Where-Object { $p.Conditions.Locations.IncludeLocations -contains $_.Id }
                ExcludeLocations                            = $namedLocationObjects | Where-Object { $p.Conditions.Locations.ExcludeLocations -contains $_.Id }

                # ----- platforms ---------------------------------------------------------------
                IncludePlatforms                            = $p.Conditions.Platforms.IncludePlatforms
                ExcludePlatforms                            = $p.Conditions.Platforms.ExcludePlatforms

                # ----- Risk Levels -----------------------------------------------
                UserRiskLevels                              = $p.Conditions.UserRiskLevels
                SignInRiskLevels                            = $p.Conditions.SignInRiskLevels
                InsiderRiskLevels                           = $p.Conditions.Users.InsiderRiskLevels

                # ----- Users / groups / roles --------------------------------------------------
                IncludeUsers                                = $p.Conditions.Users.IncludeUsers    | ForEach-Object { Resolve-Entity $_ 'User' }
                ExcludeUsers                                = $p.Conditions.Users.ExcludeUsers    | ForEach-Object { Resolve-Entity $_ 'User' }
                IncludeGroups                               = $p.Conditions.Users.IncludeGroups   | ForEach-Object { Resolve-Entity $_ 'Group' }
                ExcludeGroups                               = $p.Conditions.Users.ExcludeGroups   | ForEach-Object { Resolve-Entity $_ 'Group' }
                IncludeRoles                                = $p.Conditions.Users.IncludeRoles    | ForEach-Object { Resolve-Entity $_ 'Role' }
                ExcludeRoles                                = $p.Conditions.Users.ExcludeRoles    | ForEach-Object { Resolve-Entity $_ 'Role' }
                IncludeGuestsOrExternalUsers                = $p.Conditions.Users.IncludeGuestsOrExternalUsers.guestOrExternalUserTypes
                ExcludeGuestsOrExternalUsers                = $p.Conditions.Users.ExcludeGuestsOrExternalUsers.guestOrExternalUserTypes
                IncludeExternalTenantsMembershipKind        = $p.Conditions.Users.IncludeGuestsOrExternalUsers.externalTenants.MembershipKind
                IncludeExternalTenantsMembers               = $p.Conditions.Users.IncludeGuestsOrExternalUsers.externalTenants.AdditionalProperties.members | ForEach-Object { Resolve-Entity $_ 'Tenant' }
                ExcludeExternalTenantsMembershipKind        = $p.Conditions.Users.ExcludeGuestsOrExternalUsers.externalTenants.MembershipKind
                ExcludeExternalTenantsMembers               = $p.Conditions.Users.ExcludeGuestsOrExternalUsers.externalTenants.AdditionalProperties.members | ForEach-Object { Resolve-Entity $_ 'Tenant' }

                # ----- Grant controls ----------------------------------------------------------
                # Based on https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0
                BuiltInControls                             = $p.GrantControls.BuiltInControls
                customAuthenticationFactors                 = $p.GrantControls.CustomAuthenticationFactors
                TermsOfUse                                  = $p.GrantControls.TermsOfUse | ForEach-Object { Resolve-Entity $_ 'TermsOfUse' }
                Operator                                    = $p.GrantControls.Operator
                AuthenticationStrengthId                    = $p.GrantControls.AuthenticationStrength.Id
                AuthenticationStrengthDisplayName           = $p.GrantControls.AuthenticationStrength.DisplayName
                AuthenticationStrengthPolicyType            = $p.GrantControls.AuthenticationStrength.PolicyType
                AuthenticationStrengthAllowedCombinations   = $p.GrantControls.AuthenticationStrength.AllowedCombinations
                AuthenticationStrengthRequirementsSatisfied = $p.GrantControls.AuthenticationStrength.RequirementsSatisfied

                # ----- Session controls --------------------------------------------------------
                # Based on https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-1.0
                ApplicationEnforcedRestrictionsIsEnabled    = $p.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
                CloudAppSecurityType                        = $p.SessionControls.CloudAppSecurity.CloudAppSecurityType
                CloudAppSecurityIsEnabled                   = $p.SessionControls.CloudAppSecurity.IsEnabled
                DisableResilienceDefaults                   = $p.SessionControls.DisableResilienceDefaults
                PersistentBrowserIsEnabled                  = $p.SessionControls.PersistentBrowser.IsEnabled
                PersistentBrowserMode                       = $p.SessionControls.PersistentBrowser.Mode
                SignInFrequencyAuthenticationType           = $p.SessionControls.SignInFrequency.AuthenticationType
                SignInFrequencyInterval                     = $p.SessionControls.SignInFrequency.FrequencyInterval
                SignInFrequencyIsEnabled                    = $p.SessionControls.SignInFrequency.IsEnabled
                SignInFrequencyType                         = $p.SessionControls.SignInFrequency.Type
                SignInFrequencyValue                        = $p.SessionControls.SignInFrequency.Value
            }
        }

        #---------------------------------------------------------------------
        # 8. Combine and return results
        #---------------------------------------------------------------------
        $result = [PSCustomObject]@{
            Policies       = $policyObjects
            NamedLocations = $namedLocationObjects
        }
        return $result
    }
    catch {
        Write-Error "An unexpected error occurred: $($_.Exception.Message)"
    }
    finally {
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
