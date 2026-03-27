<#
.SYNOPSIS
    Registers SovereignShift app registrations in source and/or destination tenants.

.DESCRIPTION
    Creates Entra ID app registrations with self-signed certificates and required
    API permissions for the SovereignShift migration orchestrator. Supports
    Commercial (graph.microsoft.com) and GCCH (graph.microsoft.us) endpoints.

.PARAMETER Mode
    Which tenant(s) to register. Valid values: Source, Destination, Both.
    Defaults to Both.

.PARAMETER SourceTenantId
    The tenant ID of the source tenant. Prompted interactively if not provided.

.PARAMETER SourceCloud
    The cloud environment of the source tenant. Valid values: Commercial, GCCH.
    Defaults to Commercial.

.PARAMETER DestTenantId
    The tenant ID of the destination tenant. Prompted interactively if not provided.

.PARAMETER DestCloud
    The cloud environment of the destination tenant. Valid values: Commercial, GCCH.
    Defaults to GCCH.

.EXAMPLE
    .\Register-Apps.ps1
    Runs in interactive mode, prompts for all required information.

.EXAMPLE
    .\Register-Apps.ps1 -Mode Source -SourceTenantId "your-tenant-id" -SourceCloud Commercial
    Registers the source app only in a Commercial tenant.
#>

#Requires -Version 7.4

# PSScriptAnalyzer suppressions — Write-Host is intentional for TUI color output
# pssa:disable PSAvoidUsingWriteHost, PSUseShouldProcessForStateChangingFunctions
[CmdletBinding()]
param (
    [ValidateSet('Source', 'Destination', 'Both')]
    [string]$Mode = 'Both',

    [string]$SourceTenantId,

    [ValidateSet('Commercial', 'GCCH')]
    [string]$SourceCloud = 'Commercial',

    [string]$DestTenantId,

    [ValidateSet('Commercial', 'GCCH')]
    [string]$DestCloud = 'GCCH'
)

Import-Module Microsoft.Graph.Beta.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Beta.Identity.DirectoryManagement -ErrorAction Stop

#region Constants

$Script:GraphEndpoints = @{
    Commercial = 'https://graph.microsoft.com'
    GCCH       = 'https://graph.microsoft.us'
}

$Script:AuthEndpoints = @{
    Commercial = 'https://login.microsoftonline.com'
    GCCH       = 'https://login.microsoftonline.us'
}

$Script:ConfigPath = Join-Path $PSScriptRoot '..\Config\orchestrator.config.json'
$Script:OutputPath = Join-Path $PSScriptRoot '..\Config'

$Script:RequiredPermissions = @(
    'Mailbox.Migration'
    'Mail.ReadWrite'
    'Contacts.ReadWrite'
    'User.Read.All'
)

$Script:CertValidityYears = 2
$Script:AppPrefix = 'SovereignShift'

#endregion

#region Helper Functions

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )

    $colors = @{
        Info    = 'Cyan'
        Success = 'Green'
        Warning = 'Yellow'
        Error   = 'Red'
    }

    $prefixes = @{
        Info    = '  [~]'
        Success = '  [+]'
        Warning = '  [!]'
        Error   = '  [X]'
    }

    Write-Host "$($prefixes[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host "  $('─' * 60)" -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor White
    Write-Host "  $('─' * 60)" -ForegroundColor DarkGray
    Write-Host ""
}

function Get-OrchestratorConfig {
    if (Test-Path $Script:ConfigPath) {
        return Get-Content $Script:ConfigPath -Raw | ConvertFrom-Json
    }
    return [PSCustomObject]@{
        Source      = $null
        Destination = $null
    }
}

function Save-OrchestratorConfig {
    param([PSCustomObject]$Config)

    $configDir = Split-Path $Script:ConfigPath -Parent
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    $Config | ConvertTo-Json -Depth 10 | Set-Content $Script:ConfigPath -Force
    Write-Status "Configuration saved to $Script:ConfigPath" -Type Success
}

function Show-CurrentState {
    param([PSCustomObject]$Config)

    Write-SectionHeader "Current Configuration State"

    $sourceStatus = if ($Config.Source) {
        "$([char]0x2713) Configured  |  TenantId: $($Config.Source.TenantId)  |  Cloud: $($Config.Source.Cloud)"
    } else {
        "$([char]0x2717) Not configured"
    }

    $destStatus = if ($Config.Destination) {
        "$([char]0x2713) Configured  |  TenantId: $($Config.Destination.TenantId)  |  Cloud: $($Config.Destination.Cloud)"
    } else {
        "$([char]0x2717) Not configured"
    }

    $sourceColor = if ($Config.Source) { 'Green' } else { 'Yellow' }
    $destColor   = if ($Config.Destination) { 'Green' } else { 'Yellow' }

    Write-Host "  Source Tenant:      " -NoNewline
    Write-Host $sourceStatus -ForegroundColor $sourceColor
    Write-Host "  Destination Tenant: " -NoNewline
    Write-Host $destStatus -ForegroundColor $destColor
    Write-Host ""
}

#endregion

#region Certificate Management

function New-SovereignShiftCert {
    param(
        [string]$TenantRole,  # 'Source' or 'Destination'
        [string]$TenantId
    )

    $certName = "$Script:AppPrefix-$TenantRole-$($TenantId.Substring(0,8))"
    $certStore = 'Cert:\CurrentUser\My'

    Write-Status "Generating self-signed certificate: $certName"

    # Check if cert already exists
    $existingCert = Get-ChildItem $certStore | Where-Object { $_.Subject -eq "CN=$certName" }

    if ($existingCert) {
        Write-Status "Certificate '$certName' already exists in local store." -Type Warning
        $choice = Read-Host "  Use existing cert? (Y) or generate new? (N)"

        if ($choice -eq 'Y' -or $choice -eq 'y') {
            Write-Status "Using existing certificate: $($existingCert.Thumbprint)" -Type Info
            return $existingCert
        }

        # Remove old cert before generating new one
        Remove-Item "$certStore\$($existingCert.Thumbprint)" -Force
        Write-Status "Removed existing certificate." -Type Warning
    }

    # Generate the new self-signed cert
    $certParams = @{
        Subject           = "CN=$certName"
        CertStoreLocation = $certStore
        KeyExportPolicy   = 'NonExportable'
        KeySpec           = 'Signature'
        KeyLength         = 2048
        HashAlgorithm     = 'SHA256'
        NotAfter          = (Get-Date).AddYears($Script:CertValidityYears)
        KeyUsage          = 'DigitalSignature'
    }

    try {
        $cert = New-SelfSignedCertificate @certParams
        Write-Status "Certificate generated successfully." -Type Success
        Write-Status "Thumbprint : $($cert.Thumbprint)" -Type Info
        Write-Status "Expires    : $($cert.NotAfter.ToString('yyyy-MM-dd'))" -Type Info
        return $cert
    }
    catch {
        Write-Status "Failed to generate certificate: $_" -Type Error
        throw
    }
}

function Get-CertPublicKeyBase64 {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

    # Export public key bytes only (no private key) for upload to Entra
    $certBytes = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    return [System.Convert]::ToBase64String($certBytes)
}

#endregion

#region App Registration

function Get-GraphPermissionId {
    param(
        [string]$Cloud
    )
    Write-Status "Resolving permission IDs for $Cloud..."
    try {
        # Get the Microsoft Graph service principal
        $graphSp = Get-MgBetaServicePrincipal -Filter "displayName eq 'Microsoft Graph'" -Top 1
        if (-not $graphSp) {
            throw "Could not locate Microsoft Graph service principal in tenant."
        }

        # Get the Exchange Online service principal (hosts Mailbox.Migration)
        $exchangeSp = Get-MgBetaServicePrincipal -Filter "appId eq '00000002-0000-0ff1-ce00-000000000000'" -Top 1
        if (-not $exchangeSp) {
            throw "Could not locate Exchange Online service principal in tenant."
        }

        $graphPermissions    = @{}
        $exchangePermissions = @{}

        # Resolve Graph-hosted permissions (everything except Mailbox.Migration)
        $graphScoped = $Script:RequiredPermissions | Where-Object { $_ -ne 'Mailbox.Migration' }
        foreach ($permission in $graphScoped) {
            $appRole = $graphSp.AppRoles | Where-Object {
                $_.Value -eq $permission -and $_.AllowedMemberTypes -contains 'Application'
            }
            if ($appRole) {
                $graphPermissions[$permission] = $appRole.Id
                Write-Status "Resolved (Graph)    : $permission -> $($appRole.Id)" -Type Info
            }
            else {
                Write-Status "Could not resolve Graph permission: $permission" -Type Warning
            }
        }

        # Resolve Exchange-hosted Mailbox.Migration
        $exchangeRole = $exchangeSp.AppRoles | Where-Object {
            $_.Value -eq 'Mailbox.Migration' -and $_.AllowedMemberTypes -contains 'Application'
        }
        if ($exchangeRole) {
            $exchangePermissions['Mailbox.Migration'] = $exchangeRole.Id
            Write-Status "Resolved (Exchange) : Mailbox.Migration -> $($exchangeRole.Id)" -Type Info
        }
        else {
            Write-Status "Could not resolve Exchange permission: Mailbox.Migration" -Type Warning
        }

        return [PSCustomObject]@{
            GraphAppId          = $graphSp.AppId
            ExchangeAppId       = $exchangeSp.AppId
            GraphPermissions    = $graphPermissions
            ExchangePermissions = $exchangePermissions
        }
    }
    catch {
        Write-Status "Failed to resolve permission IDs: $_" -Type Error
        throw
    }
}

function Register-SovereignShiftApp {
    param(
        [string]$TenantRole,  # 'Source' or 'Destination'
        [string]$TenantId,
        [string]$Cloud,
        [PSCustomObject]$ExistingConfig
    )

    Write-SectionHeader "Registering $TenantRole App ($Cloud Tenant)"

    $appName = "$Script:AppPrefix-$TenantRole"

    # Check if app already exists in config
    if ($ExistingConfig.$TenantRole) {
        Write-Status "An existing $TenantRole configuration was found:" -Type Warning
        Write-Status "App Name   : $appName" -Type Info
        Write-Status "TenantId   : $($ExistingConfig.$TenantRole.TenantId)" -Type Info
        Write-Status "ClientId   : $($ExistingConfig.$TenantRole.ClientId)" -Type Info
        Write-Host ""

        $choice = Read-Host "  Overwrite existing configuration? (Y) or Skip? (N)"
        if ($choice -ne 'Y' -and $choice -ne 'y') {
            Write-Status "Skipping $TenantRole registration." -Type Warning
            return $ExistingConfig.$TenantRole
        }
    }

    # Check if app already exists in Entra
    Write-Status "Checking for existing app registration in Entra..."
    $existingApp = Get-MgBetaApplication -Filter "displayName eq '$appName'" -Top 1

    if ($existingApp) {
        Write-Status "App '$appName' already exists in Entra (AppId: $($existingApp.AppId))" -Type Warning
        $choice = Read-Host "  Overwrite existing Entra app? (Y) or Skip? (N)"

        if ($choice -ne 'Y' -and $choice -ne 'y') {
            Write-Status "Skipping $TenantRole Entra registration." -Type Warning

            # Return existing app details without changes
            return [PSCustomObject]@{
                TenantRole  = $TenantRole
                TenantId    = $TenantId
                Cloud       = $Cloud
                ClientId    = $existingApp.AppId
                AppObjectId = $existingApp.Id
            }
        }

        # Remove existing app before recreating
        Write-Status "Removing existing app registration..." -Type Warning
        Remove-MgBetaApplication -ApplicationId $existingApp.Id
        Write-Status "Existing app removed." -Type Success
    }

    # Generate certificate
    $cert = New-SovereignShiftCert -TenantRole $TenantRole -TenantId $TenantId
    $certBase64 = Get-CertPublicKeyBase64 -Cert $cert

    # Build the key credential for the app registration
    $keyCredential = @{
        Type            = 'AsymmetricX509Cert'
        Usage           = 'Verify'
        Key             = [System.Convert]::FromBase64String($certBase64)
        DisplayName     = $cert.Subject
        StartDateTime   = $cert.NotBefore.ToString('o')
        EndDateTime     = $cert.NotAfter.ToString('o')
    }

    # Resolve permission IDs from Graph and Exchange
    $permissionIds = Get-GraphPermissionId -Cloud $Cloud

    # Build Graph resource access block
    $resourceAccessGraph = foreach ($permission in $permissionIds.GraphPermissions.Keys) {
        @{
            Id   = $permissionIds.GraphPermissions[$permission]
            Type = 'Role'
        }
    }

    # Build Exchange resource access block
    $resourceAccessExchange = foreach ($permission in $permissionIds.ExchangePermissions.Keys) {
        @{
            Id   = $permissionIds.ExchangePermissions[$permission]
            Type = 'Role'
        }
    }

    $requiredResourceAccess = @(
        @{
            ResourceAppId  = $permissionIds.GraphAppId
            ResourceAccess = @($resourceAccessGraph)
        }
        @{
            ResourceAppId  = $permissionIds.ExchangeAppId
            ResourceAccess = @($resourceAccessExchange)
        }
    )

    # Create the app registration
    Write-Status "Creating app registration: $appName..."

    try {
        $newApp = New-MgBetaApplication -DisplayName $appName `
            -KeyCredentials @($keyCredential) `
            -RequiredResourceAccess $requiredResourceAccess `
            -SignInAudience 'AzureADMyOrg'

        Write-Status "App registration created successfully." -Type Success
        Write-Status "App Name   : $($newApp.DisplayName)" -Type Info
        Write-Status "ClientId   : $($newApp.AppId)" -Type Info
        Write-Status "ObjectId   : $($newApp.Id)" -Type Info

        # Return the registration details
        return [PSCustomObject]@{
            TenantRole    = $TenantRole
            TenantId      = $TenantId
            Cloud         = $Cloud
            ClientId      = $newApp.AppId
            AppObjectId   = $newApp.Id
            CertThumbprint = $cert.Thumbprint
            CertExpiry    = $cert.NotAfter.ToString('yyyy-MM-dd')
        }
    }
    catch {
        Write-Status "Failed to create app registration: $_" -Type Error
        throw
    }
}

#endregion

#region Graph Connection

function Connect-TenantGraph {
    param(
        [string]$TenantId,
        [string]$Cloud,
        [string]$TenantRole
    )

    Write-SectionHeader "Connecting to $TenantRole Tenant ($Cloud)"
    Write-Status "You will be prompted to sign in as a Global Admin of the $TenantRole tenant."
    Write-Status "TenantId: $TenantId" -Type Info
    Write-Host ""

    $connectParams = @{
        TenantId = $TenantId
        Scopes   = @(
            'Application.ReadWrite.All'
            'AppRoleAssignment.ReadWrite.All'
        )
    }

    # Set the correct environment for the cloud
    switch ($Cloud) {
        'Commercial' {
            $connectParams['Environment'] = 'Global'
        }
        'GCCH' {
            $connectParams['Environment'] = 'USGov'
        }
    }

    try {
        Connect-MgGraph @connectParams -NoWelcome
        Write-Status "Connected to $TenantRole tenant successfully." -Type Success

        # Verify we connected to the correct tenant
        $context = Get-MgContext
        if ($context.TenantId -ne $TenantId) {
            Write-Status "Tenant mismatch detected!" -Type Error
            Write-Status "Expected : $TenantId" -Type Error
            Write-Status "Connected: $($context.TenantId)" -Type Error
            throw "Connected to wrong tenant. Disconnecting."
        }

        Write-Status "Tenant verified: $($context.TenantId)" -Type Success
        return $context
    }
    catch {
        Write-Status "Failed to connect to $TenantRole tenant: $_" -Type Error
        throw
    }
}

function Disconnect-TenantGraph {
    param([string]$TenantRole)

    try {
        Disconnect-MgGraph | Out-Null
        Write-Status "Disconnected from $TenantRole tenant." -Type Info
    }
    catch {
        # Non-fatal — just warn
        Write-Status "Could not cleanly disconnect from $TenantRole tenant." -Type Warning
    }
}

function New-ConsentUrl {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$Cloud,
        [string]$TenantRole
    )

    $baseUrl = switch ($Cloud) {
        'Commercial' { 'https://login.microsoftonline.com' }
        'GCCH'       { 'https://login.microsoftonline.us' }
    }

    $consentUrl = "$baseUrl/$TenantId/adminconsent?client_id=$ClientId"

    return [PSCustomObject]@{
        TenantRole = $TenantRole
        Cloud      = $Cloud
        TenantId   = $TenantId
        ClientId   = $ClientId
        ConsentUrl = $consentUrl
    }
}

function Show-ConsentSummary {
    param(
        [PSCustomObject[]]$ConsentLinks,
        [string]$OutputFilePath
    )

    Write-SectionHeader "Admin Consent Required"

    Write-Host "  The following URLs must be visited by a Global Admin of each tenant." -ForegroundColor White
    Write-Host "  This grants SovereignShift the permissions it needs to perform migrations." -ForegroundColor White
    Write-Host ""

    foreach ($link in $ConsentLinks) {
        Write-Host "  $($link.TenantRole) Tenant ($($link.Cloud))" -ForegroundColor Cyan
        Write-Host "  TenantId  : $($link.TenantId)" -ForegroundColor DarkGray
        Write-Host "  ClientId  : $($link.ClientId)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  $($link.ConsentUrl)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  $('─' * 60)" -ForegroundColor DarkGray
        Write-Host ""
    }

    Write-Status "Consent links written to: $OutputFilePath" -Type Success
}

function Save-ConsentLink {
    param(
        [PSCustomObject[]]$ConsentLinks,
        [PSCustomObject]$Registrations
    )

    $date      = Get-Date -Format 'yyyyMMdd'
    $fileName  = "ConsentLinks_$date.txt"
    $filePath  = Join-Path $Script:OutputPath $fileName

    $lines = @()
    $lines += "SovereignShift — Admin Consent Links"
    $lines += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lines += ""
    $lines += "=" * 60
    $lines += ""

    foreach ($link in $ConsentLinks) {
        $lines += "$($link.TenantRole) Tenant ($($link.Cloud))"
        $lines += "TenantId      : $($link.TenantId)"
        $lines += "ClientId      : $($link.ClientId)"

        # Include cert details if available
        $reg = $Registrations | Where-Object { $_.TenantRole -eq $link.TenantRole }
        if ($reg.CertThumbprint) {
            $lines += "Cert Thumbprint: $($reg.CertThumbprint)"
            $lines += "Cert Expiry    : $($reg.CertExpiry)"
        }

        $lines += ""
        $lines += "Consent URL:"
        $lines += $link.ConsentUrl
        $lines += ""
        $lines += "-" * 60
        $lines += ""
    }

    $lines += "INSTRUCTIONS"
    $lines += "-" * 60
    $lines += "1. Send the consent URL for each tenant to a Global Admin of that tenant."
    $lines += "2. The admin must sign in and click 'Accept' to grant the required permissions."
    $lines += "3. Once both tenants have consented, SovereignShift is ready to run."
    $lines += ""
    $lines += "Required Permissions:"
    foreach ($perm in $Script:RequiredPermissions) {
        $lines += "  - $perm"
    }

    $lines | Set-Content -Path $filePath -Encoding UTF8
    return $filePath
}

#endregion

#region Main Execution

function Get-TenantInput {
    param(
        [string]$TenantRole,
        [string]$TenantId,
        [string]$Cloud
    )

    # Collect TenantId if not provided
    if (-not $TenantId) {
        Write-Host ""
        $TenantId = Read-Host "  Enter the $TenantRole Tenant ID"
        if (-not $TenantId) {
            Write-Status "$TenantRole Tenant ID cannot be empty." -Type Error
            throw "$TenantRole Tenant ID is required."
        }
    }

    # Collect Cloud if not provided via parameter
    if (-not $PSBoundParameters.ContainsKey("${TenantRole}Cloud")) {
        Write-Host ""
        Write-Host "  Which cloud environment is the $TenantRole tenant on?" -ForegroundColor Cyan
        Write-Host "  [1] Commercial (graph.microsoft.com)" -ForegroundColor White
        Write-Host "  [2] GCCH       (graph.microsoft.us)"  -ForegroundColor White
        Write-Host ""

        $cloudChoice = Read-Host "  Enter choice (1 or 2)"
        $Cloud = switch ($cloudChoice) {
            '1'     { 'Commercial' }
            '2'     { 'GCCH' }
            default {
                Write-Status "Invalid choice. Defaulting to Commercial." -Type Warning
                'Commercial'
            }
        }
    }

    return [PSCustomObject]@{
        TenantId = $TenantId
        Cloud    = $Cloud
    }
}

# ─────────────────────────────────────────────
#  SCRIPT ENTRY POINT
# ─────────────────────────────────────────────

# Banner
Clear-Host
Write-Host ""
Write-Host "  ███████╗ ██████╗ ██╗   ██╗███████╗██████╗ ███████╗██╗ ██████╗ ███╗  ██╗" -ForegroundColor Cyan
Write-Host "  ██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██║██╔════╝ ████╗ ██║" -ForegroundColor Cyan
Write-Host "  ███████╗██║   ██║██║   ██║█████╗  ██████╔╝█████╗  ██║██║  ███╗██╔██╗██║" -ForegroundColor Cyan
Write-Host "  ╚════██║██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══╝  ██║██║   ██║██║╚████║" -ForegroundColor Cyan
Write-Host "  ███████║╚██████╔╝ ╚████╔╝ ███████╗██║  ██║███████╗██║╚██████╔╝██║ ╚███║" -ForegroundColor Cyan
Write-Host "  ╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚══╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  SovereignShift — App Registration Init Script" -ForegroundColor White
Write-Host "  Version 0.1.0  |  Microsoft 365 Cross-Tenant Migration Orchestrator" -ForegroundColor DarkGray
Write-Host ""

# Load existing config and show current state
$config = Get-OrchestratorConfig
Show-CurrentState -Config $config

# Determine which roles to register
$rolesToProcess = switch ($Mode) {
    'Source'      { @('Source') }
    'Destination' { @('Destination') }
    'Both'        { @('Source', 'Destination') }
}

# Collect tenant inputs
$tenantInputs = @{}

foreach ($role in $rolesToProcess) {
    Write-SectionHeader "Configure $role Tenant"

    $currentTenantId = if ($role -eq 'Source') { $SourceTenantId } else { $DestTenantId }
    $currentCloud    = if ($role -eq 'Source') { $SourceCloud    } else { $DestCloud     }

    $tenantInput = Get-TenantInput `
        -TenantRole $role `
        -TenantId   $currentTenantId `
        -Cloud      $currentCloud

    $tenantInputs[$role] = $tenantInput
}

# Process each role
$registrations = @()
$consentLinks  = @()

foreach ($role in $rolesToProcess) {
    $tenantId = $tenantInputs[$role].TenantId
    $cloud    = $tenantInputs[$role].Cloud

    try {
        # Connect to the correct tenant
        Connect-TenantGraph -TenantId $tenantId -Cloud $cloud -TenantRole $role

        # Register the app
        $registration = Register-SovereignShiftApp `
            -TenantRole      $role `
            -TenantId        $tenantId `
            -Cloud           $cloud `
            -ExistingConfig  $config

        $registrations += $registration

        # Build consent URL
        $consentLink = New-ConsentUrl `
            -TenantId   $tenantId `
            -ClientId   $registration.ClientId `
            -Cloud      $cloud `
            -TenantRole $role

        $consentLinks += $consentLink

        # Update config with new registration
        $config.$role = $registration

    }
    catch {
        Write-Status "Failed to process $role tenant: $_" -Type Error
        Write-Status "Attempting to disconnect cleanly before exiting..." -Type Warning
        Disconnect-TenantGraph -TenantRole $role
        exit 1
    }
    finally {
        Disconnect-TenantGraph -TenantRole $role
    }
}

# Save updated config
Save-OrchestratorConfig -Config $config

# Save consent links to file
$outputFile = Save-ConsentLink -ConsentLinks $consentLinks -Registrations $registrations

# Display consent summary
Show-ConsentSummary -ConsentLinks $consentLinks -OutputFilePath $outputFile

Write-SectionHeader "Registration Complete"
Write-Status "All app registrations completed successfully." -Type Success
Write-Status "Next step: Send the consent links to the Global Admin of each tenant." -Type Info
Write-Status "Once consent is granted, run the Pre-Flight Sanitizer to prepare for migration." -Type Info
Write-Host ""

#endregion