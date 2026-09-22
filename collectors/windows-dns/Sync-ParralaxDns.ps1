[CmdletBinding()]
param(
    # Les paramètres explicites ont priorité sur le fichier de configuration.
    [string]$ApiBaseUrl,
    [string]$CollectorToken,
    [string]$CollectorTokenFile,
    [string]$ServerName,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'Sync-ParralaxDns.json'),
    [Nullable[int]]$TimeoutSeconds,
    [Nullable[int]]$MaxAttempts,
    [Nullable[bool]]$IncludeReverseLookupZones
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-ConfigValue {
    param(
        [AllowNull()]$Config,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$DefaultValue
    )

    if ($null -ne $Config -and $Config.PSObject.Properties.Name -contains $Name) {
        return $Config.$Name
    }
    return $DefaultValue
}

function Resolve-ConfiguredPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$BaseDirectory
    )

    if ([IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return Join-Path $BaseDirectory $Path
}

function Get-RecordValue {
    param([Parameter(Mandatory = $true)]$Record)

    $data = $Record.RecordData
    switch ($Record.RecordType) {
        'A'     { return [string]$data.IPv4Address }
        'AAAA'  { return [string]$data.IPv6Address }
        'CNAME' { return [string]$data.HostNameAlias }
        'DNAME' { return [string]$data.HostNameAlias }
        'NS'    { return [string]$data.NameServer }
        'MX'    { return "$($data.Preference) $($data.MailExchange)" }
        'PTR'   { return [string]$data.PtrDomainName }
        'SRV'   { return "$($data.Priority) $($data.Weight) $($data.Port) $($data.DomainName)" }
        'TXT'   { return ($data.DescriptiveText -join '') }
        'CAA'   { return "$($data.Flags) $($data.Tag) $($data.Value)" }
        default { return [string]$data }
    }
}

function Send-ParralaxInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][byte[]]$Body,
        [Parameter(Mandatory = $true)][int]$RequestTimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$RequestMaxAttempts
    )

    $headers = @{ 'X-Parralax-Collector-Token' = $Token }

    for ($attempt = 1; $attempt -le $RequestMaxAttempts; $attempt++) {
        try {
            return Invoke-RestMethod -Method Post -Uri $Uri -Headers $headers `
                -ContentType 'application/json; charset=utf-8' -Body $Body `
                -TimeoutSec $RequestTimeoutSeconds `
                -UserAgent 'Parralax-DNS-Windows-Collector/1.0'
        }
        catch {
            $statusCode = $null
            if ($null -ne $_.Exception.Response) {
                try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
            }

            # Une erreur d'authentification ou de validation ne sera pas corrigée
            # par une nouvelle tentative. Les erreurs réseau, 408, 429 et 5xx le peuvent.
            $retryable = ($null -eq $statusCode) -or ($statusCode -eq 408) -or `
                ($statusCode -eq 429) -or ($statusCode -ge 500)
            if (-not $retryable -or $attempt -eq $RequestMaxAttempts) {
                $statusLabel = if ($null -eq $statusCode) { 'indisponible' } else { [string]$statusCode }
                throw "Envoi de l'inventaire Parralax-DNS impossible (statut HTTP $statusLabel, tentative $attempt/$RequestMaxAttempts)."
            }

            $delaySeconds = [Math]::Min(30, [Math]::Pow(2, $attempt - 1))
            Write-Warning "Envoi impossible, nouvelle tentative dans $delaySeconds seconde(s) ($attempt/$RequestMaxAttempts)."
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

$configWasExplicit = $PSBoundParameters.ContainsKey('ConfigPath')
$config = $null
if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
    try {
        $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Le fichier de configuration '$ConfigPath' n'est pas un document JSON valide."
    }
}
elseif ($configWasExplicit) {
    throw "Le fichier de configuration '$ConfigPath' est introuvable."
}

$configDirectory = if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
    Split-Path -Parent (Resolve-Path -LiteralPath $ConfigPath).Path
} else {
    $PSScriptRoot
}

if (-not $PSBoundParameters.ContainsKey('ApiBaseUrl')) {
    $ApiBaseUrl = [string](Get-ConfigValue $config 'apiBaseUrl' '')
}
if (-not $PSBoundParameters.ContainsKey('CollectorTokenFile')) {
    $CollectorTokenFile = [string](Get-ConfigValue $config 'collectorTokenFile' '')
}
if (-not $PSBoundParameters.ContainsKey('ServerName')) {
    $ServerName = [string](Get-ConfigValue $config 'serverName' $env:COMPUTERNAME)
}
if (-not $PSBoundParameters.ContainsKey('TimeoutSeconds')) {
    $TimeoutSeconds = [int](Get-ConfigValue $config 'timeoutSeconds' 120)
}
if (-not $PSBoundParameters.ContainsKey('MaxAttempts')) {
    $MaxAttempts = [int](Get-ConfigValue $config 'maxAttempts' 3)
}
if (-not $PSBoundParameters.ContainsKey('IncludeReverseLookupZones')) {
    $IncludeReverseLookupZones = [bool](Get-ConfigValue $config 'includeReverseLookupZones' $false)
}

if ([string]::IsNullOrWhiteSpace($ApiBaseUrl)) {
    throw "apiBaseUrl est requis dans '$ConfigPath' ou via -ApiBaseUrl."
}
$parsedApiUri = $null
if (-not [Uri]::TryCreate($ApiBaseUrl, [UriKind]::Absolute, [ref]$parsedApiUri) -or $parsedApiUri.Scheme -ne 'https') {
    throw 'ApiBaseUrl doit être une URL HTTPS absolue.'
}
if ([string]::IsNullOrWhiteSpace($ServerName) -or $ServerName -notmatch '^[A-Za-z0-9._-]+$') {
    throw 'ServerName ne peut contenir que des lettres, chiffres, points, tirets et tirets bas.'
}
if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 3600) {
    throw 'TimeoutSeconds doit être compris entre 1 et 3600.'
}
if ($MaxAttempts -lt 1 -or $MaxAttempts -gt 10) {
    throw 'MaxAttempts doit être compris entre 1 et 10.'
}

# Ordre de résolution du secret : paramètre (usage interactif), variable
# d'environnement du compte de service, puis fichier protégé par ACL NTFS.
if ([string]::IsNullOrWhiteSpace($CollectorToken)) {
    $CollectorToken = [Environment]::GetEnvironmentVariable('PARRALAX_DNS_COLLECTOR_TOKEN')
}
if ([string]::IsNullOrWhiteSpace($CollectorToken) -and -not [string]::IsNullOrWhiteSpace($CollectorTokenFile)) {
    $resolvedTokenFile = Resolve-ConfiguredPath $CollectorTokenFile $configDirectory
    if (-not (Test-Path -LiteralPath $resolvedTokenFile -PathType Leaf)) {
        throw "Le fichier de jeton '$resolvedTokenFile' est introuvable."
    }
    $CollectorToken = (Get-Content -LiteralPath $resolvedTokenFile -Raw).Trim()
}
if ([string]::IsNullOrWhiteSpace($CollectorToken)) {
    throw 'Aucun jeton trouvé. Utilisez PARRALAX_DNS_COLLECTOR_TOKEN, collectorTokenFile ou -CollectorToken.'
}

Import-Module DnsServer -ErrorAction Stop

# Windows PowerShell 5.1 peut sinon négocier un protocole TLS obsolète selon la
# configuration globale du serveur. Ce réglage conserve les protocoles existants
# et garantit que TLS 1.2 est proposé.
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$allZones = Get-DnsServerZone
if (-not $IncludeReverseLookupZones) {
    $allZones = $allZones | Where-Object { -not $_.IsReverseLookupZone }
}

$zones = foreach ($zone in $allZones) {
    Write-Verbose "Lecture de la zone $($zone.ZoneName)."
    $records = foreach ($record in Get-DnsServerResourceRecord -ZoneName $zone.ZoneName) {
        [PSCustomObject]@{
            name  = [string]$record.HostName
            type  = [string]$record.RecordType
            value = Get-RecordValue $record
            ttl   = [int]$record.TimeToLive.TotalSeconds
        }
    }

    $policies = @()
    if (Get-Command Get-DnsServerQueryResolutionPolicy -ErrorAction SilentlyContinue) {
        $policies = @(Get-DnsServerQueryResolutionPolicy -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue |
            Select-Object Name, Action, AppliesOn, Condition)
    }

    [PSCustomObject]@{
        name             = [string]$zone.ZoneName
        zone_type        = [string]$zone.ZoneType
        is_ds_integrated = [bool]$zone.IsDsIntegrated
        dynamic_update   = [string]$zone.DynamicUpdate
        policies         = $policies
        records          = @($records)
    }
}

$payload = [PSCustomObject]@{
    server = $ServerName
    zones  = @($zones)
} | ConvertTo-Json -Depth 8 -Compress

$uri = $ApiBaseUrl.TrimEnd('/') + '/api/collectors/windows-dns/sync'
$body = [Text.Encoding]::UTF8.GetBytes($payload)
$result = Send-ParralaxInventory -Uri $uri -Token $CollectorToken -Body $body `
    -RequestTimeoutSeconds $TimeoutSeconds -RequestMaxAttempts $MaxAttempts

Write-Output $result
