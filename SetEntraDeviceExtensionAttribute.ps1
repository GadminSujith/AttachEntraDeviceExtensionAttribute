<# 
Author: Sujith
Reference:https://learn.microsoft.com/en-us/answers/questions/339746/filtering-doesnt-seem-to-work-on-a-newer-intuneap
Purpose: Add extension attributes to devices 
Uses Graph beta for Autopilot + device extensionAttributes
Ensure you have the following delegated permissions 
"Device.Read.All Device.ReadWrite.All Directory.Read.All offline_access DeviceManagementServiceConfig.Read.All DeviceManagementManagedDevices.Read.All "
#>


$Global:GraphBase    = "https://graph.microsoft.com"
$Global:GraphVersion = "beta"
<#
Change the variables according to your need
#>

$tenant = ""   
$client = ""
$Scope = "Device.Read.All Device.ReadWrite.All Directory.Read.All offline_access DeviceManagementServiceConfig.Read.All DeviceManagementManagedDevices.Read.All "
$SerialNumber= ""
$SelectedExtensionAttribute = "extensionAttribute15" #change it to whatever you want 1-15
$Value = "BYOD" #change it to whatever value you want to set on the device object



function Get-GraphInteractiveToken {
    param(
        [Parameter(Mandatory)][string]$TenantId,   
        [Parameter(Mandatory)][string]$ClientId,   
        [string]$Scopes = "Device.Read.All Device.ReadWrite.All Directory.Read.All offline_access DeviceManagementServiceConfig.Read.All DeviceManagementManagedDevices.Read.All ",
        [int]$Port
    )

  
    function New-CodeVerifier {
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[] 32
        $rng.GetBytes($bytes)
        [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
    }
    function New-CodeChallenge([string]$verifier) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [Text.Encoding]::ASCII.GetBytes($verifier)
        $hash  = $sha.ComputeHash($bytes)
        [Convert]::ToBase64String($hash).TrimEnd('=').Replace('+','-').Replace('/','_')
    }
    function UrlEnc([string]$s){ [System.Uri]::EscapeDataString($s) }
    function Open-Browser([string]$url){
        if ($IsWindows) { Start-Process $url | Out-Null; return }
        if ($IsMacOS)   { & open $url | Out-Null; return }
        if ($IsLinux)   { if (Get-Command xdg-open -ErrorAction SilentlyContinue) { & xdg-open $url | Out-Null } else { Start-Process $url | Out-Null } }
    }

  
    $authorizeBase = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize"
    $tokenUrl      = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

<# 
    if (-not $Port) { $Port = Get-Random -Minimum 49152 -Maximum 65535 }
    $redirectUri = "http://localhost:$Port/"
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try { $listener.Start() } catch { throw "Could not start localhost listener on $redirectUri. Try another port." }
#>

# --- loopback TCP listener (force IPv4) ---
if (-not $Port) { $Port = Get-Random -Minimum 49152 -Maximum 65535 }

# Use 127.0.0.1 explicitly to avoid IPv6/localhost quirks on Windows
$redirectUri = "http://127.0.0.1:$Port/"

# Bind to IPv4 loopback
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)

try { $listener.Start() } catch {
    throw "Could not start localhost listener on $redirectUri. Try another port."
}

# (optional but recommended) wait with timeout so it won't hang forever
$async = $listener.BeginAcceptTcpClient($null,$null)
if (-not $async.AsyncWaitHandle.WaitOne(120000)) { $listener.Stop(); throw "Timed out waiting for redirect." }
$client = $listener.EndAcceptTcpClient($async)

   
    $codeVerifier  = New-CodeVerifier
    $codeChallenge = New-CodeChallenge $codeVerifier
    $state         = [Guid]::NewGuid().ToString("N")

    $qPairs = @(
        "client_id=$(UrlEnc $ClientId)"
        "response_type=code"
        "redirect_uri=$(UrlEnc $redirectUri)"
        "response_mode=query"
        "scope=$(UrlEnc $Scopes)"
        "code_challenge=$(UrlEnc $codeChallenge)"
        "code_challenge_method=S256"
        "state=$(UrlEnc $state)"
        "prompt=select_account"
    ) -join "&"
    $ub = [System.UriBuilder]::new($authorizeBase)
    $ub.Query = $qPairs
    $authUrl = $ub.Uri.AbsoluteUri

    Write-Host "`nOpening browser for sign-in..." -ForegroundColor Cyan
    try { Open-Browser $authUrl } catch { }
    Write-Host "If a browser didn't open, copy/paste this FULL URL:" -ForegroundColor Yellow
    Write-Host $authUrl -ForegroundColor Gray


    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $reader = New-Object System.IO.StreamReader($stream)
    $requestLine = $reader.ReadLine()
    while (($line = $reader.ReadLine()) -ne $null -and $line -ne "") { }

    if ($requestLine -notmatch '^GET\s+\/\?(.+)\s+HTTP') { 
        $client.Close(); $listener.Stop()
        throw "Unexpected redirect format."
    }

    $query = [System.Web.HttpUtility]::ParseQueryString($Matches[1])
    if ($query["error"]) {
        $e = $query["error"]; $d = $query["error_description"]
        $client.Close(); $listener.Stop()
        throw "Auth error: $e - $d"
    }
    if ($query["state"] -ne $state) { $client.Close(); $listener.Stop(); throw "State mismatch." }
    $code = $query["code"]; if (-not $code) { $client.Close(); $listener.Stop(); throw "No auth code returned." }

    $html = "<html><body><h2>Authentication complete</h2><p>You can close this tab.</p></body></html>"
    $htmlBytes = [Text.Encoding]::UTF8.GetBytes($html)
    $respHead  = "HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($htmlBytes.Length)`r`nConnection: close`r`n`r`n"
    $headBytes = [Text.Encoding]::ASCII.GetBytes($respHead)
    $stream.Write($headBytes,0,$headBytes.Length)
    $stream.Write($htmlBytes,0,$htmlBytes.Length)
    $client.Close(); $listener.Stop()


    $body = @{
        grant_type    = "authorization_code"
        client_id     = $ClientId
        code          = $code
        redirect_uri  = $redirectUri
        code_verifier = $codeVerifier
    }
    $tok = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"

    return @{
        access_token  = $tok.access_token
        token_type    = $tok.token_type
        expires_in    = $tok.expires_in
        scope         = $tok.scope
        refresh_token = $tok.refresh_token
        id_token      = $tok.id_token
        redirect_uri  = $redirectUri
        auth_url      = $authUrl
    }
}

function Get-AutopilotDeviceUsingSerial {
    param (
        [Parameter(Mandatory = $true)] [string]$AccessToken,
        [Parameter(Mandatory = $true)] [string]$SerialNumber
    )

    $Headers = @{
        'Authorization' = "Bearer $AccessToken"
        'Content-Type'  = 'application/json'
    }


    $Filter_ImportWindows_SerialNumber = '?$filter=contains(serialNumber,'
    $Filter_ImportWindows_Serial_Value = "'$SerialNumber'"
    $Filter_ImportWindows_Serial_LastSyntax = ')'
    $graph_WindowsAutopilot_Uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities$Filter_ImportWindows_SerialNumber$Filter_ImportWindows_Serial_Value$Filter_ImportWindows_Serial_LastSyntax"

    try {
        $WindowsResult = (Invoke-RestMethod -Uri $graph_WindowsAutopilot_Uri -Headers $Headers -Method Get -ErrorAction SilentlyContinue).value
        return $WindowsResult
    }
    catch {
        Write-Error "Failed to query Autopilot identities: $($_.Exception.Message)"
        return $null
    }
}

function Get-EntraDeviceObjUsingDeviceID {
    param (
        [Parameter(Mandatory = $true)] [string]$AccessToken,
        [Parameter(Mandatory = $true)] [string]$EntraDeviceID
    )

    $Headers = @{
        'Authorization' = "Bearer $AccessToken"
        'Content-Type'  = 'application/json'
    }


    $Filter_ImportWindows_SerialNumber = '?$filter=deviceId eq '
    $Filter_ImportWindows_Serial_Value = "'$EntraDeviceID'"
    $graph_ImportWindowsAutopilot_Uri = "https://graph.microsoft.com/beta/devices$Filter_ImportWindows_SerialNumber$Filter_ImportWindows_Serial_Value"


    try {
        # Try imported identities first
        $ImportResult = (Invoke-RestMethod -Uri $graph_ImportWindowsAutopilot_Uri -Headers $Headers -Method Get -ErrorAction SilentlyContinue).value
        return $ImportResult 
    }
    catch {
        Write-Error "Failed to query Autopilot identities: $($_.Exception.Message)"
        return $null
    }
}

function Set-DeviceExtensionAttribute {
  
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$DeviceObjectId,
        [Parameter(Mandatory)][string]$AttributeName,
        [Parameter(Mandatory)][string]$Value
    )

    if ($AttributeName -notmatch '^extensionAttribute(1[0-5]|[1-9])$') {
        throw "AttributeName must be extensionAttribute1..extensionAttribute15."
    }
    

    $Headers = @{
        'Authorization' = "Bearer $AccessToken"
        'Content-Type'  = 'application/json'
    }


    $body = @{
        extensionAttributes = @{
            $AttributeName = $Value
        }
    } | ConvertTo-Json -Depth 5

    $URL = "https://graph.microsoft.com/beta/devices/$DeviceObjectId"
    
    try {
        $resp = Invoke-RestMethod -Headers $Headers -Method Patch -Body $body -Uri  $URL
        if ($resp) { return $resp } else { return $true }
    } catch {
        throw "Failed to patch device '$DeviceObjectId' $AttributeName : $Value. Error: $_"
    }
}



$token = Get-GraphInteractiveToken -TenantId $tenant -ClientId $client -Scopes $Scope

$GetAutopilotDeviceID = Get-AutopilotDeviceUsingSerial -AccessToken $token.access_token -SerialNumber $SerialNumber

$GetEntraObjID = Get-EntraDeviceObjUsingDeviceID -AccessToken $token.access_token -EntraDeviceID $GetAutopilotDeviceID.AzureAdDeviceId

Set-DeviceExtensionAttribute -AccessToken $token.access_token -DeviceObjectId $GetEntraObjID.id -Attribute $SelectedExtensionAttribute -Value $value
