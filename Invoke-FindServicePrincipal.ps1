

function Invoke-FindServicePrincipal {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RefreshToken,
	[Parameter(Mandatory = $true)]
        [string]$TenantID
    )


function Get-GraphAccessToken {

    $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"  # BEES Tenant  
    $body = @{
        client_id     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "refresh_token"
        refresh_token = $RefreshToken
    }

    try {
        $response = Invoke-RestMethod -Method Post -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    } catch {
        Write-Host "[-] Failed to get access token: $_" -ForegroundColor Red
        exit 1
    }
}
    $Global:GraphAccessToken = Get-GraphAccessToken -RefreshToken $RefreshToken
    $StartTime = Get-Date

    $headers = @{
        "Authorization" = "Bearer $GraphAccessToken"
        "Content-Type"  = "application/json"
    }

    $allServicePrincipalIds = @()
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals"
    Write-Host "[*] Fetching all Service Principal IDs..." -ForegroundColor Cyan

    do {
        try {
            $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
            $allServicePrincipalIds += $response.value | ForEach-Object { $_.id }
            $uri = $response.'@odata.nextLink'
        } catch {
					if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    if (-not $retryAfter) { $retryAfter = 10 }
                    Write-Host "[-] 429 received. Waiting $retryAfter seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds $retryAfter
					}
					else{
						Write-Host "[-] Failed to Service Principals" -ForegroundColor Red
						break
					}
			}
    } while ($uri)

    Write-Host "[+] Retrieved $($allServicePrincipalIds.Count) Service Principal IDs." -ForegroundColor Green
    $output = @()

    foreach ($id in $allServicePrincipalIds) {

        if ((Get-Date) -gt $StartTime.AddMinutes(7)) {
            Write-Host "[*] Refreshing Access Token..." -ForegroundColor Yellow
            $Global:GraphAccessToken = Get-GraphAccessToken -RefreshToken $RefreshToken
            $StartTime = Get-Date
            $headers = @{
                "Authorization" = "Bearer $GraphAccessToken"
                "Content-Type"  = "application/json"
            }
        }

        $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$id"
        $grantsUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$id/oauth2PermissionGrants"

        $response = $null
        $grants = $null

        while ($true) {
            try {
                $response = Invoke-RestMethod -Uri $spUri -Headers $headers -Method GET -ErrorAction Stop
                $grants = Invoke-RestMethod -Uri $grantsUri -Headers $headers -Method GET -ErrorAction SilentlyContinue
                break
            } catch {
                if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    if (-not $retryAfter) { $retryAfter = 10 }
                    Write-Host "[-] 429 received. Waiting $retryAfter seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds $retryAfter
                } else {
                    Write-Host "[-] Failed to fetch SP $id" -ForegroundColor Red
                    break
                }
            }
        }

        if ($response) {
            $clientId = $response.appId
            $displayName = $response.displayName
            $scopes = $response.oauth2PermissionScopes
            $ReplyUrls = $response.replyUrls
            $delegatedScopes = $scopes | Where-Object { $_.type -eq "User" }

            $hasNoSecret = -not $response.passwordCredentials -or $response.passwordCredentials.Count -eq 0
            $hasDelegatedScopes = $delegatedScopes.Count -gt 0
            $hasAdminConsent = $false
            if ($grants.value | Where-Object { $_.consentType -eq "AllPrincipals" }) {
                $hasAdminConsent = $true
            }

            if ($hasDelegatedScopes -and $hasNoSecret -and -not $hasAdminConsent) {
                foreach ($scope in $delegatedScopes) {
                    $line1 = "[+] $displayName | client_id: $clientId | scope: $($scope.value) | consent: $($scope.adminConsentDescription)"
                    Write-Host $line1 -ForegroundColor Green
                    Write-Host "[Reply URLs]:" -ForegroundColor DarkCyan
                    foreach ($url in $response.replyUrls) {
                        Write-Host "  - $url" -ForegroundColor DarkGreen
                    }
                    Write-Host "================="

                    $output += $line1
                    $output += $response.replyUrls | ForEach-Object { "  - $_" }
                    $output += "================="
                }
            } else {
                $line = "[-] $displayName | client_id: $clientId | Skipped (admin consent granted or not eligible)"
                Write-Host $line -ForegroundColor DarkGray
            }
        }
    }

    $output | Out-File -FilePath "ServicePrincipals_DeviceFlow_Eligible.txt" -Encoding UTF8
    Write-Host "`n✅ Exported to ServicePrincipals_DeviceFlow_Eligible.txt" -ForegroundColor Green
}
