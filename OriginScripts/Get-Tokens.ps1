function Get-Tokens {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantID
    )

    $deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
    $headers = @{ 'User-Agent' = 'Mozilla/5.0' }
    $body = @{
        "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        "scope"     = "https://graph.microsoft.com/.default"
    }

    $authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Headers $headers -Body $body
    $code = $authResponse.user_code
    $deviceCode = $authResponse.device_code

    Write-Host "`n[*] Open browser and enter code:" -ForegroundColor DarkCyan -NoNewline
    Write-Host " $code" -ForegroundColor DarkYellow
    Start-Sleep -Seconds 5
    Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

    $tokenUrl = "https://login.microsoftonline.com/common/oauth2/token?api-version=1.0"
    $tokenBody = @{
        "scope"      = "openid"
        "client_id"  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
        "code"       = $deviceCode
    }

    while ($true) {
        try {
           
            $tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Headers $headers -Body $tokenBody -ErrorAction Stop
            $RefreshToken = $tokenResponse.refresh_token

            
            Set-Content -Path "C:\Users\Public\Refreshtoken2.txt" -Value $RefreshToken
            Write-Host "`n[+] Refresh Token saved to C:\Users\Public\Refreshtoken.txt" -ForegroundColor Cyan

            
            $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
            $refreshBody = @{
                "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "scope"         = "https://graph.microsoft.com/.default"
                "grant_type"    = "refresh_token"
                "refresh_token" = $RefreshToken
            }

            try {
                $refreshResponse = Invoke-RestMethod -Method POST -Uri $url -Body $refreshBody -ContentType "application/x-www-form-urlencoded"
                $AccessToken = $refreshResponse.access_token
                Write-Host "`n[+] Access Token retrieved." -ForegroundColor Green
            } catch {
                Write-Host "`n[-] Failed to retrieve Access Token using Refresh Token." -ForegroundColor Red
                return $null
            }

           
            $Global:AccessToken  = $AccessToken
            $Global:RefreshToken = $RefreshToken

            Write-Host "`n[+] Access Token stored in variable:`n$AccessToken" -ForegroundColor Green
            return
        } catch {
            $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($errorResponse.error -eq "authorization_pending") {
                Start-Sleep -Seconds 5
            } elseif ($errorResponse.error -eq "authorization_declined" -or $errorResponse.error -eq "expired_token") {
                Write-Host "`n[-] Authorization failed or expired." -ForegroundColor Red
                return
            } else {
                Write-Host "`n[-] Unexpected error: $($errorResponse.error)" -ForegroundColor Red
                return
            }
        }
    }
}
