function Get-DeviceCodeToken {
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
            $AccessToken = $tokenResponse.access_token
            $RefreshToken = $tokenResponse.refresh_token

            Write-Host "`n[+] Access Token:`n$AccessToken" -ForegroundColor Green
            Write-Host "`n[+] Refresh Token:`n$RefreshToken" -ForegroundColor Cyan

            return [PSCustomObject]@{
                AccessToken  = $AccessToken
                RefreshToken = $RefreshToken
            }

            } catch {
                $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errorResponse.error -eq "authorization_pending") {
                    Start-Sleep -Seconds 5
                } elseif ($errorResponse.error -eq "authorization_declined" -or $errorResponse.error -eq "expired_token") {
                    return $null
                } else {
                    return $null
                }
            }
        }
		$Tokens = Get-DeviceCodeToken
			Write-Host "`n[+] Access Token:`n$($Tokens.AccessToken)" -ForegroundColor Green
			Write-Host "`n[+] Refresh Token:`n$($Tokens.RefreshToken)" -ForegroundColor Cyan

		
    }
