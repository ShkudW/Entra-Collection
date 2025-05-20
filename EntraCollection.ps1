
<#
	Entra Colection => EntraCollection.ps1
    Author: Shaked Wiessman (ShkudW), offensive cyber security at Ab-inBev.com

#>

function Get-Tokens {
	
		<#
	
		Getting Access Token and Refreshtoken for Graph API or ARM API.
		
		Get-Tokens -DomainName shakudw.local -Graph | -ARM
		
		#>	

	    param(
		    [Parameter(Mandatory = $false)]
        [string]$DomainName,
	      [Parameter(Mandatory = $false)]
        [switch]$Graph,
	      [Parameter(Mandatory = $false)]
        [switch]$ARM		
		)
		
		
				if ($DomainName -and -not $Graph -and -not $ARM){
					Write-Host "[!] Please choose between Graph Token or ARM Token" -ForegroundColor Red
					Write-Host "Usage: Get-Tokens -DomainName domain.com -Graph | -ARM"
					return
				}

				if (-not $DomainName -and -not $Graph -and -not $ARM){
					Write-Host "[!] Please provide -DomainName and select -Graph or -ARM" -ForegroundColor Red
					Write-Host "Usage: Get-Tokens -DomainName domain.com -Graph | -ARM"
					return
				}
				
				if ($Graph -and $ARM) {
					Write-Host "[!] Please select only one API: either -Graph or -ARM, not both." -ForegroundColor Red
					return
				}


			
			function Get-DomainName {
				try {
					$response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"
					$TenantID = ($response.issuer -split "/")[3]
					Write-Host "[*] Tenant ID for $DomainName is $TenantID" -ForegroundColor DarkCyan
					return $TenantID
				} catch {
						Write-Error "[-] Failed to retrieve Tenant ID from domain: $DomainName"
						return $null
					}
			}
			
			$TenantID = Get-DomainName
			
			$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0"
		
			$deviceCodeUrl = "https://login.microsoftonline.com/$TenantID/oauth2/devicecode?api-version=1.0"
			$headers = @{ 'User-Agent' = $UserAgent }
			
				$GraphBody = @{
					"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
					"scope"     = "https://graph.microsoft.com/.default"
				}
				
				$ARMBody = @{
					"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
					"scope"     = "https://management.azure.com/.default"
				}
			
			if($Graph) {
				$authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Headers $headers -Body $GraphBody
				$code = $authResponse.user_code
				$deviceCode = $authResponse.device_code

				Write-Host "`n[*] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkCyan -NoNewline
				Write-Host " $code" -ForegroundColor DarkYellow
				Start-Sleep -Seconds 5
				Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

				$tokenUrl = "https://login.microsoftonline.com/$TenantID/oauth2/token?api-version=1.0"
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

						
						Set-Content -Path "C:\Users\Public\Refreshtoken.txt" -Value $RefreshToken
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
			
			}else {
			
				$authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Headers $headers -Body $ARMBody
				$code = $authResponse.user_code
				$deviceCode = $authResponse.device_code

				Write-Host "`n[*] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkCyan -NoNewline
				Write-Host " $code" -ForegroundColor DarkYellow
				Start-Sleep -Seconds 5
				Start-Process "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "https://microsoft.com/devicelogin"

				$tokenUrl = "https://login.microsoftonline.com/$TenantID/oauth2/token?api-version=1.0"
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

					
					Set-Content -Path "C:\Users\Public\Refreshtoken.txt" -Value $RefreshToken
					Write-Host "`n[+] Refresh Token saved to C:\Users\Public\Refreshtoken.txt" -ForegroundColor Cyan

					
					$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
					$refreshBody = @{
						"client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
						"scope"         = "https://management.azure.com/.default"
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
}
				 
		
