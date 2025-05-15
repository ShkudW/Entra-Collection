function Invoke-Findupn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RefreshToken,
		
		[Parameter(Mandatory = $true)]
        [string]$TenantID,
		
		[Parameter(Mandatory = $true)]
        [string]$Word
    )

	$OutputFile = "FoundUsers.txt"
	if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }
    
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office
    $Scope    = "https://graph.microsoft.com/.default"

    function Get-AccessTokenFromRefresh {
        $TokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $Body = @{
            client_id     = $ClientId
            scope         = $Scope
            grant_type    = "refresh_token"
            refresh_token = $RefreshToken
        }
        try {
            $Response = Invoke-RestMethod -Method Post -Uri $TokenUrl -Body $Body -ContentType "application/x-www-form-urlencoded"
            return $Response.access_token
        } catch {
            Write-Error "[-] Failed to get access token from refresh token: $_"
            return $null
        }
    }

    $AccessToken = Get-AccessTokenFromRefresh
    if (-not $AccessToken) { return }

    $TokenStartTime = Get-Date
    $UsersUrl = "https://graph.microsoft.com/v1.0/users"
    $BeesUsers = @()

    while ($UsersUrl) {
        
        if ((New-TimeSpan -Start $TokenStartTime).TotalMinutes -ge 7) {
            Write-Host "[*] Refreshing Access Token..." -ForegroundColor Cyan
            $AccessToken = Get-AccessTokenFromRefresh
            if (-not $AccessToken) { break }
            $TokenStartTime = Get-Date
        }

        $Headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }

        try {
            $Response = Invoke-RestMethod -Method Get -Uri $UsersUrl -Headers $Headers -ErrorAction Stop

            foreach ($User in $Response.value) {
                if (
                    ($User.displayName -like "*$Word*" -or
                     $User.mail -like "*$Word*" -or
                     $User.userPrincipalName -like "*$Word*" -or
                     $User.givenName -like "*$Word*" -or
                     $User.surname -like "*$Word*")
                ) {
					$BeesUsers += $User
				    $Line = "$($User.displayName) | $($User.userPrincipalName)"
					Add-Content -Path $OutputFile -Value $Line
						
                 
					Write-Host ""
					Write-Host "[+] Found: " -NoNewline
					Write-Host "$($User.displayName)" -ForegroundColor Green -NoNewline
					Write-Host " | $($User.userPrincipalName)" -ForegroundColor DarkGray

                }
            }

            $UsersUrl = $Response.'@odata.nextLink'
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                if ($retryAfter) {
                    Write-Host "[!] Rate limit hit. Retrying after $retryAfter seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds ([int]$retryAfter)
                } else {
                    Write-Host "[!] Rate limit hit. Retrying after default 60 seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 60
                }
            } else {
                Write-Warning "Failed to retrieve users: $_"
                break
            }
        }
    }

    return $BeesUsers
}
