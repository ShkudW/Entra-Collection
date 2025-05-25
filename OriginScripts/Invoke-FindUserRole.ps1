function Invoke-FindUserRole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

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
