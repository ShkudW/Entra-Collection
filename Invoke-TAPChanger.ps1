function Invoke-TAPChanger {
    param(
        [Parameter(Mandatory)]
        [string]$ClientId,

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
			New-TemporaryAccessPass -UserId $ClientId -Token $AccessToken -Minutes $LifetimeMinutes -UsableOnce $IsUsableOnce -Start $StartDateTime
		} else {
			New-TemporaryAccessPass -UserId $ClientId -Token $AccessToken -Minutes $LifetimeMinutes -UsableOnce $IsUsableOnce
		}

    }

    if ($Delete) {
        Remove-TemporaryAccessPass -UserId $ClientId -Token $AccessToken
    }
}
