# Entra-Collection

Entra Collection is a powerful PowerShell-based toolkit designed for offensive security professionals, Red Teams, and penetration testers working in Microsoft Entra ID (Azure Active Directory) environments.

The collection includes modular scripts that support enumeration, privilege escalation mapping, token manipulation, and stealthy post-exploitation techniques across cloud identity and resource layers.

Whether you're performing reconnaissance, testing Conditional Access enforcement, harvesting group exposure, or manipulating cloud resource access — this toolkit provides practical functionality tailored for real-world cloud operations.


## Available Functions

###  `Invoke-GetTokens`

Retrieve **Access Token** and **Refresh Token** for **Microsoft Graph** or **Azure Resource Manager (ARM)** API.

- Uses **Device Code Flow** to authenticate against the specified Entra ID tenant.
- Saves the refresh token by default to: `C:\Users\Public\Refreshtoken.txt` (you can change this in the script).
- Select either the Graph API or ARM API using flags.

```powershell
Invoke-GetTokens -DomainName ShkudW.com -Graph
Invoke-GetTokens -DomainName ShkudW.com -ARM
  ```

###  `Invoke-CheckCABypass`
Check if Conditional Access policies can be bypassed using alternate Client IDs on the ARM API.

- This function attempts to access the Azure Resource Manager (ARM) API using the provided refresh token and a set of known Microsoft first-party Client IDs.
- The goal is to determine whether Conditional Access (CA) enforcement is tied to specific applications, and whether it can be bypassed by reusing the token with a different (trusted) client identity.
- This method is useful in Red Team assessments where access to a refresh token was obtained, and you want to test lateral use of the token across other clients.

```powershell
Invoke-CheckCABypass -DomainName ShkudW.com -RefreshToken <your_token>
  ```

###  `Invoke-FindDynamicGroups`
 Identify dynamic groups in the target Entra ID tenant and analyze their membership rules.

- This function enumerates all dynamic groups within the specified Entra ID tenant and inspects their membership rules
  to determine if they rely on attributes such as `mail`, `displayName`, or `userPrincipalName`.
- These attributes can potentially be manipulated during external user invitations (e.g., B2B scenarios) to trigger automatic inclusion
- into privileged or sensitive dynamic groups.
- This technique is commonly used in Entra ID Red Team operations to achieve privilege escalation or persistence.

```powershell
Invoke-FindDynamicGroups -DomainName contoso.com -RefreshToken <your_token>
Invoke-FindDynamicGroups -DomainName contoso.com -DeviceCodeFlow
Invoke-FindDynamicGroups -DomainName contoso.com -ClientId <App-id> -ClientSecret <App-secret>
```



