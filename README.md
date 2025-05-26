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
  into privileged or sensitive dynamic groups.
  
- This technique is commonly used in Entra ID Red Team operations to achieve privilege escalation or persistence.

```powershell
Invoke-FindDynamicGroups -DomainName ShkudW.com -RefreshToken <your_token>
Invoke-FindDynamicGroups -DomainName ShkudW.com -DeviceCodeFlow
Invoke-FindDynamicGroups -DomainName ShkudW.com -ClientId <App-id> -ClientSecret <App-secret>
```

### `Invoke-FindPublicGroups`
Enumerate public Microsoft 365 groups in the target Entra ID tenant, and optionally read their message content.

- This function identifies all Microsoft 365 groups in the target tenant that are marked as `Public`,
  meaning that any authenticated user (including external/B2B users) can add themselves to the group without approval.

- These groups may grant access to sensitive resources (e.g., SharePoint, Teams, Planner), and in some cases
  be linked to directory roles or privileged permissions.

- Using the optional `-Deep` flag, the function will attempt to read public conversations (group mailbox threads)
  and extract potentially sensitive content such as credentials, tokens, or internal communications.

```powershell
Invoke-FindPublicGroups -DomainName ShkudW.com -DeviceCodeFlow
Invoke-FindPublicGroups -DomainName ShkudW.com -RefreshToken <token>
Invoke-FindPublicGroups -DomainName ShkudW.com -ClientId <id> -SecretId <secret>

Invoke-FindPublicGroups -DomainName ShkudW.com -ClientId <id> -SecretId <secret> | -RefreshToken <token> | -DeviceCodeFlow -Deep
```

### `Invoke-FindServicePrincipals`
Enumerate service principals that support delegated user access in the target Entra ID tenant.

- This function queries the target Entra ID tenant to identify service principals (enterprise applications)
  that are configured to allow delegated user permissions via OAuth2.

- It highlights which applications can be used to access resources on behalf of a user (through `user_impersonation`),
  and extracts their associated App IDs and OAuth2 API endpoints (e.g., `replyUrls`, `identifierUris`, etc.).

- This information is useful for identifying potential lateral movement vectors, token replay opportunities, or
  abuse of existing application permissions during post-exploitation.

```powershell
Invoke-FindServicePrincipal -DomainName ShkudW.com -RefreshToken <your_token>
```

### `Invoke-FindUserRole`
Enumerate all users (UPNs) in the target Entra ID tenant and identify their assigned directory roles.

- This function retrieves all user accounts (User Principal Names) in the specified Entra ID tenant and
  maps their assigned Azure AD (directory) roles, such as Global Administrator, Privileged Role Administrator, User Administrator, etc.

- This is particularly useful during reconnaissance and privilege escalation mapping, helping to identify
  high-value targets or misconfigured role assignments.

```powershell
Invoke-FindUserRole -DomainName ShkudW.com -RefreshToken <your_token>
```

### `Invoke-FindUserByWord`
Search for user accounts in the target Entra ID tenant by matching a specific keyword.

- This function performs a keyword-based search across user accounts in the specified Entra ID tenant.
  It checks attributes such as `userPrincipalName`, `displayName`, and `mail` for matches with the provided keyword.

- Common use cases include finding accounts with names like "admin", "svc", "test", or department-specific identifiers
  that may indicate privileged or interesting users.

```powershell
Invoke-FindUserByWord -DomainName ShkudW.com -RefreshToken <your_token> -Word admin
```

### `Invoke-GroupMappingFromJWT`
Resolve group Object IDs from a JWT access token into readable group names using Microsoft Graph.

- If your access token for ARM API includes a 'groups' claim with a list of Group Object IDs (GUIDs), this function
  helps map those IDs to their actual display names and metadata by querying Microsoft Graph.

- This is particularly useful for understanding whether your token includes high-privileged group memberships
  such as Global Administrator, Privileged Role Administrator, or any custom elevated group.

```powershell
Invoke-GroupMappingFromJWT -jwt "<eyJ0eXAiOiJKV1QiLCJhbGci...>" -GraphAccessToken "<eyJ0eXAiOiJKV1QiLCJub25j...>"
```

### `Invoke-MembershipChange`
 Add or remove a user (including yourself) from one or more groups in the target Entra ID tenant.

- This function allows you to modify group memberships in Microsoft Entra ID by either adding or removing a specified user
  to/from one or more groups. You can provide the target user's Object ID explicitly using the `-UserID` parameter,
  or omit it to apply the action to yourself (in which case the script extracts your Object ID automatically using the access token).

- The script supports both interactive authentication (via refresh token or client credentials) and batch operations across multiple group IDs.

```powershell
        Invoke-MembershipChange -DomainName ShkudW.com -RefreshToken <token> -UserID <targetUserId> -GroupIdsInput C:\Path-to-Your-File\groupids.txt -Action Add | Delete
        Invoke-MembershipChange -DomainName ShkudW.com -ClientID <appId> -ClientSecret <secret> -UserID <targetUserId> -GroupIdsInput C:\Path-to-Your-File\groupids.txt -Action Add | Delete
```
You can use either your Refresh Token or a Client ID with Client Secret, without specifying the 'UserId' parameter, to add or remove your own account from a single group or a list of groups.


### `Invoke-ResourcePermissions`
Enumerate your effective role assignments on Azure resources, including Key Vaults, Storage Accounts, and Virtual Machines.

- This function queries the Azure Resource Manager (ARM) API to identify all Azure resources you have permissions on,
  and maps your effective role assignments for each supported resource type. 

- The focus is on high-value targets such as:
  - **Key Vaults**: to check for access to secrets, keys, and certificates.
    - **Storage Accounts**: to check for read/write access to blobs, files, queues, or tables.
      - **Virtual Machines**: to detect VM Contributor/Administrator roles that may allow command execution or snapshotting.
  
- The function supports multiple authentication methods and can be scoped by resource type or executed with `-All` to scan everything.

```powershell
Invoke-ResourcePermissions -DomainName ShkudW.com -ClientID <id> -ClientSecret <secret> -KeyVault | -StorageAccount | -VirtualMachine | -All
Invoke-ResourcePermissions -DomainName ShkudW.com -RefreshToken <token> -KeyVault | -StorageAccount | -VirtualMachine | -All
```

### `Invoke-TAPChanger`
Add or remove a Temporary Access Pass (TAP) for a target user in the Entra ID tenant.

- This function allows you to create or delete a Temporary Access Pass (TAP) for a specific user account in Entra ID.
  TAPs are time-limited authentication codes that can be used as a second factor or even as a primary login mechanism,
  making them extremely useful for persistence or account takeover during Red Team operations.

- This operation requires a privileged access token with sufficient permissions (such as the `Authentication Administrator` or `Privileged Authentication Administrator` roles).

```powershell
Invoke-TAPChanger -AccessToken '<Graph Access Token>' -UseTargetID '<Target User>' -Add | Delete
```


### `Invoke-ValidUPN`
Validate whether specified user accounts (UPNs) exist in a target Entra ID tenant.

- This function attempts to validate user existence in Microsoft Entra ID (formerly Azure AD) by probing the GetCredentialType API.
  It supports checking single users by first and last name, usernames from file, or full name pairs from a names file.

- Multiple username formats are generated from each name pair (e.g., Shaked.Wiessman) to maximize coverage.
  It uses heuristic analysis of the API response to infer whether the user exists.

- Key capabilities:
        - `-StopOnFirstMatch` stops checking further combinations once a valid UPN is found.
        - `-UsernameFile` accepts a list of usernames (one per line).
        - `-NamesFile` accepts a list of `firstname:lastname` entries.
        - `-OutputFilePath` allows saving an HTML report with the results.

```powershell
Invoke-ValidUPN -FirstName Shaked -LastName Wiessman -DomainName ShkudW.com
Invoke-ValidUPN -NamesFile names.txt -DomainName ShkudW.com -StopOnFirstMatch
Invoke-ValidUPN -UsernameFile usernames.txt -DomainName ShkudW.com -OutputFilePath report.html
```  
