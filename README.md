# Graphpython

<p align="center">
  <img src="./.github/python.png" />
</p>

Graphpython is a modular Python tool for cross-platform Microsoft Graph API enumeration and exploitation. It builds upon the capabilities of AADInternals (Killchain.ps1), GraphRunner, and TokenTactics(V2) to provide a comprehensive solution for interacting with the Microsoft Graph API for red team and cloud assumed breach operations. 

Graphpython covers external reconnaissance, authentication/token manipulation, enumeration, and post-exploitation of various Microsoft services, including Entra ID (Azure AD), Office 365 (Outlook, SharePoint, OneDrive, Teams), and Intune (Endpoint Management).

## Index

- [Install](#Install)
- [Usage](#Usage)
- [Commands](#Commands)
- [Demo](#demos)
  - [Outsider](#outsider-1)
      - [Invoke-ReconAsOutsider](#invoke-reconasoutsider)
      - [Invoke-UserEnumerationAsOutsider](#invoke-userenumerationasoutsider)
  - [Authentication](#authentication-1)
      - [Get-GraphTokens](#get-graphtokens)
      - [Invoke-RefreshToAzureManagementToken](#invoke-refreshtoazuremanagementtoken)
      - [Invoke-CertToAccessToken](#invoke-certtoaccesstoken)
      - [Invoke-ESTSCookieToAccessToken](#invoke-estscookietoaccesstoken)
  - [Post-Auth Enumeration](#post-auth-enumeration-1)    
      - [Get-User](#get-user)
      - [Get-UserPrivileges](#get-userprivileges)
      - [Get-Application](#get-application)
      - [List-RecentOneDriveFiles](#list-recentonedrivefiles)
  - [Post-Auth Exploitation](#post-auth-exploitation-1)    
      - [Invite-GuestUser](#invite-guestuser)
      - [Find-PrivilegedRoleUsers](#find-privilegedroleusers)
      - [Assign-PrivilegedRole](#assign-privilegedrole)
      - [Find-PrivilegedApplications](#find-privilegedapplications)
      - [Add-ApplicationPermission](#add-applicationpermission)
      - [Spoof-OWAEmailMessage](#spoof-owaemailmessage)
      - [Find-DynamicGroups](#find-dynamicgroups)
      - [Find-UpdatableGroups](#find-updatablegroups)
  - [Post-Auth Intune Enumeration](#post-auth-intune-enumeration-1)
      - [Get-ManagedDevices](#get-manageddevices)
      - [Get-UserDevices](#get-userdevices) 
      - [Get-DeviceConfigurationPolicies](#get-deviceconfigurationpolicies)
  - [Post-Auth Intune Exploitation](#post-auth-intune-exploitation-1)
      - [Display-AVPolicyRules](#display-avpolicyrules)
      - [Get-ScriptContent](#get-scriptcontent)
      - [Backdoor-Script](#backdoor-script)
      - [Deploy-MaliciousScript](#deploy-maliciousscript)
      - [Add-ExclusionGroupToPolicy](#add-exclusiongrouptopolicy)
  - [Cleanup](#cleanup-1)
      - [Remove-GroupMember](#remove-groupmember)
  - [Locators](#locators-1)
      - [Locate-ObjectID](#locate-objectid)
      - [Locate-PermissionID](#locate-permissionid)



## Install

> Reformatted entire codebase, more installation options are available now. PyPi install will be supported soon.

Either install via pip:
```
git clone https://github.com/mlcsec/Graphpython.git
cd Graphpython
pip install .
Graphpython -h
```
Or run as before via git and Python3:
```
git clone https://github.com/mlcsec/Graphpython.git
cd Graphpython
pip3 install -r requirements.txt
python3 Graphpython.py -h
```

## Usage

<p align="center">
  <img src="./.github/usage.png" />
</p>

## Commands

Please refer to the [Wiki](https://github.com/mlcsec/Graphpython/wiki) for the full user guide and details of available functionality.

### Outsider 

* **Invoke-ReconAsOutsider** - Perform outsider recon of the target domain
* **Invoke-UserEnumerationAsOutsider** - Checks whether the user exists within Azure AD

### Authentication 

* **Get-GraphTokens** - Obtain graph token via device code phish
* **Get-TenantID** - Get tenant ID for target domain
* **Get-TokenScope** - Get scope of supplied token
* **Decode-AccessToken** - Get all token payload attributes
* **Invoke-RefreshToMSGraphToken** - Convert refresh token to Microsoft Graph token
* **Invoke-RefreshToAzureManagementToken** - Convert refresh token to Azure Management token
* **Invoke-RefreshToVaultToken** - Convert refresh token to Azure Vault token
* **Invoke-RefreshToMSTeamsToken** - Convert refresh token to MS Teams token
* **Invoke-RefreshToOfficeAppsToken** - Convert refresh token to Office Apps token
* **Invoke-RefreshToOfficeManagementToken** - Convert refresh token to Office Management token
* **Invoke-RefreshToOutlookToken** - Convert refresh token to Outlook token
* **Invoke-RefreshToSubstrateToken** - Convert refresh token to Substrate token
* **Invoke-RefreshToYammerToken** - Convert refresh token to Yammer token
* **Invoke-RefreshToIntuneEnrollmentToken** - Convert refresh token to Intune Enrollment token
* **Invoke-RefreshToOneDriveToken** - Convert refresh token to OneDrive token
* **Invoke-RefreshToSharePointToken** - Convert refresh token to SharePoint token
* **Invoke-CertToAccessToken** - Convert Azure Application certificate to JWT access token
* **Invoke-ESTSCookieToAccessToken** - Convert ESTS cookie to MS Graph access token
* **Invoke-AppSecretToAccessToken** - Convert Azure Application secretText credentials to access token
* **New-SignedJWT** - Construct JWT and sign using Key Vault PEM certificate (Azure Key Vault access token required) then generate Azure Management token

### Post-Auth Enumeration 

* **Get-CurrentUser** - Get current user profile
* **Get-CurrentUserActivity** - Get recent activity and actions of current user
* **Get-OrgInfo** - Get information relating to the target organization
* **Get-Domains** - Get domain objects
* **Get-User** - Get all users (default) or target user
* **Get-UserProperties** - Get current user properties (default) or target user
* **Get-UserGroupMembership** - Get group memberships for current user (default) or target user
* **Get-UserTransitiveGroupMembership** - Get transitive group memberships for current user (default) or target user
* **Get-Group** - Get all groups (default) or target group
* **Get-GroupMember** - Get all members of target group
* **Get-AppRoleAssignments** - Get application role assignments for current user (default) or target user
* **Get-ConditionalAccessPolicy** - Get conditional access policy properties
* **Get-Application** - Get Enterprise Application details for app (NOT object) ID
* **Get-AppServicePrincipal** - Get details of the application's service principal from the app ID 
* **Get-ServicePrincipal** - Get Service Principal details
* **Get-ServicePrincipalAppRoleAssignments** - Get Service Principal app role assignments (shows available admin consent permissions that are already granted)
* **Get-PersonalContacts** - Get contacts of the current user
* **Get-CrossTenantAccessPolicy** - Get cross tenant access policy properties
* **Get-PartnerCrossTenantAccessPolicy** - Get partner cross tenant access policy
* **Get-UserChatMessages** - Get ALL messages from all chats for target user (Chat.Read.All)
* **Get-AdministrativeUnitMember** - Get members of administrative unit
* **Get-OneDriveFiles** - Get all accessible OneDrive files for current user (default) or target user 
* **Get-UserPermissionGrants** - Get permissions grants of current user (default) or target user
* **Get-oauth2PermissionGrants** - Get oauth2 permission grants for current user (default) or target user 
* **Get-Messages** - Get all messages in signed-in user's mailbox (default) or target user
* **Get-TemporaryAccessPassword** - Get TAP details for current user (default) or target user 
* **Get-Password** - Get passwords registered to current user (default) or target user
* **List-AuthMethods** - List authentication methods for current user (default) or target user
* **List-DirectoryRoles** - List all directory roles activated in the tenant
* **List-Notebooks** - List current user notebooks (default) or target user
* **List-ConditionalAccessPolicies** - List conditional access policy objects
* **List-ConditionalAuthenticationContexts** - List conditional access authentication context
* **List-ConditionalNamedLocations** - List conditional access named locations
* **List-SharePointRoot** - List root SharePoint site properties
* **List-SharePointSites** - List any available SharePoint sites
* **List-SharePointURLs** - List SharePoint site web URLs visible to current user
* **List-ExternalConnections** - List external connections
* **List-Applications** - List all Azure Applications
* **List-ServicePrincipals** - List all service principals
* **List-Tenants** - List tenants
* **List-JoinedTeams** - List joined teams for current user (default) or target user
* **List-Chats** - List chats for current user (default) or target user 
* **List-ChatMessages** - List messages in target chat
* **List-Devices** - List devices
* **List-AdministrativeUnits** - List administrative units
* **List-OneDrives** - List current user OneDrive (default) or target user 
* **List-RecentOneDriveFiles** - List current user recent OneDrive files
* **List-SharedOneDriveFiles** - List OneDrive files shared with the current user
* **List-OneDriveURLs** - List OneDrive web URLs visible to current user

### Post-Auth Exploitation 

* **Invoke-CustomQuery** - Custom GET query to target Graph API endpoint
* **Invoke-Search** - Search for string within entity type (driveItem, message, chatMessage, site, event)
* **Find-PrivilegedRoleUsers** - Find users with privileged roles assigned
* **Find-PrivilegedApplications** - Find privileged apps (via their service principal) with granted admin consent API permissions
* **Find-UpdatableGroups** - Find groups which can be updated by the current user
* **Find-SecurityGroups** - Find security groups and group members
* **Find-DynamicGroups** - Find groups with dynamic membership rules
* **Update-UserPassword** - Update the passwordProfile of the target user (NewUserS3cret@Pass!)
* **Update-UserProperties** - Update a specific user property of the target user
* **Add-UserTAP** - Add new Temporary Access Password (TAP) to target user
* **Add-GroupMember** - Add member to target group
* **Add-ApplicationPassword** - Add client secret to target application
* **Add-ApplicationCertificate** - Add client certificate to target application
* **Add-ApplicationPermission** - Add permission to target application e.g. Mail.Send and attempt to grant admin consent
* **Grant-AppAdminConsent** - Grant admin consent for Graph API permission already assigned to enterprise application
* **Create-Application** - Create new enterprise application with default settings
* **Create-NewUser** - Create new Entra ID user
* **Invite-GuestUser** - Invite guest user to Entra ID
* **Assign-PrivilegedRole** - Assign chosen privileged role to user/group/object
* **Open-OWAMailboxInBrowser** - Open an OWA Office 365 mailbox in BurpSuite's embedded Chromium browser using either a Substrate.Office.com or Outlook.Office.com access token
* **Dump-OWAMailbox** - Dump OWA Office 365 mailbox
* **Spoof-OWAEmailMessage** - Send email from current user's Outlook mailbox or spoof another user (Mail.Send)

### Post-Auth Intune Enumeration 

* **Get-ManagedDevices** - Get managed devices
* **Get-UserDevices** - Get user devices
* **Get-CAPs** - Get conditional access policies
* **Get-DeviceCategories** - Get device categories
* **Get-DeviceComplianceSummary** - Get device compliance summary
* **Get-DeviceConfigurations** - Get device configurations
* **Get-DeviceConfigurationPolicySettings** - Get device configuration policy settings
* **Get-DeviceEnrollmentConfigurations** - Get device enrollment configurations
* **Get-DeviceGroupPolicyConfigurations** - Get device group policy configurations and assignment details
* **Get-DeviceGroupPolicyDefinition** - Get device group policy definition
* **Get-RoleDefinitions** - Get role definitions
* **Get-RoleAssignments** - Get role assignments
* **Get-DeviceCompliancePolicies** - Get all device compliance policies (Android, iOS, macOS, Windows, Linux, etc.)
* **Get-DeviceConfigurationPolicies** - Get device configuration policies and assignment details (AV, ASR, DiskEnc, etc.)


### Post-Auth Intune Exploitation

* **Dump-DeviceManagementScripts** - Dump device management PowerShell scripts
* **Dump-WindowsApps**: Dump managed Windows OS applications (exe, msi, appx, msix, etc.)
* **Dump-iOSApps**: Dump managed iOS/iPadOS mobile applications
* **Dump-macOSApps**: Dump managed macOS applications
* **Dump-AndroidApps**: Dump managed Android mobile applications
* **Get-ScriptContent** - Get device management script content
* **Backdoor-Script** - Add malicious code to pre-existing device management script
* **Deploy-MaliciousScript** - Deploy new malicious device management PowerShell script (all devices)
* **Display-AVPolicyRules** - Display antivirus policy rules
* **Display-ASRPolicyRules** - Display Attack Surface Reduction (ASR) policy rules
* **Display-DiskEncryptionPolicyRules** - Display disk encryption policy rules
* **Display-FirewallConfigPolicyRules** - Display firewall configuration policy rules
* **Display-FirewallRulePolicyRules** - Display firewall rule policy rules (firewall rules not firewall config policy)
* **Display-EDRPolicyRules** - Display EDR policy rules
* **Display-LAPSAccountProtectionPolicyRules** - Display LAPS account protection policy rules
* **Display-UserGroupAccountProtectionPolicyRules** - Display user group account protection policy rules
* **Add-ExclusionGroupToPolicy** - Bypass av, asr, etc. rules by adding an exclusion group containing compromised user or device
* **Reboot-Device** - Reboot managed device
* **Retire-Device** - Retire managed device
* **Lock-Device** - Lock managed device
* **Shutdown-Device** - Shutdown managed device
* **Update-DeviceConfig** - Update properties of the managed device configuration

### Cleanup

* **Delete-User** - Delete a user
* **Delete-Group** - Delete a group
* **Remove-GroupMember** - Remove user from a group
* **Delete-Application** - Delete an application
* **Delete-Device** - Delete managed device
* **Wipe-Device** - Wipe managed device

### Locators

* **Locate-ObjectID** - Find object ID and display object properties
* **Locate-PermissionID** - Find Graph permission ID details (application/delegated, description, admin consent required, ...)


<br>

# Demo

## Outsider

### Invoke-ReconAsOutsider

Perform unauthenticated external recon of the target domain like AADInternal's [Invoke-ReconAsOutsider](https://github.com/Gerenios/AADInternals/blob/master/KillChain.ps1#L8)

#### Example:
```
# graphpython.py --command invoke-reconasoutsider --domain company.com
```
#### Output:
```
[*] Invoke-ReconAsOutsider
================================================================================
Domains: 2
Tenant brand:       Company Ltd
Tenant name:        company
Tenant id:          05aea22e-32f3-4c35-831b-52735704feb3
Tenant region:      EU
DesktopSSO enabled: False
MDI instance:       Not found
Uses cloud sync:    False

Name                                       DNS   MX    SPF    DMARC   DKIM   MTA-STS  Type        STS
----                                       ---   ---   ----   -----   ----   -------  ----        ---
company.com                                False False False  False   False  False    Federated   sts.company.com
company.onmicrosoft.com                    True  True  True   False   True   False    Managed
================================================================================
```

### Invoke-UserEnumerationAsOutsider

Perform username enumeration for the target domain like AADInternal's [Invoke-UserEnumerationAsOutsider](https://github.com/Gerenios/AADInternals/blob/master/KillChain.ps1#L283):

![](./.github/invokeuserenum.png)

<br>

## Authentication

### Get-GraphTokens

Obtain MS Graph tokens via device code authentication (can also be used for device code phishing):

![](./.github/getgraphtokens.png)

### Invoke-RefreshToAzureManagementToken

A valid refresh token can be used to generate access tokens for a [variety of services](https://github.com/mlcsec/Graphpython/wiki#authentication), Azure Management for example shown below. The `--use-cae` switch can be included to use **Continuous Access Evaluation (CAE)** to obtain an access token that's valid for 24 hours:

![](./.github/refreshtoazuremanagement.png)

The returned access token can then be used to authenticate to Azure via the Az PowerShell module:
```
PS > Connect-AzAccount -AccessToken eyJ0eXAi... -AccountId user@domain.onmicrosoft.com -Tenant 42838115-fbda-497e-b273-30944ff2786e

Subscription name    Tenant
-----------------    ------
Azure subscription   42838115-fbda-497e-b273-30944ff2786e
```

### Invoke-CertToAccesstoken

If you stumble across an enterprise application certificate (.pfx) you can use it to request a valid MS Graph access token. 

> The enterprise application must have the corresponding .crt, .pem, or .cer in the application's certificates & secrets configuration otherwise you'll receive 401 client errors as the .pfx used to sign the client assertion won't be registered with the application

![](./.github/certtoaccesstoken.png)

The [Get-Application](https://github.com/mlcsec/Graphpython?tab=readme-ov-file#get-application) command can be used to identified the Graph permissions assigned to the compromised application.

### Invoke-ESTSCookieToAccessToken

Obtain an MS Graph token for a selected client (MSTeams, MSEdge, AzurePowershell) from a captured ESTSAUTH or ESTSAUTHPERSISTENT cookie:

> ESTSAUTH and ESTSAUTHPERSISTENT cookies are often captured via successful Evilginx phishes

![](./.github/estsauthcookie.png)

<br>

## Post-Auth Enumeration

### Get-User

Get all or specific user(s) details. User object can be supplied as user ID or User Principal Name:

![](./.github/getuser.png)

### Get-UserPrivileges

Identifies assigned directory roles, Administrative Units, and Group membership information for the current user of target user:

![](./.github/getuserprivileges.png)


### Get-Application

Get details relating to the target application and now dynamically resolves the `requiredResourceAccess` attribute which contains Graph API role IDs assigned to the application:

![](./.github/getapplication-updated.png)

### List-RecentOneDriveFiles

List recent OneDrive files belonging to current user:

![](./.github/listrecentonedrivefiles.png)

<br>

## Post-Auth Exploitation

### Invite-GuestUser

Invite a malicious guest user to the target environment:

![](./.github/inviteguestuser.png)

### Find-PrivilegedRoleUsers

Loops through 27 of the most privileged directory roles in Entra and displays any assignments to help identify high-value targets:

![](./.github/findprivilegedroleusers.png)

### Assign-PrivilegedRole

Assign a privileged role via template ID to a user or group and define permission scope:

![](./.github/assignprivilegedrole.png)


### Find-PrivilegedApplications

Applications can be granted privileged Graph API permissions via 'Grant admin consent...' option for permissions marked 'Admin consent required':

![](./.github/apiperms.png)

The `Find-PrivilegedApplications` command helps to identify high-value apps that have already been assigned with privileged permssions:

1. identifies all enterprise/registered applications within Entra (no default Microsoft ones included)
2. finds the service principal ID for each application
3. enumerates app role assignments for each application service principal
4. cross-references assigned app role IDs and data against .github/graphpermissions.txt
5. displays assigned role name and description

![](./.github/findprivilegedapps.png)

### Add-ApplicationPermission

Adds desired Graph API permission to target application ID. If the role is privileged it will prompt the user to confirm whether to attempt to grant admin consent (via the `beta/directory/consentToApp` endpoint) using the current privileges:

![](./.github/addapplicationpermission.png)

> NOTE: if the admin consent grant attempt fails with 400 error the token likely doesn't have the necessary scope/permissions assigned

The permission update succeeded in this instance and the application API permission is assigned however the admin consent grant obviously failed:

![](./.github/azureperms1.png)

Once you obtain the necessary permissions or compromise a privileged token then the `Grant-AppAdminConsent` command can be used to grant admin consent to the role that was added for the target app ID:

![](./.github/grantappadminconsent.png)

Verified in the Azure portal:

![](./.github/azureperms2.png)

Or you can use the `Get-Application` command:
```
# graphpython.py --command get-application --id 3d84ebcc-0eef-4f59-ae2a-3fe0e1eb7f51 --token .\token --select requiredResourceAccess

[*] Get-Application
================================================================================
requiredResourceAccess: [{'resourceAppId': '00000003-0000-0000-c000-000000000000', 'resourceAccess': [{'id': 'd07a8cc0-3d51-4b77-b3b0-32704d1f69fa', 'type': 'Role'}]}]
================================================================================
```
The ID within `resourceAccess` corresponds to `AccessReview.Read.All` that was assigned as confirmed with [Locate-PermissionID](https://github.com/mlcsec/Graphpython/tree/main?tab=readme-ov-file#locate-permissionid):

![](./.github/locatepermissionid.png)


### Spoof-OWAEmailMessage

Send emails using a compromised user's Outlook mail box. The `--id` parameter can be used to send emails as other users within the organistion.

> Mail.Send permission REQUIRED for `--id` spoofing

Options:
1. Compromise and auth as an application service principal with the `Mail.Send` permission assigned then use `Spoof-OWAEmailMessage`
2. Obtain Global Admin/Application Admin/Cloud Admin permissions or assign role to an existing owned user with `Assign-PrivilegedRole` -> then add a password/certifcate and `Mail.Send` permission to an enterprise app -> auth as the app service principal and then use `Spoof-OWAEmailMessage`

![](./.github/spoofowaemailcommand.png)

The content of `--email email.txt` for reference:

```
Morning,

Please use following login for the devops portal whilst the main app is down:

https://malicious/login

Regards,

MC 
```
> I've not tested any HTML or similar formatted emails but in theory anything that works in Outlook normally should render correctly if supplied via `--email`.

Can see the email in the target users Outlook:

![](./.github/spoofowaemail.png)


### Find-DynamicGroups

Identify groups with dyanmic group membership rules that can be abused:

![](./.github/finddynamicgroups.png)

In this instance you could create a new user (`Create-NewUser`) with 'admin' in their UPN to be assigned to the Dynamic Admins group. Or you could update the user's Department property via `Update-UserProperties`.

### Find-UpdatableGroups

Identify groups that can be updated with the current user's permissions:

![](./.github/findupdatablegroups.png)


<br>

## Post-Auth Intune Enumeration

### Get-ManagedDevices

List Intune managed devices then select and display device properties such as name, os version, and username:

![](./.github/getmanageddevices.png)

### Get-UserDevices

Similarly you can identify all Intune managed devices and details belonging to a specific user by supplying their Entra User ID or their User Principal Name using the `--id` flag:

![](./.github/getuserdevices.png)

### Get-DeviceConfigurationPolicies

Identify all created device configuration policies across the Intune environment with colour highlighting for policies with active/no assignments. This includes Antivirus (Defender), Disk encryption (Bitlocker), Firewall (policies and rules), EDR, and Attack Surface Reduction (ASR):

![](./.github/getdeviceconfigurationpolicies.png)

In the example above you can see an ASR policy in place which is assigned to all users and devices, however members of group ID `46a6...` are excluded. There is a Bitlocker policy but it hasn't been assigned to any devices.

<br>

## Post-Auth Intune Exploitation

### Display-AVPolicyRules

Display the rules for a Microsoft Defender Antivirus policy deployed via Intune:

![](./.github/displayavpolicyrules.png)

### Get-ScriptContent

Get all device management PowerShell script details and content:

![](./.github/getscriptcontent.png)

### Backdoor-Script

Identify a pre-existing device management script you want to add malicious code to and get it's content:

![](./.github/getscriptcontent-new.png)

Create a new script locally with the existing content and your malicious code added:

![](./.github/createdirbackdoored.png)

Supply the backdoored script to the `--script` flag which will then patch the existing script:

![](./.github/backdoorscript.png)


### Deploy-MaliciousScript

Create a new script with desired properties (signature check, run as account, etc.):

![](./.github/deploymaliciousscript.png)

Verified creation and assignment options in Microsoft Intune admin center:

![](./.github/deploymaliciousscript-intuneportal.png)

> NOTE: Deploy-PrinterSettings.ps1 is used for the actual script name instead of whatever is supplied to `--script`. Recommended updating this in graphpython.py to blend in to target env.

### Add-ExclusionGroupToPolicy

Instead of updating or removing an AV, ASR, Bitlocker etc. policy you can simply add an exclusion group which will keep any groups members (users/devices) exempt from the policy rules in place.

Take the following Attack Surface Reduction (ASR) policy:

![](./.github/addexclusiongroup1.png)

Currently assigned to all users and devices:

![](./.github/addexclusiongroup2.png)

Adding an exclusion group to the ASR policy above:

![](./.github/addexclusiongroup3.png)

Verify the changes have been applied and Excluded Group ID has been added to the ASR policy:

![](./.github/addexclusiongroup4.png)

<br>

## Cleanup

### Remove-GroupMember

Check the members of the target group:

![](./.github/getgroupmember.png)

Remove the group member by first supplying the groupid and object id to the `--id` flag:

![](./.github/removegroupmember.png)

Confirm that the object has been removed from the group:

![](./.github/getgroupmemberafter.png)

<br>

## Locators

### Locate-ObjectID

Any unknown object IDs can be easily located:

![](./.github/locateobjectid.png)

### Locate-PermissionID

Graph permission IDs applied to objects can be easily located with detailed explaination of the assigned permissions:

![](./.github/getpermissionid.png)


<br>

## Acknowledgements and References

- [AADInternals](https://github.com/Gerenios/AADInternals)
- [GraphRunner](https://github.com/dafthack/GraphRunner)
- [TokenTactics](https://github.com/rvrsh3ll/TokenTactics)
- [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2)
- [https://learn.microsoft.com/en-us/graph/permissions-reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [https://graphpermissions.merill.net/](https://graphpermissions.merill.net/)
  
<br>

## Todo

- Update:
  - [ ] `Get-UserPrivileges` - update to flag any privileged directory role app ids
  - [ ] `Locate-DirectoryRoleID` - similar to other locator functions but for resolving directory role ids 
- New:
  - [ ] `Deploy-MaliciousWin32Exe/MSI` - use IntuneWinAppUtil.exe to package the EXE/MSI and deploy to devices
    - check also [here](https://learn.microsoft.com/en-us/graph/api/resources/intune-app-conceptual?view=graph-rest-1.0) for managing iOS, Android, LOB apps etc. via graph
  - [ ] `Update/Deploy-Policy` - update existing rules for av, asr, etc. policy or deploy a new one with specific groups/devices
  - [ ] `Invoke-MFASweep` - port mfa sweep and add to outsider commands 
- Options:
  - [ ] --proxy option
