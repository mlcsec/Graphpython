# Graphpython

<p align="center">
  <img src="./.github/python.png" />
</p>

Graphpython is a modular Python tool for cross-platform Microsoft Graph API enumeration and exploitation. It builds upon the capabilities of AADInternals (Killchain.ps1), GraphRunner, and TokenTactics(V2) to provide a comprehensive solution for interacting with the Microsoft Graph API for red team and cloud assumed breach operations. 

Graphpython covers external reconnaissance, authentication/token manipulation, enumeration, and post-exploitation of various Microsoft services, including Entra ID (Azure AD), Office 365 (Outlook, SharePoint, OneDrive, Teams), and Intune (Endpoint Management).

## Index

- [Installation](#Installation)
- [Usage - Updated 2026 Prompt Toolkit](#usage---updated-2026-prompt-toolkit)
- [Commands](#Commands)
- [Demos](#Demos)
 
## Installation

Graphpython is designed to be cross-platform, ensuring compatibility with both Windows and Linux based operating systems:

```
git clone https://github.com/mlcsec/Graphpython.git
cd Graphpython
pip install .
```
```bash
Graphpython -h
# or
python3 Graphpython.py -h
```

## ⚠️ Usage - Updated 2026 Prompt Toolkit

> [!IMPORTANT]
> **UPDATED** - Running Graphpython without arguments now launches an interactive shell with Tab completion, command history, and inline descriptions for all commands and flags. One-shot CLI mode remains fully supported and unchanged.

```bash
# interactive shell (new)
python Graphpython.py

# one-shot CLI (unchanged)
python Graphpython.py --command get-currentuser --token eyJ0...

# interactive shell with logging enabled from start
python Graphpython.py --log-all-commands
```

> [!TIP]
> Use `set-token` in the interactive shell to persist a token for the session, removing the need to pass `--token` on every command. Supports direct paste or importing from a local file:
> ```
> set-token <tok>              Paste raw token directly
> set-token access <file>      Import access_token from file
> set-token refresh <file>     Import refresh_token from file
> ```

<p align="center">
  <img src="./.github/prompt-toolkit-1.png" />
</p>

All existing commands are accessible from the interactive shell with Tab completion and inline descriptions:

<p align="center">
  <img src="./.github/prompt-toolkit-2.png" />
</p>

### Logging

Command logging can be enabled at launch via `--log-all-commands` or toggled at any time from within the interactive shell using `log-enable` / `log-disable`. When enabled, each command and its full output is written to a timestamped file in a `logs/` directory created in the current working directory:

```
Graphpython ❯ log-enable
[+] Logging enabled → /mnt/c/Users/user0/Documents/GitHub/Graphpython/logs
```

<p align="center">
  <img src="./.github/prompt-toolkit-4.png" />
</p>

```bash
$ ls logs/ -la
total 20
drwxrwxrwx 1 user0 user0 4096 Sep 20 10:36 .
drwxrwxrwx 1 user0 user0 4096 Sep 20 10:31 ..
-rwxrwxrwx 1 user0 user0 1421 Sep 20 10:32 20260920_103228_get-tokenscope.txt
-rwxrwxrwx 1 user0 user0  576 Sep 20 10:35 20260920_103502_get-currentuser.txt
-rwxrwxrwx 1 user0 user0 1857 Sep 20 10:35 20260920_103545_find-privilegedapplications.txt
-rwxrwxrwx 1 user0 user0 6640 Sep 20 10:36 20260920_103634_find-privilegedroleusers.txt
```

> [!IMPORTANT]
> Not every function has been tested via the new interactive shell - if you encounter any issues or have improvements, please raise a [GitHub Issue](https://github.com/mlcsec/Graphpython/issues).



## Commands

> [!NOTE]
> All commands are available via Tab completion in the interactive shell with inline descriptions. Please refer to the [Wiki](https://github.com/mlcsec/Graphpython/wiki/Commands) for full details on available commands and flags.

The initial version with the following flags and arguments still functions as before, however, the improved interactive prompt improves usability signifcantly.

<p align="center">
  <img src="./.github/usage.png" />
</p>

### Outsider

- Invoke-ReconAsOutsider
- Invoke-UserEnumerationAsOutsider

### Authentication

- Get-GraphTokens
- Get-TenantID
- Get-TokenScope
- Decode-AccessToken
- Invoke-RefreshToMSGraphToken
- Invoke-RefreshToAzureManagementToken
- Invoke-RefreshToVaultToken
- Invoke-RefreshToMSTeamsToken
- Invoke-RefreshToOfficeAppsToken
- Invoke-RefreshToOfficeManagementToken
- Invoke-RefreshToOutlookToken
- Invoke-RefreshToSubstrateToken
- Invoke-RefreshToYammerToken
- Invoke-RefreshToIntuneEnrollmentToken
- Invoke-RefreshToOneDriveToken
- Invoke-RefreshToSharePointToken
- Invoke-CertToAccessToken
- Invoke-ESTSCookieToAccessToken
- Invoke-AppSecretToAccessToken
- New-SignedJWT

### Post-Auth Enumeration

- Get-CurrentUser
- Get-CurrentUserActivity
- Get-OrgInfo
- Get-Domains
- Get-User
- Get-UserProperties
- Get-UserGroupMembership
- Get-UserTransitiveGroupMembership
- Get-Group
- Get-GroupMember
- Get-AppRoleAssignments
- Get-ConditionalAccessPolicy
- Get-Application
- Get-AppServicePrincipal
- Get-ServicePrincipal
- Get-ServicePrincipalAppRoleAssignments
- Get-PersonalContacts
- Get-CrossTenantAccessPolicy
- Get-PartnerCrossTenantAccessPolicy
- Get-UserChatMessages
- Get-AdministrativeUnitMember
- Get-OneDriveFiles
- Get-UserPermissionGrants
- Get-oauth2PermissionGrants
- Get-Messages
- Get-TemporaryAccessPassword
- Get-Password
- List-AuthMethods
- List-DirectoryRoles
- List-Notebooks
- List-ConditionalAccessPolicies
- List-ConditionalAuthenticationContexts
- List-ConditionalNamedLocations
- List-SharePointRoot
- List-SharePointSites
- List-SharePointURLs
- List-ExternalConnections
- List-Applications
- List-ServicePrincipals
- List-Tenants
- List-JoinedTeams
- List-Chats
- List-ChatMessages
- List-Devices
- List-AdministrativeUnits
- List-OneDrives
- List-RecentOneDriveFiles
- List-SharedOneDriveFiles
- List-OneDriveURLs

### Post-Auth Exploitation

- Invoke-CustomQuery
- Invoke-Search
- Find-PrivilegedRoleUsers
- Find-PrivilegedApplications
- Find-UpdatableGroups
- Find-SecurityGroups
- Find-DynamicGroups
- Update-UserPassword
- Update-UserProperties
- Add-UserTAP
- Add-GroupMember
- Add-ApplicationPassword
- Add-ApplicationCertificate
- Add-ApplicationPermission
- Grant-AppAdminConsent
- Create-Application
- Create-NewUser
- Invite-GuestUser
- Assign-PrivilegedRole
- Open-OWAMailboxInBrowser
- Dump-OWAMailbox
- Spoof-OWAEmailMessage

### Post-Auth Intune Enumeration

- Get-ManagedDevices
- Get-UserDevices
- Get-CAPs
- Get-DeviceCategories
- Get-DeviceComplianceSummary
- Get-DeviceConfigurations
- Get-DeviceConfigurationPolicySettings
- Get-DeviceEnrollmentConfigurations
- Get-DeviceGroupPolicyConfigurations
- Get-DeviceGroupPolicyDefinition
- Get-RoleDefinitions
- Get-RoleAssignments
- Get-DeviceCompliancePolicies
- Get-DeviceConfigurationPolicies

### Post-Auth Intune Exploitation

- Dump-DeviceManagementScripts
- Dump-WindowsApps
- Dump-iOSApps
- Dump-macOSApps
- Dump-AndroidApps
- Get-ScriptContent
- Backdoor-Script
- Deploy-MaliciousScript
- Deploy-MaliciousWebLink
- Display-AVPolicyRules
- Display-ASRPolicyRules
- Display-DiskEncryptionPolicyRules
- Display-FirewallConfigPolicyRules
- Display-FirewallRulePolicyRules
- Display-EDRPolicyRules
- Display-LAPSAccountProtectionPolicyRules
- Display-UserGroupAccountProtectionPolicyRules
- Add-ExclusionGroupToPolicy
- Reboot-Device
- Lock-Device
- Shutdown-Device
- Update-DeviceConfig

### Cleanup

- Delete-User
- Delete-Group
- Remove-GroupMember
- Delete-Application
- Delete-Device
- Wipe-Device
- Retire-Device

### Locators

- Locate-ObjectID
- Locate-PermissionID
- Locate-DirectoryRole

<br>

# Demos

Please refer to the [Wiki](https://github.com/mlcsec/Graphpython/wiki/Demos) for the following demos

- [Outsider](https://github.com/mlcsec/Graphpython/wiki/Demos#outsider)
    - [Invoke-ReconAsOutsider](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-reconasoutsider)
    - [Invoke-UserEnumerationAsOutsider](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-userenumerationasoutsider)
- [Authentication](https://github.com/mlcsec/Graphpython/wiki/Demos#authentication)
    - [Get-GraphTokens](https://github.com/mlcsec/Graphpython/wiki/Demos#get-graphtokens)
    - [Get-TenantID](https://github.com/mlcsec/Graphpython/wiki/Demos#get-tenantid)
    - [Invoke-RefreshToAzureManagementToken](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-refreshtoazuremanagementtoken)
    - [Invoke-RefreshToMSGraphToken](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-refreshtomsgraphtoken)
    - [Invoke-CertToAccessToken](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-certtoaccesstoken)
    - [Invoke-ESTSCookieToAccessToken](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-estscookietoaccesstoken)
- [Post-Auth Enumeration](https://github.com/mlcsec/Graphpython/wiki/Demos#post-auth-enumeration)    
    - [Get-CurrentUser](https://github.com/mlcsec/Graphpython/wiki/Demos#get-currentuser)
    - [Get-User](https://github.com/mlcsec/Graphpython/wiki/Demos#get-user)
    - [Get-Group](https://github.com/mlcsec/Graphpython/wiki/Demos#get-group)
    - [Get-UserPrivileges](https://github.com/mlcsec/Graphpython/wiki/Demos#get-userprivileges)
    - [Get-Domains](https://github.com/mlcsec/Graphpython/wiki/Demos#get-domains)
    - [Get-Application](https://github.com/mlcsec/Graphpython/wiki/Demos#get-application)
    - [List-RecentOneDriveFiles](https://github.com/mlcsec/Graphpython/wiki/Demos#list-recentonedrivefiles)
- [Post-Auth Exploitation](https://github.com/mlcsec/Graphpython/wiki/Demos#post-auth-exploitation)    
    - [Invite-GuestUser](https://github.com/mlcsec/Graphpython/wiki/Demos#invite-guestuser)
    - [Find-PrivilegedRoleUsers](https://github.com/mlcsec/Graphpython/wiki/Demos#find-privilegedroleusers)
    - [Assign-PrivilegedRole](https://github.com/mlcsec/Graphpython/wiki/Demos#assign-privilegedrole)
    - [Find-PrivilegedApplications](https://github.com/mlcsec/Graphpython/wiki/Demos#find-privilegedapplications)
    - [Add-ApplicationCertificate](https://github.com/mlcsec/Graphpython/wiki/Demos#add-applicationcertificate)
    - [Add-ApplicationPermission](https://github.com/mlcsec/Graphpython/wiki/Demos#add-applicationpermission)
    - [Spoof-OWAEmailMessage](https://github.com/mlcsec/Graphpython/wiki/Demos#spoof-owaemailmessage)
    - [Find-DynamicGroups](https://github.com/mlcsec/Graphpython/wiki/Demos#find-dynamicgroups)
    - [Find-UpdatableGroups](https://github.com/mlcsec/Graphpython/wiki/Demos#find-updatablegroups)
    - [Invoke-Search](https://github.com/mlcsec/Graphpython/wiki/Demos#invoke-search)
- [Post-Auth Intune Enumeration](https://github.com/mlcsec/Graphpython/wiki/Demos#post-auth-intune-enumeration)
    - [Get-ManagedDevices](https://github.com/mlcsec/Graphpython/wiki/Demos#get-manageddevices)
    - [Get-UserDevices](https://github.com/mlcsec/Graphpython/wiki/Demos#get-userdevices) 
    - [Get-DeviceCompliancePolicies](https://github.com/mlcsec/Graphpython/wiki/Demos#get-devicecompliancepolicies)
    - [Get-DeviceConfigurationPolicies](https://github.com/mlcsec/Graphpython/wiki/Demos#get-deviceconfigurationpolicies)
- [Post-Auth Intune Exploitation](https://github.com/mlcsec/Graphpython/wiki/Demos#post-auth-intune-exploitation)
    - [Display-AVPolicyRules](https://github.com/mlcsec/Graphpython/wiki/Demos#display-avpolicyrules)
    - [Get-ScriptContent](https://github.com/mlcsec/Graphpython/wiki/Demos#get-scriptcontent)
    - [Backdoor-Script](https://github.com/mlcsec/Graphpython/wiki/Demos#backdoor-script)
    - [Deploy-MaliciousScript](https://github.com/mlcsec/Graphpython/wiki/Demos#deploy-maliciousscript)
    - [Deploy-MaliciousWebLink](https://github.com/mlcsec/Graphpython/wiki/Demos#deploy-maliciousweblink)
    - [Add-ExclusionGroupToPolicy](https://github.com/mlcsec/Graphpython/wiki/Demos#add-exclusiongrouptopolicy)
- [Cleanup](https://github.com/mlcsec/Graphpython/wiki/Demos#cleanup)
    - [Remove-GroupMember](https://github.com/mlcsec/Graphpython/wiki/Demos#remove-groupmember)
- [Locators](https://github.com/mlcsec/Graphpython/wiki/Demos#locators)
    - [Locate-ObjectID](https://github.com/mlcsec/Graphpython/wiki/Demos#locate-objectid)
    - [Locate-PermissionID](https://github.com/mlcsec/Graphpython/wiki/Demos#locate-permissionid)
    - [Locate-DirectoryRole](https://github.com/mlcsec/Graphpython/wiki/Demos#locate-directoryrole)
  
<br>

## Acknowledgements and References

- [AADInternals](https://github.com/Gerenios/AADInternals)
- [GraphRunner](https://github.com/dafthack/GraphRunner)
- [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) and [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2)
- [https://learn.microsoft.com/en-us/graph/permissions-reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [https://graphpermissions.merill.net/](https://graphpermissions.merill.net/)
  
<br>

## Todo

- Update:
  - [x] Implement prompt tooklit instead of typing long cmdlets
  - [x] Add nextlink for `get-user` and `get-group` 
  - [ ] `Get-UserPrivileges` - update to flag any privileged directory role app ids green
  - [x] `Locate-DirectoryRoleID` - similar to other locator functions but for resolving directory role ids
  - [ ] `Deploy-MaliciousWebLink` - add option to deploy script which copies new windows web app link to all user desktops
- New:
  - [ ] `Deploy-MaliciousWin32Exe/MSI` - use IntuneWinAppUtil.exe to package the EXE/MSI and deploy to devices
    - check also [here](https://learn.microsoft.com/en-us/graph/api/resources/intune-app-conceptual?view=graph-rest-1.0) for managing iOS, Android, LOB apps etc. via graph
  - [ ] `Update/Deploy-Policy` - update existing rules for av, asr, etc. policy or deploy a new one with specific groups/devices
  - [ ] `Invoke-MFASweep` - port mfa sweep and add to outsider commands
  - [ ] `Invoke-AADIntReconAsGuest` and `Invoke-AADIntUserEnumerationAsGuest` - port from AADInternals 
- Options:
  - [ ] --proxy option
