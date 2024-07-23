import requests 
import json
import os 
import sys 
import time 
from bs4 import BeautifulSoup
from graphpython.utils.helpers import print_yellow, print_green, print_red, get_user_agent, get_access_token
from graphpython.utils.helpers import graph_api_get

##########################
# Post-Auth Enuemeration #
##########################

# get-currentuser
def get_currentuser(args):
    print_yellow("[*] Get-CurrentUser")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me"
    if args.select:
        api_url += "?$select=" + args.select
    
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }

    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        for key, value in response_json.items():
            if key != "@odata.context":
                print(f"{key}: {value}")
    else:
        print_red(f"[-] Failed to retrieve current user: {response.status_code}")
        print_red(response.text)
    print("=" * 80)

# get-currentuseractivities
def get_currentuseractivities(args):
    print_yellow("[*] Get-CurrentUserActivities")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/activities"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-orginfo
def get_orginfo(args):
    print_yellow("[*] Get-OrgInfo")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/organization"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)
    
# get-domains
def get_domains(args):
    print_yellow("[*] Get-Domains")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/domains"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-user
def get_user(args):
    print_yellow("[*] Get-User")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/users"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}"
    if args.select:
        api_url += "?$select=" + args.select
    
    user_agent = get_user_agent(args)
    access_token = get_access_token(args.token)
    headers = {
        'Authorization': f'Bearer {access_token}',
        'User-Agent': user_agent
    }
    
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        if args.id:
            for key, value in response_json.items():
                if key != "@odata.context":
                    print(f"{key}: {value}")
        else:
            if 'value' in response_json:
                for user in response_json['value']:
                    for key, value in user.items():
                        print(f"{key}: {value}")
                    print()
            else:
                print_red("[-] No users found or unexpected response format")
    else:
        print_red(f"[-] Failed to retrieve user(s): {response.status_code}")
        print_red(response.text)
    print("=" * 80)

# get-userproperties
def get_userproperties(args):
    properties = [
        "aboutMe", "accountEnabled", "ageGroup", "assignedLicenses", "assignedPlans", 
        "birthday", "businessPhones", "city", "companyName", "consentProvidedForMinor", 
        "country", "createdDateTime", "department", "displayName", "employeeId", 
        "faxNumber", "givenName", "hireDate", "id", "imAddresses", "interests", 
        "isResourceAccount", "jobTitle", "lastPasswordChangeDateTime", "legalAgeGroupClassification", 
        "licenseAssignmentStates", "mail", "mailboxSettings", "mailNickname", "mobilePhone", 
        "mySite", "officeLocation", "onPremisesDistinguishedName", "onPremisesDomainName", 
        "onPremisesImmutableId", "onPremisesLastSyncDateTime", "onPremisesSecurityIdentifier", 
        "onPremisesSyncEnabled", "onPremisesSamAccountName", "onPremisesUserPrincipalName", 
        "otherMails", "passwordPolicies", "passwordProfile", "pastProjects", "preferredDataLocation", 
        "preferredLanguage", "preferredName", "proxyAddresses", "responsibilities", 
        "schools", "showInAddressList", "skills", "state", "streetAddress", 
        "surname", "usageLocation", "userPrincipalName", "userType", "webUrl"
    ]
    
    print_yellow("[*] Get-UserProperties")
    print("=" * 80)
    
    for p in properties:
        if not args.id:
            api_url = f"https://graph.microsoft.com/v1.0/me?$select={p}"
        else:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}?$select={p}"
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {get_access_token(args.token)}',
            'User-Agent': user_agent
        }
    
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            response_json = response.json()
            print(f"{p}: {response_json.get(p, 'N/A')}")
        else:
            print_red(f"[-] Failed to retrieve {p}: {response.status_code}")
            print_red(response.text)
    print("=" * 80)

# get-userprivileges
def get_userprivileges(args):
    print_yellow("[*] Get-UserPrivileges")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/memberOf"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/memberOf"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-usertransitivegroupmembership
def get_usertransitivegroupmembership(args):
    print_yellow("[*] Get-UserTransitiveGroupMembership")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/transitiveMemberOf"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-group
def get_group(args):
    print_yellow("[*] Get-Group")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/groups"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/groups/{args.id}"
    if args.select:
        api_url += "?$select=" + args.select
    
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }
    
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        if args.id:
            for key, value in response_json.items():
                if key != "@odata.context":
                    print(f"{key}: {value}")
        else:
            if 'value' in response_json:
                for user in response_json['value']:
                    for key, value in user.items():
                        print(f"{key}: {value}")
                    print()
            else:
                print_red("[-] No users found or unexpected response format")
    else:
        print_red(f"[-] Failed to retrieve user(s): {response.status_code}")
        print_red(response.text)
    print("=" * 80)

# get-groupmember
def get_groupmember(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Get-GroupMember command")
        return
    print_yellow("[*] Get-GroupMember")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/groups/{args.id}/members"
    
    if args.select:
        api_url += f"?$select={args.select}"
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }
    
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        if 'value' in response_json and response_json['value']:
            for item in response_json['value']:
                for key, value in item.items():
                    if key != "@odata.type":  
                        if isinstance(value, list):
                            print(f"{key} :")
                            for list_item in value:
                                print(f"  - {list_item}")
                        elif isinstance(value, dict):
                            print(f"{key} :")
                            for sub_key, sub_value in value.items():
                                print(f"  {sub_key} : {sub_value}")
                        else:
                            print(f"{key} : {value}")
                print("\n")
        else:
            print_red("[-] Error: No members found in this group")
    else:
        print_red(f"[-] Failed to retrieve group members: {response.status_code}")
        print_red(response.text)
    print("=" * 80)

# get-userapproleassignments
def get_userapproleassignments(args):
    print_yellow("[*] Get-UserAppRoleAssignments")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/appRoleAssignments"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/appRoleAssignments"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-conditionalaccesspolicy
def get_conditionalaccesspolicy(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Get-ConditionalAccessPolicy command")
        return
    
    print_yellow("[*] Get-ConditionalAccessPolicy")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/{args.id}"
    
    if args.select:
        api_url += "?$select=" + args.select
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }
    
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        for key, value in response_json.items():
            if key != "@odata.context":
                print(f"{key}: {value}")
    else:
        print_red(f"[-] Failed to retrieve CAP: {response.status_code}")
        print_red(response.text)
    print("=" * 80)

# get-application
def get_application(args):
    if not args.id:
        print_red("[-] Error: --id <appid> argument is required for Get-Application command")
        return
    
    print_yellow("[*] Get-Application")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/beta/myorganization/applications(appId='{args.id}')" # app id
    #api_url = f"https://graph.microsoft.com/v1.0/applications/{args.id}" # object id
    
    if args.select:
        api_url += "?$select=" + args.select
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }
    
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        def parse_roleids(content):
            soup = BeautifulSoup(content, 'html.parser')
            permissions = {}
            for h3 in soup.find_all('h3'):
                permission_name = h3.get_text()
                table = h3.find_next('table')
                rows = table.find_all('tr')
                application_id = rows[1].find_all('td')[1].get_text()
                delegated_id = rows[1].find_all('td')[2].get_text()
                application_description = rows[2].find_all('td')[1].get_text()
                delegated_description = rows[2].find_all('td')[2].get_text()
                application_consent = rows[4].find_all('td')[1].get_text() if len(rows) > 4 else "Unknown"
                delegated_consent = rows[4].find_all('td')[2].get_text() if len(rows) > 4 else "Unknown"
                permissions[application_id] = ('Application', permission_name, application_description, application_consent)
                permissions[delegated_id] = ('Delegated', permission_name, delegated_description, delegated_consent)
            return permissions
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, 'graphpermissions.txt')
        try:
            with open(file_path, 'r') as file:
                content = file.read()
        except FileNotFoundError:
            print_red(f"\n[-] The file {file_path} does not exist.")
            sys.exit(1)
        except Exception as e:
            print_red(f"\n[-] An error occurred: {e}")
            sys.exit(1)
        permissions = parse_roleids(content)
        for key, value in response_json.items():
            if key == "requiredResourceAccess":
                if value:
                    print_green(f"{key}:")
                    for resource in value:
                        print_green(f"  Resource App ID: {resource['resourceAppId']}")
                        for access in resource['resourceAccess']:
                            role_id = access['id']
                            role_type = access['type']
                            if role_id in permissions:
                                perm_type, role_name, description, consent_required = permissions[role_id]
                                print_green(f"    Role ID: {role_id}")
                                print_green(f"    Role Name: {role_name}")
                                print_green(f"    Description: {description}")
                                print_green(f"    Type: {role_type}")
                                print_green(f"    Permission Type: {perm_type}")
                                print_green(f"    Admin Consent Required: {consent_required}")
                            else:
                                print_red(f"    Role ID: {role_id} (Information not found)")
                                print_red(f"    Type: {role_type}")
                            print("    ---")
                else:
                    print_red(f"{key} : No assignments")
            elif key != "@odata.context":
                print(f"{key}: {value}")
    else:
        print_red(f"[-] Failed to retrieve Azure Application details: {response.status_code}")
        print_red(response.text)
    print("=" * 80)

# get-appserviceprincipal
def get_appserviceprincipal(args):
    if not args.id:
        print_red("[-] Error: --id <app id> argument is required for Get-AppServicePrincipal command")
        return
        
    print_yellow("[*] Get-AppServicePrincipal")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId+eq+'{args.id}'"
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-serviceprincipal
def get_serviceprincipal(args):
    if not args.id:
        print_red("[-] Error: --id <id> argument is required for Get-ServicePrincipal command")
        return
        
    print_yellow("[*] Get-ServicePrincipal")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{args.id}"
    if args.select:
        api_url += "?$select=" + args.select
    
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }
    
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        for key, value in response_json.items():
            if key != "@odata.context":
                print(f"{key}: {value}")
    else:
        print_red(f"[-] Failed to retrieve Service Principal details: {response.status_code}")
        print_red(response.text)
    print("=" * 80)

# get-serviceprincipalapproleassignments
def get_serviceprincipalapproleassignments(args):
    print_yellow("[*] Get-ServicePrincipalAppRoleAssignments")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{args.id}/appRoleAssignments"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-personalcontacts
def get_personalcontacts(args):
    print_yellow("[*] Get-PersonalContacts")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/contacts"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-crosstenantaccesspolicy
def get_crosstenantaccesspolicy(args):
    print_yellow("[*] Get-CrossTenantAccessPolicy")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy"
    
    if args.id:
        api_url += f"/{args.id}"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-partnercrosstenantaccesspolicy
def get_partnercrosstenantaccesspolicy(args):
    print_yellow("[*] Get-PartnerCrossTenantAccessPolicy")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/templates/multiTenantOrganizationPartnerConfiguration"
    
    if args.id:
        api_url += f"/{args.id}"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-userchatmessages
def get_userchatmessages(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Get-UserChatMessages command")
        return
    print_yellow("[*] Get-UserChatMessages")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/chats"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-administrativeunitmember
def get_administrativeunitmember(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Get-AdministrativeUnitMember command")
        return
    
    print_yellow("[*] Get-AdministrativeUnitMember")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/directory/administrativeUnits/{args.id}/members"
    
    if args.select:
        api_url += "?$select=" + args.select
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-onedrivefiles
def get_onedrivefiles(args):
    print_yellow("[*] Get-OneDriveFiles")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/drive/root/children"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/drive/root/children"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-userpermissiongrants
def get_userpermissiongrants(args):
    print_yellow("[*] Get-UserPermissionGrants")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/permissionGrants"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/permissionGrants"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-oauth2permissiongrants
def get_oauth2permissiongrants(args):
    print_yellow("[*] Get-oauth2PermissionGrants")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/oauth2PermissionGrants"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-messages
def get_messages(args):
    print_yellow("[*] Get-Messages")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/messages"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/messages"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-temporaryaccesspassword
def get_temporaryaccesspassword(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Get-TemporaryAccessPassword command")
        return
    print_yellow("[*] Get-TemporaryAccessPassword")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/authentication/passwordMethods"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-password
def get_password(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Get-Password command")
        return
    print_yellow("[*] Get-Password")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/passwordCredentials"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-authmethods
def list_authmethods(args):
    print_yellow("[*] List-AuthMethods")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/authentication/methods"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/authentication/methods"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)
    
# list-directoryroles
def list_directoryroles(args):
    print_yellow("[*] List-DirectoryRoles")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/directoryRoles"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-notebooks
def list_notebooks(args):
    print_yellow("[*] List-Notebooks")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/onenote/notebooks"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/onenote/notebooks"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-conditionalaccesspolicies
def list_conditionalaccesspolicies(args):
    print_yellow("[*] List-ConditionalAccessPolicies")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-conditionalauthenticationcontexts
def list_conditionalauthenticationcontexts(args):
    print_yellow("[*] List-ConditionalAuthenticationContexts")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-conditionalnamedlocations
def list_conditionalnamedlocations(args):
    print_yellow("[*] List-ConditionalNamedLocations")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-sharepointroot
def list_sharepointroot(args):
    print_yellow("[*] List-SharePointRoot")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/sites/root"
    
    if args.select:
        api_url += "?$select=" + args.select
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }
    
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        for key, value in response_json.items():
            if key != "@odata.context":
                print(f"{key}: {value}")
    else:
        print_red(f"[-] Failed to retrieve current user: {response.status_code}")
        print_red(response.text)
    print("=" * 80)


# list-sharepointsites
def list_sharepointsites(args):
    print_yellow("[*] List-SharePointSites")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/sites"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-sharepointurls
def list_sharepointurls(args):
    print_yellow("[*] List-SharePointURLs")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/search/query"
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'Content-Type': 'application/json',
        'User-Agent': user_agent
    }
    
    data = {
        "requests": [
            {
                "entityTypes": ["drive"],
                "query": {
                    "queryString": "*"
                },
                "from": 0,
                "size": 500,
                "fields": [
                    "webUrl"
                ]
            }
        ]
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        
        response_body = response.json()
        
        if 'value' in response_body:
            for item in response_body['value']:
                for hit in item.get('hitsContainers', []):
                    for result in hit.get('hits', []):
                        web_url = result.get('resource', {}).get('webUrl')
                        if web_url:
                            print(web_url)
        else:
            print_yellow("[-] No results found in the response.")
        
        next_link = response_body.get("@odata.nextLink")
        while next_link:
            response = requests.get(next_link, headers=headers, timeout=30)
            response.raise_for_status()
            response_body = response.json()
            
            if 'value' in response_body:
                for item in response_body['value']:
                    for hit in item.get('hitsContainers', []):
                        for result in hit.get('hits', []):
                            web_url = result.get('resource', {}).get('webUrl')
                            if web_url:
                                print(web_url)
            
            next_link = response_body.get("@odata.nextLink")
    
    except requests.exceptions.RequestException as e:
        print_red(f"[-] Failed to search data: {str(e)}")
        if hasattr(e, 'response'):
            print_red(e.response.text)
    
    print("=" * 80)

# list-externalconnections
def list_externalconnections(args):
    print_yellow("[*] List-ExternalConnections")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/external/connections"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-applications
def list_applications(args):
    print_yellow("[*] List-Applications")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/applications"
    if args.select:
        api_url += "?$select=" + args.select
    
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': 'Bearer ' + get_access_token(args.token),
        'Accept': 'application/json',
        'User-Agent': user_agent
    }
    
    response = requests.get(api_url, headers=headers)
    
    if response.status_code == 200:
        applications = response.json()
    else:
        print_red(f"[-] Error: API request failed with status code {response.status_code}")
        applications = None
    
    def parse_roleids(content):
        soup = BeautifulSoup(content, 'html.parser')
        permissions = {}
        for h3 in soup.find_all('h3'):
            permission_name = h3.get_text()
            table = h3.find_next('table')
            rows = table.find_all('tr')
            application_id = rows[1].find_all('td')[1].get_text()
            delegated_id = rows[1].find_all('td')[2].get_text()
            application_description = rows[2].find_all('td')[1].get_text()
            delegated_description = rows[2].find_all('td')[2].get_text()
            application_consent = rows[4].find_all('td')[1].get_text() if len(rows) > 4 else "Unknown"
            delegated_consent = rows[4].find_all('td')[2].get_text() if len(rows) > 4 else "Unknown"
            permissions[application_id] = ('Application', permission_name, application_description, application_consent)
            permissions[delegated_id] = ('Delegated', permission_name, delegated_description, delegated_consent)
        return permissions
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, 'graphpermissions.txt')
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except FileNotFoundError:
        print_red(f"\n[-] The file {file_path} does not exist.")
        sys.exit(1)
    except Exception as e:
        print_red(f"\n[-] An error occurred: {e}")
        sys.exit(1)
    
    permissions = parse_roleids(content)
    
    if applications and 'value' in applications:
        for app in applications['value']:
            for key, value in app.items():
                if key == 'requiredResourceAccess':
                    if value:
                        print_green(f"{key}:")
                        for resource in value:
                            print_green(f"  Resource App ID: {resource['resourceAppId']}")
                            for access in resource['resourceAccess']:
                                role_id = access['id']
                                role_type = access['type']
                                if role_id in permissions:
                                    perm_type, role_name, description, consent_required = permissions[role_id]
                                    print_green(f"    Role ID: {role_id}")
                                    print_green(f"    Role Name: {role_name}")
                                    print_green(f"    Description: {description}")
                                    print_green(f"    Type: {role_type}")
                                    print_green(f"    Permission Type: {perm_type}")
                                    print_green(f"    Admin Consent Required: {consent_required}")
                                else:
                                    print_red(f"    Role ID: {role_id} (Information not found)")
                                    print_red(f"    Type: {role_type}")
                                print("    ---")
                    else:
                        print_red(f"{key} : No assignments")
                else:
                    print(f"{key} : {value}")
            print("\n")
    print("=" * 80)

# list-serviceprincipals
def list_serviceprincipals(args):
    print_yellow("[*] List-ServicePrincipals")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/servicePrincipals"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-tenants
def list_tenants(args):
    print_yellow("[*] List-Tenants")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/tenantRelationships/multiTenantOrganization/tenants"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-joinedteams
def list_joinedteams(args):
    print_yellow("[*] List-JoinedTeams")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/joinedTeams"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/joinedTeams"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-chats
def list_chats(args):
    print_yellow("[*] List-Chats")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/chats"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/chats"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-chatmessages
def list_chatmessages(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for List-ChatMessages command")
        return
    
    print_yellow("[*] List-ChatMessages")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/chats/{args.id}/messages"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-devices
def list_devices(args):
    print_yellow("[*] List-Devices")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/devices"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-administrativeunits
def list_administrativeunits(args):
    print_yellow("[*] List-AdministrativeUnits")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/directory/administrativeUnits"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-onedrives
def list_onedrives(args):
    print_yellow("[*] List-OneDrives")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/drives"
    
    if args.id:
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/drives"
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-recentonedrivefiles
def list_recentonedrivefiles(args):
    print_yellow("[*] List-RecentOneDriveFiles")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/drive/recent"
    user_agent = get_user_agent(args)
    headers = {
        "Authorization": f"Bearer {get_access_token(args.token)}",
        "User-Agent": user_agent
    }
    
    try:
        while api_url:
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()
            response_body = response.json()
            filtered_data = response_body.get('value', [])
            if filtered_data:
                file_count = 1
                for d in filtered_data:
                    print_green(f"File {file_count}")
                    if args.select:
                        selected_fields = args.select.split(',')
                        for field in selected_fields:
                            value = d
                            for part in field.split('.'):
                                if isinstance(value, dict) and part in value:
                                    value = value[part]
                                else:
                                    value = None
                                    break
                            if value is not None:
                                print(f"{field} : {value}")
                    else:
                        for key, value in d.items():
                            if isinstance(value, (str, int, float, bool)):
                                print(f"{key} : {value}")
                            elif isinstance(value, dict):
                                print(f"{key} : {json.dumps(value, indent=2)}")
                            else:
                                print(f"{key} : {str(value)}")
                    print("\n")
                    file_count += 1
            else:
                print_red("[-] No data found")
                return
            
            api_url = response_body.get("@odata.nextLink")
    except requests.RequestException as e:
        print_red(f"[-] Error making request: {str(e)}")
    print("=" * 80)

# list-sharedonedrivefiles
def list_sharedonedrivefiles(args):
    print_yellow("[*] List-SharedOneDriveFiles")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/me/drive/sharedWithMe"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# list-onedriveurls
def list_onedriveurls(args):
    print_yellow("[*] List-OneDriveURLs")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/search/query"
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'Content-Type': 'application/json',
        'User-Agent': user_agent
    }
    
    data = {
        "requests": [
            {
                "entityTypes": ["driveItem"], # get OneDrive and SharePoint - no only OneDrive option
                "query": {
                    "queryString": "*"
                },
                "from": 0,
                "size": 500,
                "fields": [
                    "webUrl"
                ]
            }
        ]
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        
        response_body = response.json()
        
        if 'value' in response_body:
            for item in response_body['value']:
                for hit in item.get('hitsContainers', []):
                    for result in hit.get('hits', []):
                        web_url = result.get('resource', {}).get('webUrl')
                        if web_url:
                            print(web_url)
        else:
            print_yellow("[-] No results found in the response.")
        
        next_link = response_body.get("@odata.nextLink")
        while next_link:
            response = requests.get(next_link, headers=headers, timeout=30)
            response.raise_for_status()
            response_body = response.json()
            
            if 'value' in response_body:
                for item in response_body['value']:
                    for hit in item.get('hitsContainers', []):
                        for result in hit.get('hits', []):
                            web_url = result.get('resource', {}).get('webUrl')
                            if web_url:
                                print(web_url)
            
            next_link = response_body.get("@odata.nextLink")
    
    except requests.exceptions.RequestException as e:
        print_red(f"[-] Failed to search data: {str(e)}")
        if hasattr(e, 'response'):
            print_red(e.response.text)
    
    print("=" * 80)