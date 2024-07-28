import requests
import os 
import re
from bs4 import BeautifulSoup
from Graphpython.utils.helpers import print_yellow, print_green, print_red, get_user_agent, get_access_token

############
# Locators #
############

def locate_objectid(args):
    if not args.id:
        print_red("[-] Error: --id required for Locate-ObjectID command")
        return

    print_yellow("[*] Locate-ObjectID")
    print("=" * 80)
    graph_api_url = f"https://graph.microsoft.com/v1.0/directoryObjects/{args.id}"

    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }

    try:
        response = requests.get(graph_api_url, headers=headers)
        response.raise_for_status()
        object_data = response.json()
        object_type = object_data.get('@odata.type', '').split('.')[-1]

        print_green(f"Object Type: {object_type}")
        print(f"ID: {object_data.get('id', 'N/A')}")
        print(f"Display Name: {object_data.get('displayName', 'N/A')}")

        if object_type == 'user':
            print(f"User Principal Name: {object_data.get('userPrincipalName', 'N/A')}")
            print(f"Mail: {object_data.get('mail', 'N/A')}")
            print(f"Job Title: {object_data.get('jobTitle', 'N/A')}")
            print(f"Department: {object_data.get('department', 'N/A')}")
            print(f"Office Location: {object_data.get('officeLocation', 'N/A')}")
            print(f"Mobile Phone: {object_data.get('mobilePhone', 'N/A')}")
            print(f"Business Phones: {', '.join(object_data.get('businessPhones', []))}")
            print(f"Account Enabled: {object_data.get('accountEnabled', 'N/A')}")
            print(f"Created DateTime: {object_data.get('createdDateTime', 'N/A')}")
            print(f"Last Sign-In DateTime: {object_data.get('signInActivity', {}).get('lastSignInDateTime', 'N/A')}")
        elif object_type == 'group':
            print(f"Mail: {object_data.get('mail', 'N/A')}")
            print(f"Security Enabled: {object_data.get('securityEnabled', 'N/A')}")
            print(f"Mail Enabled: {object_data.get('mailEnabled', 'N/A')}")
            print(f"Group Types: {', '.join(object_data.get('groupTypes', []))}")
            print(f"Visibility: {object_data.get('visibility', 'N/A')}")
            print(f"Created DateTime: {object_data.get('createdDateTime', 'N/A')}")
            print(f"Description: {object_data.get('description', 'N/A')}")
            print(f"Membership Rule: {object_data.get('membershipRule', 'N/A')}")
            print(f"Is Assignable To Role: {object_data.get('isAssignableToRole', 'N/A')}")
        elif object_type == 'servicePrincipal':
            print(f"App ID: {object_data.get('appId', 'N/A')}")
            print(f"Service Principal Type: {object_data.get('servicePrincipalType', 'N/A')}")
            print(f"App Display Name: {object_data.get('appDisplayName', 'N/A')}")
            print(f"Homepage: {object_data.get('homepage', 'N/A')}")
            print(f"Login URL: {object_data.get('loginUrl', 'N/A')}")
            print(f"Publisher Name: {object_data.get('publisherName', 'N/A')}")
            print(f"App Roles Count: {len(object_data.get('appRoles', []))}")
            print(f"OAuth2 Permissions Count: {len(object_data.get('oauth2Permissions', []))}")
            print(f"Tags: {', '.join(object_data.get('tags', []))}")
            print(f"Account Enabled: {object_data.get('accountEnabled', 'N/A')}")
        elif object_type == 'application':
            print(f"App ID: {object_data.get('appId', 'N/A')}")
            print(f"Sign In Audience: {object_data.get('signInAudience', 'N/A')}")
            print(f"Publisher Domain: {object_data.get('publisherDomain', 'N/A')}")
            print(f"Verified Publisher: {object_data.get('verifiedPublisher', {}).get('displayName', 'N/A')}")
            print(f"App Roles Count: {len(object_data.get('appRoles', []))}")
            print(f"Required Resource Access Count: {len(object_data.get('requiredResourceAccess', []))}")
            print(f"Web Redirect URIs: {', '.join(object_data.get('web', {}).get('redirectUris', []))}")
            print(f"Created DateTime: {object_data.get('createdDateTime', 'N/A')}")
        elif object_type == 'device':
            print(f"Device ID: {object_data.get('deviceId', 'N/A')}")
            print(f"Operating System: {object_data.get('operatingSystem', 'N/A')}")
            print(f"Operating System Version: {object_data.get('operatingSystemVersion', 'N/A')}")
            print(f"Trust Type: {object_data.get('trustType', 'N/A')}")
            print(f"Approximate Last Sign In DateTime: {object_data.get('approximateLastSignInDateTime', 'N/A')}")
            print(f"Compliance State: {object_data.get('complianceState', 'N/A')}")
            print(f"Is Managed: {object_data.get('isManaged', 'N/A')}")
            print(f"Is Compliant: {object_data.get('isCompliant', 'N/A')}")
            print(f"Registered Owner: {object_data.get('registeredOwners', [{}])[0].get('userPrincipalName', 'N/A')}")

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print_red(f"[-] Object with ID {args.id} not found")
        else:
            print_red(f"[-] An error occurred while retrieving object details: {str(e)}")
    except requests.exceptions.RequestException as e:
        print_red(f"[-] An error occurred while making the request: {str(e)}")

    print("=" * 80)

def locate_permissionid(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Locate-PermissionID command")
        return
    print_yellow("[*] Locate-PermissionID")
    print("=" * 80)

    def parse_html(content):
        soup = BeautifulSoup(content, 'html.parser')
        permissions = {}
   
        for h3 in soup.find_all('h3'):
            title = h3.text
            table = h3.find_next('table')
            headers = [th.text for th in table.find('thead').find_all('th')]
            rows = table.find('tbody').find_all('tr')
       
            permission_data = {}
            for row in rows:
                cells = row.find_all('td')
                category = cells[0].text
                application = cells[1].text
                delegated = cells[2].text
                permission_data[category] = {
                    headers[1]: application,
                    headers[2]: delegated
                }
            permissions[title] = permission_data
   
        return permissions

    def highlight(text, should_highlight):
        if should_highlight:
            return f"\033[92m{text}\033[0m"
        return text
   
    def print_permission(permission, data, identifiers):
        print_green(f"{permission}")
        for category, values in data.items():
            print(f"  {category}:")
            app_highlight = data['Identifier']['Application'] in identifiers or permission in identifiers
            delegated_highlight = data['Identifier']['Delegated'] in identifiers or permission in identifiers
            print(f"    Application: {highlight(values['Application'], app_highlight)}")
            print(f"    Delegated: {highlight(values['Delegated'], delegated_highlight)}")
        print()

    identifiers = args.id.split(',')
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, 'graphpermissions.txt')
   
    try:
        with open(file_path, 'r') as file:
            content = file.read()
    except FileNotFoundError:
        print_red(f"[-] The file {file_path} does not exist.")
        print("=" * 80)
        return
    except Exception as e:
        print_red(f"[-] An error occurred: {e}")
        print("=" * 80)
        return
   
    permissions = parse_html(content)
    found_permissions = False
   
    for permission, data in permissions.items():
        if (data['Identifier']['Application'] in identifiers or
            data['Identifier']['Delegated'] in identifiers or
            permission in identifiers):
            print_permission(permission, data, identifiers)
            found_permissions = True
   
    if not found_permissions:
        print_red("[-] Permission ID or name not found")
   
    print("=" * 80)

def locate_directoryrole(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Locate-DirectoryRole command")
        return
    print_yellow("[*] Locate-DirectoryRole")
    print("=" * 80)

    def parse_html(content):
        soup = BeautifulSoup(content, 'html.parser')
        roles = []
        for row in soup.find_all('tr')[1:]: # skip header row 
            cells = row.find_all('td')
            if len(cells) == 3:
                role_name = cells[0].text.strip()
                description = cells[1].text.strip()
                template_id = cells[2].text.strip()
                privileged = 'privileged-roles-permissions' in str(cells[1])
                roles.append({
                    'name': role_name,
                    'description': description,
                    'template_id': template_id,
                    'privileged': privileged
                })
        return roles

    def print_role(role):
        print(f"Role: \033[92m{role['name']}\033[0m") 
        print(f"Description: \033[92m{role['description']}\033[0m")
        print(f"Template ID: \033[92m{role['template_id']}\033[0m")
        print(f"Privileged: \033[92m{'Yes' if role['privileged'] else 'No'}\033[0m")
        print()

    identifier = args.id.lower()
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, 'directoryroles.txt')
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except FileNotFoundError:
        print_red(f"[-] The file {file_path} does not exist.")
        print("=" * 80)
        return
    except Exception as e:
        print_red(f"[-] An error occurred while reading the file: {e}")
        print("=" * 80)
        return

    roles = parse_html(content)
    found_role = False

    for role in roles:
        if identifier in role['name'].lower() or identifier == role['template_id'].lower():
            print_role(role)
            found_role = True

    if not found_role:
        print_red("[-] Directory role ID or name not found")

    print("=" * 80)