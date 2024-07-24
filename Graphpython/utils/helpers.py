import requests
import json
import os
import re
import base64
from tabulate import tabulate
from datetime import datetime, timedelta
import uuid
import xml.etree.ElementTree as ET
from termcolor import colored

def print_yellow(message):
    print(f"\033[93m{message}\033[0m")

def print_green(message):
    print(f"\033[92m{message}\033[0m")

def print_red(message):
    print(f"\033[91m{message}\033[0m")

def list_commands():
    outsider_commands = [
        ["Invoke-ReconAsOutsider", "Perform outsider recon of the target domain"],
        ["Invoke-UserEnumerationAsOutsider", "Checks whether the user exists within Azure AD"]
    ]

    auth_commands = [
        ["Get-GraphTokens", "Obtain graph token via device code phish (saved to graph_tokens.txt)"],
        ["Get-TenantID", "Get tenant ID for target domain"],
        ["Get-TokenScope", "Get scope of supplied token"],
        ["Decode-AccessToken", "Get all token payload attributes"],
        ["Invoke-RefreshToMSGraphToken", "Convert refresh token to Microsoft Graph token (saved to new_graph_tokens.txt)"],
        ["Invoke-RefreshToAzureManagementToken", "Convert refresh token to Azure Management token (saved to az_tokens.txt)"],
        ["Invoke-RefreshToVaultToken", "Convert refresh token to Azure Vault token (saved to vault_tokens.txt)"],
        ["Invoke-RefreshToMSTeamsToken", "Convert refresh token to MS Teams token (saved to teams_tokens.txt)"],
        ["Invoke-RefreshToOfficeAppsToken", "Convert refresh token to Office Apps token (saved to officeapps_tokens.txt)"],
        ["Invoke-RefreshToOfficeManagementToken", "Convert refresh token to Office Management token (saved to officemanagement_tokens.txt)"],
        ["Invoke-RefreshToOutlookToken", "Convert refresh token to Outlook token (saved to outlook_tokens.txt)"],
        ["Invoke-RefreshToSubstrateToken", "Convert refresh token to Substrate token (saved to substrate_tokens.txt)"],
        ["Invoke-RefreshToYammerToken", "Convert refresh token to Yammer token (saved to yammer_tokens.txt)"],
        ["Invoke-RefreshToIntuneEnrollmentToken", "Convert refresh token to Intune Enrollment token (saved to intune_tokens.txt)"],
        ["Invoke-RefreshToOneDriveToken", "Convert refresh token to OneDrive token (saved to onedrive_tokens.txt)"],
        ["Invoke-RefreshToSharePointToken", "Convert refresh token to SharePoint token (saved to sharepoint_tokens.txt)"],
        ["Invoke-CertToAccessToken", "Convert Azure Application certificate to JWT access token (saved to cert_tokens.txt)"],
        ["Invoke-ESTSCookieToAccessToken", "Convert ESTS cookie to MS Graph access token (saved to estscookie_tokens.txt)"],
        ["Invoke-AppSecretToAccessToken", "Convert Azure Application secretText credentials to access token (saved to appsecret_tokens.txt)"],
        ["New-SignedJWT", "Construct JWT and sign using Key Vault PEM certificate (Azure Key Vault access token required) then generate Azure Management token"]
    ]

    post_authenum_commands = [
        ["Get-CurrentUser", "Get current user profile"],
        ["Get-CurrentUserActivities", "Get recent activity and actions of current user"],
        ["Get-OrgInfo", "Get information relating to the target organisation"],
        ["Get-Domains", "Get domain objects"],
        ["Get-User", "Get all users (default) or target user (--id)"],
        ["Get-UserProperties", "Get current user properties (default) or target user (--id)"],
        ["Get-UserPrivileges", "Get group/AU memberships and directory roles assigned for current user (default) or target user (--id)"],
        ["Get-UserTransitiveGroupMembership", "Get transitive group memberships for current user (default) or target user (--id)"],
        ["Get-Group", "Get all groups (default) or target group (-id)"],
        ["Get-GroupMember", "Get all members of target group"],
        ["Get-UserAppRoleAssignments", "Get user app role assignments for current user (default) or target user (--id)"],
        ["Get-ConditionalAccessPolicy", "Get conditional access policy properties"],
        ["Get-Application", "Get Enterprise Application details for app (NOT object) ID (--id)"],
        ["Get-AppServicePrincipal", "Get details of the application's service principal from the app ID (--id)"], 
        ["Get-ServicePrincipal", "Get all or specific Service Principal details (--id)"],
        ["Get-ServicePrincipalAppRoleAssignments", "Get Service Principal app role assignments (shows available admin consent permissions that are already granted)"],
        ["Get-PersonalContacts", "Get contacts of the current user"],
        ["Get-CrossTenantAccessPolicy", "Get cross tenant access policy properties"],
        ["Get-PartnerCrossTenantAccessPolicy", "Get partner cross tenant access policy"],
        ["Get-UserChatMessages", "Get ALL messages from all chats for target user (Chat.Read.All)"],
        ["Get-AdministrativeUnitMember", "Get members of administrative unit"],
        ["Get-OneDriveFiles", "Get all accessible OneDrive files for current user (default) or target user (--id)"],
        ["Get-UserPermissionGrants", "Get permission grants of current user (default) or target user (--id)"],
        ["Get-oauth2PermissionGrants", "Get oauth2 permission grants for current user (default) or target user (--id)"],
        ["Get-Messages", "Get all messages in signed-in user's mailbox (default) or target user (--id)"],
        ["Get-TemporaryAccessPassword", "Get TAP details for current user (default) or target user (--id)"],
        ["Get-Password", "Get passwords registered to current user (default) or target user (--id)"],
        ["List-AuthMethods", "List authentication methods for current user (default) or target user (--id)"],
        ["List-DirectoryRoles", "List all directory roles activated in the tenant"],
        ["List-Notebooks", "List current user notebooks (default) or target user (--id)"],
        ["List-ConditionalAccessPolicies", "List conditional access policy objects"],
        ["List-ConditionalAuthenticationContexts", "List conditional access authentication context"],
        ["List-ConditionalNamedLocations", "List conditional access named locations"],
        ["List-SharePointRoot", "List root SharePoint site properties"],
        ["List-SharePointSites", "List any available SharePoint sites"],
        ["List-SharePointURLs", "List SharePoint site web URLs visible to current user"],
        ["List-ExternalConnections", "List external connections"],
        ["List-Applications", "List all Azure Applications"],
        ["List-ServicePrincipals", "List all service principals"],
        ["List-Tenants", "List tenants"],
        ["List-JoinedTeams", "List joined teams for current user (default) or target user (--id)"],
        ["List-Chats", "List chats for current user (default) or target user (--id)"],
        ["List-ChatMessages", "List messages in target chat (--id)"],
        ["List-Devices", "List devices"],
        ["List-AdministrativeUnits", "List administrative units"],
        ["List-OneDrives", "List current user OneDrive (default) or target user (--id)"],
        ["List-RecentOneDriveFiles", "List current user recent OneDrive files"],
        ["List-SharedOneDriveFiles", "List OneDrive files shared with the current user"],
        ["List-OneDriveURLs", "List OneDrive web URLs visible to current user"]
    ]

    post_authexploit_commands = [
        ["Invoke-CustomQuery", "Custom GET query to target Graph API endpoint"],
        ["Invoke-Search", "Search for string within entity type (driveItem, message, chatMessage, site, event)"],
        ["Find-PrivilegedRoleUsers", "Find users with privileged roles assigned"],
        ["Find-PrivilegedApplications", "Find privileged apps (via their service principal) with granted admin consent API permissions"],
        ["Find-UpdatableGroups", "Find groups which can be updated by the current user"],
        ["Find-SecurityGroups", "Find security groups and group members"],
        ["Find-DynamicGroups", "Find groups with dynamic membership rules"],
        ["Update-UserPassword", "Update the passwordProfile of the target user (NewUserS3cret@Pass!)"],
        ["Update-UserProperties", "Update the user properties of the target user"],
        ["Add-UserTAP", "Add new Temporary Access Password (TAP) to target user"],
        ["Add-GroupMember", "Add member to target group"],
        ["Add-ApplicationPassword", "Add client secret to target application"],
        ["Add-ApplicationCertificate", "Add client certificate to target application"],
        ["Add-ApplicationPermission", "Add permission to target application e.g. Mail.Send and attempt to grant admin consent"],
        ["Grant-AppAdminConsent", "Grant admin consent for Graph API permission already assigned to enterprise application"],
        ["Create-Application", "Create new enterprise application with default settings"],
        ["Create-NewUser", "Create new Entra ID user"],
        ["Invite-GuestUser", "Invite guest user to Entra ID"],
        ["Assign-PrivilegedRole", "Assign chosen privileged role to user/group/object"],
        ["Open-OWAMailboxInBrowser", "Open an OWA Office 365 mailbox in BurpSuite's embedded Chromium browser using either a Substrate.Office.com or Outlook.Office.com access token"],
        ["Dump-OWAMailbox", "Dump OWA Office 365 mailbox"],
        ["Spoof-OWAEmailMessage", "Send email from current user's Outlook mailbox or spoof another user (--id) (Mail.Send)"]
    ]

    intune_enum = [
        ["Get-ManagedDevices", "Get managed devices"],
        ["Get-UserDevices", "Get user devices"],
        ["Get-CAPs", "Get conditional access policies"],
        ["Get-DeviceCategories", "Get device categories"],
        ["Get-DeviceComplianceSummary", "Get device compliance summary"],
        ["Get-DeviceConfigurations", "Get device configurations"],
        ["Get-DeviceConfigurationPolicySettings", "Get device configuration policy settings"],
        ["Get-DeviceEnrollmentConfigurations", "Get device enrollment configurations"],
        ["Get-DeviceGroupPolicyConfigurations", "Get device group policy configurations and assignment details"],
        ["Get-DeviceGroupPolicyDefinition", "Get device group policy definition"],
        ["Get-RoleDefinitions", "Get role definitions"],
        ["Get-RoleAssignments", "Get role assignments"],
        ["Get-DeviceCompliancePolicies", "Get all device compliance policies (Android, iOS, macOS, Windows, Linux, etc.)"],
        ["Get-DeviceConfigurationPolicies", "Get device configuration policies and assignment details (AV, ASR, DiskEnc, etc.)"]
    ]

    intune_exploit = [
        ["Dump-DeviceManagementScripts", "Dump device management PowerShell scripts"],
        ["Dump-WindowsApps", "Dump managed Windows OS applications (exe, msi, appx, msix, etc.)"],
        ["Dump-iOSApps", "Dump managed iOS/iPadOS mobile applications"],
        ["Dump-macOSApps", "Dump managed macOS applications"],
        ["Dump-AndroidApps", "Dump managed Android mobile applications"],
        ["Get-ScriptContent", "Get device management script content"],
        ["Backdoor-Script", "Add malicious code to pre-existing device management script"],
        ["Deploy-MaliciousScript", "Deploy new malicious device management PowerShell script"],
        ["Deploy-MaliciousWebLink", "Deploy malicious Windows web link application"],
        ["Display-AVPolicyRules", "Display antivirus policy rules"],
        ["Display-ASRPolicyRules", "Display Attack Surface Reduction (ASR) policy rules"],
        ["Display-DiskEncryptionPolicyRules", "Display disk encryption policy rules"],
        ["Display-FirewallConfigPolicyRules", "Display firewall configuration policy rules"],
        ["Display-FirewallRulePolicyRules", "Display firewall RULE policy rules"],
        ["Display-EDRPolicyRules", "Display EDR policy rules"],
        ["Display-LAPSAccountProtectionPolicyRules", "Display LAPS account protection policy rules"],
        ["Display-UserGroupAccountProtectionPolicyRules", "Display user group account protection policy rules"],
        ["Add-ExclusionGroupToPolicy", "Bypass av, asr, etc. rules by adding an exclusion group containing compromised user or device"],
        ["Reboot-Device", "Reboot managed device"],
        ["Lock-Device", "Lock managed device"],
        ["Shutdown-Device", "Shutdown managed device"],
        ["Update-DeviceConfig", "Update properties of the managed device configuration"]
    ]

    cleanup_commands = [
        ["Delete-User", "Delete a user"],
        ["Delete-Group", "Delete a group"],
        ["Remove-GroupMember", "Remove user from a group"],
        ["Delete-Application", "Delete an application"],
        ["Delete-Device", "Delete managed device"],
        ["Wipe-Device", "Wipe managed device"],
        ["Retire-Device", "Retire managed device"]
    ]

    locator_commands = [
        ["Locate-ObjectID", "Locate object ID and display object properties"],
        ["Locate-PermissionID", "Locate Graph permission details (application/delegated, description, admin consent required, ...) for ID"]
    ]

    print("Outsider")
    print("=" * 80)
    print(tabulate(outsider_commands, tablefmt="plain"))

    print("\nAuthentication")
    print("=" * 80)
    print(tabulate(auth_commands, tablefmt="plain"))

    print("\nPost-Auth Enumeration")
    print("=" * 80)
    print(tabulate(post_authenum_commands, tablefmt="plain"))

    print("\nPost-Auth Exploitation")
    print("=" * 80)
    print(tabulate(post_authexploit_commands, tablefmt="plain"))

    print("\nPost-Auth Intune Enumeration")
    print("=" * 80)
    print(tabulate(intune_enum, tablefmt="plain"))

    print("\nPost-Auth Intune Exploitation")
    print("=" * 80)
    print(tabulate(intune_exploit, tablefmt="plain"))

    print("\nCleanup")
    print("=" * 80)
    print(tabulate(cleanup_commands, tablefmt="plain"))

    print("\nLocators")
    print("=" * 80)
    print(tabulate(locator_commands, tablefmt="plain"))
    print("\n")

def forge_user_agent(device=None, browser=None):

    user_agent = ''

    if device == 'Mac':
        if browser == 'Chrome':
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
        elif browser == 'Firefox':
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:70.0) Gecko/20100101 Firefox/70.0'
        elif browser == 'Edge':
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/604.1 Edg/91.0.100.0'
        elif browser == 'Safari':
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
        else:
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'

    elif device == 'Windows':
        if browser == 'IE':
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
        elif browser == 'Chrome':
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
        elif browser == 'Firefox':
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
        elif browser == 'Edge':
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
        else:
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'

    elif device == 'AndroidMobile':
        if browser == 'Android':
            user_agent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
        elif browser == 'Chrome':
            user_agent = 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36'
        elif browser == 'Firefox':
            user_agent = 'Mozilla/5.0 (Android 4.4; Mobile; rv:70.0) Gecko/70.0 Firefox/70.0'
        elif browser == 'Edge':
            user_agent = 'Mozilla/5.0 (Linux; Android 8.1.0; Pixel Build/OPM4.171019.021.D1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.109 Mobile Safari/537.36 EdgA/42.0.0.2057'
        else:
            user_agent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'

    elif device == 'iPhone':
        if browser == 'Chrome':
            user_agent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.114 Mobile/15E148 Safari/604.1'
        elif browser == 'Firefox':
            user_agent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) FxiOS/1.0 Mobile/12F69 Safari/600.1.4'
        elif browser == 'Edge':
            user_agent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 EdgiOS/44.5.0.10 Mobile/15E148 Safari/604.1'
        elif browser == 'Safari':
            user_agent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'
        else:
            user_agent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1'

    else:
        if browser == 'Android':
            user_agent = 'Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
        elif browser == 'IE':
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
        elif browser == 'Chrome':
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
        elif browser == 'Firefox':
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:70.0) Gecko/20100101 Firefox/70.0'
        elif browser == 'Safari':
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Safari/605.1.15'
        else:
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'

    return user_agent

def get_user_agent(args):
    if args.device:
        if args.browser:
            return forge_user_agent(device=args.device, browser=args.browser)
        else:
            return forge_user_agent(device=args.device)
    else:
        if args.browser:
            return forge_user_agent(browser=args.browser)
        else:
            return forge_user_agent()

def get_access_token(token_input):
    if os.path.isfile(token_input):
        encodings = ['utf-8', 'utf-16', 'ascii', 'iso-8859-1']
        for encoding in encodings:
            try:
                with open(token_input, 'r', encoding=encoding) as file:
                    access_token = file.read().strip()
                return access_token
            except UnicodeDecodeError:
                continue
        
        raise ValueError(f"Unable to decode the file {token_input} with any of the tried encodings.")
    else:
        access_token = token_input
    return access_token

def read_file_content(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='utf-16') as file:
            return file.read()

def format_list_style(data):
    if not data.get('value'):
        print_red("[-] No data found")
        return

    for d in data.get('value', []):
        for key, value in d.items():
            print(f"{key} : {value}")
        print("\n")

def read_and_encode_cert(cert_path):
    try:
        if not os.path.isfile(cert_path):
            print_red(f"[-] The certificate file '{cert_path}' does not exist.")
            return None
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
        # Base64 encode the binary data
        encoded_cert = base64.b64encode(cert_data).decode('ascii')
        return encoded_cert
    except Exception as e:
        print_red(f"[-] Error reading certificate: {str(e)}")
        return None

def highlight_search_term(text, search_term):
    return text.replace(search_term, colored(search_term, 'green'))

def graph_api_get(access_token, url, args):
    try:
        output_returned = False
        while url:
            user_agent = get_user_agent(args)
            headers = {
                "Authorization": f"Bearer {access_token}",
                "User-Agent": user_agent
            }
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            response_body = response.json()
            filtered_data = {key: value for key, value in response_body.items() if not key.startswith("@odata")}

            if filtered_data:
                format_list_style(filtered_data)
                output_returned = True

            url = response_body.get("@odata.nextLink")
        
        if not output_returned:
            print_red("[-] No data found")

    except requests.exceptions.RequestException as ex:
        print_red(f"[-] HTTP Error: {ex}")

def get_tenant_domains(domain):

    domains = [domain]
    try:
        openid_config_url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
        response = requests.get(openid_config_url)
        response.raise_for_status()
        openid_config = response.json()
        tenant_region_sub_scope = openid_config.get("tenant_region_sub_scope", "")

        if tenant_region_sub_scope == "DOD":
            autodiscover_url = "https://autodiscover-s-dod.office365.us/autodiscover/autodiscover.svc"
        elif tenant_region_sub_scope == "DODCON":
            autodiscover_url = "https://autodiscover-s.office365.us/autodiscover/autodiscover.svc"
        else:
            autodiscover_url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"

        autodiscover_body = f"""
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
                    xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
                    xmlns:a="http://www.w3.org/2005/08/addressing"
                    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:xsd="http://www.w3.org/2001/XMLSchema">
            <soap:Header>
                <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
                <a:To soap:mustUnderstand="1">{autodiscover_url}</a:To>
                <a:ReplyTo>
                    <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
                </a:ReplyTo>
            </soap:Header>
            <soap:Body>
                <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                    <Request>
                        <Domain>{domain}</Domain>
                    </Request>
                </GetFederationInformationRequestMessage>
            </soap:Body>
        </soap:Envelope>
        """.strip()

        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
            "User-Agent": "AutodiscoverClient"
        }

        autodiscover_response = requests.post(autodiscover_url, data=autodiscover_body, headers=headers)
        autodiscover_response.raise_for_status() 
        autodiscover_xml = autodiscover_response.content
        tree = ET.ElementTree(ET.fromstring(autodiscover_xml))
        namespaces = {
            's': 'http://schemas.xmlsoap.org/soap/envelope/',
            'a': 'http://www.w3.org/2005/08/addressing',
            'm': 'http://schemas.microsoft.com/exchange/services/2006/messages',
            't': 'http://schemas.microsoft.com/exchange/services/2006/types',
            'ns2': 'http://schemas.microsoft.com/exchange/2010/Autodiscover'
        }

        found_domains = [elem.text for elem in tree.findall('.//ns2:Domain', namespaces)]

        if domain not in found_domains:
            found_domains.append(domain)

        domains = sorted(found_domains)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return domains

##############
# NOT IN USE #
##############
def get_credential_type(username, flow_token=None, original_request=None):
    body = {
        "username": username,
        "isOtherIdpSupported": True,
        "checkPhones": True,
        "isRemoteNGCSupported": False,
        "isCookieBannerShown": False,
        "isFidoSupported": False,
        "originalRequest": original_request,
        "flowToken": flow_token
    }

    if original_request:
        body["isAccessPassSupported"] = True

    try:
        response = requests.post("https://login.microsoftonline.com/common/GetCredentialType",
                                 json=body,
                                 headers={"Content-Type": "application/json; charset=UTF-8"})
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error in Get-CredentialType: {e}")
        return None

##############
# NOT IN USE #
##############
def get_rst_token(url, endpoint_address, username, password="none"):
    request_id = str(uuid.uuid4())
    now = datetime.utcnow()
    created = now.isoformat() + "Z"
    expires = (now + timedelta(minutes=10)).isoformat() + "Z"

    body = f"""
    <?xml version='1.0' encoding='UTF-8'?>
    <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust' xmlns:ic='http://schemas.xmlsoap.org/ws/2005/05/identity'>
        <s:Header>
            <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
            <wsa:To s:mustUnderstand='1'>{url}</wsa:To>
            <wsa:MessageID>urn:uuid:{str(uuid.uuid4())}</wsa:MessageID>
            <wsse:Security s:mustUnderstand="1">
                <wsu:Timestamp wsu:Id="_0">
                    <wsu:Created>{created}</wsu:Created>
                    <wsu:Expires>{expires}</wsu:Expires>
                </wsse:Timestamp>
                <wsse:UsernameToken wsu:Id="uuid-{str(uuid.uuid4())}">
                    <wsse:Username>{username}</wsse:Username>
                    <wsse:Password>{password}</wsse:Password>
                </wsse:UsernameToken>
            </wsse:Security>
        </s:Header>
        <s:Body>
            <wst:RequestSecurityToken Id='RST0'>
                <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>{endpoint_address}</wsa:Address>
                    </wsp:AppliesTo>
                    <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
            </wst:RequestSecurityToken>
        </s:Body>
    </s:Envelope>
    """

    try:
        response = requests.post(url,
                                 data=body,
                                 headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
                                 timeout=10)
        response.raise_for_status()
        response_xml = response.content

        if "urn:oasis:names:tc:SAML:1.0:assertion" in response_xml.decode():
            return True
        return False
    except requests.exceptions.RequestException as e:
        print(f"Error in Get-RSTToken: {e}")
        return None

##############
# NOT IN USE #
##############
def does_user_exist(user, method="Normal"):
    exists = False
    error_details = ""

    if method == "Normal":
        cred_type = get_credential_type(user)
        if cred_type:
            if cred_type.get('ThrottleStatus') == 1:
                print("Requests throttled!")
                return None
            exists = cred_type.get('IfExistsResult') in [0, 6]
    else:
        if method == "Login":
            random_guid = str(uuid.uuid4())
            body = {
                "resource": random_guid,
                "client_id": random_guid,
                "grant_type": "password",
                "username": user,
                "password": "none",
                "scope": "openid"
            }
            try:
                response = requests.post("https://login.microsoftonline.com/common/oauth2/token",
                                         data=body,
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
                response.raise_for_status()
                exists = True
            except requests.exceptions.RequestException as e:
                error_details = e.response.json().get("error_description", "")

        elif method in ["Autologon", "RST2"]:
            request_id = str(uuid.uuid4())
            domain = user.split("@")[1]
            password = "none"
            now = datetime.utcnow()
            created = now.isoformat() + "Z"
            expires = (now + timedelta(minutes=10)).isoformat() + "Z"

            if method == "RST2":
                url = "https://login.microsoftonline.com/RST2.srf"
                end_point = "sharepoint.com"
            else:
                url = f"https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/usernamemixed?client-request-id={request_id}"
                end_point = "urn:federation:MicrosoftOnline"

            try:
                response = get_rst_token(url, end_point, user, password)
                exists = response is not None
            except Exception as e:
                error_details = str(e)

    if not exists and error_details:
        if error_details.startswith("AADSTS50053"):
            exists = True
        elif error_details.startswith("AADSTS50126"):
            exists = True
        elif error_details.startswith("AADSTS50076"):
            exists = True
        elif error_details.startswith("AADSTS700016"):
            exists = True
        elif error_details.startswith("AADSTS50034"):
            exists = False
        elif error_details.startswith("AADSTS50059"):
            exists = False
        elif error_details.startswith("AADSTS81016"):
            print("Got Invalid STS request. The tenant may not have DesktopSSO or Directory Sync enabled.")
            return None
        else:
            return None

    return exists

# todo:
# - add mfasweep functions