import requests 
from tqdm import tqdm
import dns.resolver
import os
from Graphpython.utils.helpers import print_yellow, print_green, print_red, get_user_agent, get_access_token
from Graphpython.utils.helpers import get_tenant_domains

############
# Outsider #
############

def invoke_reconasoutsider(args):
    if not args.domain:
        print_red("[-] Error: --domain argument is required for Invoke-ReconAsOutsider command")
        return

    print_yellow("[*] Invoke-ReconAsOutsider")
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


def invoke_userenumerationasoutsider(args):
    if not args.username:
        print_red("[-] Error: --username argument is required for Invoke-UserEnumerationAsOutsider command")
        return
        
    print_yellow("[*] Invoke-UserEnumerationAsOutsider")
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