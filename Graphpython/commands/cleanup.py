import requests
from Graphpython.utils.helpers import print_yellow, print_green, print_red, get_user_agent, get_access_token

###########
# Cleanup #
###########

# delete-user
def delete_user(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Delete-User command")
        return

    print_yellow("[*] Delete-User")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/users/{args.id}"
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
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
def delete_group(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Delete-Group command")
        return

    print_yellow("[*] Delete-Group")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/groups/{args.id}"
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
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
def remove_groupmember(args):
    if not args.id:
        print_red("[-] Error: --id groupid,objectid required for Remove-GroupMember command")
        return

    ids = args.id.split(',')
    if len(ids) != 2:
        print_red("[-] Please provide two IDs separated by a comma (group ID, object ID).")
        return

    group_id, member_id = ids[0].strip(), ids[1].strip()
    print_yellow("[*] Remove-GroupMember")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/{member_id}/$ref"
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
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
def delete_application(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Delete-Application command")
        return

    print_yellow("[*] Delete-Application")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/applications/{args.id}"
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
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
def delete_device(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Delete-Device command")
        return

    print_yellow("[*] Delete-Device")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/devices/{args.id}"
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }

    response = requests.delete(api_url, headers=headers)
    if response.ok:
        print_green(f"[+] Device deleted")
    else:
        print_red(f"[-] Failed to delete device: {response.status_code}")
        print_red(response.text)
    print("=" * 80)

# wipe-device 
def wipe_device(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Wipe-Device command")
        return

    print_yellow("[*] Wipe-Device")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/beta/deviceManagement/managedDevices/{args.id}/wipe"
    
    user_agent = get_user_agent(args)
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
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

# retire-device
def retire_device(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Retire-Device command")
        return

    print_yellow("[*] Retire-Device")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/beta/deviceManagement/managedDevices/{args.id}/retire"
    user_agent = get_user_agent(args)
    
    headers = {
        'Authorization': f'Bearer {get_access_token(args.token)}',
        'User-Agent': user_agent
    }
    
    response = requests.post(api_url, headers=headers)
    if response.ok:
        print_green(f"[+] Device retire initiated successfully")
    else:
        print_red(f"[-] Failed to initiate device retire: {response.status_code}")
        print_red(response.text)
    print("=" * 80)