import requests 
import json
from Graphpython.utils.helpers import print_yellow, print_green, print_red, get_user_agent, get_access_token
from Graphpython.utils.helpers import graph_api_get

################################
# Post-Auth Intune Enumeration #
################################

# get-manageddevices
def get_manageddevices(args):
    print_yellow("[*] Get-ManagedDevices")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-userdevices
def get_userdevices(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Get-UserDevices command")
        return
    
    print_yellow("[*] Get-UserDevices")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$filter=userPrincipalName eq '{args.id}'"
    
    if args.select:
        api_url += "&$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-caps
def get_caps(args):
    print_yellow("[*] Get-CAPs")
    print("=" * 80)
    api_url = "https://graph.microsoft.com//beta/identity/conditionalAccess/policies"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-devicecategories
def get_devicecategories(args):
    print_yellow("[*] Get-DeviceCategories")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCategories"
    
    if args.select:
        api_url += "?$select=" + args.select

    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-devicecompliancesummary
def get_devicecompliancesummary(args):
    print_yellow("[*] Get-DeviceComplianceSummary")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicyDeviceStateSummary"
    if args.select:
        api_url += "?$select=" + args.select

    user_agent = get_user_agent(args)
    headers = {
    'Authorization': f'Bearer {get_access_token(args.token)}',
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
def get_deviceconfigurations(args):
    print_yellow("[*] Get-DeviceConfigurations")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations"
    
    if args.select:
        api_url += "?$select=" + args.select

    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-deviceconfigurationpolicysettings
def get_deviceconfigurationpolicysettings(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Get-DeviceConfigurationPolicySettings command")
        return

    print_yellow("[*] Get-DeviceConfigurationPolicySettings")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{args.id}')/settings?expand=settingDefinitions"
    user_agent = get_user_agent(args)
    headers = {
    'Authorization': f'Bearer {get_access_token(args.token)}',
    'User-Agent': user_agent
    }
    
    response = requests.get(api_url, headers=headers)
    
    if response.ok:
        response_body = response.json()
        for key, value in response_body.items():
            if not key.startswith("@odata.context"):
                pretty_value = json.dumps(value, indent=4)
                print(f"{key}: {pretty_value}") # redo this
    else:
        print_red(f"[-] Failed to retrieve settings: {response.status_code}")
        print_red(response.text)
    print("=" * 80)

# get-deviceenrollmentconfigurations
def get_deviceenrollmentconfigurations(args):
    print_yellow("[*] Get-DeviceEnrollmentConfigurations")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations"
    if args.select:
        api_url += "?$select=" + args.select
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-devicegrouppolicyconfigurations
def get_devicegrouppolicyconfigurations(args):
    print_yellow("[*] Get-DeviceGroupPolicyConfigurations")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
   
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
        group_policies = response.json()
    else:
        print_red(f"[-] Error: API request failed with status code {response.status_code}")
        group_policies = None
   
    if group_policies and 'value' in group_policies:
        for policy in group_policies['value']:
            for key, value in policy.items():
                print(f"{key} : {value}")
           
            policy_id = policy.get('id')
            if policy_id:
                assignments_api_url = f"https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{policy_id}/assignments"
                assignments_response = requests.get(assignments_api_url, headers=headers)
               
                if assignments_response.status_code == 200:
                    assignments = assignments_response.json()
                    if not assignments.get('value'):
                        print_red("assignmentTarget: No assignments")
                    else:
                        print_green("assignmentTargets:")
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
                                    print(f"   {odata_type}: {target}")
                            else:
                                print_red("assignmentTarget: No assignments")
                else:
                    print_red(f"[-] Error: API request for assignments failed with status code {assignments_response.status_code}")
            print("\n")
        print("=" * 80)

# get-devicegrouppolicydefinition
# - remove 
def get_devicegrouppolicydefinition(args):
    if not args.id:
        print_red("[-] Error: --id argument is required for Get-DeviceGroupPolicyDefinition command")
        return
        
    print_yellow("[*] Get-DeviceGroupPolicyDefinition")
    print("=" * 80)
    api_url = f"https://graph.microsoft.com//beta/deviceManagement/groupPolicyConfigurations('{args.id}')/definitionValues?$expand=definition($select=id,classType,displayName,policyType,hasRelatedDefinitions,version,minUserCspVersion,minDeviceCspVersion)"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)
    
# get-roledefinitions
def get_roledefinitions(args):
    print_yellow("[*] Get-RoleDefinitions")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions"
    
    if args.select:
        api_url += "?$select=" + args.select

    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)
    
# get-roleassignments
def get_roleassignments(args):
    print_yellow("[*] Get-RoleAssignments")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/deviceManagement/roleAssignments"
    
    if args.select:
        api_url += "?$select=" + args.select
    
    graph_api_get(get_access_token(args.token), api_url, args)
    print("=" * 80)

# get-devicecompliancepolicies
def get_devicecompliancepolicies(args):
    print_yellow("[*] Get-DeviceCompliancePolicies")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$expand=scheduledActionsForRule($expand=scheduledActionConfigurations)"
    if args.select:
        api_url += "&$select=" + args.select
   
    try:
        user_agent = get_user_agent(args)
        headers = {
            "Authorization": f"Bearer {get_access_token(args.token)}",
            "Accept": "application/json",
            "User-Agent": user_agent
        }
        
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        policies = response.json()
        
        if policies and 'value' in policies:
            for policy in policies['value']:
                for key, value in policy.items():
                    if key not in ['assignments', 'scheduledActionsForRule']:
                        print(f"{key} : {value}")
                
                # Display assignments for each policy
                policy_id = policy.get('id')
                if policy_id:
                    assignments_api_url = f"https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies('{policy_id}')/assignments"
                    assignments_response = requests.get(assignments_api_url, headers=headers)
                    assignments_response.raise_for_status()
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
                
                # Display scheduled actions for rule
                scheduled_actions = policy.get('scheduledActionsForRule', [])
                if not scheduled_actions:
                    print_red("scheduledActionsForRule: None")
                else:
                    print_green("scheduledActionsForRule:")
                    for action in scheduled_actions:
                        #print(f"- Config ID: {action.get('id')}")
                        for config in action.get('scheduledActionConfigurations', []):
                            print(f"  - Action Type: {config.get('actionType')}")
                            print(f"  - Grace Period Hours: {config.get('gracePeriodHours')}")
                            print(f"  - Notification Template Type: {config.get('notificationTemplateType')}")
                
                print("\n")
        else:
            print_red("[-] No data found")
    except requests.exceptions.RequestException as ex:
        print_red(f"[-] HTTP Error: {ex}")
    print("=" * 80)

# get-deviceconfigurationpolicies
def get_deviceconfigurationpolicies(args):
    print_yellow("[*] Get-DeviceConfigurationPolicies")
    print("=" * 80)
    api_url = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
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