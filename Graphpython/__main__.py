#!/usr/bin/env python3

import sys
import argparse
import textwrap
from Graphpython.commands import outsider, auth, enum, exploit, intune_enum, intune_exploit, cleanup, locators
from Graphpython.utils.helpers import list_commands, print_red

def parseArgs():

    version = "1.0"
    print(f"\n\033[3mGraphpython v{version} - @mlcsec\033[0m\n")
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            examples:
              Graphpython --command invoke-reconasoutsider --domain company.com
              Graphpython --command invoke-userenumerationasoutsider --username <email@company.com/emails.txt>
              Graphpython --command get-graphtokens
              Graphpython --command invoke-refreshtoazuremanagementtoken --tenant <tenant-id> --token refresh-token
              Graphpython --command get-users --token eyJ0... -- select displayname,id [--id <userid>]
              Graphpython --command list-recentonedrivefiles --token token
              Graphpython --command invoke-search --search "credentials" --entity driveItem --token token
              Graphpython --command invoke-customquery --query https://graph.microsoft.com/v1.0/sites/{siteId}/drives --token token
              Graphpython --command assign-privilegedrole --token token
              Graphpython --command spoof-owaemailmessage [--id <userid to spoof>] --token token --email email-body.txt
              Graphpython --command get-manageddevices --token intune-token
              Graphpython --command deploy-maliciousscript --script malicious.ps1 --token token
              Graphpython --command backdoor-script --id <scriptid> --script backdoored-script.ps1 --token token
              Graphpython --command add-exclusiongrouptopolicy --id <policyid> --token token
              Graphpython --command reboot-device --id <deviceid> --token eyj0...
        ''')
    )
    parser.add_argument("--command", help="Command to execute")
    parser.add_argument("--list-commands", action="store_true", help="List available commands")
    parser.add_argument("--token", help="Microsoft Graph access token or refresh token for FOCI abuse")
    parser.add_argument("--estsauthcookie", help="'ESTSAuth' or 'ESTSAuthPersistent' cookie")
    parser.add_argument("--use-cae", action="store_true", help="Flag to use Continuous Access Evaluation (CAE)")
    parser.add_argument("--cert", help="X509Certificate path (.pfx, .crt, .pem, .cer)")
    parser.add_argument("--domain", help="Target domain")
    parser.add_argument("--tenant", help="Target tenant ID")
    parser.add_argument("--username", help="Username or file containing usernames (invoke-userenumerationasoutsider)")
    parser.add_argument("--secret", help="Enterprise application secretText (invoke-appsecrettoaccesstoken)")
    parser.add_argument("--id", help="ID of target object")
    parser.add_argument("--select", help="Fields to select from output")
    parser.add_argument("--query", help="Raw API query URL (GET only)")
    parser.add_argument("--search", help="Search string")
    parser.add_argument("--entity", choices=['driveItem', 'message', 'chatMessage', 'site', 'event'],help="Search entity type: driveItem(OneDrive), message(Mail), chatMessage(Teams), site(SharePoint), event(Calenders)")
    parser.add_argument("--device", choices=['Mac', 'Windows', 'AndroidMobile', 'iPhone'], help="Device type for User-Agent forging")
    parser.add_argument("--browser", choices=['Android', 'IE', 'Chrome', 'Firefox', 'Edge', 'Safari'], help="Browser type for User-Agent forging")
    parser.add_argument("--only-return-cookies", action="store_true", help="Only return cookies from the request (open-owamailboxinbrowser)")
    parser.add_argument("--mail-folder", choices=['Allitems', 'inbox', 'archive', 'drafts', 'sentitems', 'deleteditems', 'recoverableitemsdeletions'], help="Mail folder to dump (dump-owamailbox)")
    parser.add_argument("--top", type=int, help="Number (int) of messages to retrieve (dump-owamailbox)")
    parser.add_argument("--script", help="File containing the script content (deploy-maliciousscript or backdoor-script)")
    parser.add_argument("--email", help="File containing OWA email message body content (spoof-owaemailmessage)")
    
    args = parser.parse_args()
    return args, parser 

def main():  
   
    args, parser = parseArgs()

    available_commands = [
        "invoke-reconasoutsider","invoke-userenumerationasoutsider","get-graphtokens", "get-tenantid", "get-tokenscope", "decode-accesstoken",
        "invoke-refreshtomsgraphtoken", "invoke-refreshtoazuremanagementtoken", "invoke-refreshtovaulttoken",
        "invoke-refreshtomsteamstoken", "invoke-refreshtoofficeappstoken", "invoke-refreshtoofficemanagementtoken",
        "invoke-refreshtooutlooktoken", "invoke-refreshtosubstratetoken", "invoke-refreshtoyammertoken", "invoke-refreshtointuneenrollmenttoken",
        "invoke-refreshtoonedrivetoken", "invoke-refreshtosharepointtoken", "invoke-certtoaccesstoken", "invoke-estscookietoaccesstoken", "invoke-appsecrettoaccesstoken",
        "new-signedjwt", "get-currentuser", "get-currentuseractivities", "get-orginfo", "get-domains", "get-user", "get-userproperties", 
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
        "delete-user", "delete-group", "remove-groupmember", "delete-application", "delete-device", "wipe-device", "retire-device", "locate-directoryrole",
        "get-manageddevices", "get-userdevices", "get-caps", "get-devicecategories", "get-devicecompliancepolicies", "update-deviceconfig",
        "get-devicecompliancesummary", "get-deviceconfigurations", "get-deviceconfigurationpolicies", "get-deviceconfigurationpolicysettings", 
        "get-deviceenrollmentconfigurations", "get-devicegrouppolicyconfigurations","update-userproperties", "dump-windowsapps", "dump-iosapps", "dump-androidapps",
        "get-devicegrouppolicydefinition", "dump-devicemanagementscripts", "get-scriptcontent", "find-privilegedapplications", "dump-macosapps", "deploy-maliciousweblink",
        "get-roledefinitions", "get-roleassignments", "display-avpolicyrules", "display-asrpolicyrules", "display-diskencryptionpolicyrules", "display-firewallconfigpolicyrules",
        "display-firewallrulepolicyrules", "display-lapsaccountprotectionpolicyrules", "display-usergroupaccountprotectionpolicyrules", "get-appserviceprincipal",
        "display-edrpolicyrules","add-exclusiongrouptopolicy", "deploy-maliciousscript", "reboot-device", "shutdown-device", "lock-device", "backdoor-script",
        "add-applicationpermission", "new-signedjwt", "add-applicationcertificate", "get-application", "locate-permissionid", "get-serviceprincipal", "grant-appadminconsent"
    ]

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

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
            "list-applications", "list-serviceprincipals", "list-tenants", "list-joinedteams", "list-chats", "deploy-maliciousweblink",
            "list-chatmessages", "list-devices", "list-administrativeunits", "list-onedrives", "list-recentonedrivefiles", "list-onedriveurls",
            "list-sharedonedrivefiles", "invoke-customquery", "invoke-search", "find-privilegedroleusers", "display-firewallconfigpolicyrules",
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

    try:
        # Outsider commands
        if args.command in ["invoke-reconasoutsider", "invoke-userenumerationasoutsider"]:
            getattr(outsider, args.command.replace("-", "_"))(args)

        # Authentication commands
        elif args.command in ["get-graphtokens", "get-tenantid", "get-tokenscope", "decode-accesstoken",
                            "invoke-refreshtomsgraphtoken", "invoke-refreshtoazuremanagementtoken",
                            "invoke-refreshtovaulttoken", "invoke-refreshtomsteamstoken",
                            "invoke-refreshtoofficeappstoken", "invoke-refreshtoofficemanagementtoken",
                            "invoke-refreshtooutlooktoken", "invoke-refreshtosubstratetoken",
                            "invoke-refreshtoyammertoken", "invoke-refreshtointuneenrollmenttoken",
                            "invoke-refreshtoonedrivetoken", "invoke-refreshtosharepointtoken",
                            "invoke-certtoaccesstoken", "invoke-estscookietoaccesstoken",
                            "invoke-appsecrettoaccesstoken", "new-signedjwt"]:
            getattr(auth, args.command.replace("-", "_"))(args)

        # Enumeration commands
        elif args.command in ["get-currentuser", "get-currentuseractivities", "get-orginfo", "get-domains",
                        "get-user", "get-userproperties", "get-userprivileges",
                        "get-usertransitivegroupmembership", "get-group", "get-groupmember",
                        "get-userapproleassignments", "get-conditionalaccesspolicy",
                        "get-application", "get-personalcontacts", "get-crosstenantaccesspolicy",
                        "get-partnercrosstenantaccesspolicy", "get-userchatmessages",
                        "get-administrativeunitmember", "get-onedrivefiles", "get-userpermissiongrants",
                        "get-oauth2permissiongrants", "get-messages", "get-temporaryaccesspassword",
                        "get-password", "list-authmethods", "list-directoryroles", "list-notebooks",
                        "list-conditionalaccesspolicies", "list-conditionalauthenticationcontexts",
                        "list-conditionalnamedlocations", "list-sharepointroot", "list-sharepointsites",
                        "list-sharepointurls", "list-externalconnections", "list-applications", "list-onedriveurls",
                        "list-serviceprincipals", "list-tenants", "list-joinedteams", "list-chats",
                        "list-chatmessages", "list-devices", "list-administrativeunits", "list-onedrives",
                        "list-recentonedrivefiles", "list-sharedonedrivefiles", "get-appserviceprincipal",
                        "get-serviceprincipal", "get-serviceprincipalapproleassignments"]:
            getattr(enum, args.command.replace("-", "_"))(args)

        # Exploitation commands
        elif args.command in ["invoke-customquery","invoke-search", "find-privilegedroleusers", "find-privilegedapplications",
                            "find-updatablegroups","find-dynamicgroups", "find-securitygroups",
                            "update-userpassword", "update-userproperties", "add-usertap", "add-groupmember",
                            "create-application", "create-newuser", "invite-guestuser",
                            "assign-privilegedrole", "open-owamailboxinbrowser", "dump-owamailbox",
                            "spoof-owaemailmessage", "add-applicationpermission", "add-applicationcertificate",
                            "add-applicationpassword", "grant-appadminconsent"]:
            getattr(exploit, args.command.replace("-", "_"))(args)

        # Intune enum commands
        elif args.command in ["get-manageddevices", "get-userdevices", "get-caps", "get-devicecategories",
                            "get-devicecompliancesummary", "get-deviceconfigurations",
                            "get-deviceconfigurationpolicies", "get-deviceconfigurationpolicysettings",
                            "get-deviceenrollmentconfigurations", "get-devicegrouppolicyconfigurations",
                            "get-devicegrouppolicydefinition", "get-roledefinitions", "get-roleassignments",
                            "get-devicecompliancepolicies"]:
            getattr(intune_enum, args.command.replace("-", "_"))(args)
        
        # Intune exploit commands
        elif args.command in ["dump-devicemanagementscripts","dump-windowsapps", "dump-iosapps", 
                            "dump-androidapps", "dump-macosapps","get-scriptcontent",
                            "display-avpolicyrules", "display-asrpolicyrules",
                            "display-diskencryptionpolicyrules", "display-firewallconfigpolicyrules",
                            "display-firewallrulepolicyrules", "display-edrpolicyrules",
                            "display-lapsaccountprotectionpolicyrules",
                            "display-usergroupaccountprotectionpolicyrules", "add-exclusiongrouptopolicy",
                            "deploy-maliciousscript", "deploy-maliciousweblink", "backdoor-script",
                            "update-deviceconfig", "reboot-device", "lock-device", "shutdown-device"]:
            getattr(intune_exploit, args.command.replace("-", "_"))(args)

        # Cleanup commands
        elif args.command in ["delete-user", "delete-group", "remove-groupmember", "delete-application",
                            "delete-device", "wipe-device", "retire-device"]:
            getattr(cleanup, args.command.replace("-", "_"))(args)

        # Locator commands
        elif args.command in ["locate-objectid", "locate-permissionid", "locate-directoryrole"]:
            getattr(locators, args.command.replace("-", "_"))(args)

        # ...
        elif args.command and args.command.lower() not in available_commands:
            print_red(f"[-] Error: Unknown command '{args.command}'. Use --list-commands to see available commands")
    
    except KeyboardInterrupt:
        print_red("\n[-] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print_red(f"\n[-] An error occurred while executing '{args.command}': {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()