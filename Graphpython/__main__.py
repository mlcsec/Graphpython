#!/usr/bin/env python3

import sys
import argparse
import textwrap
import shlex
import os 
import datetime 
from Graphpython.commands import outsider, auth, enum, exploit, intune_enum, intune_exploit, cleanup, locators
from Graphpython.utils.helpers import list_commands, print_red

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.shortcuts import clear

# ─── Colour style ────────────────────────────────────────────────────────────
STYLE = Style.from_dict({
    "prompt":                                "#4da3e0 bold",
    "command":                               "#ff6600",
    "bottom-toolbar":                        "bg:#1a1a1a #888888",
    "completion-menu.completion":            "bg:#1e1e1e #cccccc",
    "completion-menu.completion.current":    "bg:#0078d4 #ffffff bold",
    "completion-menu.meta.completion":       "bg:#1e1e1e #666666",
    "completion-menu.meta.completion.current":"bg:#0078d4 #cccccc",
})

# ─── Command registry with descriptions ──────────────────────────────────────
COMMAND_REGISTRY = {
    # Outsider
    "invoke-reconasoutsider":                        "Recon target tenant as outsider",
    "invoke-userenumerationasoutsider":              "Enumerate valid users without auth",
    # Auth
    "get-graphtokens":                               "Obtain MS Graph tokens interactively",
    "get-tenantid":                                  "Resolve tenant ID from domain",
    "get-tokenscope":                                "Show scopes for current token",
    "decode-accesstoken":                            "Decode and display JWT access token",
    "invoke-refreshtomsgraphtoken":                  "Refresh token → MS Graph token",
    "invoke-refreshtoazuremanagementtoken":          "Refresh token → Azure Management token",
    "invoke-refreshtovaulttoken":                    "Refresh token → Azure Vault token",
    "invoke-refreshtomsteamstoken":                  "Refresh token → MS Teams token",
    "invoke-refreshtoofficeappstoken":               "Refresh token → Office Apps token",
    "invoke-refreshtoofficemanagementtoken":         "Refresh token → Office Management token",
    "invoke-refreshtooutlooktoken":                  "Refresh token → Outlook token",
    "invoke-refreshtosubstratetoken":                "Refresh token → Substrate token",
    "invoke-refreshtoyammertoken":                   "Refresh token → Yammer token",
    "invoke-refreshtointuneenrollmenttoken":         "Refresh token → Intune Enrollment token",
    "invoke-refreshtoonedrivetoken":                 "Refresh token → OneDrive token",
    "invoke-refreshtosharepointtoken":               "Refresh token → SharePoint token",
    "invoke-certtoaccesstoken":                      "Exchange certificate for access token",
    "invoke-estscookietoaccesstoken":                "Exchange ESTS cookie for access token",
    "invoke-appsecrettoaccesstoken":                 "Exchange app secret for access token",
    "new-signedjwt":                                 "Create a new signed JWT assertion",
    # Enum
    "get-currentuser":                               "Get current authenticated user info",
    "get-currentuseractivities":                     "Get current user recent activities",
    "get-orginfo":                                   "Get organisation details",
    "get-domains":                                   "List all tenant domains",
    "get-user":                                      "Get specific user details",
    "get-userproperties":                            "Get all properties for a user",
    "get-userprivileges":                            "Check user's assigned privileges",
    "get-usertransitivegroupmembership":             "Get transitive group memberships",
    "get-group":                                     "Get group details",
    "get-groupmember":                               "List members of a group",
    "get-userapproleassignments":                    "Get app role assignments for user",
    "get-serviceprincipalapproleassignments":        "Get app role assignments for SP",
    "get-conditionalaccesspolicy":                   "Get a specific CAP by ID",
    "get-personalcontacts":                          "Get user's personal contacts",
    "get-crosstenantaccesspolicy":                   "Get cross-tenant access policy",
    "get-partnercrosstenantaccesspolicy":            "Get partner cross-tenant access policy",
    "get-userchatmessages":                          "Get Teams chat messages for user",
    "get-administrativeunitmember":                  "Get members of administrative unit",
    "get-onedrivefiles":                             "List OneDrive files for user",
    "get-userpermissiongrants":                      "Get OAuth2 permission grants for user",
    "get-oauth2permissiongrants":                    "List all OAuth2 permission grants",
    "get-messages":                                  "Get mailbox messages",
    "get-temporaryaccesspassword":                   "Get temporary access password for user",
    "get-password":                                  "Retrieve stored password info",
    "get-application":                               "Get application registration details",
    "get-appserviceprincipal":                       "Get service principal for app",
    "get-serviceprincipal":                          "Get service principal details",
    "list-authmethods":                              "List auth methods for a user",
    "list-directoryroles":                           "List all directory roles",
    "list-notebooks":                                "List OneNote notebooks",
    "list-conditionalaccesspolicies":                "List all conditional access policies",
    "list-conditionalauthenticationcontexts":        "List CA authentication contexts",
    "list-conditionalnamedlocations":                "List CA named locations",
    "list-sharepointroot":                           "Get SharePoint root site",
    "list-sharepointsites":                          "List all SharePoint sites",
    "list-sharepointurls":                           "List SharePoint site URLs",
    "list-externalconnections":                      "List external connections",
    "list-applications":                             "List all app registrations",
    "list-serviceprincipals":                        "List all service principals",
    "list-tenants":                                  "List accessible tenants",
    "list-joinedteams":                              "List Teams the user has joined",
    "list-chats":                                    "List user Teams chats",
    "list-chatmessages":                             "List messages in a Teams chat",
    "list-devices":                                  "List registered devices",
    "list-administrativeunits":                      "List administrative units",
    "list-onedrives":                                "List OneDrive instances",
    "list-recentonedrivefiles":                      "List recently accessed OneDrive files",
    "list-onedriveurls":                             "List OneDrive URLs",
    "list-sharedonedrivefiles":                      "List files shared with current user",
    # Exploit
    "invoke-customquery":                            "Execute a raw Graph API GET query",
    "invoke-search":                                 "Search across Graph entities",
    "find-privilegedroleusers":                      "Find users with privileged roles",
    "find-updatablegroups":                          "Find groups current user can update",
    "find-dynamicgroups":                            "Find dynamic membership groups",
    "find-securitygroups":                           "Find security groups",
    "find-privilegedapplications":                   "Find apps with privileged permissions",
    "locate-objectid":                               "Locate object by ID",
    "locate-permissionid":                           "Locate permission ID",
    "locate-directoryrole":                          "Locate a directory role",
    "update-userpassword":                           "Update a user's password",
    "update-userproperties":                         "Update arbitrary user properties",
    "add-applicationpassword":                       "Add a secret to an application",
    "add-usertap":                                   "Add temporary access pass to user",
    "add-groupmember":                               "Add user to a group",
    "add-applicationpermission":                     "Add API permission to application",
    "add-applicationcertificate":                    "Add certificate credential to app",
    "create-application":                            "Create a new app registration",
    "create-newuser":                                "Create a new Azure AD user",
    "invite-guestuser":                              "Invite a guest user to tenant",
    "assign-privilegedrole":                         "Assign privileged directory role",
    "open-owamailboxinbrowser":                      "Open OWA mailbox in browser",
    "dump-owamailbox":                               "Dump OWA mailbox messages",
    "spoof-owaemailmessage":                         "Send spoofed OWA email message",
    "grant-appadminconsent":                         "Grant admin consent to application",
    # Intune enum
    "get-manageddevices":                            "List Intune managed devices",
    "get-userdevices":                               "Get devices registered to user",
    "get-caps":                                      "Get compliance/config assignment policies",
    "get-devicecategories":                          "List Intune device categories",
    "get-devicecompliancepolicies":                  "List device compliance policies",
    "get-devicecompliancesummary":                   "Get compliance policy summary",
    "get-deviceconfigurations":                      "List device configuration profiles",
    "get-deviceconfigurationpolicies":               "List device configuration policies",
    "get-deviceconfigurationpolicysettings":         "Get settings for a config policy",
    "get-deviceenrollmentconfigurations":            "List enrollment configurations",
    "get-devicegrouppolicyconfigurations":           "List group policy configurations",
    "get-devicegrouppolicydefinition":               "Get group policy definition",
    "get-roledefinitions":                           "List Intune role definitions",
    "get-roleassignments":                           "List Intune role assignments",
    # Intune exploit
    "dump-devicemanagementscripts":                  "Dump all device management scripts",
    "dump-windowsapps":                              "Dump deployed Windows apps",
    "dump-iosapps":                                  "Dump deployed iOS apps",
    "dump-androidapps":                              "Dump deployed Android apps",
    "dump-macosapps":                                "Dump deployed macOS apps",
    "get-scriptcontent":                             "Get content of a management script",
    "display-avpolicyrules":                         "Display AV policy rules",
    "display-asrpolicyrules":                        "Display ASR policy rules",
    "display-diskencryptionpolicyrules":             "Display disk encryption policy rules",
    "display-firewallconfigpolicyrules":             "Display firewall config policy rules",
    "display-firewallrulepolicyrules":               "Display firewall rule policy rules",
    "display-edrpolicyrules":                        "Display EDR policy rules",
    "display-lapsaccountprotectionpolicyrules":      "Display LAPS account protection rules",
    "display-usergroupaccountprotectionpolicyrules": "Display user group protection rules",
    "add-exclusiongrouptopolicy":                    "Add exclusion group to a policy",
    "deploy-maliciousscript":                        "Deploy malicious script via Intune",
    "deploy-maliciousweblink":                       "Deploy malicious web link via Intune",
    "backdoor-script":                               "Backdoor an existing Intune script",
    "update-deviceconfig":                           "Update a device configuration",
    "reboot-device":                                 "Force reboot a managed device",
    "lock-device":                                   "Lock a managed device",
    "shutdown-device":                               "Shutdown a managed device",
    # Cleanup
    "delete-user":                                   "Delete a user from the tenant",
    "delete-group":                                  "Delete a group",
    "remove-groupmember":                            "Remove a user from a group",
    "delete-application":                            "Delete an app registration",
    "delete-device":                                 "Delete a device object",
    "wipe-device":                                   "Wipe a managed Intune device",
    "retire-device":                                 "Retire a managed Intune device",
}

SHELL_COMMANDS = {
    "help":          "Show shell commands",
    "clear":         "Clear the screen",
    "exit":          "Quit Graphpython",
    "quit":          "Quit Graphpython",
    "list-commands": "List all Graph commands",
    "set-token":     "set-token <tok> | set-token access <file> | set-token refresh <file>",
    "log-enable":    "Enable command logging to ./logs/",
    "log-disable":   "Disable command logging",
}

FLAG_DESCRIPTIONS = {
    "--token":               "Access or refresh token",
    "--estsauthcookie":      "ESTSAuth or ESTSAuthPersistent cookie",
    "--use-cae":             "Enable Continuous Access Evaluation",
    "--cert":                "X509 certificate path (.pfx/.pem/.cer)",
    "--domain":              "Target domain",
    "--tenant":              "Target tenant ID",
    "--username":            "Username or file of usernames",
    "--secret":              "App secret text",
    "--id":                  "Target object ID",
    "--select":              "Fields to select from output",
    "--query":               "Raw API query URL (GET only)",
    "--search":              "Search string",
    "--entity":              "Search entity type",
    "--device":              "Device type for User-Agent forging",
    "--browser":             "Browser type for User-Agent forging",
    "--only-return-cookies": "Only return cookies from request",
    "--mail-folder":         "Mail folder to target",
    "--top":                 "Number of messages to retrieve",
    "--script":              "Path to script file",
    "--email":               "Path to email body file",
}

# ─── Commands that require --token ───────────────────────────────────────────
REQUIRES_TOKEN = {
    "invoke-refreshtomsgraphtoken", "invoke-refreshtoazuremanagementtoken",
    "invoke-refreshtovaulttoken", "invoke-refreshtomsteamstoken",
    "invoke-refreshtoofficeappstoken", "invoke-refreshtoofficemanagementtoken",
    "invoke-refreshtooutlooktoken", "invoke-refreshtosubstratetoken",
    "invoke-refreshtoyammertoken", "invoke-refreshtointuneenrollmenttoken",
    "invoke-refreshtoonedrivetoken", "invoke-refreshtosharepointtoken",
    "get-tokenscope", "decode-accesstoken", "get-manageddevices",
    "get-userdevices", "get-user", "get-userproperties", "get-userprivileges",
    "get-usertransitivegroupmembership", "get-group", "get-groupmember",
    "get-userapproleassignments", "get-conditionalaccesspolicy",
    "get-personalcontacts", "get-crosstenantaccesspolicy",
    "get-partnercrosstenantaccesspolicy", "get-userchatmessages",
    "get-administrativeunitmember", "get-onedrivefiles",
    "get-userpermissiongrants", "get-oauth2permissiongrants", "get-messages",
    "get-temporaryaccesspassword", "get-password", "get-currentuser",
    "get-currentuseractivities", "get-orginfo", "get-domains",
    "list-authmethods", "list-directoryroles", "list-notebooks",
    "list-conditionalaccesspolicies", "list-conditionalauthenticationcontexts",
    "list-conditionalnamedlocations", "list-sharepointroot", "list-sharepointsites",
    "list-sharepointurls", "list-externalconnections", "list-applications",
    "list-onedriveurls", "list-serviceprincipals", "list-tenants",
    "list-joinedteams", "list-chats", "list-chatmessages", "list-devices",
    "list-administrativeunits", "list-onedrives", "list-recentonedrivefiles",
    "list-sharedonedrivefiles", "invoke-customquery", "invoke-search",
    "find-privilegedroleusers", "find-updatablegroups", "find-dynamicgroups",
    "find-securitygroups", "locate-objectid", "update-userpassword",
    "add-applicationpassword", "add-usertap", "add-groupmember",
    "create-application", "create-newuser", "invite-guestuser",
    "assign-privilegedrole", "open-owamailboxinbrowser", "dump-owamailbox",
    "spoof-owaemailmessage", "add-applicationpermission",
    "add-applicationcertificate", "grant-appadminconsent", "delete-user",
    "delete-group", "remove-groupmember", "delete-application", "delete-device",
    "wipe-device", "retire-device", "get-caps", "get-devicecategories",
    "get-devicecompliancesummary", "get-deviceconfigurations",
    "get-deviceconfigurationpolicies", "get-deviceconfigurationpolicysettings",
    "get-deviceenrollmentconfigurations", "get-devicegrouppolicyconfigurations",
    "get-devicegrouppolicydefinition", "dump-devicemanagementscripts",
    "dump-windowsapps", "dump-iosapps", "dump-androidapps", "dump-macosapps",
    "get-scriptcontent", "display-avpolicyrules", "display-asrpolicyrules",
    "display-diskencryptionpolicyrules", "display-firewallconfigpolicyrules",
    "display-firewallrulepolicyrules", "display-edrpolicyrules",
    "display-lapsaccountprotectionpolicyrules",
    "display-usergroupaccountprotectionpolicyrules", "add-exclusiongrouptopolicy",
    "deploy-maliciousscript", "deploy-maliciousweblink", "backdoor-script",
    "update-deviceconfig", "reboot-device", "lock-device", "shutdown-device",
    "find-privilegedapplications", "get-roledefinitions", "get-roleassignments",
    "get-appserviceprincipal", "get-application", "get-serviceprincipal",
    "get-serviceprincipalapproleassignments", "update-userproperties",
    "new-signedjwt",
}

# ─── Token file parser ────────────────────────────────────────────────────────
def parse_token_from_file(filepath: str, token_type: str) -> str | None:
    """
    Parse access_token or refresh_token from a Graphpython output file.
    Expects lines in the format: [*] access_token: <value>
    """
    key = f"{token_type}_token:"
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if key in line:
                    parts = line.split(key, 1)
                    if len(parts) == 2:
                        return parts[1].strip()
    except FileNotFoundError:
        print_red(f"[-] File not found: {filepath}")
    except Exception as e:
        print_red(f"[-] Error reading file: {e}")
    return None

# ─── Command logger ───────────────────────────────────────────────────────────
class CommandLogger:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.log_dir = os.path.join(os.getcwd(), "logs")

    def enable(self):
        self.enabled = True
        os.makedirs(self.log_dir, exist_ok=True)
        print(f"[+] Logging enabled → {self.log_dir}")

    def log(self, command: str, output: str):
        if not self.enabled:
            return
        os.makedirs(self.log_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # Sanitise command for use as filename
        safe_cmd = command.strip().split()[0].replace("/", "_").replace("\\", "_")
        filename = f"{timestamp}_{safe_cmd}.txt"
        filepath = os.path.join(self.log_dir, filename)
        with open(filepath, "w") as f:
            f.write(f"Timestamp : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Command   : {command}\n")
            f.write(f"{'─' * 60}\n")
            f.write(output)
        print(f"[*] Logged → {filepath}")

# ─── Output capture ───────────────────────────────────────────────────────────
import io
import contextlib

def capture_output(fn, *args, **kwargs) -> str:
    """Run fn(*args) and return its stdout+stderr as a string."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        fn(*args, **kwargs)
    return buf.getvalue()
        
class GraphCompleter(Completer):
    def get_completions(self, document, complete_event):
        import os
        text = document.text_before_cursor
        word = document.get_word_before_cursor(WORD=True)
        parts = text.strip().split()

        # ── set-token: isolated completion ────────────────────────────────
        if parts and parts[0].lower() == "set-token":

            # "set-token " → show access/refresh only
            if len(parts) == 1 and text.endswith(" "):
                for opt, desc in {
                    "access":  "Import access_token from file",
                    "refresh": "Import refresh_token from file",
                }.items():
                    yield Completion(opt, start_position=0, display_meta=desc)
                return

            # "set-token ac..." → filter access/refresh by what's typed
            if len(parts) == 2 and not text.endswith(" "):
                for opt, desc in {
                    "access":  "Import access_token from file",
                    "refresh": "Import refresh_token from file",
                }.items():
                    if opt.startswith(word.lower()):
                        yield Completion(
                            opt,
                            start_position=-len(word),
                            display_meta=desc,
                        )
                return

            # "set-token access " or "set-token refresh " → local cwd files
            if len(parts) >= 2 and parts[1].lower() in ("access", "refresh"):
                cwd_files = [
                    f for f in os.listdir(".")
                    if os.path.isfile(f)
                ]
                typed = parts[2] if len(parts) == 3 and not text.endswith(" ") else ""
                for f in cwd_files:
                    if f.startswith(typed):
                        yield Completion(
                            f,
                            start_position=-len(typed),
                            display_meta="local file",
                        )
                return

            # anything else under set-token → no completions
            return

        # ── Flag completion ───────────────────────────────────────────────
        if word.startswith("-"):
            for flag, desc in FLAG_DESCRIPTIONS.items():
                if flag.startswith(word):
                    yield Completion(
                        flag,
                        start_position=-len(word),
                        display_meta=desc,
                    )
            return

        # ── First word = command completion ───────────────────────────────
        is_first_word = len(parts) == 0 or (len(parts) == 1 and not text.endswith(" "))
        if is_first_word:
            for cmd, desc in {**COMMAND_REGISTRY, **SHELL_COMMANDS}.items():
                if cmd.startswith(word.lower()):
                    yield Completion(
                        cmd,
                        start_position=-len(word),
                        display_meta=desc,
                    )
            return

        # ── Subsequent words = flag completion ────────────────────────────
        for flag, desc in FLAG_DESCRIPTIONS.items():
            if flag.startswith(word):
                yield Completion(
                    flag,
                    start_position=-len(word),
                    display_meta=desc,
                )

# ─── Argument parser ──────────────────────────────────────────────────────────
def build_parser():
    parser = argparse.ArgumentParser(
        prog="",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command",                   nargs="?")
    parser.add_argument("--token")
    parser.add_argument("--estsauthcookie")
    parser.add_argument("--use-cae",                 action="store_true")
    parser.add_argument("--cert")
    parser.add_argument("--domain")
    parser.add_argument("--tenant")
    parser.add_argument("--username")
    parser.add_argument("--secret")
    parser.add_argument("--id")
    parser.add_argument("--select")
    parser.add_argument("--query")
    parser.add_argument("--search")
    parser.add_argument("--entity",
        choices=["driveItem", "message", "chatMessage", "site", "event"])
    parser.add_argument("--device",
        choices=["Mac", "Windows", "AndroidMobile", "iPhone"])
    parser.add_argument("--browser",
        choices=["Android", "IE", "Chrome", "Firefox", "Edge", "Safari"])
    parser.add_argument("--only-return-cookies",     action="store_true")
    parser.add_argument("--mail-folder",
        choices=["Allitems", "inbox", "archive", "drafts",
                 "sentitems", "deleteditems", "recoverableitemsdeletions"])
    parser.add_argument("--top",                     type=int)
    parser.add_argument("--script")
    parser.add_argument("--email")
    return parser

# ─── Dispatch ────────────────────────────────────────────────────────────────
def dispatch(args):
    cmd = args.command.lower()

    if cmd in ["invoke-reconasoutsider", "invoke-userenumerationasoutsider"]:
        getattr(outsider, cmd.replace("-", "_"))(args)
    elif cmd in ["get-graphtokens", "get-tenantid", "get-tokenscope",
                 "decode-accesstoken", "invoke-refreshtomsgraphtoken",
                 "invoke-refreshtoazuremanagementtoken", "invoke-refreshtovaulttoken",
                 "invoke-refreshtomsteamstoken", "invoke-refreshtoofficeappstoken",
                 "invoke-refreshtoofficemanagementtoken", "invoke-refreshtooutlooktoken",
                 "invoke-refreshtosubstratetoken", "invoke-refreshtoyammertoken",
                 "invoke-refreshtointuneenrollmenttoken", "invoke-refreshtoonedrivetoken",
                 "invoke-refreshtosharepointtoken", "invoke-certtoaccesstoken",
                 "invoke-estscookietoaccesstoken", "invoke-appsecrettoaccesstoken",
                 "new-signedjwt"]:
        getattr(auth, cmd.replace("-", "_"))(args)
    elif cmd in ["get-currentuser", "get-currentuseractivities", "get-orginfo",
                 "get-domains", "get-user", "get-userproperties", "get-userprivileges",
                 "get-usertransitivegroupmembership", "get-group", "get-groupmember",
                 "get-userapproleassignments", "get-conditionalaccesspolicy",
                 "get-application", "get-personalcontacts", "get-crosstenantaccesspolicy",
                 "get-partnercrosstenantaccesspolicy", "get-userchatmessages",
                 "get-administrativeunitmember", "get-onedrivefiles",
                 "get-userpermissiongrants", "get-oauth2permissiongrants",
                 "get-messages", "get-temporaryaccesspassword", "get-password",
                 "list-authmethods", "list-directoryroles", "list-notebooks",
                 "list-conditionalaccesspolicies", "list-conditionalauthenticationcontexts",
                 "list-conditionalnamedlocations", "list-sharepointroot",
                 "list-sharepointsites", "list-sharepointurls", "list-externalconnections",
                 "list-applications", "list-onedriveurls", "list-serviceprincipals",
                 "list-tenants", "list-joinedteams", "list-chats", "list-chatmessages",
                 "list-devices", "list-administrativeunits", "list-onedrives",
                 "list-recentonedrivefiles", "list-sharedonedrivefiles",
                 "get-appserviceprincipal", "get-serviceprincipal",
                 "get-serviceprincipalapproleassignments"]:
        getattr(enum, cmd.replace("-", "_"))(args)
    elif cmd in ["invoke-customquery", "invoke-search", "find-privilegedroleusers",
                 "find-privilegedapplications", "find-updatablegroups",
                 "find-dynamicgroups", "find-securitygroups", "update-userpassword",
                 "update-userproperties", "add-usertap", "add-groupmember",
                 "create-application", "create-newuser", "invite-guestuser",
                 "assign-privilegedrole", "open-owamailboxinbrowser", "dump-owamailbox",
                 "spoof-owaemailmessage", "add-applicationpermission",
                 "add-applicationcertificate", "add-applicationpassword",
                 "grant-appadminconsent"]:
        getattr(exploit, cmd.replace("-", "_"))(args)
    elif cmd in ["get-manageddevices", "get-userdevices", "get-caps",
                 "get-devicecategories", "get-devicecompliancesummary",
                 "get-deviceconfigurations", "get-deviceconfigurationpolicies",
                 "get-deviceconfigurationpolicysettings",
                 "get-deviceenrollmentconfigurations",
                 "get-devicegrouppolicyconfigurations",
                 "get-devicegrouppolicydefinition", "get-roledefinitions",
                 "get-roleassignments", "get-devicecompliancepolicies"]:
        getattr(intune_enum, cmd.replace("-", "_"))(args)
    elif cmd in ["dump-devicemanagementscripts", "dump-windowsapps", "dump-iosapps",
                 "dump-androidapps", "dump-macosapps", "get-scriptcontent",
                 "display-avpolicyrules", "display-asrpolicyrules",
                 "display-diskencryptionpolicyrules", "display-firewallconfigpolicyrules",
                 "display-firewallrulepolicyrules", "display-edrpolicyrules",
                 "display-lapsaccountprotectionpolicyrules",
                 "display-usergroupaccountprotectionpolicyrules",
                 "add-exclusiongrouptopolicy", "deploy-maliciousscript",
                 "deploy-maliciousweblink", "backdoor-script", "update-deviceconfig",
                 "reboot-device", "lock-device", "shutdown-device"]:
        getattr(intune_exploit, cmd.replace("-", "_"))(args)
    elif cmd in ["delete-user", "delete-group", "remove-groupmember",
                 "delete-application", "delete-device", "wipe-device", "retire-device"]:
        getattr(cleanup, cmd.replace("-", "_"))(args)
    elif cmd in ["locate-objectid", "locate-permissionid", "locate-directoryrole"]:
        getattr(locators, cmd.replace("-", "_"))(args)
    else:
        print_red(f"[-] Unknown command '{args.command}'. Type 'help' or 'list-commands'.")

# ─── Bottom toolbar ───────────────────────────────────────────────────────────
def make_toolbar(session_token):
    token_display = f"{session_token[:24]}…" if session_token else "not set"
    return HTML(
        f"  Token: <b>{token_display}</b>  |  "
        "Tab: autocomplete  |  ↑↓: history  |  "
        "'help' for commands  |  'exit' to quit"
    )

# ─── Interactive shell ────────────────────────────────────────────────────────
def interactive_shell(log_all: bool = False):
    version = "1.1"
    logger = CommandLogger(enabled=log_all)
    if log_all:
        logger.enable()

    session = PromptSession(
        history=FileHistory(".graphpython_history"),
        auto_suggest=AutoSuggestFromHistory(),
        completer=GraphCompleter(),
        complete_while_typing=True,
        style=STYLE,
        mouse_support=False,
        complete_in_thread=True,
        reserve_space_for_menu=20,
    )

    session_token = None

    BLUE   = "\033[94m"
    RESET  = "\033[0m"
    DIM    = "\033[2m"
    ITALIC = "\033[3m"

    banner = (
        f"\n"
        f"  {ITALIC}Graphpython v{version} - @mlcsec{RESET}\n"
        f"\n"
        f"  {DIM}{'─' * 52}{RESET}\n"
        f"  {BLUE}help{RESET}                        Show available shell commands\n"
        f"  {BLUE}list-commands{RESET}               List all Microsoft Graph commands\n"
        f"  {BLUE}set-token <tok>{RESET}             Persist raw token for session\n"
        f"  {BLUE}set-token access <file>{RESET}     Import access_token from file\n"
        f"  {BLUE}set-token refresh <file>{RESET}    Import refresh_token from file\n"
        f"  {BLUE}log-enable{RESET}                  Enable command logging to ./logs/\n"
        f"  {BLUE}log-disable{RESET}                 Disable command logging\n"
        f"  {BLUE}exit{RESET}                        Quit Graphpython\n"
        f"  {DIM}{'─' * 52}{RESET}\n"
        f"\n"
    )
    print(banner)

    while True:
        try:
            raw = session.prompt(
                HTML("<prompt>Graphpython</prompt> ❯ "),
                bottom_toolbar=lambda: make_toolbar(session_token),
                style=STYLE,
                refresh_interval=0.5,
            ).strip()
        except KeyboardInterrupt:
            print()
            continue
        except EOFError:
            print("\n[*] Exiting.")
            break

        if not raw:
            continue

        if raw.lower() in ("exit", "quit"):
            print("[*] Exiting.")
            break

        if raw.lower() == "clear":
            clear()
            continue

        if raw.lower() == "help":
            print(textwrap.dedent(f"""
            {DIM}{'─' * 52}{RESET}
            {BLUE}help{RESET}                        Show this message
            {BLUE}clear{RESET}                       Clear the screen
            {BLUE}exit / quit{RESET}                 Quit Graphpython
            {BLUE}list-commands{RESET}               List all Graph commands
            {BLUE}set-token <tok>{RESET}             Persist raw token for session
            {BLUE}set-token access <file>{RESET}     Import access_token from file
            {BLUE}set-token refresh <file>{RESET}    Import refresh_token from file
            {BLUE}log-enable{RESET}                  Enable command logging to ./logs/
            {BLUE}log-disable{RESET}                 Disable command logging
            {DIM}{'─' * 52}{RESET}

            Usage:
            <command> [--token <tok>] [--flags...]

            Examples:
            get-user --id <userid>
            invoke-search --search "credentials" --entity driveItem
            set-token eyJ0eXAiOiJKV1Q...
            set-token access tokens.txt
            set-token refresh tokens.txt
            """))
            continue

        if raw.lower() == "list-commands":
            list_commands()
            continue

        if raw.lower() == "log-enable":
            logger.enable()
            continue

        if raw.lower() == "log-disable":
            logger.enabled = False
            print("[*] Logging disabled.")
            continue

        # ── set-token handling ─────────────────────────────────────────────
        if raw.lower().startswith("set-token"):
            parts = raw.split()

            # set-token access <filepath> — fully specified inline
            if len(parts) == 3 and parts[1].lower() == "access":
                token = parse_token_from_file(parts[2], "access")
                if token:
                    session_token = token
                    print(f"[+] Access token imported from '{parts[2]}': {session_token[:30]}…")
                else:
                    print_red(f"[-] access_token not found in '{parts[2]}'")
                continue

            # set-token refresh <filepath> — fully specified inline
            elif len(parts) == 3 and parts[1].lower() == "refresh":
                token = parse_token_from_file(parts[2], "refresh")
                if token:
                    session_token = token
                    print(f"[+] Refresh token imported from '{parts[2]}': {session_token[:30]}…")
                else:
                    print_red(f"[-] refresh_token not found in '{parts[2]}'")
                continue

            # set-token <raw_token> — direct paste
            elif len(parts) >= 2 and parts[1].lower() not in ("access", "refresh"):
                session_token = parts[1].strip()
                print(f"[+] Session token set: {session_token[:30]}…")
                continue

            # set-token alone OR set-token access/refresh without filepath → interactive prompt
            else:
                try:
                    from prompt_toolkit import prompt as pt_prompt
                    from prompt_toolkit.completion import WordCompleter
                    from prompt_toolkit.completion import PathCompleter
                    import os

                    print(f"\n  {BLUE}[1]{RESET} Paste raw token")
                    print(f"  {BLUE}[2]{RESET} Import access_token from file")
                    print(f"  {BLUE}[3]{RESET} Import refresh_token from file\n")

                    # Tab-complete option choice
                    option_completer = WordCompleter(
                        ["1", "2", "3"],
                        ignore_case=True,
                    )
                    choice = pt_prompt(
                        "  Select option [1/2/3]: ",
                        completer=option_completer,
                        style=STYLE,
                    ).strip()

                    if choice == "1":
                        tok = pt_prompt("  Paste token: ", style=STYLE).strip()
                        if tok:
                            session_token = tok
                            print(f"[+] Session token set: {session_token[:30]}…")
                        else:
                            print_red("[-] No token provided.")

                    elif choice in ("2", "3"):
                        token_type = "access" if choice == "2" else "refresh"

                        # Tab-complete type (access/refresh)
                        type_completer = WordCompleter(
                            ["access", "refresh"],
                            ignore_case=True,
                        )
                        confirmed_type = pt_prompt(
                            f"  Token type: ",
                            completer=type_completer,
                            default=token_type,
                            style=STYLE,
                        ).strip().lower()

                        if confirmed_type not in ("access", "refresh"):
                            print_red("[-] Invalid token type. Use 'access' or 'refresh'.")
                            continue

                        # Build file list from cwd for tab completion
                        cwd_files = [
                            f for f in os.listdir(".")
                            if os.path.isfile(f)
                        ]
                        file_completer = PathCompleter(
                            only_directories=False,
                            expanduser=True,
                        )

                        filepath = pt_prompt(
                            f"  File [{confirmed_type}_token]: ",
                            completer=file_completer,
                            style=STYLE,
                        ).strip()

                        if filepath:
                            token = parse_token_from_file(filepath, confirmed_type)
                            if token:
                                session_token = token
                                print(f"[+] {confirmed_type.capitalize()} token imported from '{filepath}': {session_token[:30]}…")
                            else:
                                print_red(f"[-] {confirmed_type}_token not found in '{filepath}'")
                        else:
                            print_red("[-] No file path provided.")

                    else:
                        print_red("[-] Invalid option.")

                except KeyboardInterrupt:
                    print("\n[-] Cancelled.")
                continue

        # ── Parse & dispatch ───────────────────────────────────────────────
        try:
            tokens = shlex.split(raw)
        except ValueError as e:
            print_red(f"[-] Parse error: {e}")
            continue

        if not tokens:
            continue

        if session_token and "--token" not in tokens:
            tokens += ["--token", session_token]

        parser = build_parser()
        try:
            args = parser.parse_args(tokens)
        except SystemExit:
            continue

        if not args.command:
            continue

        cmd = args.command.lower()

        if cmd in REQUIRES_TOKEN and not args.token:
            print_red(f"[-] --token required for '{cmd}'. Use 'set-token <tok>' to persist one.")
            continue

        try:
            if logger.enabled:
                output = capture_output(dispatch, args)
                print(output, end="")
                logger.log(raw, output)
            else:
                dispatch(args)
        except KeyboardInterrupt:
            print_red("\n[-] Command cancelled.")
        except Exception as e:
            print_red(f"[-] Error executing '{cmd}': {e}")

# ─── One-shot CLI mode ────────────────────────────────────────────────────────
def one_shot():
    version = "1.1"
    print(f"\n\033[3mGraphpython v{version} - @mlcsec\033[0m\n")

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              Graphpython --command invoke-reconasoutsider --domain company.com
              Graphpython --command get-graphtokens
              Graphpython --command get-users --token eyJ0... --select displayname,id
              Graphpython --command invoke-search --search "credentials" --entity driveItem --token token
              Graphpython --command deploy-maliciousscript --script malicious.ps1 --token token
        """),
    )
    parser.add_argument("--command")
    parser.add_argument("--list-commands",           action="store_true")
    parser.add_argument("--token")
    parser.add_argument("--estsauthcookie")
    parser.add_argument("--use-cae",                 action="store_true")
    parser.add_argument("--cert")
    parser.add_argument("--domain")
    parser.add_argument("--tenant")
    parser.add_argument("--username")
    parser.add_argument("--secret")
    parser.add_argument("--id")
    parser.add_argument("--select")
    parser.add_argument("--query")
    parser.add_argument("--search")
    parser.add_argument("--entity",
        choices=["driveItem", "message", "chatMessage", "site", "event"])
    parser.add_argument("--device",
        choices=["Mac", "Windows", "AndroidMobile", "iPhone"])
    parser.add_argument("--browser",
        choices=["Android", "IE", "Chrome", "Firefox", "Edge", "Safari"])
    parser.add_argument("--only-return-cookies",     action="store_true")
    parser.add_argument("--mail-folder",
        choices=["Allitems", "inbox", "archive", "drafts",
                 "sentitems", "deleteditems", "recoverableitemsdeletions"])
    parser.add_argument("--top",                     type=int)
    parser.add_argument("--script")
    parser.add_argument("--email")
    parser.add_argument(
    "--log-all-commands",
    action="store_true",
    help="Log all commands and output to ./logs/",
)
    
    args = parser.parse_args()

    if args.list_commands:
        list_commands()
        return

    if not args.command:
        parser.print_help()
        return

    if args.command.lower() in REQUIRES_TOKEN and not args.token:
        print_red("[-] Error: --token is required for this command.")
        return

    logger = CommandLogger(enabled=args.log_all_commands)
    if args.log_all_commands:
        logger.enable()

    try:
        if logger.enabled:
            output = capture_output(dispatch, args)
            print(output, end="")
            cmd_str = " ".join(
                f"--{k} {v}" for k, v in vars(args).items()
                if v and k not in ("log_all_commands",)
            )
            logger.log(f"{args.command} {cmd_str}", output)
        else:
            dispatch(args)
    except KeyboardInterrupt:
        print_red("\n[-] Operation cancelled.")
        sys.exit(1)
    except Exception as e:
        print_red(f"\n[-] Error executing '{args.command}': {e}")
        sys.exit(1)

# ─── Entry point ─────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) == 1:
        interactive_shell()
    else:
        # Check for --log-all-commands before full parse
        # so interactive shell can also receive it
        if "--log-all-commands" in sys.argv and len(sys.argv) == 1:
            interactive_shell(log_all=True)
        else:
            one_shot()

if __name__ == "__main__":
    main()