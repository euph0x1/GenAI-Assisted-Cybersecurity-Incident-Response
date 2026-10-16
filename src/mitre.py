"""Small MITRE ATT&CK technique-name lookup. Unknown IDs fall back to the bare ID
(nothing is invented). Extend this dict as you meet new IDs in your data:
run `python -m src.mitre data/incidents_train.jsonl` to list IDs missing from the table."""
import json, sys
from collections import Counter

MITRE_NAMES = {
    "T1005": "Data from Local System", "T1018": "Remote System Discovery",
    "T1027": "Obfuscated Files or Information", "T1036": "Masquerading",
    "T1046": "Network Service Discovery", "T1048": "Exfiltration Over Alternative Protocol",
    "T1049": "System Network Connections Discovery", "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection", "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "PowerShell",
    "T1070": "Indicator Removal", "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols", "T1074": "Data Staged", "T1078": "Valid Accounts",
    "T1078.002": "Valid Accounts: Domain Accounts", "T1078.003": "Valid Accounts: Local Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts", "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery", "T1087": "Account Discovery",
    "T1098": "Account Manipulation", "T1003": "OS Credential Dumping",
    "T1003.001": "OS Credential Dumping: LSASS Memory", "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force", "T1110.003": "Brute Force: Password Spraying",
    "T1114": "Email Collection", "T1114.003": "Email Collection: Email Forwarding Rule",
    "T1133": "External Remote Services", "T1135": "Network Share Discovery",
    "T1136": "Create Account", "T1140": "Deobfuscate/Decode Files or Information",
    "T1189": "Drive-by Compromise", "T1190": "Exploit Public-Facing Application",
    "T1195": "Supply Chain Compromise", "T1204": "User Execution",
    "T1204.002": "User Execution: Malicious File", "T1218": "System Binary Proxy Execution",
    "T1219": "Remote Access Software", "T1021": "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol", "T1041": "Exfiltration Over C2 Channel",
    "T1486": "Data Encrypted for Impact", "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery", "T1496": "Resource Hijacking",
    "T1528": "Steal Application Access Token", "T1531": "Account Access Removal",
    "T1539": "Steal Web Session Cookie", "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder", "T1548": "Abuse Elevation Control Mechanism",
    "T1550": "Use Alternate Authentication Material", "T1550.001": "Application Access Token",
    "T1552": "Unsecured Credentials", "T1555": "Credentials from Password Stores",
    "T1556": "Modify Authentication Process", "T1558": "Steal or Forge Kerberos Tickets",
    "T1560": "Archive Collected Data", "T1562": "Impair Defenses",
    "T1562.001": "Impair Defenses: Disable or Modify Tools", "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment", "T1566.002": "Phishing: Spearphishing Link",
    "T1567": "Exfiltration Over Web Service", "T1569": "System Services",
    "T1574": "Hijack Execution Flow", "T1621": "Multi-Factor Authentication Request Generation",
}

MITRE_NAMES.update({
    "T1110.001": "Brute Force: Password Guessing", "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1059.007": "Command and Scripting Interpreter: JavaScript", "T1106": "Native API",
    "T1559": "Inter-Process Communication", "T1087.002": "Account Discovery: Domain Account",
    "T1008": "Fallback Channels", "T1568": "Dynamic Resolution", "T1485": "Data Destruction",
    "T1210": "Exploitation of Remote Services", "T1552.001": "Unsecured Credentials: Credentials In Files",
    "T1552.002": "Unsecured Credentials: Credentials in Registry", "T1012": "Query Registry",
    "T1069": "Permission Groups Discovery", "T1069.001": "Permission Groups Discovery: Local Groups",
    "T1069.002": "Permission Groups Discovery: Domain Groups", "T1007": "System Service Discovery",
    "T1047": "Windows Management Instrumentation", "T1216": "System Script Proxy Execution",
    "T1220": "XSL Script Processing", "T1016": "System Network Configuration Discovery",
    "T1119": "Automated Collection", "T1218.003": "System Binary Proxy Execution: CMSTP",
    "T1218.004": "System Binary Proxy Execution: InstallUtil", "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32", "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1003.006": "OS Credential Dumping: DCSync", "T1573": "Encrypted Channel",
    "T1030": "Data Transfer Size Limits", "T1569.002": "System Services: Service Execution",
    "T1534": "Internal Spearphishing", "T1557": "Adversary-in-the-Middle",
    "T1550.004": "Use Alternate Authentication Material: Web Session Cookie",
    "T1555.003": "Credentials from Password Stores: Credentials from Web Browsers",
    "T1555.004": "Credentials from Password Stores: Windows Credential Manager",
    "T1537": "Transfer Data to Cloud Account", "T1112": "Modify Registry",
    "T1053.005": "Scheduled Task/Job: Scheduled Task", "T1033": "System Owner/User Discovery",
})

def name(tid: str) -> str:
    return MITRE_NAMES.get(tid) or MITRE_NAMES.get(tid.split(".")[0], "")

def label(tid: str) -> str:
    n = MITRE_NAMES.get(tid)
    if n: return f"{tid} ({n})"
    parent = MITRE_NAMES.get(tid.split(".")[0])
    return f"{tid} (sub-technique of {parent})" if "." in tid and parent else tid

if __name__ == "__main__":  # list IDs in your data that are missing from the table
    path = sys.argv[1] if len(sys.argv) > 1 else "data/incidents_train.jsonl"
    c = Counter(t for l in open(path) for t in json.loads(l)["mitre"])
    missing = [(t, n) for t, n in c.most_common() if t not in MITRE_NAMES]
    print(f"{len(c)} distinct techniques, {len(missing)} not in lookup:")
    for t, n in missing[:40]: print(f"  {t}: {n} incidents")
