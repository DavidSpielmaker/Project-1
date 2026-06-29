from auth import token,graph_get
from colorama import init, Fore, Back, Style

init(autoreset=True)

policies = graph_get(token, "/identity/conditionalAccess/policies")

findings = []

def check_ca_policy_states(policies):

    findings = []
    for p in policies:
        state = p['state']
        if state == "enabled":
            continue
        
        if state == "enabledForReportingButNotEnforced":
            label = "Report Only"
            severity = "High"
        else:
            label = "Disabled"
            severity = "Medium"
            
        findings.append({
            "title": "Conditional Access policy not enforced",
            "severity": severity,
            "object": p["displayName"],
            "detail": f"Policy is in '{label}' state and is not actively enforcing.",
            "remediation": "Set the policy state to 'On' to enforce it.",
        })
    return findings

def print_findings(findings):
    if not findings:
        print("No findings - all checks passed.")
        return

    print(f"Found {len(findings)} finding(s):\n")
    for f in findings:
        if f["severity"] == "High":
            color = Fore.RED
        elif f["severity"] == "Medium":
            color = Fore.YELLOW
        else:
            color = Fore.WHITE

        print(color + f"[{f['severity']}] {f['title']}")
        print(color + f"    Object:      {f['object']}")
        print(color + f"    Detail:      {f['detail']}")
        print(color + f"    Remediation: {f['remediation']}")
        print()

def main():
    policies = graph_get(token, "/identity/conditionalAccess/policies")
    
    all_findings = []
    all_findings += check_ca_policy_states(policies)
    
    print_findings(all_findings)
    
main()