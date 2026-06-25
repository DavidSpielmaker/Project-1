import os
import sys
import msal
import requests
from dotenv import load_dotenv

load_dotenv()

def get_token():
    tenant_id = os.environ.get("TENANT_ID")
    client_id = os.environ.get("CLIENT_ID")
    client_secret = os.environ.get("SECRET_KEY")

    if tenant_id is None:
        sys.exit("No Tenant_ID configured")

    if client_id is None:
        sys.exit("No Client_ID configured")
    
    if client_secret is None:
        sys.exit("No Client_Secret configured")
        
    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )

    result = app.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )
    
    if "access_token" in result:
        return result["access_token"]
    else:
        sys.exit(f"Token request failed: {result.get('error_description')}")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def graph_get(token, path):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{GRAPH_BASE}{path}"
    
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        sys.exit(response.text)
    
    return response.json()["value"]
    
token = get_token()
policies = graph_get(token, "/identity/conditionalAccess/policies")

print(f"Retrieved {len(policies)} conditional access policy(ies)\n")
for p in policies:
    print(p["state"], "-", p["displayName"])
