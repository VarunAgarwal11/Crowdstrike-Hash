import requests
import pandas as pd
from openpyxl import Workbook


# CrowdStrike API credentials
CLIENT_ID = "Your_Client_ID"
CLIENT_SECRET = "Your_Client_Secret"
BASE_URL = "Your_Base_URL"  # e.g., "https://api.us-2.crowdstrike.com/"

def process_sheet(file_path, sheet_name, column_name, replace_dot=False):
    try:
        data = pd.read_excel(file_path, sheet_name)
        result = []
        for item in data[column_name]:
            if replace_dot:
                item = item.replace("[.]", ".")
            result.append(str(item))
        return result
    except ValueError as e:
        print(f"Error: {e}. Sheet '{sheet_name}' not found in the Excel file.")
        return []

file_path = r"your_file_path_here.xlsx"  # Update with your file path

# Indicators to block
HASHES_TO_BLOCK = process_sheet(file_path, 'HASH', 'SHA256')
print(*HASHES_TO_BLOCK, sep="\n")

IPS_TO_BLOCK  = process_sheet(file_path, 'IP ADDRESS', 'IP Address', replace_dot=True)
print(*IPS_TO_BLOCK , sep="\n")

DOMAINS_TO_BLOCK = process_sheet(file_path, 'DOMAIN', 'Domain', replace_dot=True)
print(*DOMAINS_TO_BLOCK, sep="\n")

def get_access_token():
    url = f"{BASE_URL}oauth2/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        print(f"Access Token Response:\nStatus: {response.status_code}\nBody: {response.text}")
        return response.json().get("access_token")
    except requests.RequestException as e:
        print(f"Failed to get access token: {e}")
        return None

    
def block_indicator(token, indicator_type, value):
    if not token:
        print("No valid token provided.")
        return
    url = f"{BASE_URL}iocs/entities/indicators/v1"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "indicators": [
            {
                "type": indicator_type,
                "value": value,
                "action": "detect",  
                "source": "API Script",
                "description": f"Blocked {indicator_type} by automation script",
                "severity": "high",
                "applied_globally": True,
                "platforms": ["Windows", "Mac", "Linux"]
            }
        ]
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        print(f"Block {indicator_type.capitalize()} Response for {value}:\nStatus: {response.status_code}\nBody: {response.text}")
        if response.status_code == 201:
            print(f"Successfully blocked {indicator_type}: {value}")
        else:
            print(f"{value} The {indicator_type} already exists \n Status {response.status_code}")
    except requests.RequestException as e:
        print(f"Error blocking {indicator_type} {value}: {e}")

def block_hashes(token, hashes):
    if not token:
        print("No valid token provided.")
        return
    url = f"{BASE_URL}iocs/entities/indicators/v1"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    for hash_value in hashes:
            payload = {
                "indicators": [
                    {
                        "type": "sha256",
                        "value": hash_value,
                        "action": "prevent",  #block
                        "source": "API Script",
                        "description": "Blocked by automation script",
                        "severity": "high",
                        "applied_globally": True,
                        "platforms": ["Windows", "Mac", "Linux"]
                    }
                ]
            }
            try:
                response = requests.post(url, headers=headers, json=payload)
                print(f"Block Hash Response for {hash_value}:\nStatus: {response.status_code}\nBody: {response.text}")
                if response.status_code == 201:
                    print(f"Successfully blocked hash: {hash_value}")
                else:
                    print(f"{hash_value} The hash already exists \n Status {response.status_code}")
            except requests.RequestException as e:
                print(f"Error blocking hash {hash_value}: {e}")

def block_domains(token, domains):
    if not token:
        print("No valid token provided.")
        return
    for domain in domains:
        block_indicator(token, "domain", domain)

def block_ips(token, ips):
    if not token:
        print("No valid token provided.")
        return
    for ip in ips:
        block_indicator(token, "ipv4", ip)
                
def main():
    token = get_access_token()
    if token:
        print(f"Using token: {token[:10]}...")  # Print first 10 chars of token for debugging
        
        # Block hashes
        block_hashes(token, HASHES_TO_BLOCK)
        #Detect IPs and Domains
        block_domains(token, DOMAINS_TO_BLOCK)
        block_ips(token, IPS_TO_BLOCK)
    else:
        print("Cannot proceed without a valid access token.")
        
if __name__ == "__main__":
    main()
    