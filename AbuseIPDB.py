import requests
import subprocess
import platform

# Your AbuseIPDB API key (Replace this with your own API key)
API_KEY = 'd48138213d3d91f88944cf0320e0bd8695962c6b6f25ee0789bcf7a95121b62b41c0ebb700c8cdc1'

# Function to get IP reputation from AbuseIPDB
def get_ip_reputation(ip):
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'  # Check IP reputation for the past 90 days
    }
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('data'):
            abuse_score = data['data']['abuseConfidenceScore']
            print(f"IP {ip} is {'suspicious' if abuse_score > 50 else 'clean'} with a confidence score of {abuse_score}.")
            return abuse_score
        else:
            print(f"IP {ip} is not found in the database.")
            return 0
    else:
        print(f"Error: Unable to fetch data for IP {ip}. Status code: {response.status_code}")
        return -1

# Function to block IP depending on the OS (macOS uses pfctl)
def block_ip(ip):
    os_type = platform.system()
    
    if os_type == "Darwin":  # macOS
        # Blocking using pfctl on macOS
        pf_config = '/etc/pf.conf'
        
        # Check if the rule already exists before adding it
        with open(pf_config, 'r') as f:
            existing_rules = f.read()
        
        if f"block drop from {ip} to any" not in existing_rules:
            with open(pf_config, 'a') as f:
                f.write(f"\nblock drop from {ip} to any\n")
            
            # Apply the new rule
            subprocess.run(["sudo", "pfctl", "-f", pf_config])
            subprocess.run(["sudo", "pfctl", "-e"])
            print(f"Blocked {ip} on macOS using pfctl.")
        else:
            print(f"IP {ip} is already blocked.")
    
    else:
        print(f"Unsupported OS: {os_type}")

# Main function
def main():
    ip_address = input("Enter the IP address to check: ")

    # Get the IP reputation score
    abuse_score = get_ip_reputation(ip_address)

    if abuse_score > 50:
        print(f"IP {ip_address} has a high abuse score ({abuse_score}), blocking it.")
        block_ip(ip_address)
    else:
        print(f"IP {ip_address} is clean or has a low abuse score ({abuse_score}).")

if __name__ == "__main__":
    main()
