import requests
import pyfiglet
import ipaddress
from termcolor import colored
from prettytable import PrettyTable
import os

########################################### - HEADER - ###########################################
def print_header():
    header = pyfiglet.figlet_format("IP Reputation Tool", font="slant")
    summary = "This tool checks the reputation of an IP address using various online services, including ipinfo, AbuseIPDB, and VirusTotal. \n \nIt's designed to be user-friendly, quickly providing information in a visually appealing manner.\n"
    subheader = "Created by TEPG - 2024\n"  
    print(colored(header, 'cyan'))
    print(colored(summary, 'white'))
    print(colored(subheader, 'yellow'))

################################### - IP INFO FUNCTION - ##########################################################
def get_ip_info(ip_address):
    print(colored(f"Checking ipinfo for {ip_address}...", 'cyan'))
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/json')
        ip_info = response.json()
        print_ip_info(ip_info)
    except Exception as e:
        print(colored(f"Error retrieving info from ipinfo: {e}", 'red'))

def print_ip_info(ip_info):
    table = PrettyTable()
    table.field_names = ["Property", "Value"]
    for key, value in ip_info.items():
        table.add_row([key, value])
    print(table)
    
################################### - AbuseIPD FUNCTION - ##########################################################
def check_abuseipdb(ip_address, api_key):
    print(colored(f"Checking AbuseIPDB for {ip_address}...", 'cyan'))
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        response = requests.get(url, headers=headers, params=params)
        result = response.json()
        print_abuseipdb_info(result)
    except Exception as e:
        print(colored(f"Error retrieving info from AbuseIPDB: {e}", 'red'))

def print_abuseipdb_info(result):
    data = result['data']
    table = PrettyTable()
    table.field_names = ["Property", "Value"]
    properties = ['ipAddress', 'isPublic', 'ipVersion', 'isWhitelisted', 'abuseConfidenceScore',
                  'countryCode', 'usageType', 'isp', 'domain', 'hostnames', 'isTor',
                  'totalReports', 'numDistinctUsers', 'lastReportedAt']
    for prop in properties:
        if prop in data:
            value = data[prop] if prop != 'hostnames' else ", ".join(data[prop])
            # Color coding 'abuseConfidenceScore' based on its value
            if prop == 'abuseConfidenceScore':
                score = int(value)  # Ensure the score is an integer for comparison
                if score <= 10:
                    value = colored(value, 'green')
                elif score <= 50:
                    value = colored(value, 'yellow')
                else:
                    value = colored(value, 'red')
            # Coloring 'isTor' based on boolean value
            if prop == 'isTor':
                if value == True:
                    value = colored("True", 'red')  # Display as red if True
                else:
                    value = colored("False", 'green')  # Display as green if False
            table.add_row([prop, value])
    print(table)

########################################### - Virus Total - ###########################################
def check_virustotal(ip_address, api_key):
    print(colored(f"Checking VirusTotal for {ip_address}...", 'cyan'))
    try:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            print_virustotal_info(result)
        else:
            # Provide more specific feedback based on the status code
            print(colored(f"Failed to retrieve info from VirusTotal. HTTP Status: {response.status_code}", 'red'))
    except Exception as e:
        print(colored(f"Error contacting VirusTotal: {e}", 'red'))

def print_virustotal_info(result):
    # Simplify to focus on malicious detection highlighting
    data = result.get('data', {})
    attributes = data.get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    total_detections = sum(last_analysis_stats.values())
    malicious_detections = last_analysis_stats.get('malicious', 0)
    suspicious_detections = last_analysis_stats.get('suspicious', 0)

    # Creating a table for the output
    table = PrettyTable()
    table.field_names = ["Property", "Value"]
    
    # Determine the color based on the number of malicious detections
    malicious_color = 'green' if malicious_detections == 0 else 'red'
    suspicious_color = 'green' if suspicious_detections == 0 else 'red'

    # Adding the most relevant rows to keep the output clear
    table.add_row(["Malicious Detections", colored(f"{malicious_detections} out of {total_detections}", malicious_color)])
    table.add_row(["Suspicious Detections", colored(f"{suspicious_detections} out of {total_detections}", suspicious_color)])
    
    if 'country' in attributes:
        table.add_row(["Country", attributes['country']])
    if 'asn' in attributes:
        table.add_row(["ASN", attributes['asn']])
    if 'as_owner' in attributes:
        table.add_row(["AS Owner", attributes['as_owner']])
    
    print(table)
    
# Centralizing configuration for easier management
ABUSEIPDB_API_KEY = '{YOUR_ABUSEIPD_API}'
VIRUSTOTAL_API_KEY = '{YOUR_VIRUS_TOTAL_API}'

####################################################################################################

def user_choice():
    print("\nSelect the service to check against:")
    print("1. ipinfo")
    print("2. AbuseIPDB")
    print("3. VirusTotal")
    print("4. All")
    print("5. Exit")
    return input("Enter your choice (1/2/3/4/5): ")

# Validate entered IP is legit
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    
def main():
    # ASCII art header for visual appeal
    print_header()

    while True:
        ip_address = input("Enter the IP address: ")
        if is_valid_ip(ip_address):
            print(colored(f"Valid IP address. Using {ip_address} as the source IP.", 'green'))
            break
        else:
            print(colored(f"Invalid IP address. Please enter a valid IPv4 or IPv6 address.", 'red'))
            
    while True:
        choice = user_choice()
        
        if choice == '1':
            get_ip_info(ip_address)
        elif choice == '2':
            check_abuseipdb(ip_address, ABUSEIPDB_API_KEY)
        elif choice == '3':
            check_virustotal(ip_address, VIRUSTOTAL_API_KEY)
        elif choice == '4':
            # Checking all services sequentially
            get_ip_info(ip_address)
            check_abuseipdb(ip_address, ABUSEIPDB_API_KEY)
            check_virustotal(ip_address, VIRUSTOTAL_API_KEY)
        elif choice == '5':
            print("Thank you, Exiting...")
            break
        else:
            print(colored("Invalid choice. Please select a valid option.", 'red'))

        again = input(colored("\nWant to check another service or IP? (yes/no): ", 'yellow'))
        if again.lower() != 'yes':
            break
        ip_address = input("\nEnter the IP address (or press enter to use the previous one): ") or ip_address


if __name__ == "__main__":
    main()
