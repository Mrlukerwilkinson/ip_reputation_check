# IP Reputation Tool

This tool checks the reputation of an IP address using various online services, including ipinfo, AbuseIPDB, and VirusTotal. It's designed to be user-friendly, quickly providing information in a visually appealing manner.

## Features

- Validate IP addresses to ensure they are correctly formatted.
- Query ipinfo for general IP information.
- Check IP addresses against AbuseIPDB to assess their abuse score.
- Verify IP addresses on VirusTotal for malicious activities.
- Display results in a clear, tabular format with color-coded warnings.

## Prerequisites

Before you can use this script, you need to have Python installed on your system. The script has been tested with Python 3.8 and above. Additionally, you will need the following Python packages:

- `requests`
- `pyfiglet`
- `termcolor`
- `prettytable`
- `dnspython` (if integrating DNS-based services like Spamhaus)

You will also need API keys for:
- AbuseIPDB
- VirusTotal

These keys should be inserted into the script in place of the placeholders.

## Installation

Clone this repository to your local machine using:

````
git clone https://github.com/Mrlukerwilkinson/ip_reputation_check.git
````

Navigate to the script's directory:

````
cd ip_reputation_check
````

Install the required Python packages:

````
pip install -r requirements.txt
````

## Usage
Run the script from the command line:

````
python ip_reputation_check.py
````
![image](https://github.com/Mrlukerwilkinson/ip_reputation_check/assets/140768032/8bad6a6b-0eca-4e71-ac82-f1695c425b6c)
![image](https://github.com/Mrlukerwilkinson/ip_reputation_check/assets/140768032/a04619da-c239-4a82-9f48-c4104dc633c2)


## Contributing
Contributions to the IP Reputation Check Tool are welcome. Please follow the standard GitHub pull request process to propose changes.

## Acknowledgments
Thanks to ipinfo, AbuseIPDB, and VirusTotal for providing the APIs.
