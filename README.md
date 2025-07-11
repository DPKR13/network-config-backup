Network Device Configuration Backup Script
Overview
This Python script automates the process of collecting configuration and operational data from network devices (Juniper Junos and Cisco IOS/NX-OS). It connects to devices, executes a predefined set of commands, and saves the full output as timestamped backup files. This is ideal for maintaining historical records of device configurations and for basic auditing.

The script is designed for efficiency, supporting concurrent connections to multiple devices using a ThreadPoolExecutor.

Features
Multi-Vendor Support: Configurable for Juniper Junos and Cisco IOS/NX-OS devices.

Concurrent Backups: Utilizes threading to connect to and backup multiple devices simultaneously, speeding up the process for large networks.

YAML-based Configuration: Device details and commands are managed in easy-to-read YAML files (devices.yaml and commands.yaml).

Timestamped Backups: All backup files are organized into directories named with the date and time of the script run, ensuring clear versioning.

Detailed Logging: Comprehensive logs capture connection attempts, command execution, and any errors encountered.

Customizable Filenames: Backup filenames can be customized per device group using f-string-like formatting.

Retry Mechanism: Includes a configurable retry mechanism for initial device connections to handle transient network issues.

Prerequisites
Before running this script, ensure you have the following installed:

Python 3.x

netmiko library: For connecting to network devices.

PyYAML library: For parsing YAML configuration files.

You can install the required Python libraries using pip:

pip install -r requirements.txt

Setup
Clone the Repository:

git clone https://github.com/DPKR13/network-config-backup.git
cd network-config-backup

Create a Virtual Environment (Recommended):

python3 -m venv venv
source venv/bin/activate # On Linux/macOS
# venv\Scripts\activate # On Windows

Install Dependencies:

pip install -r requirements.txt

Configure devices.yaml:
Create a file named devices.yaml in the same directory as the script. This file should define your device groups and their connection parameters.

# devices.yaml
groups:
  - name: MyCiscoSwitches
    device_type: cisco_ios
    username: your_cisco_username
    password: your_cisco_password
    port: 22 # Optional, default is 22
    global_delay_factor: 2 # Optional, default is 2
    max_retries: 3 # Optional, default is 3
    retry_delay: 5 # Optional, default is 5 seconds
    filename_format: "{hostname}_cisco_backup_{timestamp}.txt" # Optional, default is "config_backup_{hostname}_{ip}.txt"
    hosts:
      - 192.168.1.10
      - 192.168.1.11
    optional_args:
      secret: your_enable_password # Use this if your Cisco devices require an enable password

  - name: MyJuniperRouters
    device_type: juniper_junos
    username: your_juniper_username
    password: your_juniper_password
    hosts:
      - 10.0.0.1
      - 10.0.0.2
filename_format: "{hostname}_juniper_{timestamp}.txt"

Important: Replace your_cisco_username, your_cisco_password, your_juniper_username, your_juniper_password, your_enable_password, and the example IP addresses with your actual device credentials and IPs.

Configure commands.yaml:
Create a file named commands.yaml in the same directory as the script. This file specifies the commands to run for each device type.

# commands.yaml
cisco_ios:
  - show version
  - show running-config
  - show ip interface brief
  - show cdp neighbors detail
juniper_junos:
  - show version
  - show configuration | display set
  - show interfaces terse
  - show chassis hardware

Running the Script
Execute the script from your terminal:

python Juniper_config-backup.py

Command-Line Arguments:
--devices <path>: Specify the path to your devices.yaml file (default: devices.yaml).

--commands <path>: Specify the path to your commands.yaml file (default: commands.yaml).

--output <directory>: Specify the root directory where backups will be saved (default: network_backups).

--max-workers <N>: Set the maximum number of concurrent connections (default: 10).

--debug: Enable verbose DEBUG level logging.

Example with arguments:

python Juniper_config-backup.py --devices my_devices_list.yaml --output /var/network_backups --max-workers 5 --debug

Output Structure
The script will create a directory structure similar to this:

network_backups/
├── YYYYMMDD_HHMMSS/
│   ├── cisco_ios/
│   │   ├── hostname_ip_YYYYMMDD_HHMMSS.txt
│   │   ├── another_hostname_ip_YYYYMMDD_HHMMSS.txt
│   ├── juniper_junos/
│   │   ├── router_hostname_ip_YYYYMMDD_HHMMSS.txt
│   ├── detailed_log_YYYYMMDD_HHMMSS.log
│   └── status_log.txt
└── logs/
    └── detailed_log_YYYYMMDD_HHMMSS.log (symlink or duplicate for easier access)

Contributing
Feel free to fork this repository, open issues, or submit pull requests.

License
This project is licensed under the MIT License - see the LICENSE file for details.