import sys
import datetime
import yaml
import os
import re
import time
import argparse
import logging

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor

# --- Configure Logging ---
logger = logging.getLogger(__name__)
# Default logging level is INFO. Can be set to DEBUG via command-line argument.
logger.setLevel(logging.INFO) 

detailed_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def setup_logging_handlers(log_dir, timestamp_run, debug_mode=False):
    """
    Sets up file handlers for detailed logging and console logging.
    """
    # Remove any existing handlers to prevent duplicate logs if called multiple times
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    os.makedirs(log_dir, exist_ok=True)

    detailed_log_filename = os.path.join(log_dir, f"detailed_log_{timestamp_run}.log")
    detailed_file_handler = logging.FileHandler(detailed_log_filename)
    # Set file log level to DEBUG if debug_mode is True, otherwise INFO
    detailed_file_handler.setLevel(logging.DEBUG if debug_mode else logging.INFO) 
    detailed_file_handler.setFormatter(detailed_formatter)
    logger.addHandler(detailed_file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO) # Console output remains INFO level by default
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    logger.info(f"Detailed logs will be saved to: {detailed_log_filename}")
    if debug_mode:
        logger.info("Debug mode is enabled. More verbose logging will be outputted.")


def load_yaml_config(filepath):
    """
    Loads configuration data from a YAML file.
    """
    try:
        with open(filepath, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found at {filepath}")
        return None
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file {filepath}: {e}")
        return None

def save_output_to_file(directory, filename, content):
    """
    Saves the provided content to a specified file within a given directory.
    """
    os.makedirs(directory, exist_ok=True)
    full_path = os.path.join(directory, filename)
    try:
        with open(full_path, 'w') as f:
            f.write(content)
        logger.info(f"Output successfully saved to {full_path}")
    except IOError as e:
        logger.error(f"Error saving file {full_path}: {e}")

def save_status_log_to_file(directory, filename, log_content):
    """
    Saves the status log content to a specified file within a given directory.
    """
    os.makedirs(directory, exist_ok=True)
    full_path = os.path.join(directory, filename)
    try:
        with open(full_path, 'w') as f:
            f.write("\n".join(log_content))
        logger.info(f"Status log successfully saved to {full_path}")
    except IOError as e:
        logger.error(f"Error saving status log file {full_path}: {e}")

def _get_device_hostname(net_connect, device_type, host):
    """
    Attempts to retrieve the device's hostname using a specific command.
    """
    hostname = host # Default to IP if hostname cannot be fetched
    
    try:
        if device_type == 'juniper_junos':
            # For Juniper, use 'show version' and specifically look for "Hostname: <name>"
            hostname_output = net_connect.send_command("show version", expect_string=r'[#>]\s*$', strip_prompt=True, strip_command=True).strip()
            
            match = re.search(r'Hostname:\s*(\S+)', hostname_output, re.IGNORECASE)
            if match:
                hostname = match.group(1).strip()
                logger.info(f"Fetched hostname for {host} from 'show version': {hostname}")
            else:
                # Fallback: if "Hostname:" not found, try to get the first word of the first non-empty line
                lines = [line.strip() for line in hostname_output.splitlines() if line.strip()]
                if lines:
                    hostname = lines[0].split(' ')[0].strip()
                    logger.info(f"Fetched hostname for {host} (fallback from 'show version'): {hostname}")
                else:
                    logger.warning(f"'show version' returned empty or unparseable output for hostname on {host}.")
        elif device_type.startswith('cisco_'):
            # Cisco 'show hostname' is usually reliable
            hostname_output = net_connect.send_command("show hostname", expect_string=r'[#>]\s*$', strip_prompt=True, strip_command=True).strip()
            hostname = hostname_output.splitlines()[-1].strip()
            if not hostname: # Fallback for Cisco if show hostname is empty
                hostname_output_version = net_connect.send_command("show version", expect_string=r'[#>]\s*$', strip_prompt=True, strip_command=True).strip()
                match = re.search(r'^\S+\s+uptime', hostname_output_version, re.MULTILINE)
                if match:
                    hostname = hostname_output_version.splitlines()[0].split(' ')[0].strip()
            logger.info(f"Fetched hostname for {host}: {hostname}")
    except Exception as e:
        logger.warning(f"Could not fetch hostname for {host} (Type: {device_type}): {e}")
    return hostname


def process_device(device_info, commands_for_device, timestamp_run, output_base_dir):
    """
    Connects to a single device, executes commands, and returns its status and output content.
    Includes a retry mechanism for initial connection.
    """
    host = device_info['host']
    device_type = device_info.get('device_type', 'unknown_device')
    max_retries = device_info.get('max_retries', 3) # Get from device_info, default to 3
    retry_delay = device_info.get('retry_delay', 5) # Get from device_info, default to 5
    
    device_overall_status = "Not Successful"
    device_output_content = []
    error_detail_message = ""
    net_connect = None
    fetched_hostname = host

    # Create a copy of device_info for Netmiko, ensuring only valid Netmiko parameters are passed
    netmiko_device_info = device_info.copy()
    netmiko_device_info.pop('name', None) 
    netmiko_device_info.pop('filename_format', None) 
    netmiko_device_info.pop('max_retries', None) # Ensure these are not passed to ConnectHandler
    netmiko_device_info.pop('retry_delay', None) # Ensure these are not passed to ConnectHandler

    for attempt in range(max_retries):
        try:
            logger.info(f"Attempting connection to {host}:{device_info['port']} (Type: {device_type}) - Attempt {attempt + 1}/{max_retries}...")
            net_connect = ConnectHandler(**netmiko_device_info)
            logger.info(f"Initial connection to {host} successful.")
            device_overall_status = "Successful"
            break
        except NetmikoTimeoutException as e:
            error_detail_message = "Connection Timeout"
            logger.error(f"{error_detail_message} for {host} (Attempt {attempt + 1}/{max_retries}): {e}")
        except NetmikoAuthenticationException as e:
            error_detail_message = "Authentication Failed"
            logger.error(f"{error_detail_message} for {host} (Attempt {attempt + 1}/{max_retries}): {e}")
            break
        except Exception as e:
            error_detail_message = f"Unexpected Error: {type(e).__name__}"
            logger.error(f"{error_detail_message} for {host} (Attempt {attempt + 1}/{max_retries}): {e}")
        
        if attempt < max_retries - 1:
            logger.info(f"Retrying connection to {host} in {retry_delay} seconds...")
            time.sleep(retry_delay)
    else:
        device_overall_status = "Not Successful"
        logger.error(f"Failed to connect to {host} after {max_retries} attempts.")

    if device_overall_status == "Successful" and net_connect:
        try:
            fetched_hostname = _get_device_hostname(net_connect, device_type, host)

            for command in commands_for_device:
                try:
                    logger.info(f"Executing command: '{command}' on {host}...")
                    output = net_connect.send_command(command, strip_prompt=True, strip_command=True)
                    logger.info(f"Command '{command}' executed successfully on {host}.")
                    separator = f"\n--- Output for command: '{command}' ---\n"
                    device_output_content.append(separator)
                    device_output_content.append(output)
                    device_output_content.append("\n" + "="*80 + "\n")
                except Exception as e:
                    cmd_error_message = f"Command '{command}' failed: {type(e).__name__}"
                    logger.error(f"{cmd_error_message} on {host}")
                    device_overall_status = "Not Successful"
                    if not error_detail_message:
                        error_detail_message = cmd_error_message
                    else:
                        error_detail_message += f"; {cmd_error_message}"
        finally:
            if net_connect:
                net_connect.disconnect()
                logger.info(f"Disconnected from {host}.")
    else:
        fetched_hostname = host 

    return host, device_overall_status, device_output_content, error_detail_message, fetched_hostname, device_type

if __name__ == "__main__":
    # --- Command-line argument parsing ---
    parser = argparse.ArgumentParser(description="Network device configuration backup script.")
    parser.add_argument('--devices', default='devices.yaml', help='Path to the YAML file containing device details.')
    parser.add_argument('--commands', default='commands.yaml', help='Path to the YAML file containing commands.')
    parser.add_argument('--output', default='network_backups', help='Root directory for saving backup files.')
    parser.add_argument('--max-workers', type=int, default=10, help='Maximum number of concurrent connections.') # Centralized MAX_WORKERS
    parser.add_argument('--debug', action='store_true', help='Enable DEBUG level logging for more verbose output.') # New debug argument
    args = parser.parse_args()

    DEVICES_FILE = args.devices
    COMMANDS_FILE = args.commands
    OUTPUT_ROOT_DIR = args.output
    MAX_WORKERS = args.max_workers # Use value from argparse
    DEBUG_MODE = args.debug # Use value from argparse

    # --- Setup output directory and logging ---
    timestamp_run = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    current_run_output_dir = os.path.join(OUTPUT_ROOT_DIR, timestamp_run)
    os.makedirs(current_run_output_dir, exist_ok=True)

    setup_logging_handlers(current_run_output_dir, timestamp_run, debug_mode=DEBUG_MODE) # Pass debug_mode to setup_logging_handlers
    if DEBUG_MODE:
        logger.setLevel(logging.DEBUG) # Set global logger level if debug mode is on

    logger.info(f"Starting network backup script at {timestamp_run}")
    logger.info(f"Devices file: {DEVICES_FILE}")
    logger.info(f"Commands file: {COMMANDS_FILE}")
    logger.info(f"Output directory: {current_run_output_dir}")
    logger.info(f"Max concurrent workers: {MAX_WORKERS}")

    # --- Load Device Details ---
    device_data = load_yaml_config(DEVICES_FILE)
    if not device_data or 'groups' not in device_data:
        logger.critical(f"Could not load device details from {DEVICES_FILE} or 'groups' key is missing. Exiting.")
        sys.exit(1)
    device_groups = device_data['groups']

    # --- Load Commands ---
    command_data = load_yaml_config(COMMANDS_FILE)
    if not command_data:
        logger.critical(f"Could not load commands from {COMMANDS_FILE}. Ensure it's structured by device type. Exiting.")
        sys.exit(1)

    # --- Initialize simplified status log ---
    status_log_messages = []
    status_log_filename = "status_log.txt"
    status_log_messages.append(f"--- Device and Command Execution Status Log - {timestamp_run} ---")

    # --- Prepare tasks for ThreadPoolExecutor ---
    tasks = []
    for group_info in device_groups:
        group_name = group_info.get('name', 'default_group')
        group_username = group_info.get('username')
        group_password = group_info.get('password')
        group_port = group_info.get('port', 22)
        group_device_type = group_info.get('device_type', 'juniper_junos')
        group_global_delay_factor = group_info.get('global_delay_factor', 2) # Added missing definition
        # Allow per-group override for max_retries and retry_delay
        group_max_retries = group_info.get('max_retries', 3) 
        group_retry_delay = group_info.get('retry_delay', 5)
        group_filename_format = group_info.get('filename_format', "config_backup_{hostname}_{ip}.txt")
        
        hosts = group_info.get('hosts')
        if hosts is None:
            hosts = []

        if not all([group_username, group_password]):
            logger.warning(f"Skipping group '{group_name}' due to missing username or password.")
            status_log_messages.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Group: {group_name} - Skipped (Missing Credentials)")
            continue

        commands_for_group = command_data.get(group_device_type, [])
        if not commands_for_group:
            logger.warning(f"No commands defined for device type '{group_device_type}' in {COMMANDS_FILE}. Skipping group '{group_name}'.")
            status_log_messages.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Group: {group_name} - Skipped (No commands for device type '{group_device_type}')")
            continue

        for host in hosts:
            device_info = {
                "host": host,
                "username": group_username,
                "password": group_password,
                "port": group_port,
                "device_type": group_device_type,
                "global_delay_factor": group_global_delay_factor,
                "filename_format": group_filename_format,
                "max_retries": group_max_retries,
                "retry_delay": group_retry_delay
            }
            tasks.append((device_info, commands_for_group, timestamp_run, current_run_output_dir))

    # --- Process devices concurrently ---
    logger.info(f"Processing {len(tasks)} devices concurrently with {MAX_WORKERS} workers...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_device, *task_args) for task_args in tasks]

        for future in futures:
            try:
                host, device_overall_status, device_output_content, error_detail_message, fetched_hostname, device_type = future.result()

                log_entry = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {fetched_hostname} ({host}) - Status - {device_overall_status}"
                if device_overall_status == "Not Successful" and error_detail_message:
                    log_entry += f" - Reason: {error_detail_message.split(';')[0].strip()}"
                elif device_overall_status == "Successful" and device_output_content:
                    log_entry += " - Backup Successful"
                status_log_messages.append(log_entry)

                if device_output_content and device_overall_status == "Successful":
                    device_type_output_dir = os.path.join(current_run_output_dir, device_type)
                    
                    sanitized_hostname = fetched_hostname.replace('.', '_').replace(' ', '_').replace('-', '_')
                    sanitized_host = host.replace('.', '_').replace(' ', '_').replace('-', '_')
                    
                    filename_data = {
                        "hostname": sanitized_hostname,
                        "ip": sanitized_host,
                        "device_type": device_type,
                        "timestamp": timestamp_run
                    }
                    
                    current_device_task_info = next((task[0] for task in tasks if task[0]['host'] == host), None)
                    filename_format = current_device_task_info.get('filename_format', "config_backup_{hostname}_{ip}.txt") if current_device_task_info else "config_backup_{hostname}_{ip}.txt"
                    
                    output_filename = filename_format.format(**filename_data)
                    save_output_to_file(device_type_output_dir, output_filename, "\n".join(device_output_content))

                elif not device_output_content and device_overall_status == "Successful":
                    logger.warning(f"No command outputs retrieved for {fetched_hostname} ({host}) despite successful connection. No configuration file created.")
                elif device_overall_status == "Not Successful":
                    logger.warning(f"Skipping configuration file creation for {fetched_hostname} ({host}) due to overall failure.")
            except Exception as e:
                # Catch any unexpected errors from the thread itself, not just Netmiko errors
                logger.critical(f"An unhandled exception occurred in a worker thread: {e}", exc_info=True)
                status_log_messages.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] UNHANDLED ERROR: An unexpected error occurred for a device: {e}")


    # --- Save the final status log ---
    save_status_log_to_file(current_run_output_dir, status_log_filename, status_log_messages)
    logger.info("Script execution completed.")
