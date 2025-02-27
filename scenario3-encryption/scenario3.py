#!/usr/bin/env python3
"""A Windows 10 scenario simulating ransomware-like file encryption
The scenario is configured through the YAML located in this directory.

This scenario demonstrates how files in the Documents folder are encrypted
by malware disguised as a PowerPoint presentation.

Typical usage:
    > source .venv/bin/activate
    > python scenarios/scenario3-encryption/scenario3.py
"""
import pathlib
import time
import random
import sys
from time import sleep
from pathlib import PureWindowsPath

from fortrace.core.simulation_monitor import SimulationMonitor
from fortrace.core.virsh_domain import GraphicalVirshDomain
from fortrace.fortrace_definitions import FORTRACE_ROOT_DIR
from fortrace.utility.applications.application import (
    ApplicationType,
)
from fortrace.utility.applications.file_manager.windows_explorer import Explorer
from fortrace.utility.applications.text_editor.notepad import Notepad
from fortrace.utility.logger_helper import setup_logger

# Create a logger using ForTrace++'s logger helper
logger = setup_logger(__name__)

# Sample business document content for generating files
INVOICE_TEMPLATES = [
    """INVOICE #INV-{invoice_num}
Date: {date}
Customer: {customer}

Item                  Quantity    Price       Total
{item:<20} {quantity:<10} ${price:<10.2f} ${total:<10.2f}

Subtotal: ${subtotal:.2f}
Tax (7%): ${tax:.2f}
Total Due: ${total_due:.2f}

Payment due within 30 days.
Thank you for your business!
""",
    """RECEIPT
Transaction ID: TXN-{invoice_num}
Date: {date}

Billed To:
{customer}

Description                                Amount
{item:<40} ${total:<10.2f}

Tax: ${tax:.2f}
Total: ${total_due:.2f}

PAID IN FULL
"""
]

CUSTOMER_NAMES = [
    "Acme Corp", "TechSolutions Inc.", "Global Industries",
    "Smith Manufacturing", "Johnson Services Ltd", "Data Systems LLC",
    "Pacific Distributors", "Mountain View Tech", "Sunrise Electronics"
]

ITEM_NAMES = [
    "IT Consulting Services", "Server Maintenance", "Software License",
    "Network Setup", "Cloud Storage (Annual)", "Security Audit",
    "Hardware Upgrade", "Web Development", "Database Migration"
]

def generate_invoice_content():
    """Generate random invoice content for test files"""
    invoice_num = random.randint(10000, 99999)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    year = 2025
    date = f"{month:02d}/{day:02d}/{year}"

    customer = random.choice(CUSTOMER_NAMES)
    item = random.choice(ITEM_NAMES)
    quantity = random.randint(1, 20)
    price = random.uniform(50, 500)
    total = quantity * price

    subtotal = total
    tax = subtotal * 0.07
    total_due = subtotal + tax

    template = random.choice(INVOICE_TEMPLATES)

    return template.format(
        invoice_num=invoice_num,
        date=date,
        customer=customer,
        item=item,
        quantity=quantity,
        price=price,
        total=total,
        subtotal=subtotal,
        tax=tax,
        total_due=total_due
    )


def scenario_3():
    monitor = SimulationMonitor(
        pathlib.Path(
            FORTRACE_ROOT_DIR,
            "scenarios/scenario3-encryption/scenario3.yaml",
        )
    )
    domain = monitor.participant[0].domain  # type: GraphicalVirshDomain
    config = monitor.participant[0].config

    try:
        # Boot the domain with the specified snapshot
        domain.boot(
            start_sniffer=config["domain"]["start_sniffer"],
            snapshot=config["domain"]["snapshot"],
        )

        # Try login with retry mechanism
        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info(f"Login attempt {attempt+1}/{max_retries}")
                domain.env.login(config["domain"]["username"], config["domain"]["password"])
                break  # Exit retry loop if login succeeds
            except ValueError as e:
                logger.warning(f"Login failed on attempt {attempt+1}: {e}")
                if attempt < max_retries - 1:
                    logger.info("Waiting and trying again...")
                    sleep(10)  # Wait and retry
                else:
                    logger.error("Max retries reached for login. Aborting.")
                    raise

        # Log that the scenario is starting
        logger.info("System state: Windows 10 machine, user is creating business documents.")

        # Create documents and then execute the encryption malware
        create_business_documents(domain, config)
        execute_encryption_malware(domain, config)

    except Exception as e:
        logger.error(f"Scenario execution failed: {e}")
        raise
    finally:
        # Always try to clean up, even if there's an error
        try:
            # Only perform post-scenario tasks if needed
            monitor.post_scenario()
            logger.info("Scenario post-processing completed")
        except Exception as e:
            logger.warning(f"Failed to clean up properly: {e}")


def create_business_documents(domain: GraphicalVirshDomain, config: dict):
    """
    Simulates a user creating business documents in the Documents folder.
    Creates multiple folders and files to represent a typical user's document organization.
    """
    logger.info("User: Creating business documents in Documents folder")

    # Open Explorer and navigate to Documents
    explorer = domain.env.open_application(
        ApplicationType.FILE_MANAGER, "File Explorer"
    )  # type: Explorer

    # Use PureWindowsPath as specified in the documentation
    documents_path = PureWindowsPath(config["explorer"]["path2"])
    explorer.browse_to_directory(documents_path)
    sleep(2)

    # Create folders for organizing documents
    folder_names = ["Invoices", "Contracts", "Clients", "Projects"]
    for folder_name in folder_names:
        logger.info(f"User: Creating folder '{folder_name}'")
        explorer.create_folder(folder_name)
        sleep(1)

    # Navigate to Invoices folder using proper path handling
    invoices_path = documents_path / "Invoices"
    explorer.browse_to_directory(invoices_path)
    sleep(1)

    # Create invoice documents
    for i in range(1, 4):  # Create 3 invoice files
        # Open Notepad
        notepad = domain.env.open_application(
            ApplicationType.TEXT_EDITOR, "Notepad"
        )  # type: Notepad

        # Generate and write invoice content
        invoice_content = generate_invoice_content()
        notepad.send_text(invoice_content)

        # Save the file using proper path handling
        invoice_filename = f"Invoice_{i}_{random.randint(1000, 9999)}.txt"
        logger.info(f"User: Creating invoice document '{invoice_filename}'")

        # Use PureWindowsPath for file path and save_as
        invoice_file_path = invoices_path / invoice_filename
        notepad.save_as(invoice_file_path)
        notepad.close()
        sleep(1)

    # Navigate to Contracts folder using proper path handling
    contracts_path = documents_path / "Contracts"
    explorer.browse_to_directory(contracts_path)
    sleep(1)

    # Create a contract document
    notepad = domain.env.open_application(
        ApplicationType.TEXT_EDITOR, "Notepad"
    )  # type: Notepad

    contract_content = """SERVICE AGREEMENT

THIS AGREEMENT is made on February 25, 2025

BETWEEN:
ABC Corporation ("Client")
AND
XYZ Services Ltd ("Service Provider")

1. SERVICES
   The Service Provider agrees to provide IT support services as described in Appendix A.

2. TERM
   This agreement shall commence on March 1, 2025 and continue for a period of 12 months.

3. COMPENSATION
   Client agrees to pay $3,500 per month for services rendered.

4. CONFIDENTIALITY
   Both parties agree to maintain confidentiality of all proprietary information.

SIGNED:

________________________       ________________________
For ABC Corporation             For XYZ Services Ltd
"""

    notepad.send_text(contract_content)
    logger.info("User: Creating contract document 'IT_Service_Agreement_2025.txt'")

    # Use proper path handling for contract file
    contract_file_path = contracts_path / "IT_Service_Agreement_2025.txt"
    notepad.save_as(contract_file_path)
    notepad.close()
    sleep(1)

    # Return to Documents root
    explorer.browse_to_directory(documents_path)
    sleep(1)

    # Keep Explorer open to show the file encryption later
    logger.info("User: Business documents have been created successfully")


def execute_encryption_malware(domain: GraphicalVirshDomain, config: dict):
    """
    Simulates the execution of encryption malware disguised as a PowerPoint file.
    The malware will encrypt all files in the Documents directory.
    """
    logger.info("User: Notices a PowerPoint file on Desktop")

    # Open Explorer and navigate to Desktop
    explorer = domain.env.open_application(
        ApplicationType.FILE_MANAGER, "File Explorer"
    )  # type: Explorer

    # Navigate to Desktop where the malware executable is located using the config
    desktop_path = PureWindowsPath(config["explorer"]["path"])
    explorer.browse_to_directory(desktop_path)
    sleep(2)

    # Execute the malware
    logger.info("User: Executes what appears to be a PowerPoint presentation")
    explorer.focus_on_item("Business_Presentation.exe")
    sleep(1)

    # Use send_key_combination directly on the explorer object,
    explorer.send_key_combination("ret")  # 'ret' is the keycode for Return/Enter

    # Wait for encryption to complete
    logger.info("System: Encryption process running in background")
    sleep(5)  # Allow time for encryption to complete

    # Navigate to Documents to show encrypted files using the config
    documents_path = PureWindowsPath(config["explorer"]["path2"])
    explorer.browse_to_directory(documents_path)
    sleep(2)


    # Log the ransomware activity
    logger.info("Attack: Files in Documents folder have been encrypted")
    logger.info("Attack: Ransom note 'YOU_GOT_HACKED.txt' created on Desktop")
    logger.info("Forensic Artifact: Encrypted files in Documents folder")
    logger.info("Forensic Artifact: Log file in Downloads folder")

    # Navigate back to Desktop to see ransom note
    explorer.browse_to_directory(desktop_path)
    sleep(2)

    # Close Explorer
    explorer.close()


if __name__ == "__main__":
    try:
        scenario_3()
        logger.info("Scenario completed successfully")
    except Exception as e:
        logger.error(f"Scenario failed: {e}")
        sys.exit(1)
