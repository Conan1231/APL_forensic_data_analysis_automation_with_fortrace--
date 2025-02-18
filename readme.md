# Project Work (APL): Automated Image Creation for Forensic Data Analysis with Fortrace++
- **main focus**: Malicious and Malware Scenarios, Automation
## Table of Contents
- [Introduction](#introduction)
- [Task Description](#task-description)
- [Installation of Fortrace++](#installation-of-fortrace)
  - [Kali Linux](#kali-linux)
  - [EndeavourOS (Arch Linux)](#endeavouros-arch-linux)
  - [Preparing the Windows VM](#preparing-the-windows-vm)
- [Scenarios](#scenarios)
  - [Scenario 1: Easy – Unauthorized Remote Access via Backdoor](#scenario-1-easy--unauthorized-remote-access-via-backdoor)
  - [Scenario 2: Medium – Simulation of Secure Malware / Ransomware-like Behavior](#scenario-2-medium--simulation-of-secure-malware--ransomware-like-behavior)
  - [Scenario 3: Hard – Complex Multi-Stage Attack and Persistent Infection](#scenario-3-hard--complex-multi-stage-attack-and-persistent-infection)
- [Expected Artifacts and Analysis](#expected-artifacts-and-analysis)
- [Summary and Conclusion](#summary-and-conclusion)

---

## Introduction

This project work, part of the Master's program in Applied Computer Science within the "Forensic Data Analysis" module, focuses on the creation and analysis of VM images using the open-source software **Fortrace++**. Controlled scenarios depicting common attack vectors and system compromises are generated and automated using Python scripts and YAML configuration files. The resulting VM image serves educational purposes, providing practical training in forensic analysis.

In simple terms: Targeted attacks and malware simulations are executed in a virtual environment, which can later be analyzed using forensic tools (e.g., Autopsy, Magnet Axiom).

---

## Task Description

- **Creation of a VM Image:** Using Fortrace++ and Python, simulated attack scenarios are automatically performed in a VM.
- **Documentation:** Detailed description of each scenario, technical procedures, and resulting artifacts in Markdown.
- **Focus on Automation:** Scenarios should be largely automated for repeatability and reproducibility.
- **Educational Purpose:** The final image is intended for training and research in forensic analysis.

---

## Installation of Fortrace++
- Installation steps are documented here for completeness. 
For individual installations and potential issues, 
please refer to the official [Fortrace++ documentation](https://gitlab.com/DW0lf/fortrace#installation).
- I used two Maschines while working on the task (I. Kali Linux, II. EndeavourOS (similar to Arch Linux, the Distro used by the Fortrace++ Project Maintainer))

### Kali Linux
- System setup for this documentation:
    - OS: Kali GNU/Linux kali-rolling (kali-rolling) x86_64
    - Kernel: 6.11.2-amd64
    - CPU: Intel i7-8700K (12) @ 4.7GHz
    - GPU: NVIDIA GeForce GTX 1080 Mobile
    - Memory: 64 GiB
```sh
git clone https://gitlab.com/DW0lf/fortrace.git
# Debian (Kali) / Ubuntu
sudo apt install qemu-kvm libvirt-daemon-system libvirt-dev python3 python3-dev
sudo adduser $USER libvirt
sudo apt install build-essential
sudo apt install virt-manager
sudo apt install tesseract-ocr tesseract-ocr-eng wireshark-common libguestfs-tools libguestfs-dev
sudo apt install python3-venv
```

**Create a Virtual Environment for Python**
- In the future, a GUI setup will be available or is at least planned, but as of February 2025, manual command-line and Python setup is required.

```sh
python -m venv .venv
source .venv/bin/activate
FILE_SUFFIX=$(python --version | grep -oP '(?<=Python )\d+\.\d+' | sed 's/\./_/g')
pip install -r requirements_lock_$FILE_SUFFIX.txt
```

- If you plan to modify the VM disk image with ForTrace++ (e.g., to place files there), install the following dependency:
    - Check for the latest version [here](https://download.libguestfs.org/python/)
    - `pip install http://libguestfs.org/download/python/guestfs-1.40.2.tar.gz`

**Download Submodules**
```
git submodule init
git submodule update --force --recursive --init --remote
```

**Setup the Environment**
```
PYTHON_VERSION=$(python --version | grep -oP '(?<=Python )\d+\.\d+')
readlink -f src > .venv/lib/python$PYTHON_VERSION/site-packages/fortrace_src.pth
```

**Usage**
- Refer to the official documentation: https://fortrace.readthedocs.io/en/latest/index.html

---

### EndeavourOS (Arch Linux)


### Preparing the Windows VM
- Download the official Win10 .iso from [here](https://www.microsoft.com/en-us/software-download/windows10) (recommended Language: English International)
  - To bypass Microsoft's restrictions and download the English ISO in Germany, the following tricks may be necessary:
  1. Open the developer console in your browser (F12) → Switch device emulation to a mobile device to enable the ISO download option.
  2. Use Microsoft Edge (other browsers may cause download errors, or adjust the user agent to mimic Edge).
  3. Use a VPN and select a US location (try different servers until one works).

- Use the `create_vm.sh` script for automated Win10 VM creation or manually follow the steps in the [official documentation](https://gitlab.com/DW0lf/fortrace/-/tree/main/examples/Windows/ForTrace_Workshop/VeraCrypt#installation-of-windows-10-vm), as Windows OS initial installation requires manual configuration within the VM.

---

## Scenarios

### Scenario 1: Easy – Unauthorized Remote Access via Backdoor

**Description:**

This scenario simulates a simple case where a laptop is left unattended. An attacker takes the opportunity to set up remote access by installing a backdoor on the system. This backdoor can later be detected in a forensic analysis (e.g., using Autopsy).

**Technical Implementation:**

- **Environment:**  
  - VM image where the laptop (simulated machine) is operated in an "unattended" state.
  - Network: Local network allowing remote access.
- **Execution:**
  1. **Initial State:** The laptop is powered on but left unattended.
  2. **Attack:** A script is automatically triggered (via scheduled tasks or other triggers) to establish a remote connection.
  3. **Backdoor Installation:** A Python-based exploit installs a persistent backdoor (e.g., as a hidden service).
  4. **Logging:** All actions (connection, installation, system registration) are recorded in log files.
- **Forensic Artifacts:**
  - Log entries documenting the time and process of backdoor installation.
  - System modifications (new services, changed configurations).
  - Network connections evidencing remote access.

---

### Scenario 2: Medium – Exfiltrate Passwords from the SQLite Database of the Webbrowser



---

### Scenario 3: Hard - File Encryption (Ransomware-like Behavior)

**Description:**

This scenario simulates controlled malware activity resembling a ransomware attack. System files are encrypted, but in a safe test environment to prevent actual damage.

**Technical Implementation:**

- **Environment:**  
  - VM image where special test files and directories are created.
  - Isolated network to prevent spread.
- **Execution:**
  1. **Preparation:** Create a test directory with dummy files.
  2. **Malware Simulation:** A Python script "encrypts" (simulates encryption of) the files using a simple encryption method (e.g., XOR encryption). All actions are logged.
  3. **Recovery:** A decryption script is provided to restore test environment integrity.
- **Forensic Artifacts:**
  - Log files documenting encryption timestamps and actions.
  - Changed file attributes and unusual file naming conventions.
  - Memory traces and temporary files showing malware activity.

#### 📌 Description of the script 
This script encrypts all files and folders in the **"Documents"** directory of the current user.  
- Encryption is performed using a **XOR operation**.  
- Filenames are additionally **Base64 encoded** to avoid invalid characters.  
- At the end, a **"YOU_GOT_HACKED.txt"** file is created on the desktop listing all encrypted files.  
- A **log file with debug information** is stored in the "Downloads" folder.  
- The **console window remains hidden** to execute the process in the background.  

#### ⚙️ Creating the Executable File  
```sh
cd scenario3-encryption/
pyinstaller --onefile --noconsole --icon=PowerPoint.ico ./simple_xor_encrypt.py
```
- ![encryption](pictures/before_encryption.png)  
- ![encryption](pictures/after_encryption.png)
--- 

## Expected Artifacts and Analysis

For all scenarios, the following artifacts are expected:

- **Log Files:** Detailed logs documenting timestamps, execution flow, and types of performed actions.
- **System Changes:** Recorded modifications to system configurations, file attributes, and new or altered services/processes.
- **Network Activity:** Documentation of network access and connections (e.g., using pcap files).
- **Temporary Files and Memory Dumps:** Snapshots of RAM and temporary files providing clues about malware activity.

Forensic analysis (e.g., via Autopsy) should reconstruct the exact attack flow and identify the techniques used.

---

## Summary and Conclusion

This documentation outlines three different attack scenarios that can be simulated with ForTrace++ in a Windows VM:

1. **Backdoor Installation:**
   Demonstrates how a physical attack in an unsecured environment can lead to persistent remote access.

2. **Password Exfiltration from Browser Databases:**
   Highlights the risks of storing passwords insecurely in browsers and underscores the necessity of using secure password managers.

3. **Word Macro Ransomware:**
   Shows how malicious macros in Office documents can encrypt critical data, disrupting business operations.

These scenarios provide both a practical insight into common attack vectors and valuable case studies for forensic analysis. The combination of YAML configuration and Python automation with ForTrace++ ensures a repeatable and controlled workflow—ideal for training and research purposes.

**Outlook:**
- Further development of automation scripts to simulate even more realistic attack scenarios.
- Integration of additional analysis tools for advanced forensic investigation.
- Evaluation and comparison of results with real-world attack data.

---
