# Project Work (APL): Automated Image Creation for Forensic Data Analysis with Fortrace++
- **main focus**: Malicious and Malware Scenarios, Automation
## Table of Contents
- [Introduction](#introduction)
- [Task Description](#task-description)
- [Installation of Fortrace++](#installation-of-fortrace)
  - [Kali Linux](#kali-linux)
  - [EndeavourOS (Arch Linux)](#endeavouros-arch-linux)
  - [Preparing the Windows ISO](#preparing-the-windows-iso)
  - [Setting up the Windows VM](#setting-up-the-windows-vm)
  - [Preparing the Windows VM for the Scenarios](#preparing-the-windows-vm-for-the-scenarios)
- [Scenarios](#scenarios)
  - [Scenario 1: Easy – Unauthorized Remote Access via Backdoor](#scenario-1-easy--unauthorized-remote-access-via-backdoor)
  - [Scenario 2: Medium – Simulation of Secure Malware / Ransomware-like Behavior](#scenario-2-medium--simulation-of-secure-malware--ransomware-like-behavior)
  - [Scenario 3: Hard - File Encryption (Ransomware-like Behavior)](#scenario-3-hard---file-encryption-ransomware-like-behavior)
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
- I used two Maschines while working on the task (I. Kali Linux, II. EndeavourOS (similar to Arch Linux, the distro used by the Fortrace++ project maintainer))

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
- System Specifications:
  - OS: EndeavourOS x86_64 (Dual-Boot with Win10)
  - Kernel: Linux 6.13.2-arch1-1
  - CPU: AMD Ryzen 7 4700U (8) @ 2.00 GHz
  - GPU: AMD Radeon Vega Series / Radeon Vega Mobile Series [Integrated]
  - Memory: 16 GiB

```sh
git clone https://gitlab.com/DW0lf/fortrace.git
sudo pacman -Syu --needed libvirt qemu-system-x86 iptables-nft dnsmasq
sudo usermod -aG libvirt $USER
sudo systemctl enable --now libvirtd.service
sudo pacman -Syu virt-manager
sudo pacman -Syu tesseract tesseract-data-eng wireshark-cli guestfs-tools
sudo usermod -aG wireshark $USER
```
- Reboot system or relogin with the user to let take effect the new assigned groups
  - verify: `groups` (user should have groups "wireshark" and "libvirt")

**Create a Virtual Environment for Python**
```sh
python -m venv .venv
source .venv/bin/activate
FILE_SUFFIX=$(python --version | grep -oP '(?<=Python )\d+\.\d+' | sed 's/\./_/g')
pip install -r requirements_lock_$FILE_SUFFIX.txt
```

- If you plan to modify the VM disk image with ForTrace++ (e.g., to place files there), install the following dependency:
    - Check for the latest version [here](https://download.libguestfs.org/python/)
    - `pip install http://libguestfs.org/download/python/guestfs-1.40.2.tar.gz`
    - last version (1.40.2) released 2019 and seems not to be working on Arch (ERROR: Failed building wheel for guestfs)

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
---

### Preparing the Windows ISO
- Download the official Win10 .iso from [here](https://www.microsoft.com/en-us/software-download/windows10) (recommended Language: English International)
  - To bypass Microsoft's restrictions and download the English ISO in Germany, the following tricks may be necessary:
  1. Open the developer console in your browser (F12) → Switch device emulation to a mobile device to enable the ISO download option.
  2. Use Microsoft Edge (other browsers may cause download errors, or adjust the user agent to mimic Edge).
  3. Use a VPN and select a US location (try different servers until one works).

#### Create an Unattended Windows 10 ISO
- the current official instruction guide has many manual steps to initially prepare the Windows 10 VM
- One way to speed up and, above all, automate this process is to create a *fully unattended Windows 10 installation ISO* by modifying the installation media
- This allows you to automate the entire setup process, including disk partitioning, user creation, and software installation

**Steps for the ISO Modification**
1. Extract the ISO
- Use a tool like **7-Zip** or **Rufus** to extract the contents
  - `sudo pacman -S p7zip`
  - `7z x Win10_22H2_EnglishInternational_x64v1.iso -o/DESTINATION/PATH/Win10_ISO`
- or just mount it in Linux/Windows and copy the files
  - `sudo mount /YOUR_PATH/Win10_22H2_Unattended_BIOS.iso /mnt/iso`

2. Create an `autounattend.xml` File
- This file automates the Windows installation by answering all prompts
- generate one using **Windows System Image Manager (SIM)** (part of Windows ADK)
  - or use an online tool like this: https://www.windowsafg.com/win10x86_x64_uefi.html
  - **Recommended alternative:** https://schneegans.de/windows/unattend-generator/
    - more options for customization available
    - it's even possible to add custom PowerShell scripts that run after the automatic installation process
    - there are multiple manual steps in the Fortrace Documentation to prepare the Windows 10 VM that can be automated this way
- example `autounattend.xml` can be found in the `scripts/`-folder
  - during the installation process is no user interaction required
  - some of the automated steps are for instance:
    - Language and Locale Configuration (System Locale: `en-US`)
    - Partitioning and Disk Formatting (via `diskpart`)
    - Install OS on `Disk 0, Partition 2`
    - Accept EULA automatically
    - Use generic product key (Windows is now activated)
    - Set the computer name to `fortrace-PC`
    - Create user `fortrace` (Administrator)
    - Auto-logon enabled for one session with stored password
    - Mouse Settings Tweaks for Default User (Modify registry keys to disable pointer acceleration)
    - it's also possible to turn off Windows Defender (interesting for the Malware Scenarios)

3. Place `autounattend.xml` in the ISO
- Copy the `autounattend.xml` file into `\sources\` for a network install or just into the root `\` of the extracted ISO folder for booting from USB / CD-ROM (default case for VMs)

4. Rebuild the ISO
- Windows (using `oscdimg` from Windows ADK):
  - Installation: `winget install --id Microsoft.WindowsADK --source winget` (could take a while, approx. 2GB of disk space needed)
  - If command doesn't work a possible fix is to add it to the PATH for this session: `$env:Path += ";C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg"`
```sh
oscdimg -m -o -u2 -udfver102 -bootdata:2#p0,e,bD:\YOUR_PATH\Win10_22H2_EnglishInternational_x64v1\boot\etfsboot.com#pEF,e,bD:\YOUR_PATH\Win10_22H2_EnglishInternational_x64v1\efi\microsoft\boot\efisys.bin D:\YOUR_PATH\Win10_22H2_EnglishInternational_x64v1 D:\YOUR_PATH\Win10_22H2_Unattended.iso
```
- Linux (using `xorriso`):
  - The Windows approach is recommended, as the building process on Linux was not as successful and resulted in significant time loss
```sh
xorriso -as mkisofs -iso-level 3 -full-iso9660-filenames -volid "Win10" \
-eltorito-boot boot/etfsboot.com -no-emul-boot -boot-load-size 8 \
-eltorito-alt-boot -e efi/boot/bootx64.efi -no-emul-boot \
-o Win10Unattended.iso extracted_iso_folder/
```

5. Test the ISO in a Virtual Machine to verify if the installation runs without manual input.

- **Important** (if using the virt-manager): Before starting the installation, configure the VM in **virt-manager** to use either **UEFI** or **BIOS** as needed since it is not possible to change that setting after the first initialisation

**BIOS Mode**  
- The installation works without any keyboard interaction.  
- Important: In the **unattend.xml** file, set **MBR** instead of **GPT** to ensure BIOS compatibility.  

**UEFI Mode** 
- The installation works, but requires **one** keyboard input to start.  


**Optional Customizations**
- **Pre-install drivers**: Add them to `\$OEM$\$1\Drivers\` in the ISO.
- **Pre-install software**: Use `setupcomplete.cmd` in `\$OEM$\$1\Setup\Scripts\`.
- **Auto-activate Windows**: Embed a volume license key in `autounattend.xml`.

- There are also great ressources to optimize the unattended Windows ISO creation process
  - https://github.com/memstechtips/UnattendedWinstall
  - https://github.com/memstechtips/WIMUtil

### Setting up the Windows VM
The Instructions from the official Fortrace++ Documentation are describing multiple manual steps to create the Windows VM with the virt-manager GUI, but there is also the possibility to automate this process with a script.

- Use the `create_vm.sh` script for an automated Win10 VM creation or manually follow the steps in the [official documentation](https://gitlab.com/DW0lf/fortrace/-/tree/main/examples/Windows/ForTrace_Workshop/VeraCrypt#installation-of-windows-10-vm)
  - Notice: The script is just a reference and needs still to be adjusted for the system it's running on
  - with more testing, there could be the possibility to create a generic script, that works on most of the user systems


- Using **libvirt** and the **virt-manager**
  - to check the network connections: `virsh net-list --all` (default needs to be running)
  - start default network: `virsh net-start default` or on-boot: `virsh net-autostart default`

**Troubleshooting** 
- #1: Error starting network 'default': internal error: firewalld can't find the 'libvirt' zone that should have been installed with libvirt
  - `sudo firewall-cmd --permanent --new-zone=libvirt`
  - `sudo firewall-cmd --permanent --zone=libvirt --set-target=ACCEPT`
  - `sudo firewall-cmd --reload`
  - `sudo firewall-cmd --permanent --zone=libvirt --add-interface=virbr0`
  - `sudo firewall-cmd --reload`
  - verify: `sudo firewall-cmd --get-active-zones`
  - `sudo virsh net-start default` --> verify: `sudo virsh net-list --all`
- #2: how to use virsh commands without `sudo`
  - check if `s -l /var/run/libvirt/libvirt-sock` is owned by root
  - change to libvirt group: `sudo chown root:libvirt /var/run/libvirt/libvirt-sock`
  - `sudo chmod 660 /var/run/libvirt/libvirt-sock`
  - `nano ~/.config/libvirt/libvirt.conf` --> add the line: `uri_default = "qemu:///system"`
  - restart libvirt: `sudo systemctl restart libvirtd`
  - now no sudo is needed: `virsh net-list --all`

**Create Snapshots**
- after the preparation of the VM make sure to make a snapshot (maintain a secure state of the virtual machine)
- create multiple snapshots after some more customization/preparation of the maschine to act as an entry point for the Fortrace++ Scenarios
- use the GUI (virt-manager): Show virtual maschine details --> Manage VM snapshots
- commandline: `virsh snapshot-create-as "$VM_NAME" "Clean_Install" "Snapshot for ForTrace++ scenario" --atomic`

### Preparing the Windows VM for the Scenarios
- For the given example scenario (Windows, VeraCrypt) in the Fortrace++ Repo are some more preparation steps described
- These can be also automated with a PowerShell script (immediately with the first unattended installation or later on)
`scripts/vm_preparation.ps1` (run as administrator)
  - **Enable Script Execution**: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force`
  - **(Optional) Revert Execution Policy**: `Set-ExecutionPolicy Restricted -Scope CurrentUser -Force`
- Windows VM: `Win+X` > press `A` or select `PowerShell as Administrator`
  - `cd C:\Users\fortrace\Desktop\`
  - `.\powershell_script.ps1`

```ps1
# Run as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force

# 1. Ensure NuGet Provider is Installed (No User Input)
Write-Host "Installing NuGet Provider..."
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

# 2. Ensure Winget is Installed
Write-Host "Checking for Winget..."
if (-Not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "Winget not found. Installing..."
    $wingetInstaller = "$env:TEMP\winget.msixbundle"
    Invoke-WebRequest -Uri "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -OutFile $wingetInstaller
    Add-AppxPackage -Path $wingetInstaller
}

# 3. Install VeraCrypt Silently (No User Prompts)
Write-Host "Installing VeraCrypt..."
winget install --id IDRIX.VeraCrypt -e --silent --accept-source-agreements --accept-package-agreements

# 4. Set Network Profile to Private
Write-Host "Setting Network Profile to Private..."
$network = Get-NetConnectionProfile
if ($network) {
    Set-NetConnectionProfile -Name $network.Name -NetworkCategory Private
}

# 5. Disable Notifications
Write-Host "Disabling Windows Notifications..."
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
Set-ItemProperty -Path $RegPath -Name ToastEnabled -Value 0

# 6. Disable 'SecureBootEncodeUEFI' in Task Scheduler
Write-Host "Disabling SecureBootEncodeUEFI Task..."
$taskName = "\Microsoft\Windows\PI\SecureBootEncodeUEFI"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Disable-ScheduledTask -TaskName $taskName
}

# 7. Apply Windows Updates (No User Input)
Write-Host "Applying Windows Updates..."
Install-Module PSWindowsUpdate -Force -SkipPublisherCheck
Install-WindowsUpdate -AcceptAll -IgnoreReboot

# 8. Restart the System if Updates Require It
Write-Host "Restarting System..."
shutdown /r /t 10

# 9. After VM Shutdown, Take a Snapshot (Run from Host)
Write-Host "Once the VM shuts down, take a snapshot from the host machine:"
Write-Host "virsh snapshot-create-as win10_bios 'veracrypt' 'Snapshot after installation' --atomic"
```
- Create the Snapshot: `virsh snapshot-create-as win10_bios "veracrypt" "Snapshot for VeraCrypt scenario" --atomic`

### How to copy the PowerShell script into the VM
- over the **network** (create SAMBA share on the Linux host)
  - `sudo nano /etc/samba/smb.conf`
```ini
[global]
   workgroup = WORKGROUP
   server string = Samba Server
   security = user
   map to guest = Bad User

[shared]
   path = /home/YOUR_USER/shared
   read only = no
   guest ok = yes

```
- `sudo systemctl restart smb`
- On the Win10 Host: `\\192.168.122.1\shared`
- or install the [SPICE Guest Tools](https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe) on the Windows 10 VM to allow copy/paste

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

#### 📌 Description of the encryption script 
The script (simple_xor_encrypt.py) encrypts all files and folders in the **"Documents"** directory of the current user.  
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
![encryption](pictures/before_encryption.png)  
![encryption](pictures/after_encryption.png)
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

## Potential Improvements (To-Do)
- modify the unattend.xml to automatically execute the PowerShell scripts
  - allow the PowerShell Execution Policy
  - automatic Install of the Windows SPICE Guest Tools

---
