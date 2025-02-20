#!/bin/bash
# This script creates a new Windows 10 VM using virt-install.
# Note: It assumes that libvirt and all necessary tools are installed.

# Define variables
VM_NAME="win10"
ISO_PATH="/path/to/windows10.iso"         # Path to the Windows 10 ISO image (e.g., downloaded from Microsoft)
DISK_PATH="/var/lib/libvirt/images/${VM_NAME}.qcow2"
DISK_SIZE=40                              # Size in GiB
MEMORY=8192                               # RAM in MB
VCPUS=6                                   # Number of CPUs
NETWORK="default"                         # Name of the libvirt network, usually "default"
OS_VARIANT="win10"                        # libvirt OS variant (adjust if necessary)

# Check if the ISO image exists
if [ ! -f "$ISO_PATH" ]; then
  echo "The ISO image was not found: $ISO_PATH"
  exit 1
fi

# Create the disk image if it doesn't already exist
if [ ! -f "$DISK_PATH" ]; then
  echo "Creating disk image: $DISK_PATH"
  qemu-img create -f qcow2 "$DISK_PATH" ${DISK_SIZE}G || { echo "Error creating disk image."; exit 1; }
fi

# Create the virtual machine and start the installation
echo "Starting virt-install for VM $VM_NAME..."
virt-install \
  --name "$VM_NAME" \
  --os-variant "$OS_VARIANT" \
  --ram "$MEMORY" \
  --vcpus "$VCPUS" \
  --cpu host-model \
  --disk path="$DISK_PATH",size="$DISK_SIZE",format=qcow2 \
  --cdrom "$ISO_PATH" \
  --network network="$NETWORK" \
  --graphics spice \
  --video qxl \
  --boot cdrom,hd,menu=on \
  --noautoconsole

echo "The VM $VM_NAME has been created. Please complete the Windows installation (and any manual configuration steps) using a GUI client like Virtual Machine Manager."

# Optional: Wait for the installation to finish and create a snapshot
# Note: Windows installations often require manual intervention.
# The following command assumes that the VM has been shut down.
#
# read -p "Has the Windows installation finished and the VM been shut down? (Press Enter to continue)"
# virsh snapshot-create-as "$VM_NAME" "Clean_Install" "Snapshot for ForTrace++ scenario" --atomic
