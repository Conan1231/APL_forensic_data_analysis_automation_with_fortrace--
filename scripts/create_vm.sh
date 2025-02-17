#!/bin/bash
# Dieses Skript erstellt eine neue Windows 10 VM via virt-install.
# Hinweis: Es wird vorausgesetzt, dass libvirt und alle notwendigen Tools installiert sind.

# Variablen definieren
VM_NAME="win10"
ISO_PATH="/pfad/zur/windows10.iso"         # Pfad zum Windows 10 ISO-Image (z.B. von Microsoft heruntergeladen)
DISK_PATH="/var/lib/libvirt/images/${VM_NAME}.qcow2"
DISK_SIZE=40                               # Größe in GiB
MEMORY=8192                                # Arbeitsspeicher in MB
VCPUS=6                                    # Anzahl der CPUs
NETWORK="default"                          # Name des libvirt-Netzwerks, meist "default"
OS_VARIANT="win10"                         # libvirt OS-Variant (ggf. anpassen)

# Prüfen, ob das ISO-Image vorhanden ist
if [ ! -f "$ISO_PATH" ]; then
  echo "Das ISO-Image wurde nicht gefunden: $ISO_PATH"
  exit 1
fi

# Festplatten-Image erstellen (falls noch nicht vorhanden)
if [ ! -f "$DISK_PATH" ]; then
  echo "Erstelle Festplatten-Image: $DISK_PATH"
  qemu-img create -f qcow2 "$DISK_PATH" ${DISK_SIZE}G || { echo "Fehler beim Erstellen des Disk-Images."; exit 1; }
fi

# Virtuelle Maschine erstellen und Installation starten
echo "Starte virt-install für die VM $VM_NAME..."
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

echo "Die VM $VM_NAME wurde erstellt. Bitte schließe die Windows-Installation (und alle manuellen Konfigurationsschritte) über einen GUI-Client wie Virtual Machine Manager ab."

# Optional: Warte, bis die Installation abgeschlossen ist, und erstelle einen Snapshot
# Hierbei ist zu beachten, dass Windows-Installationen meist manuelle Eingriffe benötigen.
# Das folgende Kommando setzt voraus, dass die VM ausgeschaltet ist.
#
# read -p "Ist die Windows-Installation abgeschlossen und die VM ausgeschaltet? (Enter zum Fortfahren)"
# virsh snapshot-create-as "$VM_NAME" "veracrypt" "Snapshot für ForTrace++ Szenario" --atomic