# Projektarbeit (APL): Automatisierte Imageerstellung für die Forensische Datenanalyse mit Fortrace++

## Inhaltsverzeichnis
- [Einführung](#einführung)
- [Aufgabenstellung](#aufgabenstellung)
- [Vorgehensweise und Automatisierung](#vorgehensweise-und-automatisierung)
    - [Installation von Fortrace++](#installation-von-fortrace++)
- [Szenarien](#szenarien)
  - [Szenario 1: Leicht – Unbefugter Fernzugang via Backdoor](#szenario-1-leicht--unbefugter-fernzugang-via-backdoor)
  - [Szenario 2: Mittel – Simulation sicherer Malware / Ransomware-ähnliches Verhalten](#szenario-2-mittel--simulation-sicherer-malware--ransomware-ähnliches-verhalten)
  - [Szenario 3: Schwer – Komplexer Multi-Stage Angriff und persistente Infektion](#szenario-3-schwer--komplexer-multi-stage-angriff-und-persistente-infektion)
- [Erwartete Artefakte und Analyse](#erwartete-artefakte-und-analyse)
- [Fazit und Ausblick](#fazit-und-ausblick)

---
## Einführung

Diese Projektarbeit im Rahmen des Masterstudiums Angewandte Informatik im Modul "Forensische Datenanalyse" beschäftigt sich mit der Erstellung und Analyse von VM-Images unteranderem mithilfe der Open-Source-Software **Fortrace++**. Mithilfe von Python-Skripten und YAML-Konfigurationsscripten werden kontrollierte Szenarien erstellt, die typische Angriffsvektoren und Kompromittierungen abbilden. Das daraus resultierende VM-Image dient unter anderem Bildungszwecken, um forensische Analysen praxisnah zu schulen.

In einfachen Worten: Es werden gezielt Angriffe und Malware-Simulationen in einer virtuellen Umgebung ausgeführt, die anschließend in einer forensischen Analyse (z.B. mittels Autopsy) untersucht werden können.

---

## Aufgabenstellung

- **Erstellung eines VM-Images:** Mithilfe von Fortrace++ und Python werden simulierte Angriffsszenarien in einer VM implementiert.
- **Dokumentation:** Eine ausführliche Beschreibung der einzelnen Szenarien, der technischen Abläufe und der resultierenden Artefakte in Markdown.
- **Schwerpunkt Automatisierung:** Die Szenarien sollen weitgehend automatisiert erstellt und dokumentiert werden, um den Wiederholungsprozess und die Reproduzierbarkeit zu gewährleisten.
- **Bildungszwecke:** Das fertige Image soll in der Ausbildung und Forschung genutzt werden, um forensische Analysen zu trainieren.

---


## Installation von Fortrace++
- Installationsschritte werden hier nur zur Vollständigkeit dokumentiert. Bei individuellen Installationen und möglicherweise auftretenen Problemen bitte auf der offizielen Dokumentation des Projekts [Fortrace++](https://gitlab.com/DW0lf/fortrace#installation) nachschauen.
- System dieser Dokumentation:
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

### Virtual Environment für Python erstellen
- Später wird es laut Roadmap des Projekts auch per GUI funktionieren, aber derzeit (Stand: Februar 2025) ist die Einrichtung noch über Commandline und Python manuell notwendig!

- Run the four commands below in the project's root
folder to create a new virtual environment named .venv and activate it

```sh
python -m venv .venv
source .venv/bin/activate
FILE_SUFFIX=$(python --version | grep -oP '(?<=Python )\d+\.\d+' | sed 's/\./_/g')
pip install -r requirements_lock_$FILE_SUFFIX.txt
```

- if you plan to alter the disk image of the VM with ForTrace++ (e.g. for placing files there) install the following dependency
    - check for the latest version [here](https://download.libguestfs.org/python/)
    - `pip install http://libguestfs.org/download/python/guestfs-1.40.2.tar.gz`

### Download submodules
- the weights for OpenCV's EAST text detection
```
git submodule init
git submodule update --force --recursive --init --remote
```

### Setup the environment
```
PYTHON_VERSION=$(python --version | grep -oP '(?<=Python )\d+\.\d+')
readlink -f src > .venv/lib/python$PYTHON_VERSION/site-packages/fortrace_src.pth
```

### Usage
- refer to official documentation: https://fortrace.readthedocs.io/en/latest/index.html