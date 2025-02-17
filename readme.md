# Projektarbeit (APL): Automatisierte Imageerstellung für die Forensische Datenanalyse mit Fortrace++

## Inhaltsverzeichnis
- [Einführung](#einführung)
- [Aufgabenstellung](#aufgabenstellung)
- [Installation von Fortrace++](#installation-von-fortrace)
  - [Windows VM vorbereiten](#windows-vm-vorbereiten)
- [Szenarien](#szenarien)
  - [Szenario 1: Leicht – Unbefugter Fernzugang via Backdoor](#szenario-1-leicht--unbefugter-fernzugang-via-backdoor)
  - [Szenario 2: Mittel – Simulation sicherer Malware / Ransomware-ähnliches Verhalten](#szenario-2-mittel--simulation-sicherer-malware--ransomware-ähnliches-verhalten)
  - [Szenario 3: Schwer – Komplexer Multi-Stage Angriff und persistente Infektion](#szenario-3-schwer--komplexer-multi-stage-angriff-und-persistente-infektion)
- [Erwartete Artefakte und Analyse](#erwartete-artefakte-und-analyse)
- [Zusammenfassung und Fazit](#zusammenfassung-und-fazit)

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

**Virtual Environment für Python erstellen**
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

**Download submodules**
- the weights for OpenCV's EAST text detection
```
git submodule init
git submodule update --force --recursive --init --remote
```

**Setup the environment**
```
PYTHON_VERSION=$(python --version | grep -oP '(?<=Python )\d+\.\d+')
readlink -f src > .venv/lib/python$PYTHON_VERSION/site-packages/fortrace_src.pth
```

**Usage**
- refer to official documentation: https://fortrace.readthedocs.io/en/latest/index.html

---

### Windows VM vorbereiten
- Download official Win10 .iso from [here](https://www.microsoft.com/en-us/software-download/windows10)
  - Um Microsofts Schutzmechanismen zu umgehen und auch in Deutschland die englische ISO herunterzuladen sind möglicherweise einige Tricks notwendig.
  1. Dev-Console im Browser öffnen (F12) --> Geräte-Emulation umschalten auf ein mobiles Device, damit die Download-Option für die ISO erscheint!
  2. Verwenden vom Microsoft Edge Browser (andere Browser lieferten einen Fehler beim Download, alternativ den User-Agent anpassen im beliebigen Browser der Wahl auf Edge)
  3. VPN verwenden und einen USA-Standort auswählen (ggf. verschiedene Server ausprobieren bis einer funktioniert!)

- Script `create_vm.sh` zur automatisierten Erstellung der Win10-VM verwenden oder einfach manuell die Schritte aus der [offiziellen Doku](https://gitlab.com/DW0lf/fortrace/-/tree/main/examples/Windows/ForTrace_Workshop/VeraCrypt#installation-of-windows-10-vm) folgen, da die Erstinstallation des Windows OS leider zwangsweise händische Konfigurationen innerhalb der VM benötigt


---

## Szenarien

### Szenario 1: Leicht – Unbefugter Fernzugang via Backdoor

**Beschreibung:**

In diesem Szenario wird ein simpler Fall simuliert, bei dem ein Laptop unbeaufsichtigt zurückgelassen wurde. Ein Angreifer nutzt die Gelegenheit, um einen Fernzugang vorzubereiten. Hierbei wird eine Backdoor auf dem System installiert, die in einer späteren forensischen Analyse (z.B. mittels Autopsy) entdeckt werden kann.

**Technische Umsetzung:**

- **Umgebung:** 
  - VM-Image, in dem der Laptop (simulierte Maschine) im "unbeaufsichtigten" Zustand betrieben wird.
  - Netzwerk: Lokales Netzwerk, in dem Remote-Zugriffe möglich sind.
- **Ablauf:**
  1. **Ausgangssituation:** Der Laptop ist eingeschaltet, jedoch unbeaufsichtigt.
  2. **Angriff:** Ein Skript wird automatisch (über geplante Aufgaben oder Trigger) aktiviert, das eine Remote-Verbindung initialisiert.
  3. **Installation der Backdoor:** Über einen Python-basierten Exploit wird eine persistente Backdoor installiert (z.B. als versteckter Dienst).
  4. **Logging:** Alle Aktionen (Verbindung, Installation, Registrierung im System) werden in Logfiles geschrieben.
- **Forensische Artefakte:**
  - Logeinträge, die den Zeitpunkt und Ablauf der Backdoor-Installation dokumentieren.
  - Veränderungen im System (neue Dienste, veränderte Konfigurationen).
  - Netzwerkverbindungen, die den Remote-Zugriff belegen.


### Szenario 2: Mittel – Simulation sicherer Malware / Ransomware-ähnliches Verhalten

**Beschreibung:**

Dieses Szenario simuliert den Ablauf einer kontrollierten Malware-Aktivität, die beispielsweise einem Ransomware-Angriff ähnelt. Dabei werden Systemdateien verschlüsselt – allerdings in einer sicheren Testumgebung, sodass keine realen Schäden entstehen.

**Technische Umsetzung:**

- **Umgebung:** 
  - VM-Image, in dem spezielle Testdateien und -verzeichnisse angelegt werden.
  - Ein abgeschottetes Netzwerk, um eine Verbreitung zu verhindern.
- **Ablauf:**
  1. **Vorbereitung:** Anlegen eines Testverzeichnisses mit Dummy-Dateien.
  2. **Malware-Simulation:** Ein Python-Skript "verschlüsselt" (simuliert) die Dateien mithilfe einer einfachen Verschlüsselungsmethode (z.B. XOR-Verschlüsselung). Die Aktion wird protokolliert.
  3. **Wiederherstellbarkeit:** Bereitstellung eines Entschlüsselungs-Skripts, um die Integrität der Testumgebung zu gewährleisten.
- **Forensische Artefakte:**
  - Logdateien, die die Zeitpunkte und Aktionen der Verschlüsselung dokumentieren.
  - Geänderte Dateiattribute und ungewöhnliche Dateinamenskonventionen.
  - Spuren im Speicher und in temporären Verzeichnissen.

---

### Szenario 3: Schwer – Komplexer Multi-Stage Angriff und persistente Infektion

**Beschreibung:**

Das dritte Szenario bildet einen komplexeren Angriff ab, der in mehreren Stufen abläuft. Hierbei wird ein initialer Angriffspunkt genutzt, um sich lateral im System zu bewegen, weitere Malware-Komponenten zu installieren und persistente Mechanismen zu etablieren. Dies soll reale Advanced Persistent Threats (APTs) simulieren.

**Technische Umsetzung:**

- **Umgebung:** 
  - VM-Image mit mehreren simulierten Netzwerkknoten und unterschiedlichen Benutzerkonten.
  - Realistische Netzwerkeinstellungen, um laterale Bewegungen zu ermöglichen.
- **Ablauf:**
  1. **Initialer Angriff:** Ein Penetrationstest-Skript nutzt eine Schwachstelle in einer öffentlich zugänglichen Dienstleistung (z.B. veralteter SSH-Dienst).
  2. **Laterale Bewegung:** Nach erfolgreicher Erstanmeldung wird ein Skript gestartet, das weitere Systeme im Netzwerk scannt und kompromittiert.
  3. **Persistenz:** Installation von Tools, die einen dauerhaften Zugang ermöglichen (z.B. Rootkits, zusätzliche Backdoors).
  4. **Verschleierung:** Löschen von Spuren und Manipulation von Logdateien.
- **Forensische Artefakte:**
  - Mehrstufige Logdateien mit verschiedenen Zeitstempeln, die den Ablauf des Angriffs dokumentieren.
  - Veränderungen in Systemdateien und Konfigurationen (z.B. veränderte SSH-Konfiguration).
  - Reste von gelöschten Logdateien und Anzeichen für Manipulation der Systemuhr.
  - Speicherabbilder, die Hinweise auf laufende Prozesse und persistente Dienste enthalten.

---

## Erwartete Artefakte und Analyse

Für alle Szenarien werden folgende Artefakte erwartet:

- **Logdateien:** Detaillierte Protokolle, die den Zeitpunkt, Ablauf und die Art der durchgeführten Aktionen dokumentieren.
- **Systemveränderungen:** Registrierte Änderungen in Systemkonfigurationen, Dateiattribute, neue oder modifizierte Dienste und Prozesse.
- **Netzwerkaktivitäten:** Dokumentation der Netzwerkzugriffe und -verbindungen (z.B. mittels pcap-Dateien).
- **Temporäre Dateien und Speicherabbilder:** Abbildungen des Arbeitsspeichers und temporäre Dateien, die Hinweise auf Malware-Aktivitäten geben.

Die forensische Analyse (z.B. via Autopsy) soll anhand dieser Artefakte den genauen Ablauf des Angriffs rekonstruieren und die verwendeten Techniken identifizieren.

---

## Zusammenfassung und Fazit

In dieser Dokumentation wurden drei unterschiedliche Angriffsszenarien beschrieben, die mit ForTrace++ in einer Windows-VM simuliert werden können:

1. **Backdoor-Installation:**  
   Zeigt, wie ein physischer Angriff in einer ungesicherten Umgebung zu einem persistierenden Fernzugang führen kann.

2. **Passwort-Exfiltration aus Browser-Datenbanken:**  
   Verdeutlicht die Risiken des ungeschützten Speicherns von Passwörtern in Browsern und macht auf die Notwendigkeit sicherer Passwortmanager aufmerksam.

3. **Word-Makro-Ransomware:**  
   Demonstriert, wie durch bösartige Makros in Office-Dokumenten kritische Daten verschlüsselt und somit Geschäftsprozesse lahmgelegt werden können.

Diese Szenarien bieten sowohl einen praxisnahen Einblick in typische Angriffsvektoren als auch wertvolle Lehrbeispiele für forensische Analysen. Durch die Kombination aus YAML-Konfiguration und Python-Automatisierung mit ForTrace++ wird ein wiederholbarer und kontrollierter Ablauf gewährleistet – ideal für Schulungs- und Forschungszwecke.

**Ausblick:**
- Weiterentwicklung der Automatisierungsskripte, um noch realistischere Angriffsszenarien zu simulieren.
- Integration zusätzlicher Analyse-Tools zur erweiterten forensischen Untersuchung.
- Evaluation und Vergleich der Ergebnisse mit realen Angriffsdaten.

---






# Szenario 3 – Dateiverschlüsselung (Ransomware)  

## 📌 Beschreibung  
Dieses Skript verschlüsselt alle Dateien und Ordner im **"Documents"**-Ordner des aktuellen Benutzers.  
- Die Verschlüsselung erfolgt mit einer **XOR-Operation**.  
- Dateinamen werden zusätzlich in **Base64 kodiert**, um ungültige Zeichen zu vermeiden.  
- Am Ende wird eine Datei **"YOU_GOT_HACKED.txt"** auf dem Desktop erstellt, die eine Liste aller verschlüsselten Dateien enthält.  
- Eine **Log-Datei mit Debug-Informationen** wird im "Downloads"-Ordner gespeichert.  
- Das **Konsolenfenster bleibt verborgen**, um den Prozess im Hintergrund auszuführen.  

## ⚙️ Erstellung der ausführbaren Datei  
```sh
cd szenario3-encryption/
pyinstaller --onefile --noconsole --icon=PowerPoint.ico .\simple_xor_encrypt.py
```
- ![encryption](pictures/before_encryption.png)
- ![encryption](pictures/after_encryption.png)