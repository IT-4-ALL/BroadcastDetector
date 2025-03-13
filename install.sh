#!/bin/bash

# MIT License
#
# Copyright (c) 2025 Philipp Schmid
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


# This script performs the following steps:
# 1. Runs apt update.
# 2. Installs apache2, php, tshark, python3-venv, and python3-pip.
# 3. Deletes and recreates the /home/broadcastdetector directory.
# 4. Creates a Python virtual environment inside /home/broadcastdetector.
# 5. Activates the virtual environment and installs pyshark.
# 6. Creates the broadcast.py file with the provided code.
# 7. Deactivates the virtual environment.
# 8. Adds a tmpfs entry to /etc/fstab for /var/www/html/temp and creates the mount point directory.
# 9. Creates setup_files.sh in /home/broadcastdetector with the specified content.
# 10. Creates /var/www/html/index.php with the provided HTML/PHP code.
# 11. Adds a sudoers entry (in /etc/sudoers.d) to allow www-data to execute the shutdown command without a password.
# 12. Makes all files in /home/broadcastdetector executable, changes ownership of /var/www/html,
#     and adds three cron jobs as root:
#      - @reboot sleep 15 && /home/broadcastdetector/setup_files.sh
#      - @reboot sleep 20 && chown pi:www-data -R /var/www/html
#      - @reboot sleep 25 && /usr/bin/python3 /home/broadcastdetector/broadcast.py

# Ensure the script is run as root

if [ "$EUID" -ne 0 ]; then
  echo "Please run the script as root or with sudo."
  exit 1
fi

echo "Running apt update..."
apt update

echo "Installing apache2, php, tshark, python3-venv, and python3-pip..."
apt install -y apache2 php tshark python3-venv python3-pip
apt install -y libpcap-dev
apt install -y tcpdump

# Define the target directory for broadcast detector files
DIR="/home/broadcastdetector"

# If the directory exists, delete it and create it anew
if [ -d "$DIR" ]; then
  echo "Directory $DIR already exists. Deleting it..."
  rm -rf "$DIR"
fi

echo "Creating directory $DIR..."
mkdir "$DIR"
echo "Directory created."

# Change to the new directory
cd "$DIR" || { echo "Failed to change directory to $DIR"; exit 1; }

# Create the Python virtual environment (named "venv")
echo "Creating Python virtual environment..."
python3 -m venv venv
echo "Virtual environment created."

# Activate the virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install the pyshark package in the virtual environment
echo "Installing pyshark..."
pip install pyshark
pip install pcapy

# Create the broadcast.py file with the provided Python code
TARGET_FILE="$DIR/broadcast.py"
echo "Creating Python file $TARGET_FILE..."
cat << 'EOF' > "$TARGET_FILE"
# MIT License
#
# Copyright (c) 2025 Philipp Schmid
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import pyshark
import os
import csv
import subprocess
import time
from collections import deque
from datetime import datetime
import sys
import logging

# Logging-Konfiguration: Nur Fehler werden geloggt.
logging.basicConfig(
    filename='/home/pi/log.txt',
    level=logging.ERROR,
    format='%(asctime)s: %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def main():
    file_path = "/var/www/html/temp/lastscan.csv"
    file_path_timestamp = "/var/www/html/temp/timestamp.txt"
    file_path_txt = "/var/www/html/temp/intervall.txt"
    pcap_file = "/var/www/html/temp/captured_broadcast.pcap"

    # Erstelle CSV-Datei mit Spaltenüberschriften, falls sie nicht existiert
    if not os.path.isfile(file_path):
        print("❌ Datei nicht gefunden. Erstelle 'lastscan.csv' mit Spaltenüberschriften...")
        with open(file_path, mode="w", newline="") as file:
            writer = csv.writer(file, delimiter="\t")
            writer.writerow(["vlan", "mac", "anzahl", "start", "ende", "intervall"])
        print("✅ Datei 'lastscan.csv' wurde erfolgreich erstellt!")
    else:
        print("✅ Datei 'lastscan.csv' existiert bereits.")

    # Stelle sicher, dass das Intervall-Datei-Verzeichnis existiert und die Datei existiert
    os.makedirs(os.path.dirname(file_path_txt), exist_ok=True)
    if not os.path.exists(file_path_txt):
        with open(file_path_txt, "w") as file:
            file.write("10")
    os.chmod(file_path_txt, 0o777)
    print(f"Die Datei '{file_path_txt}' wurde erstellt (falls nicht vorhanden) und hat nun die Berechtigungen 777.")

    try:
        while True:
            try:
                # Initialisiere Statistiken
                vlan_stats = {}
                vlan_mac_addresses = {}
                loop_macs = {}
                mac_counter = {}
                mac_counter_unicast = {}
                intervall = 10

                # Lese Intervall aus Datei
                try:
                    with open(file_path_txt, "r") as file:
                        intervall = int(file.read().strip())
                except (ValueError, FileNotFoundError):
                    print(f"Fehler beim Lesen des Intervalls. Standardwert 10 Sekunden wird verwendet.")
                    intervall = 10

                print(f"Der gelesene Intervall-Wert ist: {intervall}")

                # Lösche ggf. vorhandene pcap-Datei
                if os.path.exists(pcap_file):
                    os.remove(pcap_file)
                    print(f"✅ Datei {pcap_file} wurde gelöscht.")
                else:
                    print(f"⚠️ Datei {pcap_file} existiert nicht.")

                # Starte tcpdump zur Erfassung von Broadcast-Paketen
                tcpdump_cmd = [
                    "sudo", "tcpdump",
                    "-i", "eth0",                    # Schnittstelle
                    "ether", "broadcast",             # Nur Broadcast-Pakete
                    "-w", pcap_file,                  # Ausgabe-Datei
                    "-G", str(intervall),             # Intervall
                    "-W", "1"                         # Nur 1 Datei (überschreibt)
                ]
                ts_start = int(time.time())
                print(f"📡 Starte tcpdump mit {intervall} Sekunden Intervall...")
                print(f"📁 Ausgabe: {pcap_file}")
                subprocess.run(tcpdump_cmd, check=True)
                ts_end = int(time.time())

                # Verarbeitung der pcap-Datei mit Kontextmanager (schließt automatisch)
                with pyshark.FileCapture(pcap_file, display_filter="eth", keep_packets=False) as cap:
                    cap.set_debug()  # Falls Debug-Ausgaben gewünscht sind

                    for packet in cap:
                        print(f"Verarbeite Paket: {packet}")
                        if 'eth' in packet:
                            src_mac = packet.eth.src
                            dst_mac = packet.eth.dst
                            print(f"Source MAC: {src_mac} -> Destination MAC: {dst_mac}")
                            if 'vlan' in packet:
                                try:
                                    vlan_id = int(packet.vlan.id)
                                except Exception:
                                    vlan_id = 0
                                print(f"VLAN-ID: {vlan_id}")
                                if vlan_id < 1 or vlan_id > 4095:
                                    continue
                            else:
                                vlan_id = 0
                                print("Kein VLAN-Tag gefunden, aber Ethernet-Header erkannt.")

                            # Initialisiere Datenstrukturen, falls noch nicht vorhanden
                            if vlan_id not in vlan_stats:
                                vlan_stats[vlan_id] = {'broadcasts': 0, 'unicasts': 0}
                            if vlan_id not in vlan_mac_addresses:
                                vlan_mac_addresses[vlan_id] = set()
                            if vlan_id not in mac_counter:
                                mac_counter[vlan_id] = {}
                                mac_counter_unicast[vlan_id] = {}
                            if vlan_id not in loop_macs:
                                loop_macs[vlan_id] = set()

                            # Unterscheide zwischen Broadcast und Unicast
                            if dst_mac.lower() == 'ff:ff:ff:ff:ff:ff':
                                print(f"Broadcast Paket erkannt im VLAN {vlan_id}")
                                vlan_stats[vlan_id]['broadcasts'] += 1
                                loop_macs[vlan_id].add(src_mac)
                                mac_counter[vlan_id][src_mac] = mac_counter[vlan_id].get(src_mac, 0) + 1
                            else:
                                print(f"Unicast Paket erkannt im VLAN {vlan_id}")
                                vlan_stats[vlan_id]['unicasts'] += 1
                                mac_counter_unicast[vlan_id][src_mac] = mac_counter_unicast[vlan_id].get(src_mac, 0) + 1

                # Schreibe Ergebnisse in die CSV-Datei
                print("\nZusammenfassung der VLAN-Statistiken:")
                for vlan_id, stats in vlan_stats.items():
                    print(f"VLAN {vlan_id}: {stats['broadcasts']} Broadcast(s), {stats['unicasts']} Unicast(s)")

                print("\n📊 Anzahl der MAC-Adressen pro VLAN Broadcast:")
                for vlan_id, macs in mac_counter.items():
                    print(f"\n🔹 VLAN {vlan_id}:")
                    for mac, count in macs.items():
                        print(f"   ➡ MAC {mac} wurde {count}-mal gefunden")
                        with open(file_path, mode="a", newline="") as file:
                            writer = csv.writer(file, delimiter="\t")
                            writer.writerow([vlan_id, mac, count, ts_start, ts_end, intervall])
                            file.flush()  # ✨ Erzwingt sofortiges Schreiben auf die Festplatte
                            os.fsync(file.fileno())  # ✨ Synchronisiert mit dem Dateisystem
                        print("✅ Daten wurden in 'lastscan.csv' geschrieben.")

                print("\n📊 Anzahl der MAC-Adressen pro VLAN Unicast:")
                for vlan_id, macs in mac_counter_unicast.items():
                    print(f"\n🔹 VLAN {vlan_id}:")
                    for mac, count in macs.items():
                        print(f"   ➡ MAC {mac} wurde {count}-mal gefunden")

                # CSV-Datei bereinigen, wenn zu viele Zeilen vorhanden sind
                max_lines = 120000  # inkl. Header
                with open(file_path, "r") as f:
                    line_count = sum(1 for _ in f)
                print(f"Anzahl der Zeilen vor Bereinigung: {line_count}")
                if line_count > max_lines:
                    with open(file_path, "r") as f:
                        header = f.readline()
                        body = deque(f, maxlen=max_lines - 1)
                    with open(file_path, "w") as f:
                        f.write(header)
                        f.writelines(body)
                    print(f"CSV-Datei bereinigt: Letzte {max_lines} Zeilen wurden beibehalten.")
                else:
                    print("Keine Bereinigung nötig.")

                # Schreibe aktuellen Timestamp
                os.makedirs(os.path.dirname(file_path_timestamp), exist_ok=True)
                current_timestamp = int(datetime.now().timestamp())
                with open(file_path_timestamp, 'w') as f:
                    f.write(str(current_timestamp))
                print(f"Aktueller Timestamp {current_timestamp} wurde in {file_path_timestamp} geschrieben.")

            except subprocess.CalledProcessError as e:
                logging.error(f"Fehler beim tcpdump-Aufruf: {e}")
                print(f"❌ Fehler beim tcpdump: {e}. Nächster Zyklus in 10 Sekunden.")
            except Exception as e:
                logging.error(f"Fehler im Hauptzyklus: {e}")
                print(f"❌ Ein Fehler ist aufgetreten: {e}. Nächster Zyklus in 10 Sekunden.")
            # Warte kurz, bevor der nächste Zyklus startet
            time.sleep(5)
    except KeyboardInterrupt:
        print("Programm wird beendet...")
        sys.exit(0)

if __name__ == '__main__':
    main()
EOF

echo "broadcast.py created successfully in $DIR."

# Make broadcast.py executable
chmod +x "$TARGET_FILE"

# Deactivate the virtual environment
echo "Deactivating virtual environment..."
deactivate
echo "Virtual environment deactivated."

# Add tmpfs entry to /etc/fstab if not already present
FSTAB_ENTRY="tmpfs   /var/www/html/temp   tmpfs   rw,noatime,mode=1777,uid=pi,gid=www-data,size=100M   0   0"
if ! grep -q "/var/www/html/temp" /etc/fstab; then
  echo "Adding tmpfs entry to /etc/fstab..."
  echo "$FSTAB_ENTRY" >> /etc/fstab
  echo "fstab entry added."
else
  echo "fstab already contains an entry for /var/www/html/temp."
fi

# Ensure the mount point directory exists
if [ ! -d "/var/www/html/temp" ]; then
  echo "Creating mount point directory /var/www/html/temp..."
  mkdir -p /var/www/html/temp
  echo "Mount point directory created."
fi

# Create setup_files.sh in /home/broadcastdetector with the specified content
SETUP_FILES="$DIR/setup_files.sh"
echo "Creating file $SETUP_FILES..."
cat << 'EOF' > "$SETUP_FILES"
#!/bin/bash
# Erstelle die Datei intervall.txt mit dem Wert 10 und setze die Berechtigungen auf 777
echo "10" > /var/www/html/temp/intervall.txt
chmod 777 /var/www/html/temp/intervall.txt

# Erstelle die Datei timestamp.txt mit dem Wert 0 und setze die Berechtigungen auf 777
echo "0" > /var/www/html/temp/timestamp.txt
chmod 777 /var/www/html/temp/timestamp.txt
EOF

chmod +x "$SETUP_FILES"
echo "File setup_files.sh has been created in $DIR and made executable."

# Create /var/www/html/index.php with the provided HTML/PHP code
INDEX_FILE="/var/www/html/index.php"
echo "Creating file $INDEX_FILE..."
# Ensure the /var/www/html directory exists
mkdir -p /var/www/html
cat << 'EOF' > "$INDEX_FILE"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Broadcast Analysis Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f4f4f4;
      margin: 20px;
      color: #333;
    }
    h2, h3 {
      color: #444;
      border-bottom: 2px solid #ddd;
      padding-bottom: 5px;
      text-align: center;
    }
    table {
      width: 90%;
      border-collapse: collapse;
      margin-bottom: 20px;
      background: #fff;
      box-shadow: 0 2px 3px rgba(0,0,0,0.1);
      margin: auto;
    }
    table, th, td {
      border: 1px solid #ddd;
    }
    th, td {
      padding: 10px;
      text-align: left;
    }
    th {
      background-color: #f2f2f2;
    }
    ul {
      list-style: none;
      padding: 0;
      text-align: center;
    }
    ul li {
      background: #fff;
      margin: 5px auto;
      padding: 10px;
      border: 1px solid #ddd;
      width: fit-content;
    }
    /* Styling for the dropdown menus */
    form#intervalForm, form#dataForm {
      text-align: center;
      margin-bottom: 20px;
    }
    form#intervalForm select, form#dataForm select {
      font-size: 16px;
      padding: 8px;
      border: 1px solid #ccc;
      border-radius: 4px;
      background: #fff;
    }
    form#intervalForm input[type="submit"], form#dataForm input[type="submit"] {
      padding: 8px 15px;
      font-size: 16px;
      border: none;
      border-radius: 4px;
      background: #66cc66;
      color: #fff;
      cursor: pointer;
      margin-left: 10px;
    }
    form#intervalForm input[type="submit"]:hover, form#dataForm input[type="submit"]:hover {
      background: #5cb85c;
    }
    hr {
      margin: 30px 0;
    }
    .status p {
      text-align: center;
      padding: 10px;
      border-radius: 4px;
      font-size: 1.2em;
      margin-bottom: 20px;
    }
    .active {
      background-color: #d4edda;
      color: #155724;
      border: 1px solid #c3e6cb;
    }
    .inactive {
      background-color: #f8d7da;
      color: #721c24;
      border: 1px solid #f5c6cb;
    }
    .warning {
      background-color: #fff3cd;
      color: #856404;
      border: 1px solid #ffeeba;
    }
    
    iframe {
      display: block;
      margin: 0 auto 20px;
      border: none;
      max-width: 100%;
    }

    .news-help-button {
      display: inline-block;
      padding: 12px 25px;
      font-size: 18px;
      font-weight: bold;
      color: #fff;
      background-color: #007bff;
      border: none;
      border-radius: 8px;
      text-decoration: none;
      transition: background-color 0.3s ease, box-shadow 0.3s ease;
      margin: 15px auto;
    }

    .news-help-button:hover {
      background-color: #0056b3;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    }

    .reboot-button {
      display: inline-block;
      padding: 12px 25px;
      font-size: 18px;
      font-weight: bold;
      color: #fff;
      background-color: #dc3545;
      border: none;
      border-radius: 8px;
      text-decoration: none;
      transition: background-color 0.3s ease, box-shadow 0.3s ease;
      margin: 15px auto;
    }

    .reboot-button:hover {
      background-color: #b21f2d;
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    }
  </style>
</head>
<body>
<!-- Embed the iframe at the top -->
  <iframe src="https://itfourall.com/loopdedection.php" width="100%" height="250" style="border: none;"></iframe>

 <div style="text-align: center; margin: 20px 0;">
  <a href="https://itfourall.com/news-help.php" target="_blank" class="news-help-button">News/Help</a>
</div>

<?php
$file_path_timestamp = "/var/www/html/temp/timestamp.txt";
$service_status = "unknown"; // Default status

if (file_exists($file_path_timestamp)) {
    $file_timestamp = trim(file_get_contents($file_path_timestamp));
    $file_timestamp = (int)$file_timestamp;
    $current_time = time();
    
    if (($current_time - $file_timestamp) > 180) {
        $service_status = "inactive";
        echo '<div style="text-align: center; margin: 20px 0;">
                <form method="post" action="">
                  <button type="submit" name="reboot" class="reboot-button">Reboot</button>
                </form>
              </div>';
    } else {
        $service_status = "active";
    }
} else {
    $service_status = "Timestamp file not found";
}
?>

<div class="status">
  <?php if ($service_status == "active"): ?>
    <p class="active">Status: Service Active</p>
  <?php elseif ($service_status == "inactive"): ?>
    <p class="inactive">Status: Service Inactive</p>
  <?php else: ?>
    <p class="warning"><?php echo htmlspecialchars($service_status); ?></p>
  <?php endif; ?>
</div>

<!-- GET Form: Select the interval (value appended as GET parameter "data") -->
<form id="dataForm" method="get" action="">
    <label for="data">Interval:</label>
    <select id="data" name="data">
        <option value="0">Last Interval</option>
        <option value="10">10 seconds</option>
        <option value="15">15 seconds</option>
        <option value="20">20 seconds</option>
        <option value="25">25 seconds</option>
        <option value="30">30 seconds</option>
        <option value="35">35 seconds</option>
        <option value="40">40 seconds</option>
        <option value="45">45 seconds</option>
        <option value="50">50 seconds</option>
        <option value="55">55 seconds</option>
        <option value="60">1 minute</option>
        <option value="120">2 minutes</option>
        <option value="180">3 minutes</option>
        <option value="240">4 minutes</option>
        <option value="300">5 minutes</option>
        <option value="360">6 minutes</option>
        <option value="420">7 minutes</option>
        <option value="480">8 minutes</option>
        <option value="540">9 minutes</option>
        <option value="600">10 minutes</option>
        <option value="660">11 minutes</option>
        <option value="720">12 minutes</option>
        <option value="780">13 minutes</option>
        <option value="840">14 minutes</option>
        <option value="900">15 minutes</option>
        <option value="960">16 minutes</option>
        <option value="1020">17 minutes</option>
        <option value="1080">18 minutes</option>
        <option value="1140">19 minutes</option>
        <option value="1200">20 minutes</option>
        <option value="1260">21 minutes</option>
        <option value="1320">22 minutes</option>
        <option value="1380">23 minutes</option>
        <option value="1440">24 minutes</option>
        <option value="1500">25 minutes</option>
        <option value="1560">26 minutes</option>
        <option value="1620">27 minutes</option>
        <option value="1680">28 minutes</option>
        <option value="1740">29 minutes</option>
        <option value="1800">30 minutes</option>
    </select>
    <input type="submit" value="Apply">
    <p class="description" style="text-align: center; font-style: italic; margin-top: 10px;">
    This option allows you to select the desired time interval for data retrieval. When "Last Interval" is selected, only the most recent data from that interval is displayed. For example, if 1 minute is selected, then all data from the last minute will be output.
    </p>
</form>

<hr>

<!-- POST Form: Set the interval value in intervall.txt -->
<form id="intervalForm" method="post" action="">
    <label for="interval">Interval (seconds):</label>
    <select id="interval" name="interval">
        <?php
        // Options from 1 to 60, default is 10 seconds
        for ($i = 1; $i <= 60; $i++) {
            $selected = ($i == 10) ? "selected" : "";
            echo "<option value=\"$i\" $selected>$i</option>";
        }
        ?>
    </select>
    <input type="submit" name="submit_interval" value="Set Interval">
    <p class="description" style="text-align: center; font-style: italic; margin-top: 10px;">
        This setting defines the duration for which the network is scanned before data is analyzed.
        By default, the network is scanned for 10 seconds and the collected data is then processed.
    </p>
</form>

<?php
// If the POST form is submitted, write the selected value into intervall.txt
if (isset($_POST['submit_interval'])) {
    $selectedInterval = intval($_POST['interval']);
    $result = file_put_contents('/var/www/html/temp/intervall.txt', $selectedInterval);
    if ($result === false) {
        echo "<p>Error: Could not write the interval value to intervall.txt.</p>";
    }
}

// Read the current interval value directly from the text file and display it
$intervalFile = '/var/www/html/temp/intervall.txt';
if (file_exists($intervalFile)) {
    $interval_from_txt = trim(file_get_contents($intervalFile));
    echo "<h2>Current Interval Setting: $interval_from_txt seconds</h2>";
} else {
    echo "<h2>No interval set.</h2>";
}
?>

<?php
// Evaluate GET parameter for CSV analysis
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $data = isset($_GET['data']) ? trim($_GET['data']) : '';
    if ($data === "0" || empty($data)) {
        $data = 0;
    } else {
        $currentTimestamp = time();
        $selection = $currentTimestamp - $data;
    }
} else {
    $data = 0;
}

// Helper function: Display VLAN value professionally
function displayVlan($vlan) {
    return ($vlan == 0) ? "Untagged" : "VLAN $vlan";
}

$csv_file = "/var/www/html/temp/lastscan.csv";
if (!file_exists($csv_file)) {
    die("❌ File not found: Refresh page in 60 seconds." . $csv_file);
}

$vlan_data = [];
$total_broadcast = 0;
$rows = [];
$last_ende = null;
$last_intervall = null;

if (($handle = fopen($csv_file, "r")) !== false) {
    $header = fgetcsv($handle, 1000, "\t");
    $vlanIndex      = array_search("vlan", $header);
    $macIndex       = array_search("mac", $header);
    $anzahlIndex    = array_search("anzahl", $header);
    $startIndex     = array_search("start", $header);
    $endeIndex      = array_search("ende", $header);
    $intervallIndex = array_search("intervall", $header);

    if ($vlanIndex === false || $macIndex === false || $anzahlIndex === false || $endeIndex === false || $intervallIndex === false) {
        die("❌ Required columns are missing in the CSV file!");
    }
    
    while (($data_line = fgetcsv($handle, 1000, "\t")) !== false) {
        $rows[] = $data_line;
        $last_ende = trim($data_line[$endeIndex]);
        $last_intervall = trim($data_line[$intervallIndex]);
    }
    fclose($handle);
}

if ($data == 0 && !empty($last_ende)) {
    $rows = array_filter($rows, function($row) use ($endeIndex, $last_ende) {
        return trim($row[$endeIndex]) === $last_ende;
    });
} elseif ($data != 0 && isset($selection)) {
    $rows = array_filter($rows, function($row) use ($endeIndex, $selection) {
        return (int) trim($row[$endeIndex]) >= $selection;
    });
}

foreach ($rows as $data_line) {
    $vlan = trim($data_line[$vlanIndex]);
    $mac  = trim($data_line[$macIndex]);
    $anzahl = (int) trim($data_line[$anzahlIndex]);
    $current_ende = trim($data_line[$endeIndex]);

    if (strtolower($vlan) === "untagged") {
        $vlan = 0;
    } else {
        $vlan = (int)$vlan;
    }

    if (!isset($vlan_data[$vlan])) {
        $vlan_data[$vlan] = [
            "broadcast" => [],
            "total_broadcast" => 0
        ];
    }

    $vlan_data[$vlan]["broadcast"][$mac] = ($vlan_data[$vlan]["broadcast"][$mac] ?? 0) + $anzahl;
    $vlan_data[$vlan]["total_broadcast"] += $anzahl;
    $total_broadcast += $anzahl;
}
?>

<h2>📊 Total Broadcast Packets per VLAN</h2>
<table>
  <tr>
    <th>VLAN</th>
    <th>Total Broadcast</th>
  </tr>
  <?php
  ksort($vlan_data, SORT_NUMERIC);
  foreach ($vlan_data as $vlan => $data) {
      echo "<tr>";
      echo "<td>" . displayVlan($vlan) . "</td>";
      echo "<td>{$data['total_broadcast']}</td>";
      echo "</tr>";
  }
  ?>
</table>

<h2>📌 Total Number of Broadcast Packets</h2>
<ul>
  <li>📡 Total Broadcasts: <strong><?php echo $total_broadcast; ?></strong></li>
</ul>

<h2>🔥 Top 3 MAC Addresses per VLAN</h2>
<?php
foreach ($vlan_data as $vlan => $data) {
    arsort($data["broadcast"]);
    echo "<h3>" . displayVlan($vlan) . "</h3>";
    echo "<table>";
    echo "<tr><th>MAC Address</th><th>Count</th></tr>";
    $top_macs = array_slice($data["broadcast"], 0, 3, true);
    foreach ($top_macs as $mac => $anzahl) {
        echo "<tr><td>$mac</td><td>$anzahl</td></tr>";
    }
    echo "</table>";
}

$all_macs = [];
foreach ($vlan_data as $vlan => $data) {
    foreach ($data["broadcast"] as $mac => $anzahl) {
        $all_macs["$vlan|$mac"] = $anzahl;
    }
}
arsort($all_macs);
$top_10_global = array_slice($all_macs, 0, 10, true);
?>
<h2>🔥 MAC Addresses with High Traffic (Top 10)</h2>
<table>
  <tr>
    <th>VLAN</th>
    <th>MAC Address</th>
    <th>Count</th>
  </tr>
  <?php
  foreach ($top_10_global as $key => $anzahl) {
      list($vlan, $mac) = explode("|", $key);
      echo "<tr><td>" . displayVlan($vlan) . "</td><td>$mac</td><td>$anzahl</td></tr>";
  }
  ?>
</table>

<h2>📋 All MAC Addresses by VLAN (Sorted Ascending)</h2>
<table>
  <tr>
    <th>VLAN</th>
    <th>MAC Address</th>
    <th>Count</th>
  </tr>
  <?php
  foreach ($vlan_data as $vlan => $data) {
      ksort($data["broadcast"]);
      foreach ($data["broadcast"] as $mac => $anzahl) {
          echo "<tr><td>" . displayVlan($vlan) . "</td><td>$mac</td><td>$anzahl</td></tr>";
      }
  }
  ?>
</table>

<?php
// If the reboot button was pressed, execute the command
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reboot'])) {
    $output = [];
    $return_var = 0;
    exec("sudo /sbin/shutdown -r now 2>&1", $output, $return_var);

    if ($return_var !== 0) {
        $message = "Error during restart:<br>" . nl2br(htmlspecialchars(implode("\n", $output)));
    } else {
        $message = "Restart initiated.";
    }
}
?>
<form method="post" action="">
    <button type="submit" name="reboot" class="reboot-button">Reboot</button>
</form>

</body>
</html>
EOF

echo "index.php created successfully in /var/www/html."

# Add sudoers entry to allow www-data to execute the shutdown command without password
SUDOERS_FILE="/etc/sudoers.d/allow_shutdown"
if [ ! -f "$SUDOERS_FILE" ]; then
  echo "Creating sudoers file to allow shutdown command without password for www-data..."
  echo "www-data ALL=NOPASSWD: /sbin/shutdown -r now" > "$SUDOERS_FILE"
  chmod 440 "$SUDOERS_FILE"
  echo "Sudoers entry created at $SUDOERS_FILE."
else
  echo "Sudoers file $SUDOERS_FILE already exists."
fi

# Make all files in /home/broadcastdetector executable
echo "Making all files in $DIR executable..."
chmod +x "$DIR"/*

# Change ownership of /var/www/html to pi:www-data
echo "Changing ownership of /var/www/html to root:www-data..."
chown pi:www-data -R /var/www/html
rm /var/www/html/index.html
# Add cron jobs as root
echo "Adding cron jobs as root..."
#(crontab -l 2>/dev/null; echo "@reboot sleep 15 && /home/broadcastdetector/setup_files.sh") | crontab -
#(crontab -l 2>/dev/null; echo "@reboot sleep 20 && chown root:www-data -R /var/www/html") | crontab -
#(crontab -l 2>/dev/null; echo "@reboot sleep 25 && /home/broadcastdetector/venv/bin/python /home/broadcastdetector/broadcast.py") | crontab -

# Definiere die gewünschten Cronjobs
CRON1="@reboot sleep 15 && /home/broadcastdetector/setup_files.sh"
CRON2="@reboot sleep 20 && chown root:www-data -R /var/www/html"
CRON3="@reboot sleep 25 && /home/broadcastdetector/venv/bin/python /home/broadcastdetector/broadcast.py"

# Lade die aktuelle Crontab in eine temporäre Datei (erstellt diese, falls nicht vorhanden)
TMP_CRON=$(mktemp)
crontab -l 2>/dev/null > "$TMP_CRON"

# Funktion zum Hinzufügen, falls nicht vorhanden
add_cronjob() {
    local job="$1"
    if ! grep -Fxq "$job" "$TMP_CRON"; then
        echo "$job" >> "$TMP_CRON"
        echo "Cronjob hinzugefügt: $job"
    else
        echo "Cronjob existiert bereits: $job"
    fi
}

# Cronjobs prüfen und ggf. hinzufügen
add_cronjob "$CRON1"
add_cronjob "$CRON2"
add_cronjob "$CRON3"

# Aktualisiere die Crontab
crontab "$TMP_CRON"
rm "$TMP_CRON"


echo "Cron jobs added."
echo "Full setup completed successfully."
echo -e "\n\033[1;34m🔄 Please reboot your system manually.\033[0m"
echo -e "\033[1;32mAfter rebooting, open your default web browser.\033[0m"
echo -e "\033[1;33mThen navigate to:\033[0m"
echo -e "\033[1;36mhttp://YourIP\033[0m\n"
