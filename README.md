Follow the installation instructions at https://itfourall.com/broadcast.php
📡 BroadcastDetector
Real-time detection of network loops, ARP spoofing, and broadcast storms.
Monitor and protect your network from invisible Layer 2 threats using a lightweight, passive analysis tool.

🔍 What is BroadcastDetector?
BroadcastDetector is a Linux-based tool designed to detect:

🌀 Switch & Network Loops

⚠️ ARP Spoofing Attacks

📡 Broadcast Storms & Anomalies

🔁 Loop Protection Failures

It passively listens to broadcast traffic (via tcpdump) and analyzes it using pyshark. The tool identifies suspicious patterns in real time and helps sysadmins and network engineers take action before the network becomes unstable.

✅ Key Features
Real-time broadcast traffic analysis

ARP spoofing detection & alerting

Loop detection (switch & network level)

CSV-based logging (MAC, VLAN, timestamp, frequency)

Web-based dashboard for live insights

Designed for Raspberry Pi 4/5 and Debian systems

Completely local – no external/cloud dependencies

💻 Live Demo / Installation
Try the live dashboard or install it on your own device:

🌐 Web & Docs:
https://itfourall.com/broadcast.php

🖥️ Raspberry Pi Image:
Pre-installed & ready-to-use image available

⚙️ Manual Install:
Clone the repo and run the auto-installer:

bash
Kopieren
Bearbeiten
wget https://raw.githubusercontent.com/IT-4-ALL/BroadcastDetector/main/install.sh
chmod +x install.sh
sudo ./install.sh
📂 Use Cases
HomeLab or enterprise LAN monitoring

Diagnosing broadcast loops and VLAN misconfigurations

Detecting rogue switches or devices causing traffic storms

Enhancing Layer 2 visibility in complex network environments

🔒 Privacy by Design
All traffic is analyzed locally. Nothing is sent to the cloud. You retain full control over your data.

🛠 Tech Stack
Python 3.11+

tcpdump & pyshark

Apache2 + PHP (for dashboard)

Raspberry Pi OS / Debian 12 (Bookworm)

🙌 Contributions & Feedback
Feedback, issues, and contributions are welcome!
Have ideas for detecting more network anomalies? Open a PR or start a discussion.


