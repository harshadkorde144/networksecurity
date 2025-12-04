# Week 1: Setting Up the Virtual Network Lab

## Goal
The main aim of this week is to establish a small internal network using OPNsense as a firewall/router along with Kali Linux and Ubuntu virtual machines. The focus is on ensuring that devices can communicate with the OPNsense LAN interface and receive IP addresses automatically through DHCP.

## Virtual Machines Overview
| VM Name  | Network Adapter 1 | Network Adapter 2 (Optional) |
|----------|-----------------|-----------------------------|
| OPNsense | Internal Network | NAT for Internet access    |
| Kali     | Internal Network | NAT (if needed)            |
| Ubuntu   | Internal Network | NAT (if needed)            |

> Note: All VMs connected to the internal network can communicate with each other.  

## Network Configuration Details
- **LAN Interface (em0)** on OPNsense: 192.168.1.1/24  
- **WAN Interface (em1)** on OPNsense: gets IP via DHCP from NAT (example: 10.0.3.x)  
- **DHCP Range for LAN clients**: 192.168.1.10 – 192.168.1.100  
- **Default Gateway**: 192.168.1.1  
- **DNS Server**: 8.8.8.8  

## Verification
- Kali Linux obtained an IP automatically from the LAN DHCP server (example: 192.168.1.100).  
- Ping test from Kali to OPNsense LAN gateway is successful (`ping 192.168.1.1`).  

## Screenshots to Include
1. **OPNsense Dashboard** – Shows LAN and WAN IP addresses.  
2. **LAN DHCP Settings** – Screenshots of DHCP configuration page.  
3. **Kali Terminal** – Displaying the obtained IP address and ping test results.  =

---

**Summary:**  
By the end of Week 1, the internal network is functional. OPNsense is running as the LAN gateway and DHCP server, and Kali Linux is able to communicate within the network. This setup forms the foundation for all the upcoming lab exercises.


# Week 2 — Network Scanning & Mapping (Nmap)

## Objective
Perform network discovery and service enumeration on the lab's internal network to build a baseline of live hosts, open ports and running services. These results will be used later for IDS/firewall testing and documentation.

---

## Environment
- **OPNsense (LAN gateway):** 192.168.1.1  
- **Kali Linux (scanner):** 192.168.1.10  
- **Subnet:** 192.168.1.0/24  
- **Tool:** nmap (Kali Linux)

---

## Exact commands executed
Run these on the Kali VM. Outputs were saved under `Week2/scans/`.

```bash
# 1) Discover live hosts on the LAN
sudo nmap -sn 192.168.1.0/24 -oN Week2/scans/lan_ping_scan.nmap

# 2) Enumerate services and versions on discovered hosts (save text + xml + gnmap)
sudo nmap -sV 192.168.1.1 192.168.1.10 -oA Week2/scans/lan_service_scan 
```
#  Week 3 – Firewall Configuration & Traffic Filtering (OPNsense)

## Objective
In this week, the goal was to configure firewall security rules in **OPNsense** to monitor and block malicious traffic, set up network aliases, and test firewall protection using **Kali Linux**.

---

## 🧩 Steps Performed

### 1. OPNsense Dashboard Overview
- Verified that both LAN (`192.168.1.1/24`) and WAN (`10.0.3.x`) interfaces were configured correctly.
- Ensured LAN connection with the Kali VM using internal network mode.

📷 **Screenshot:** `1_dashboard.png`

---

### 2. Created Aliases
- Added aliases to simplify firewall rule management:
  - **SUS_IPS:** Suspicious host IPs (e.g., `10.0.2.99`)
  - **SUS_PORTS:** Common suspicious ports (`23, 445, 3389`)
  - **Internal_LAN:** Internal network range (`192.168.1.0/24`)

📷 **Screenshot:** `2_aliases.png`

---

### 3. Configured Firewall Rules (LAN)
- Added rules to **block** suspicious hosts and ports.
- Rule Order:
  1. Block traffic from `SUS_IPS` to `LAN net`
  2. Block suspicious ports (`SUS_PORTS`)
  3. Allow remaining LAN to any (default rule)

📷 **Screenshot:** `3_rules_lan.png`  
📷 **Screenshot:** `4_rule_edit.png`

---

### 4. Performed Network Scanning
- Used **Nmap** from Kali to test firewall detection and filtering:
  ```bash
  sudo nmap 192.168.1.1
-Verified open ports (22, 53, 443) and confirmed blocked access as per rules.

📷 **Screenshot:** `5_nmap_scan.png`

---

### 5. Checked Firewall Logs

  1. Viewed logs under Firewall → Log Files → Live View.

  2. Confirmed blocked traffic attempts and verified rule actions.

📷 **Screenshot:** `6_firewall_logs.png`

---

### 6. Verified Network Connectivity

Checked Interfaces → Overview to confirm:
 ```bash
LAN: 192.168.1.1/24

Kali VM: 192.168.1.10
```
Both interfaces were active and communicating properly.

📷 **Screenshot:** `7_interfaces.png`

---

### 🧠 Learning Outcomes

- Understood creation and use of aliases in OPNsense.
- Learned how to apply and test firewall filtering rules.
- Practiced network scanning and log verification.
- Gained hands-on experience in blocking suspicious traffic in a virtual lab.

Week 4: Wireshark Network Traffic Analysis
Experiment Objective
Use Wireshark to understand the difference between normal network traffic and malicious/suspicious traffic and analyze OPNsense firewall behavior.

Virtual Machines Used
VM Name	Role	Network Interface	IP Address
Kali Linux	Attacker/Analyst	eth0	192.168.1.10
OPNsense	Firewall/Target	LAN Interface	192.168.1.1
Network Configuration
LAN Subnet: 192.168.1.0/24

OPNsense LAN IP: 192.168.1.1

Kali Linux IP: 192.168.1.10 (DHCP assigned)

Target IP for Scanning: 192.168.1.1 (OPNsense firewall)

Step-by-Step Procedure
Step 1: Wireshark Initialization
Open Wireshark in Kali Linux with root permissions

Select active network interface (eth0)

Step 2: Capture Configuration
Go to Capture Options

Select Interface: eth0

Enable Promiscuous Mode ✅

Click Start Capturing 🔴

Step 3: Capture Normal Traffic
Commands Executed:

text
ping 8.8.8.8
Open browser → google.com

Observed in Wireshark:

ICMP packets (ping)

DNS queries

TCP handshake (SYN, ACK)

HTTP/HTTPS requests

Screenshot: normal_traffic.png

Step 4: Generate Malicious/Suspicious Traffic (Attack Simulation)
NMAP Scan Command:

text
sudo nmap 192.168.1.1
Observed in Wireshark:

SYN flood like repeated TCP SYN packets

ICMP echo requests

Different port scans (22, 80, 443, etc.)

Screenshot: malicious_traffic.png

Step 5: Analyze the Captures
Wireshark Display Filters:

Normal traffic:

text
http || icmp
Suspicious traffic:

text
tcp.flags.syn==1 && tcp.flags.ack==0
Comparison Table:

Type	Source	Destination	Protocol	Notes
Normal	192.168.1.10	8.8.8.8	ICMP	Ping
Malicious	192.168.1.10	192.168.1.1	TCP	Port Scan
Screenshot: traffic_analysis.png

Step 6: Save and Export
Stop capturing (🔴)

Save as → week4_capture.pcapng

Upload this file to GitHub for documentation

Screenshot List (GitHub Folder /Week4)
text
Week4/
 ├── 1_wireshark_start.png
 ├── 2_normal_ping_testing.png
 ├── 3_normal_traffic.png
 ├── 4_sending_malicious_traffic.png
 ├── 5_malicious_traffic.png
 ├── traffic_analysis.png
 └── week4_capture.pcapng
Key Observations
Normal Traffic: Regular patterns, established connections, expected protocols

Malicious Traffic: Multiple rapid connection attempts, port scanning patterns, unusual packet flags

Firewall Response: OPNsense shows different behavior on suspicious traffic

Precautions
This is for educational purposes only

Test only on your own network

Maintain legal boundaries

Expected Results
Wireshark analysis should show clear differences between normal and malicious traffic, which will help improve understanding of network security monitoring.

Note: This is an important step in learning practical network security and intrusion detection.




✅ 1) Snort Start Screenshot (Snort चलाते समय)
Command (Terminal 1):
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast

Screenshot में क्या दिखना चाहिए:

✔ Snort modules load होते हुए
✔ "Commencing packet processing"
✔ नीचे alerts live आते हुए

📸 File name suggestion:
1_snort_running.png

✅ 2) ICMP Ping Attack Test (Snort Alert: ICMP Ping Detected)
Command (Terminal 2):
ping -c 3 192.168.1.1

Expected Snort alert:
[**] [1:100001:1] ICMP Ping Detected


📸 Output Screenshots:

Terminal 2 में ping का output
→ 2_ping_test_output.png

Terminal 1 में Snort alert दिखाई दे
→ 3_snort_icmp_alert.png

✅ 3) Nmap SYN Scan Test (Snort Alert: Possible Nmap SYN Scan)
Command (Terminal 2):
sudo nmap -sS 192.168.1.1

Expected Snort alert:
[**] [1:100002:1] Possible Nmap SYN Scan


📸 Output Screenshots:

Nmap scan terminal output
→ 4_nmap_scan_output.png

Snort terminal showing SYN Scan alert
→ 5_snort_syn_alert.png

📦 4) local.rules File Screenshot
Command:
sudo nano /etc/snort/rules/local.rules


📸 Screenshot name
6_local_rules_file.png

📦 5) Snort Config Test Screenshot
Command:
sudo snort -T -c /etc/snort/snort.lua


Expected output:

Snort successfully validated the configuration


📸 Screenshot name
7_snort_validation.png

📝 Summary for Week 5 (You will need these points in your README):
✔ Snort Installed
✔ Custom Detection Rules Created

ICMP ping rule

Nmap SYN scan rule

✔ Alerts Captured

ICMP alert

SYN scan alert

❓अगर चाहो तो मैं अभी Week 5 का पूरा ready-made README.md भी बना दूँ।

बस बोल दो!

You said:
yes
ChatGPT said:

Great Harshad! नीचे तुम्हारे Week-5 Snort IDS Practical के लिए पूरा तैयार किया हुआ README.md दे रहा हूँ —
इसको तुम सीधे GitHub पर copy-paste कर सकते हो।
(Formatting, headings, explanation सब बिल्कुल perfect है.)

✅ WEEK-5 – Intrusion Detection System using Snort (README.md Complete)
# WEEK-5 – Intrusion Detection System using Snort

This practical demonstrates how to install, configure, and run **Snort IDS** to detect suspicious activities such as **ICMP ping probes** and **Nmap SYN scans**.  
We created custom rules in `local.rules` and verified alerts in real time.

---

## 📌 1. Environment Setup

### **Snort Version**
Snort++ 3.9.x running on Kali Linux (VirtualBox NAT/Bridge).

### **Network Interface**
Snort is listening on:


eth0 – 192.168.1.10/24


---

## 📌 2. Snort Configuration Changes

### Updated `/etc/snort/snort.lua`

RULE_PATH = "/etc/snort/rules"

ips =
{
    variables = default_variables,

    rules =
    {
        RULE_PATH .. "/local.rules"
    }
}


✔ This ensures Snort loads our custom rules.

📌 3. Custom Rules (local.rules)

Path:

/etc/snort/rules/local.rules

Added Rules:
alert icmp any any -> any any (
    msg:"ICMP Ping Detected";
    sid:100001;
    gid:1;
)

alert tcp any any -> any any (
    msg:"Possible Nmap SYN Scan";
    flags:S;
    sid:100002;
    gid:1;
)


✔ First rule detects ICMP echo requests
✔ Second rule detects TCP SYN scans (used by Nmap)

📌 4. Validate Snort Configuration

Command:

sudo snort -T -c /etc/snort/snort.lua


Expected Output:

Snort successfully validated the configuration

📌 5. Running Snort in IDS Mode

Command:

sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast


✔ Snort starts listening on eth0
✔ Shows “Commencing packet processing”

📌 6. Attack Simulation & Alerts
✅ A) ICMP Ping Test

Command:

ping -c 3 192.168.1.1


Expected Snort Alert:

[**] [1:100001:1] ICMP Ping Detected


📸 Screenshot:

Ping output

Snort alert window

✅ B) Nmap SYN Scan Test

Command:

sudo nmap -sS 192.168.1.1


Expected Snort Alert:

[**] [1:100002:1] Possible Nmap SYN Scan


📸 Screenshot:

Nmap output

Snort alert window

📸 7. Screenshots Required (for report)

Snort running (snort -c … -A alert_fast)

Ping test output

Snort ICMP alert popup

Nmap SYN scan output

Snort SYN scan alert

local.rules file screenshot

Snort validation (snort -T) screenshot

📌 8. Conclusion

In this practical we:

✔ Installed and configured Snort IDS
✔ Created custom detection rules
✔ Detected ICMP ping attempts
✔ Detected Nmap SYN scans
✔ Verified alerts in real-time

Snort successfully identified suspicious activity using signature-based detection, demonstrating its usefulness for network security monitoring.
