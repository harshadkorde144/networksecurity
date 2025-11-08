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

