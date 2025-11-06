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
