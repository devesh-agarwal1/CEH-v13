
## Module 08: Sniffing - Key Concepts and Notes

This module covers the concepts of network sniffing, various sniffing techniques, tools used for sniffing, and essential countermeasures to detect and prevent sniffing attacks.

### Learning Objectives

-   Summarize Sniffing Concepts.
-   Demonstrate Different Sniffing Techniques.
-   Use Sniffing Tools.
-   Explain Sniffing Countermeasures.

### 1. Sniffing Concepts

What is Packet Sniffing?

The process of monitoring and capturing all data packets passing through a given network using a software application or hardware device. It allows an attacker to observe and access the entire network traffic.

**How a Sniffer Works:**

-   A sniffer turns the Network Interface Card (NIC) of a system into **promiscuous mode**.
-   In promiscuous mode, the NIC listens to all data transmitted on its segment, regardless of the destination MAC address.
-   Sniffing programs turn off the filter normally employed by Ethernet NICs.
-   Sniffers can capture sensitive information like passwords (Telnet, FTP), email traffic, web traffic, DNS traffic, chat sessions, and account information (if not encrypted).

#### Network Environments and Sniffing

-   **Hub-based Networks (Shared Ethernet):**
    -   All machines on the segment receive all packets.
    -   Sniffing is **passive** and thus **difficult to detect**.
    -   Hubs are outdated; most modern networks use switches.
-   **Switched Ethernet Networks:**
    -   Switches maintain a MAC address table (CAM table) to send packets only to the intended destination port.
    -   Sniffing is **more challenging** but still possible using **active sniffing techniques**.

#### Sniffing in the Data Link Layer (OSI Model)

-   Sniffers primarily operate at the Data Link layer (Layer 2) of the OSI model to capture frames.
-   Upper OSI layers are not aware of the sniffing.

#### Hardware Protocol Analyzers

-   Devices that capture traffic passing through a network segment.
-   Capture data, decode it, and analyze its content according to predetermined rules.
-   Examples: Xgig 1000, SierraNet M1288.

#### Switched Port Analyzer (SPAN) Port / Port Mirroring

-   A Cisco switch feature where traffic from one or more source ports is mirrored to a destination (SPAN) port.
-   Allows a network administrator to monitor traffic from multiple ports simultaneously.
-   Attackers can compromise a SPAN port to sniff traffic.

#### Wiretapping and Lawful Interception

-   **Wiretapping:** Monitoring telephone or Internet conversations.
    -   Methods: Official tapping of lines, unofficial tapping, recording conversations, direct line wiretap, radio wiretap.
    -   Types: Active (MITM, alters traffic) and Passive (sniffing/eavesdropping, monitoring/recording traffic).
-   **Lawful Interception (LI):** Legally intercepting communication data for surveillance purposes by law enforcement agencies.

### 2. Sniffing Techniques

#### Types of Sniffing (Revisited)

-   **Passive Sniffing:**
    -   Captures and monitors packets without sending any additional data packets.
    -   Used in hub environments (common collision domains).
    -   Provides significant stealth advantages.
    -   Can be achieved by compromising physical security or installing Trojans with sniffing capability.
-   **Active Sniffing:**
    -   Actively injects traffic into a switched LAN to discover traffic.
    -   More difficult to perform and easier to detect than passive sniffing.

#### Active Sniffing Techniques

-   **MAC Flooding:**
    
    -   Bombards a switch with fake MAC addresses until its CAM (Content Addressable Memory) table overflows.
    -   When the CAM table is full, the switch enters "fail-open mode" and acts like a hub, broadcasting all packets to all ports.
    -   This allows the attacker in promiscuous mode to sniff all traffic.
    -   Tools like `macof` (from `dsniff` suite) are used.
-   **Switch Port Stealing:**
    
    -   Attacker floods the switch with forged ARP packets that claim the target's IP address and MAC address are associated with the attacker's port.
    -   The switch updates its CAM table, redirecting target traffic to the attacker's port.
    -   Can lead to DoS if the switch's CAM table is overloaded.
-   **DHCP Attacks:**
    
    -   **DHCP Starvation Attack:** Attacker floods the DHCP server with numerous DHCP requests using spoofed MAC addresses, exhausting the pool of available IP addresses. This results in a DoS, preventing legitimate users from obtaining IP addresses. Tools like `yersinia` are used.
    -   **Rogue DHCP Server Attack:** An attacker sets up an unauthorized DHCP server to issue IP addresses to clients. This allows the attacker to control network configurations (DNS, gateway) for victims, redirecting traffic through the rogue server. Tools like `mitm6`, `Ettercap`, `Gobbler` are used.
-   **ARP Poisoning / ARP Spoofing Attack:**
    
    -   ARP (Address Resolution Protocol) maps IP addresses to MAC addresses. It is stateless.
    -   Attackers send fake ARP reply messages to target hosts and the gateway, associating the attacker's MAC address with the gateway's IP, and vice-versa.
    -   This makes traffic flow through the attacker's machine (Man-in-the-Middle).
    -   **Threats of ARP Poisoning:** Packet Sniffing, Session Hijacking, VoIP Call Tapping, Manipulating Data, Data Interception, Connection Hijacking, Connection Resetting, Stealing Passwords, DoS Attack.
    -   Tools: `arpspoof`, `Ettercap`, `RITM`, `Habu`, `ARP-GUARD`.
-   **MAC Spoofing / Duplicating:**
    
    -   Attacker changes their MAC address to impersonate a legitimate user or device on the network.
    -   Can be used to bypass MAC-based filtering or gain unauthorized access.
    -   Tools: `MAC Address Changer`, `SMAC`, `Technitium MAC Address Changer`.
-   **IRDP Spoofing (ICMP Router Discovery Protocol Spoofing):**
    
    -   Attacker sends spoofed IRDP router advertisement messages to mislead hosts into using the attacker's system as their default gateway.
    -   Allows sniffing, MITM, and DoS attacks.
-   **VLAN Hopping:**
    
    -   Attack technique to gain unauthorized access to resources on a different VLAN.
    -   **Methods:**
        -   **Switch Spoofing:** Attacker's machine pretends to be a trunking switch (e.g., using DTP - Dynamic Trunking Protocol) to negotiate a trunk link with the legitimate switch, then gains access to all VLANs.
        -   **Double Tagging:** Attacker adds an extra 802.1Q tag to the Ethernet frame. The outer tag is processed by the first switch, which then forwards the frame to the target VLAN based on the inner tag, bypassing VLAN segmentation.
-   **STP Attack (Spanning Tree Protocol Attack):**
    
    -   Attacker introduces a rogue switch with a lower STP priority into the network.
    -   This forces the legitimate switches to reconfigure the network topology, making the rogue switch the "root bridge."
    -   All traffic then flows through the attacker's rogue switch, allowing sniffing.

### 3. Sniffing Tools

System administrators use these for network monitoring, but attackers misuse them.

-   **Wireshark:**
    -   A powerful, widely used network protocol analyzer.
    -   Captures and interactively displays packet data.
    -   Features: WinPcap capture, supports many protocols, filters for customized data display (e.g., `tcp.port==23`, `ip.addr==192.168.1.1`).
    -   Can "Follow TCP Stream" to see cleartext data of a session.
-   **Capsa Portable Network Analyzer:**
    -   Portable network performance analysis and diagnostics tool.
    -   Packet capture and analysis capabilities, helps in detecting ARP poisoning/flooding.
-   **OmniPeek:**
    -   Network analyzer for real-time visibility and expert analysis.
    -   Provides drill-down, performance bottlenecks, and a map of IP addresses.
-   **Other Tools:** RITA (Real Intelligence Threat Analytics), Observer Analyzer, PRTG Network Monitor, Network Performance Monitor, Xplico.

### 4. Sniffing Countermeasures

To defend against sniffing, a multi-layered approach is essential.

#### General Countermeasures

-   **Restrict Physical Access:** Prevent direct connection of sniffers.
-   **End-to-End Encryption:** Encrypt confidential information (e.g., SSH, SSL/TLS, PGP, S/MIME, VPN).
-   **Use Secure Protocols:** Use HTTPS instead of HTTP, SFTP instead of FTP, encrypted email protocols (S/MIME) instead of SMTP/POP/IMAP for sensitive data.
-   **Static ARP Tables:** Manually add MAC addresses to the ARP cache to prevent spoofing.
-   **Disable Unnecessary Services/Broadcasts:** Turn off network identification broadcasts.
-   **Use IPv6:** IPv6 has built-in IPsec, offering better security.
-   **Switch to a Hub/Switch:** For intended recipient only (Hubs are outdated, use secure switches).
-   **Randomize MAC Addresses:** Makes MAC spoofing harder to track.
-   **Monitor for Promiscuous Mode:** Detect if NICs are running in promiscuous mode.
-   **Access Control Lists (ACLs):** Restrict access to trusted IP addresses.
-   **Change Default Passwords/SSIDs:** For network devices.
-   **Avoid unsecured/open Wi-Fi networks.**
-   **Network Segmentation (VLANs):** Divide the network into smaller, manageable segments to limit sniffers' scope.
-   **Regular Audits:** Regularly audit network traffic for unusual patterns.
-   **IDS/IPS:** Use Intrusion Detection/Prevention Systems to detect sniffing or malicious activities.
-   **Firewalls:** Implement firewall rules to block unauthorized traffic.
-   **DLP (Data Loss Prevention):** Prevent sensitive data exfiltration.

#### Countermeasures for Specific Attacks

-   **Defend against MAC Attacks (Flooding, Spoofing):**
    
    -   **Port Security (Cisco Switches):** Limit the number of MAC addresses per port, sticky MAC, aging time.
    -   **DHCP Snooping Binding Table:** Filters untrusted DHCP messages and builds a binding table of trusted MAC-IP pairs.
    -   **Dynamic ARP Inspection (DAI):** Validates ARP packets against the DHCP snooping binding table.
    -   **IP Source Guard:** Filters IP traffic based on DHCP snooping binding table.
    -   **Encryption (WPA2/WPA3):** Secure wireless networks.
-   **Defend against DHCP Starvation and Rogue Server Attacks:**
    
    -   **DHCP Snooping:** Configures switch ports to distinguish trusted DHCP messages from untrusted ones.
    -   **Port Security:** Limits MAC addresses on ports to prevent starvation.
    -   **Dynamic ARP Inspection (DAI):** Works with DHCP Snooping to validate ARP packets.
    -   **Configure Trust on Switch Ports:** Mark legitimate DHCP server ports as trusted.
    -   **MAC Limiting Configuration on Juniper Switches:** Limit MAC addresses on interfaces.
    -   **DHCP Filtering on Oracle Switches:** Ensure DHCP traffic is from trusted sources.
-   **Defend against ARP Poisoning:**
    
    -   **Dynamic ARP Inspection (DAI):** Validates ARP packets on VLANs.
    -   **Static ARP Entries:** Manually configure static ARP entries.
    -   **Implement IPS/Firewalls:** To detect and block spoofed ARP traffic.
    -   **ARP Spoofing Detection Tools:** Capasa, Wireshark filters, OpUtils, netspionage, NetProbe, ARP-GUARD.
-   **Defend against MAC Spoofing:**
    
    -   **DHCP Snooping Binding Table, Dynamic ARP Inspection, IP Source Guard:** (As above)
    -   **Encryption:** Use WPA2/WPA3.
    -   **Retrieval of MAC Address:** Always retrieve MAC address from NIC directly instead of retrieving it from OS.
    -   **IEEE 802.1X Suites (NAC):** Port-based network access control.
-   **Defend against VLAN Hopping:**
    
    -   **Defend against Switch Spoofing:** Explicitly configure access ports (no trunk negotiation).
    -   **Defend against Double Tagging:** Specify the default VLAN, ensure native VLANs on trunk ports are changed to an unused VLAN ID (`switchport trunk native vlan 999`), and explicitly tag native VLANs.
    -   **Use Private VLANs:** Isolate ports from each other.
    -   **Regularly Audit and Monitor VLAN Configurations.**
-   **Defend against STP Attacks:**
    
    -   **BPDU Guard:** Enables protection on ports to discard BPDUs from untrusted devices, preventing root bridge changes.
    -   **Root Guard:** Protects the root bridge and ensures that it remains the designated root.
    -   **Loop Guard:** Prevents bridging loops.
    -   **UDLD (Unidirectional Link Detection):** Detects unidirectional links.
    -   **Deploy PortFast:** Speeds up port transition to listening/learning states.
    -   **Regular Updates:** Update firmware and software on network devices.
    -   **Restrict Network Access:** Limit physical access.
    -   **Network Segmentation.**
-   **Defend against DNS Spoofing:**
    
    -   **Implement Domain Name System Security Extensions (DNSSEC):** Secures DNS with digital signatures.
    -   **Use a Secure Socket Layer (SSL) for securing traffic.**
    -   **Resolve DNS Queries to Local DNS Server.**
    -   **Block DNS Requests to External Servers.**
    -   **Configure Firewall to Restrict External DNS Lookups.**
    -   **Implement an Intrusion Detection System (IDS).**
    -   **Configure DNS Resolver to use new random source port.**
    -   **Restrict DNS Recursing Service.**
    -   **Use DNS Non-Existent Domain (NXDOMAIN) rate limiting.**
    -   **Use Secure Shell (SSH) encryption.**
    -   **Do not allow outgoing traffic to UDP port 53 as default source port.**
    -   **Audit DNS server for vulnerabilities.**
    -   **Randomize source and destination IP addresses, query IDs.**
    -   **Implement Public Key Infrastructure (PKI).**
    -   **Maintain Single/Specific Range of IP addresses to log into systems.**
    -   **Restrict DNS zone transfers to limited set of IPs.**
    -   **Employ DNS Cookie RFC 7873.**
    -   **Use Remote Name Daemon Control (RNDC).**
    -   **Ensure "Hosts" file resolution is disabled.**
    -   **Configure STUB zones.**
    -   **Implement Robust Password Policies for DNS records.**
    -   **Use DNS Resolvers that support DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT).**
    -   **Regularly update DNS server software.**
    -   **Configure ACLs on DNS servers.**
    -   **Ensure DNS software uses secure random number generation for transaction IDs.**
    -   **Implement a DNS firewall solution or subscribe to a protective DNS service.**

----------

## Key Terms for Last-Minute Revision

-   **Sniffing:** Monitoring/capturing network traffic.
-   **Promiscuous Mode:** NIC listens to all traffic on segment.
-   **Passive Sniffing:** No packets sent, only monitoring (hubs).
-   **Active Sniffing:** Injecting traffic to gather info (switches).
-   **MAC Flooding:** Overwhelming switch CAM table, forcing hub-like behavior.
-   **CAM Table (Content Addressable Memory):** Switch table mapping MACs to ports.
-   **ARP Spoofing/Poisoning:** Sending false ARP messages to redirect traffic.
-   **DHCP Starvation:** Flooding DHCP server with requests to exhaust IP pool.
-   **Rogue DHCP Server:** Unauthorized DHCP server issuing IP addresses.
-   **MAC Spoofing:** Changing MAC address to impersonate another device.
-   **IRDP Spoofing:** Misleading hosts about default router via ICMP.
-   **VLAN Hopping:** Gaining access to traffic on other VLANs.
-   **Switch Spoofing:** Attacker's machine pretends to be a trunking switch.
-   **Double Tagging:** Adding extra VLAN tag to bypass first switch.
-   **STP (Spanning Tree Protocol):** Prevents network loops; vulnerable if rogue root bridge.
-   **DNS Spoofing/Poisoning:** Redirecting domain names to malicious IP addresses.
-   **Wireshark:** Popular network protocol analyzer (software sniffer).
-   **Nessus / OpenVAS:** Vulnerability scanners (often used in conjunction with sniffing findings).
-   **SPAN Port (Port Mirroring):** Duplicating traffic to a monitoring port.
-   **Lawful Interception:** Legal wiretapping.
-   **Dynamic ARP Inspection (DAI):** Countermeasure against ARP poisoning.
-   **DHCP Snooping:** Countermeasure against DHCP starvation/rogue servers.
-   **Port Security:** Limits MAC addresses on switch ports.
-   **BPDU Guard:** STP countermeasure against rogue root bridges.
-   **DNSSEC:** Secures DNS with digital signatures.
-   **HTTPS/SSL/TLS/SSH:** Secure protocols to prevent sniffing of sensitive data.
