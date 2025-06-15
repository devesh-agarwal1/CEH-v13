## Module 12: Evading IDS, Firewalls, and Honeypots - Key Concepts and Notes

This module provides deep insights into network security technologies like IDS, IPS, firewalls, and honeypots. It explains their operations, techniques used by attackers to evade them, and necessary countermeasures.

### Learning Objectives

-   Summarize IDS, IPS, and Firewall Concepts.
-   Demonstrate IDS, IPS, and Firewall Solutions.
-   Demonstrate Different Techniques to Bypass IDS/Firewalls.
-   Demonstrate Different Techniques to Bypass NAC and Endpoint Security.
-   Understand Honeypot Concepts and Different Techniques to Detect Honeypots.
-   Explain IDS/Firewall Evasion Countermeasures.

### 1. IDS, IPS, and Firewall Concepts

#### Intrusion Detection System (IDS)

-   **Definition:** A software system or hardware device that inspects all inbound and outbound network traffic for suspicious patterns indicating a security breach. It alerts security personnel upon detection.
-   **Main Functions:**
    -   Gathers and analyzes information to identify policy violations and misuse.
    -   Acts as a "packet sniffer," intercepting and analyzing TCP/IP packets.
    -   Evaluates traffic for suspected intrusions and raises alarms.
-   **Placement:** Can be placed outside/inside the firewall. Best practice is layered defense (before and after the firewall).
-   **How it Works:** Uses sensors to detect malicious signatures or behavioral anomalies. If a match occurs, it performs predefined actions (terminate connection, block IP, drop packet, alarm).
-   **Types:**
    -   **Passive IDS:** Only detects intrusions and alerts.
    -   **Active IDS (IPS):** Detects and also prevents intrusions.

#### Intrusion Prevention System (IPS)

-   **Definition:** An active IDS placed _inline_ in the network (between source and destination) to actively analyze traffic and make automated decisions to prevent intrusions.
-   **Actions:** Generates alerts, records real-time logs, blocks/filters malicious traffic, detects/eliminates threats quickly, identifies threats accurately.
-   **Advantages over IDS:** Can actively block/drop illegal packets, monitor activities within an organization, prevent direct attacks by controlling traffic.
-   **Classification:**
    -   **Host-based IPS (HIPS):** Protects a single host.
    -   **Network-based IPS (NIPS):** Protects network segments.

#### How an IDS Detects an Intrusion

1.  **Signature Recognition (Misuse Detection):**
    -   Compares incoming traffic with known attack signatures (binary patterns of known attacks).
    -   Detects known attacks but can generate false positives if innocuous packets match signatures.
    -   Requires a massive number of signatures, which can impact performance.
2.  **Anomaly Detection:**
    -   Detects intrusions based on deviations from established "normal" behavioral characteristics of users and system components.
    -   Builds a baseline of normal activity; anything outside this threshold is an anomaly.
    -   Challenging to create precise models due to network traffic unpredictability.
3.  **Protocol Anomaly Detection:**
    -   Analyzes network traffic to detect deviations from established protocol standards or expected behavior patterns (e.g., unusual packet structures, unexpected sequence orders).
    -   Assumes most protocols have defined rules; violations indicate malicious activity or misconfiguration.

#### General Indications of Intrusions

-   **File System Intrusions:** Modification/deletion of files, unauthorized access, unexplained file changes, rogue SUID/SGID files, missing files, unexplained disk usage, abnormal system behavior.
-   **Network Intrusions:** Sudden increase in bandwidth consumption, repeated probes, connection requests from unauthorized IPs, repeated login attempts, sudden influx of log data, unexpected network configuration changes.
-   **System Intrusions:** Sudden changes in logs, slow performance, missing logs/permissions, disabled security software, unusual graphic displays, system crashes/reboots, unfamiliar processes, presence of attacker tools.

#### Types of Intrusion Detection Systems

-   **Network-Based IDS (NIDS):** Inspects traffic passing through network segments (e.g., promiscuous mode, detects DoS, port scans).
-   **Host-Based IDS (HIDS):** Analyzes system behavior on individual hosts (e.g., file modification, login attempts, audit logs, system calls). Focuses on OS and application integrity.

#### Types of IDS Alerts

-   **True Positive (Attack - Alert):** An actual attack occurs and the IDS correctly raises an alarm.
-   **False Positive (No Attack - Alert):** No actual attack, but the IDS incorrectly raises an alarm.
-   **False Negative (Attack - No Alert):** An actual attack occurs, but the IDS fails to raise an alarm (most dangerous).
-   **True Negative (No Attack - No Alert):** No attack occurs and the IDS correctly remains silent.

#### Firewall

-   **Definition:** A software or hardware-based system that protects network resources by filtering incoming and outgoing traffic based on predefined security rules.
-   **Function:** Examines all messages entering/leaving a private network and blocks those that do not meet specific criteria.
-   **Key Capabilities:**
    -   Intrusion detection mechanism.
    -   Filters packets based on address, type, port numbers.
    -   Recognizes source/destination addresses.
    -   Identifies network traffic type and data packet attributes.
    -   Logging all attempts for auditing.

#### Firewall Architecture

-   **Bastion Host:** A highly secured computer designed to protect network resources from attacks. Has two interfaces: public (to Internet) and private (to intranet).
-   **Screened Subnet (DMZ - Demilitarized Zone):** A protected network created with two or three-homed firewalls. Acts as a buffer between the Internet and the internal network. Contains publicly accessible servers (web, email, FTP).
-   **Multi-homed Firewall:** A firewall with multiple NICs connecting to two or more networks, segmenting them physically and logically.

#### Types of Firewalls (Based on Configuration & Working Mechanism)

-   **Network-based Firewalls:** Dedicated devices placed at the perimeter. (e.g., Cisco Secure Firewall ASA, FortiGate, Check Point Quantum Security Gateway).
-   **Host-based Firewalls:** Software installed on individual computers. (e.g., Microsoft Defender Firewall, ZoneAlarm, Comodo Firewall).
-   **Packet Filtering Firewall:** Filters packets based on IP address, port number, protocol, and TCP flags. Operates at Network/Transport layers.
-   **Circuit-Level Gateway Firewall:** Operates at the Session layer. Monitors TCP/IP handshakes to determine if a session is legitimate.
-   **Application-Level Firewall (Proxy Firewall):** Operates at the Application layer. Filters traffic based on specific application protocols (HTTP, FTP). Can filter content, perform caching.
-   **Stateful Multilayer Inspection Firewall:** Combines packet filtering, circuit-level, and application-level inspections. Tracks state of connections.
-   **Application Proxy:** Acts as an intermediary between client and server, filtering application-specific protocols.
-   **Network Address Translation (NAT) Firewall:** Translates private IP addresses to public ones to hide internal network structure.
-   **Virtual Private Network (VPN) Firewall:** Creates a secure, encrypted tunnel over an untrusted network.
-   **Next-Generation Firewalls (NGFWs):** Sophisticated firewalls with integrated features like IPS, anti-malware, content filtering, application awareness, and threat intelligence.

#### Firewall Limitations

-   Cannot do anything if design is faulty.
-   Not an alternative to antivirus.
-   Does not block attacks from higher protocol layers (unless it's an application firewall).
-   Cannot prevent attacks from common ports/applications if allowed.
-   Cannot prevent dial-in connections.
-   Unable to understand tunneled traffic.
-   Can be bypassed by internal attackers.

### 2. IDS, IPS, and Firewall Solutions

-   **YARA Rules (Intrusion Detection based on YARA):**
    -   A malware research tool that allows security analysts to detect and classify malware based on patterns (rules).
    -   Rules define conditions (Boolean expressions) and strings (text, hex, regex) that indicate malware.
    -   Tools: `yarGen` (generates YARA rules).
-   **Intrusion Detection Tools:**
    -   **Snort:** Open-source network intrusion detection system. Performs real-time traffic analysis, packet logging, and intrusion prevention. Uses rules to identify patterns.
    -   **Suricata:** Open-source network IDS/IPS/NSM engine. Offers high performance, multi-threading.
    -   Other NIDS/HIDS: Juniper Network's IDP system, Samhain HIDS, OSSEC, Zeek, Cisco Secure IPS.
-   **Intrusion Prevention Tools:**
    -   **Trellix Intrusion Prevention System:** Detects and blocks advanced threats, worms, and reconnaissance attacks.
    -   Other IPS: Check Point Quantum IPS, Atomic OSSEC, McAfee Host IPS, Secure IPS (NGIPS), Palo Alto Advanced Threat Prevention.
-   **Firewall Solutions:** (Various vendors based on configuration and working mechanism, as covered in concepts).

### 3. Evading IDS/Firewalls

Attackers use various techniques to manipulate attack sequence, obfuscate payloads, and use encrypted communication channels to bypass these security measures.

#### IDS/Firewall Evasion Techniques

-   **Port Scanning:** Using specific ports (e.g., HTTP, HTTPS, DNS, FTP) that are allowed by firewalls to scan for vulnerabilities.
-   **Firewalking:** Using TTL values to map firewall rulesets and identify open ports.
-   **Banner Grabbing:** Obtaining service banners (vendor, version info) to identify devices and their configurations, which may reveal vulnerabilities.
-   **IP Address Spoofing:** Masquerading as a trusted IP source to bypass IP-based filters.
-   **Source Routing:** Specifies the path of packets to bypass monitoring or less-monitored segments.
-   **Tiny Fragments:** Sending tiny IP fragments that IDS struggles to reassemble, causing them to miss malicious patterns.
-   **Using an IP Address in Place of a URL:** Bypassing URL-based filtering by directly using the IP address.
-   **Using Anonymous Website Surfing Sites:** Using proxy servers or VPNs to hide real IP addresses.
-   **Using a Proxy Server:** Directing traffic through a proxy to bypass local network filters.
-   **ICMP Tunneling:** Encapsulating malicious commands/payloads within ICMP Echo packets to create a covert channel.
-   **ACK Tunneling:** Using ACK packets to carry data or commands through firewalls, as ACK packets are often less scrutinized.
-   **HTTP Tunneling:** Encapsulating non-HTTP traffic (e.g., SSH, FTP) within HTTP requests (port 80/443) to bypass firewalls.
    -   **HTTPPort and HTTPHost:** Tools to perform HTTP tunneling.
-   **SSH Tunneling:** Creating an encrypted SSH tunnel to bypass firewall rules and access remote services (Local, Remote, Dynamic Port Forwarding).
-   **DNS Tunneling:** Encapsulating traffic within DNS queries and responses to create a covert channel.
    -   **Iodine/dns2tcp:** Tools for DNS tunneling.
-   **Bypassing through External Systems:** Compromising an external system (e.g., employee's home machine, third-party vendor) to launch attacks from a trusted source.
-   **Bypassing through MITM Attacks:** Performing DNS server poisoning or routing manipulation to redirect traffic through the attacker's system.
-   **Bypassing through Content:** Embedding malicious code within legitimate files (images, documents, audio/video) or disguising it using steganography or obfuscation.
-   **Bypassing WAF (Web Application Firewall) using XSS Attack:** Exploiting XSS vulnerabilities to bypass WAFs by using ASCII values, Hex encoding, or obfuscation to hide malicious payloads.
    -   **HTTP Header Spoofing:** Modifying HTTP headers to trick WAFs or bypass rules.
    -   **Blacklist Detection:** Identifying and bypassing WAFs that use blacklists by finding unlisted keywords.
    -   **Fuzzing/Brute-forcing:** Sending multiple payloads to find a bypass.
    -   **Abusing SSL/TLS ciphers:** Exploiting weak SSL/TLS cipher suites to bypass WAFs.
-   **Bypassing IDS/Firewall through HTML Smuggling:** Embedding malicious code as a JavaScript Blob within an HTML attachment or web page. The client's browser downloads and executes the malicious payload.
-   **Evading IDS/Firewall through Windows BITS (Background Intelligent Transfer Service):** Using BITS, a legitimate Windows service for file transfers, to download and execute malicious payloads, bypassing security solutions.

#### Other Techniques for IDS Evasion

-   **Insertion Attack:** Attacker sends invalid packets that the IDS accepts but the destination system rejects, leading to desynchronization.
-   **Evasion Attack:** Attacker sends packets that IDS discards but the host accepts, leading to desynchronization.
-   **Denial-of-Service Attack (DoS):** Overwhelming IDS resources (memory, CPU) with noise traffic to prevent it from detecting true attacks.
-   **Obfuscation:** Making code difficult to understand or detect (e.g., Unicode, ASCII, polymorphism, metamorphism).
-   **False Positive Generation:** Constructing malicious packets to trigger numerous false alarms, distracting IDS administrators.
-   **Session Splicing:** Exploiting IDS's inability to reconstruct sessions from fragmented packets.
-   **Unicode Evasion:** Using Unicode characters to bypass signature-based detection.
-   **Fragmentation Attack:** Breaking packets into small fragments that IDS fails to reassemble or incorrectly analyzes.
-   **Time-to-Live (TTL) Attacks:** Manipulating TTL values to bypass IDS by making packets expire before reaching the IDS or router.
-   **Urgency Flag:** Using the TCP urgency pointer to hide malicious data within normal data streams.
-   **Invalid RST Packets:** Sending invalid RST packets to desynchronize communication.
-   **Polymorphic Shellcode:** Mutating shellcode to evade signature detection.
-   **ASCII Shellcode:** Using only ASCII characters for shellcode to bypass IDS filters.
-   **Application-Layer Attacks:** Exploiting vulnerabilities in application layer protocols.
-   **Desynchronization:** Breaking the synchronization between IDS and the target host (Pre-Connection SYN, Post-Connection SYN).
-   **Domain Generation Algorithms (DGA):** Malicious software generates new domain names for C&C communication, evading static blacklists.
-   **Encryption:** Using encrypted communication (SSH, SSL/TLS, VPN) to hide malicious traffic from IDS/firewalls.
-   **Flooding:** Overloading IDS resources with traffic to bypass security.

### 4. Evading NAC and Endpoint Security

Network Access Control (NAC): Security control to block unauthorized users/hosts from internal services.

Endpoint Security: Protects end-user devices (desktops, laptops, mobiles, servers) from malware and other cyber threats.

#### NAC and Endpoint Security Evasion Techniques

-   **VLAN Hopping:** Bypassing VLAN segmentation to access restricted networks.
-   **Using a Pre-authenticated Device:** Using a device that is already authenticated to the network.
-   **Ghostwriting:** Using fake credentials or bypassing authentication mechanisms.
-   **CPL (Control Panel) Side-loading:** Exploiting legitimate Windows features.
-   **Using Application Whitelisting:** Bypassing application whitelisting.
-   **Dechaining Macros:** Obfuscating malicious macros.
-   **Clearing Memory Hooks:** Removing traces of malware from memory.
-   **Process Injection:** Injecting malicious code into legitimate processes.
-   **Using LOLBins (Living Off the Land Binaries):** Using legitimate system binaries for malicious purposes.
-   **Using ChatGPT:** For generating attack payloads or social engineering content.
-   **Using Metasploit Templates:** Exploiting template vulnerabilities.
-   **Windows Antimalware Scan Interface (AMSI) Bypass:** Techniques to evade AMSI detection.
-   **Hosting Phishing Sites:** Hosting malicious sites for credential harvesting.
-   **Reducing Entropy:** Reducing randomness in payloads to bypass detection.
-   **Escaping the Sandbox:** Techniques to detect and evade sandbox environments.
-   **Disabling Event Tracing for Windows:** Preventing security logging.
-   **Spoofing "Admins at the Syn/Ack":** Mimicking legitimate network traffic.
-   **Timing-Based Evasion:** Delaying execution to bypass time-based detection.
-   **Signed Binary Proxy Execution:** Using legitimate signed binaries to proxy malicious code.
-   **Bypassing the Thread Call Stack:** Modifying thread stack to evade detection.
-   **Shared Memory Encryption:** Encrypting data in shared memory.
-   **Summary/Encryption of Beacon:** Obfuscating beacon communication.

### 5. Honeypot Concepts and Detection

What is a Honeypot?

A security resource designed to be attacked and exploited, serving as a trap for cyber attackers. It's a decoy system used to lure attackers, gather intelligence on their methods, and distract them from real production systems.

-   **Purpose:**
    -   Gain information about attacker methods/tools/motivations.
    -   Divert attackers from critical systems.
    -   Record detailed attack activities.
    -   Identify new threats and vulnerabilities (zero-days).
    -   Learn about attacker behavior in real-time.
-   **Types:**
    -   **Low-interaction Honeypots:** Simulate limited services and operating systems (less resource-intensive, easy to deploy, less risk of compromise).
    -   **High-interaction Honeypots:** Full operating systems and applications, allowing attackers full interaction (more realistic, provide rich data, higher risk).

#### Techniques to Detect Honeypots

Attackers try to identify honeypots to avoid wasting time or revealing their true tactics.

-   **Check the ARP Cache:** If the ARP cache contains too many entries for a small network, it might indicate a honeypot.
-   **Checking for Time Delay:** Honeypots might introduce artificial delays.
-   **Check for Large Ping Size:** Honeypots may not respond to large ICMP pings.
-   **Checking for Open Ports:** Honeypots often have many open ports.
-   **Check the System Uptime:** Unusually short uptime for a server might indicate a honeypot.
-   **DNS Resolution Check:** Reverse DNS lookups for unusual names.
-   **Behavioral Analysis:** Observing inconsistent or unusual system behavior.
-   **Network Latency:** Higher latency than expected.
-   **Specific Tool Detection:** Tools like `send-e`, `honeydetect`, `nmap` scripts (e.g., `nmap --script http-honeypot-detect`), `Xprobe2`.
-   **CPU and Memory Usage:** Unusual or low resource usage.
-   **Registry Keys/Files:** Specific registry keys or files that indicate a VM or sandbox environment.
-   **Service Banners:** Default or generic service banners.
-   **Time Check:** If time is sped up in a VM.
-   **Disk Size:** Small disk size.
-   **Common VM Software:** Presence of VMware, VirtualBox, etc. drivers or files.

### 6. IDS/Firewall Evasion Countermeasures

-   **Regular Updates:** Keep IDS/IPS/Firewall software and signatures up-to-date.
-   **Strong Policies:** Implement strict security policies and access controls.
-   **Layered Defense:** Deploy multiple security layers (firewall, IDS, IPS, EDR, NAC).
-   **Encryption:** Use strong encryption for all sensitive communication (SSL/TLS, IPsec, VPN).
-   **Traffic Analysis & Baselines:** Continuously monitor network traffic for anomalies and deviations from normal baselines.
-   **Network Segmentation:** Divide the network into smaller segments to limit the scope of an attack.
-   **Egress Filtering:** Filter outbound traffic to prevent IP spoofing and unauthorized connections.
-   **Ingress Filtering:** Filter inbound traffic to ensure legitimate source IPs.
-   **TCP Intercept/SYN Cookies:** Protect against SYN flood attacks.
-   **Rate Limiting:** Limit the number of connections or requests from a single source.
-   **Unified Threat Management (UTM) / Next-Gen Firewalls (NGFW):** Integrated security solutions with advanced features.
-   **Anti-Phishing & Anti-Malware:** Prevent initial infection vectors.
-   **Authentication & Authorization:** Strong authentication mechanisms (MFA) and proper access privileges.
-   **Patch Management:** Regularly patch all systems and applications.
-   **User Awareness Training:** Educate users about evasion techniques and social engineering.
-   **Web Development Guidelines:** Secure session ID generation, HSTS, secure cookies.
-   **DNSSEC:** Secure DNS infrastructure.
-   **Traffic Normalization:** Normalize traffic to remove ambiguities that attackers exploit.
-   **Behavioral Biometrics:** Use typing rhythm, mouse movements for continuous authentication.
-   **Challenge-Response Mechanisms:** CAPTCHA to detect suspicious activity.
-   **Session Timeout:** Automatically terminate inactive sessions.
-   **Centralized Logging & SIEM:** Aggregate logs for correlation and anomaly detection.
-   **Threat Intelligence Feeds:** Integrate threat intelligence to identify new evasion techniques.
-   **DDoS Protection Services/Appliances:** To mitigate volumetric attacks.

----------

## Key Terms for Last-Minute Revision

-   **IDS (Intrusion Detection System):** Detects suspicious network/system activity.
-   **IPS (Intrusion Prevention System):** Detects and _prevents_ suspicious activity.
-   **Firewall:** Filters network traffic based on rules.
-   **Signature Recognition (IDS):** Detects known attack patterns.
-   **Anomaly Detection (IDS):** Detects deviations from normal behavior.
-   **Protocol Anomaly Detection (IDS):** Detects deviations from protocol standards.
-   **NIDS (Network-Based IDS):** Monitors network traffic.
-   **HIDS (Host-Based IDS):** Monitors individual hosts.
-   **True Positive:** Correctly identified attack.
-   **False Positive:** Incorrectly identified attack.
-   **False Negative:** Missed attack (most critical).
-   **Bastion Host:** Highly secured gateway server.
-   **DMZ (Demilitarized Zone):** Perimeter network segment.
-   **Packet Filtering:** Basic firewall filtering based on headers.
-   **Circuit-Level Gateway:** Firewall operating at Session layer.
-   **Application-Level Firewall (Proxy Firewall):** Filters at Application layer.
-   **Stateful Multilayer Inspection:** Firewall that tracks connection state across layers.
-   **NAT (Network Address Translation):** Hides internal IPs.
-   **VPN (Virtual Private Network):** Creates secure, encrypted tunnel.
-   **NGFW (Next-Generation Firewall):** Advanced, integrated firewall.
-   **YARA Rules:** Pattern-matching for malware detection.
-   **Snort:** Popular open-source NIDS/NIPS.
-   **Suricata:** High-performance NIDS/NIPS.
-   **Port Scanning:** Identifying open ports on a target.
-   **Firewalking:** Mapping firewall rulesets.
-   **Banner Grabbing:** Obtaining service version info.
-   **IP Spoofing:** Forging source IP addresses.
-   **Source Routing:** Specifying packet path.
-   **Tiny Fragments:** Breaking packets to evade detection.
-   **ICMP Tunneling:** Encapsulating data in ICMP packets.
-   **ACK Tunneling:** Using ACK packets to carry data.
-   **HTTP Tunneling:** Encapsulating traffic within HTTP requests.
-   **SSH Tunneling:** Creating an encrypted tunnel over SSH.
-   **DNS Tunneling:** Encapsulating data within DNS queries.
-   **HTML Smuggling:** Embedding malicious code as a JavaScript Blob in HTML.
-   **Windows BITS:** Using Background Intelligent Transfer Service for malware transfer.
-   **Obfuscation:** Making code difficult to understand or detect.
-   **Polymorphic Shellcode:** Mutating shellcode.
-   **ASCII Shellcode:** Shellcode using only ASCII characters.
-   **Fragmentation Attack (IDS):** Overloading IDS with fragmented packets.
-   **TTL (Time-to-Live) Attacks:** Manipulating TTL to bypass IDS/routers.
-   **Urgency Flag:** Using TCP urgency pointer to hide data.
-   **Desynchronization (IDS):** Breaking synchronization between IDS and target.
-   **DGA (Domain Generation Algorithm):** Generates random domain names for C&C.
-   **NAC (Network Access Control):** Controls access to network based on policy.
-   **Endpoint Security:** Protects individual devices.
-   **LOLBins (Living Off the Land Binaries):** Using legitimate system tools for malicious purposes.
-   **Honeypot:** Decoy system to lure and study attackers.
-   **Low-interaction Honeypot:** Simulates limited services.
-   **High-interaction Honeypot:** Full system emulation.
-   **HSTS (HTTP Strict Transport Security):** Forces HTTPS.
-   **Token Binding:** Binds tokens to TLS session.
-   **DNS over HTTPS (DoH):** Encrypts DNS queries.
-   **IPsec:** Suite of protocols for secure IP communication.
-   **SIEM (Security Information and Event Management):** Centralized logging and analysis.
