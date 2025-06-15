## Module 10: Denial-of-Service - Key Concepts and Notes

This module focuses on Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attacks, which aim to make network resources unavailable to legitimate users. It covers concepts, attack techniques, tools, and countermeasures.

### Learning Objectives

-   Describe DoS/DDoS concepts.
-   Describe botnets.
-   Understand various DoS/DDoS attack techniques.
-   Explain different DoS/DDoS attack tools.
-   Illustrate DoS/DDoS case study.
-   Apply best practices to mitigate DoS/DDoS attacks.
-   Apply various DoS/DDoS protection tools.

### 1. DoS/DDoS Concepts

#### What is a DoS Attack?

-   **Denial-of-Service (DoS):** An attack on a computer or network that reduces, restricts, or prevents accessibility of system resources to its legitimate users.
-   Attackers flood the victim system with non-legitimate service requests or traffic to overload its resources.
-   **Goal:** To make the system unavailable to legitimate users, not necessarily to gain unauthorized access or corrupt data.
-   **Impact:** Loss of goodwill, network outages, financial losses, operational disruptions, potential data destruction.
-   **Examples:** Flooding with traffic, overloading services, crashing TCP/IP stacks with corrupt packets, causing infinite loops, consuming resources (bandwidth, disk space, CPU time).

#### What is a DDoS Attack?

-   **Distributed Denial-of-Service (DDoS):** A large-scale, coordinated DoS attack launched indirectly through multiple compromised computers (**botnets**) on the Internet.
-   Uses many compromised computers (**zombies**) to launch a coordinated attack, making it difficult to trace the original attacker.
-   **Primary objective:** Gain administrative access on as many systems as possible, then launch coordinated attacks.
-   The attack is amplified significantly due to the large number of sources.

#### How DoS/DDoS Attacks Work (General Flow)

1.  Attacker compromises multiple systems (secondary victims) and turns them into **zombie agents** or **bots**.
2.  These bots form a **botnet** controlled by the attacker via a **Command and Control (C&C) server**.
3.  The attacker sends commands to the bots.
4.  Bots flood the primary target system with connection requests or malicious traffic, often using **spoofed IP addresses** to hide their true origin and amplify the attack via **reflector systems**.
5.  The target system is overwhelmed, leading to denial of service.

#### Botnets

-   A network of compromised computers (bots or zombies) controlled by an attacker to perform malicious tasks.
-   Can be used for DDoS attacks, spamming, spreading malware, sniffing traffic, keylogging, installing advertisement add-ons, crypto-mining.
-   **Hierarchical Setup (Cybercrime Syndicates):** Often involves a "Criminal Boss" (entrepreneur), "Underboss" (Trojan provider, C&C manager), "Campaign Managers" (distribute Trojans), and "Stolen Data Resellers."

#### Scanning Methods for Finding Vulnerable Machines (for Botnets)

-   **Random Scanning:** Bots randomly probe IP addresses within a target network range for vulnerabilities.
-   **Hit-list Scanning:** Attackers collect a list of potentially vulnerable machines and target them.
-   **Topological Scanning:** Uses information obtained from an infected machine to find new vulnerable machines.
-   **Local Subnet Scanning:** Searches for new vulnerable machines in its local network.
-   **Permutation Scanning:** Uses a pseudorandom permutation list of IP addresses to find new vulnerable machines.

#### How Malicious Code Propagates (for Botnets)

-   **Central Source Propagation:** Attacker places an attack toolkit on a central source, and compromised machines automatically download it.
-   **Back-chaining Propagation:** Attacker places an attack toolkit on their own system, and a copy is transferred to newly discovered vulnerable systems. Often uses TFTP (Trivial File Transfer Protocol).
-   **Autonomous Propagation:** The attack toolkit hosts itself on the newly discovered vulnerable system, autonomously spreading.

### 2. DoS/DDoS Attack Techniques

DoS/DDoS attacks are categorized by the layer of the OSI model they target:

#### Volumetric Attacks (Bandwidth Consumption)

These attacks exhaust the bandwidth between the target and the rest of the Internet by generating a massive volume of traffic.

-   **UDP Flood Attack:** Floods a remote host with spoofed UDP packets to random ports. Responses from the target (ICMP Destination Unreachable) consume bandwidth.
-   **ICMP Flood Attack:** Overwhelms the target with ICMP ECHO requests (ping flood), consuming bandwidth.
-   **Ping of Death (PoD):** Sends an oversized ICMP packet (larger than 65,535 bytes) to crash the target's TCP/IP stack.
-   **Smurf Attack:** Uses a spoofed source IP (victim's IP) and sends ICMP ECHO requests to a network's broadcast address. All hosts on the network respond to the victim, flooding it.
-   **Pulse Wave Attack:** Repeated short bursts of high-volume traffic designed to overwhelm defenses and cause intermittent outages.
-   **NTP Amplification Attack:** Exploits Network Time Protocol (NTP) servers by sending small spoofed requests to an NTP server, which replies with a much larger response to the victim.
-   **Zero-day Attack:** Exploits newly discovered vulnerabilities with no public patch.
-   **Spoofed IP packet flood attack:** Generates traffic from spoofed source IP addresses.
-   **DNS Flood:** Overwhelms a DNS server.
-   **Simple Network Discovery Protocol (SSDP) flood attack:** Leverages SSDP for amplification.
-   **User Datagram Protocol (UDP) flood attack:** Generic UDP flood.
-   **Internet Control Message Protocol (ICMP) flood attack:** Generic ICMP flood.

#### Protocol Attacks (Resource Consumption)

These attacks consume connection state tables or other resources on network infrastructure components or the target server.

-   **SYN Flood Attack:** Exploits the TCP three-way handshake. Attacker sends a large number of SYN requests with spoofed source IPs but never completes the handshake (no ACK). This leaves the target server with many half-open connections, consuming resources.
    -   **SYN-ACK Flood Attack:** Similar to SYN flood, but the attacker exploits the second stage of a three-way handshake.
    -   **ACK and PUSH ACK Flood Attack:** Sends large numbers of ACK or PUSH ACK packets to a target machine.
-   **Fragmentation Attack:** Floods the target with fragmented IP or UDP packets. The target expends excessive resources reassembling incomplete fragments, leading to a crash.
-   **Spoofed Session Flood Attack (SYN/ACK/RST/FIN):** Attackers create fake or spoofed TCP sessions to bypass firewalls and exhaust network resources.
-   **Permanent Denial-of-Service (PDoS) Attack / Phlashing:** An attack that causes irreparable damage to a system's hardware, requiring replacement or reinstallation. Often involves corrupting firmware.
-   **TCP SACK Panic Attack:** Remote attack vector that crashes Linux machines by sending SACK packets with malformed maximum segment size, causing integer overflow.
-   **TCP Connection Flood Attack:** Consumes all available OS resources by initiating a large number of connection requests.
-   **RST Attack:** Sending TCP RST packets to abruptly terminate connections.
-   **TCP state exhaustion attack:** Consumes the connection table.

#### Application Layer Attacks (Application Resource Consumption)

These attacks target vulnerabilities in the application layer (Layer 7) of the OSI model, attempting to disrupt specific application services.

-   **HTTP GET/POST Attack:** Floods web servers with HTTP GET or POST requests.
    -   **Single-Session HTTP Flood:** Exploits HTTP 1.1 to bombard with multiple requests in a single session.
    -   **Single-Request HTTP Flood:** Attacker sends multiple HTTP requests from a single session by concealing these requests within a single HTTP packet.
    -   **Recursive HTTP GET Flood:** Designed for forums/blogs; recursively requests pages to exhaust resources.
    -   **Random Recursive GET Flood:** Similar, but uses random numbers or page ranges.
-   **Slowloris Attack:** A DDoS tool that performs Layer 7 DDoS attacks by sending partial HTTP requests to a web server. It keeps the connections open for as long as possible, exhausting the server's connection pool without a high volume of traffic.
-   **UDP Application Layer Flood Attack:** Attacks application layer protocols that rely on UDP (e.g., Character Generator Protocol (CHARGEN), Quote of the Day (QOTD), NTP, SSDP, VoIP).
-   **DDoS Extortion Attack:** Attackers threaten organizations with a DDoS attack unless a ransom is paid (RDDoS - Ransom DDoS).
-   **HTTP/2 Rapid Reset Attack:** Rapidly opens and closes HTTP/2 streams to exhaust server resources.

#### Other Attack Techniques

-   **Multi-Vector Attack:** Attacks that combine different types of volumetric, protocol, and application-layer attacks.
-   **Peer-to-Peer Attack:** Exploits vulnerabilities in P2P servers/clients to launch DDoS attacks.
-   **Distributed Reflection DoS (DRDoS) Attack:** Uses third-party servers (reflectors) to bounce traffic off of them onto the target. The attacker sends requests to the reflectors with a spoofed source IP (the victim's IP), and the reflectors send responses to the victim.

### 3. DoS/DDoS Attack Toolkits in the Wild

-   **ISB (I'm So Bored):** Performs HTTP, UDP, TCP, and ICMP flood attacks.
-   **UltraDDoS-v2:** GUI tool for DDoS attacks against web servers.
-   **High Orbit Ion Cannon (HOIC):** Flood tool for HTTP GET/POST.
-   **Low Orbit Ion Cannon (LOIC):** Simple DoS tool.
-   **HULK:** HTTP Unbearable Load King (HTTP flood).
-   **Slowloris:** Layer 7 HTTP DoS tool.
-   **UFONet:** Uses "zombies" to create/manage botnets and perform DoS/DDoS.
-   **Packet Flooder Tool:** Generic packet flooding tool.

### 4. DoS/DDoS Attack Countermeasures

Mitigating DoS/DDoS attacks requires a multi-layered approach involving detection, prevention, and response.

#### Detection Techniques

-   **Activity Profiling:** Monitors average packet rates, network flow clusters.
-   **Sequential Change Detection:** Identifies abnormal traffic patterns that deviate from normal behavior.
-   **Wavelet-Based Signal Analysis:** Analyzes statistical properties of traffic for anomalies.
-   **Traffic Pattern Analysis:** Identifies characteristics of incoming traffic.
-   **Packet Traceback:** Traces packets back to their source.
-   **Event Log Analysis:** Identifies DoS/DDoS attacks and their sources from logs.

#### DoS/DDoS Countermeasure Strategies

-   **Absorbing the Attack:** Increasing capacity to handle attack traffic (e.g., Load Balancing, Throttling).
-   **Degrading Services:** Maintain critical service functionality while shedding non-critical services.
-   **Shutting Down Services:** Shutting down all services until the attack has subsided (last resort).

#### Protecting Secondary Victims (for DDoS)

-   **Monitor for DDoS Agent Software:** Regularly scan and remove agent software.
-   **Anti-virus/Anti-Trojan software:** Keep up-to-date.
-   **Security Patches/Updates:** Increase awareness, keep systems patched.
-   **Disable Unnecessary Services/Scans:** Remove unused applications and scan all files.
-   **Hardened Systems:** Properly configure hardware/software for defense.

#### Detecting and Neutralizing Handlers

-   **Network Traffic Analysis:** Analyze C&C traffic patterns.
-   **Neutralize Botnet Handlers:** Disrupt C&C servers.
-   **Spoofed Source Address Prevention:** Block packets with invalid source addresses (e.g., Egress Filtering).

#### Preventing Potential Attacks

-   **Egress Filtering:** Filters outgoing packets at network boundaries to prevent spoofed IP addresses from leaving the network.
-   **Ingress Filtering:** Filters incoming packets to ensure source addresses are legitimate.
-   **TCP Intercept:** Router feature that protects TCP servers from SYN flood attacks by intercepting SYNs and completing handshakes.
-   **Rate Limiting:** Controls the volume of inbound traffic to prevent network overflow.
-   **Honeypots:** Decoy systems designed to lure attackers and collect information about attack methods without affecting production systems.

#### Mitigate Attacks (Load Balancing, Throttling, Drop Requests)

-   **Load Balancing:** Distributes incoming traffic across multiple servers to prevent overload.
-   **Throttling:** Limiting inbound traffic to prevent resource exhaustion.
-   **Drop Requests:** Discarding requests when server load is too high.

#### Post-Attack Forensics

-   **Traffic Pattern Analysis:** Analyze attack traffic to identify characteristics and update defenses.
-   **Packet Traceback:** Trace attack traffic back to its source.
-   **Event Log Analysis:** Analyze logs to identify DoS/DDoS attacks.

#### Defending against Botnets

-   **RFC 3704 Filtering (Unicast Reverse Path Forwarding - uRPF):** Basic access-control list filter that limits DDoS attacks from spoofed source addresses.
-   **Cisco IPS Source IP Reputation Filtering:** Uses reputation services to identify and block known botnet/malware IPs.
-   **Black Hole Filtering:** Discards undesirable traffic by routing it to a "null0" interface.
-   **DDoS Prevention Offerings from ISP or DDoS Service:** ISPs offer managed DDoS protection.

#### DDoS Protection at ISP Level

-   ISPs provide "clean pipes" services, filtering malicious traffic before it reaches the customer network.
-   Redirect attack traffic to ISP's scrubbing centers.

#### Advanced DDoS Protection Appliances/Tools

-   **FortiDDoS:** Machine learning-based DDoS mitigation.
-   **Quantum DDoS Protector (Check Point):** Multi-layered protection, behavioral analysis.
-   **Huawei AntiDDoS1000:** Big Data analytics for large-scale attacks.
-   **A10 Thunder TPS:** Ensures reliable access to key network services.
-   **Anti DDoS Guardian:** Protects IIS, Apache, mail servers from DDoS attacks.
-   **DDoS-GUARD, Radware DefensePro, Gatekeeper, F5 DDoS Attack Protection.**

#### DDoS Protection Services (Cloud-based)

-   **Cloudflare:** Provides DDoS mitigation via a global network, BGP-based protection, L7 services.
-   **Akamai DDoS Protection:** Leverages dedicated infrastructure to safeguard internet-facing applications.
-   **Stormwall PRO, Imperva DDoS Protection, Nexusguard, BlockDoS.**

----------

## Key Terms for Last-Minute Revision

-   **DoS (Denial-of-Service):** Attack to make a resource unavailable.
-   **DDoS (Distributed Denial-of-Service):** DoS attack from multiple sources.
-   **Botnet:** Network of compromised computers (bots/zombies).
-   **Zombie/Bot:** A compromised computer in a botnet.
-   **C&C (Command and Control) Server:** Server used by attacker to control botnet.
-   **Volumetric Attack:** Overloads bandwidth (e.g., UDP Flood, ICMP Flood, Smurf, NTP Amplification).
-   **Protocol Attack:** Consumes server/network device resources (e.g., SYN Flood, Fragmentation, Ping of Death).
-   **Application Layer Attack:** Targets specific application flaws (e.g., HTTP GET/POST Flood, Slowloris).
-   **SYN Flood:** Exploits TCP three-way handshake by leaving half-open connections.
-   **Smurf Attack:** Amplified ICMP flood using broadcast addresses.
-   **NTP Amplification:** Uses NTP servers to amplify traffic to victim.
-   **Slowloris:** Keeps HTTP connections open with partial requests to exhaust server resources.
-   **PDoS (Permanent Denial-of-Service) / Phlashing:** Irreparably damages hardware/firmware.
-   **DRDoS (Distributed Reflection DoS):** Uses third-party "reflectors" to bounce traffic to the victim.
-   **DDoS Extortion (RDDoS):** Ransomware variant demanding payment to stop a DDoS attack.
-   **Egress Filtering:** Filters outgoing traffic to prevent IP spoofing.
-   **Ingress Filtering:** Filters incoming traffic to ensure legitimate source IPs.
-   **TCP Intercept:** Router feature to protect against SYN floods.
-   **Rate Limiting:** Controls traffic volume.
-   **Honeypots:** Decoy systems to lure attackers and gather intel.
-   **Load Balancing:** Distributes traffic across multiple servers.
-   **Throttling:** Limits traffic to a server.
-   **Traffic Pattern Analysis:** Detecting anomalies in network traffic.
-   **Packet Traceback:** Tracing attack packets to their source.
-   **RFC 3704 Filtering:** Basic ACL for spoofed IP packets.
-   **Black Hole Filtering:** Discarding unwanted traffic.
-   **DDoS Protection Services (Cloud-based):** Cloudflare, Akamai, etc.
-   **DDoS Protection Appliances:** FortiDDoS, Quantum DDoS Protector, A10 Thunder TPS.
