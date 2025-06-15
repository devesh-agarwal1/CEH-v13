## Module 16: Hacking Wireless Networks - Key Concepts and Notes

This module describes the types of wireless networks, their security mechanisms, threats, and measures to combat these threats to keep the network secure. It analyzes various wireless encryption algorithms and wireless network attack techniques, and discusses countermeasures to protect information systems.

### Learning Objectives

-   Summarize Wireless Concepts.
-   Explain Different Wireless Encryption Algorithms.
-   Explain Different Wireless Threats.
-   Demonstrate Wireless Hacking Methodology.
-   Explain Wireless Attack Countermeasures.

### 1. Wireless Concepts

What is a Wireless Network (Wi-Fi)?

An unbounded data communication system that uses radio-frequency technology (electromagnetic waves) to communicate with devices without physical cables. Wi-Fi refers to Wireless Local Area Networks (WLANs) based on the IEEE 802.11 standard.

#### Wireless Terminology

-   **GSM (Global System for Mobile Communications):** Universal system for mobile data transmission.
-   **Bandwidth:** Amount of information that can be broadcast over a connection (data transfer rate in bps).
-   **Access Point (AP):** Connects wireless devices to a wired/wireless network. Acts as a hub/switch.
    -   **Software APs (SAPs):** Run on a computer with a wireless NIC.
    -   **Hardware APs (HAPs):** Dedicated devices supporting most wireless features.
-   **BSSID (Basic Service Set Identifier):** MAC address of an AP.
-   **ISM Band (Industrial, Scientific, and Medical Band):** Frequencies used by international industrial, scientific, and medical communities.
-   **Hotspot:** Places where wireless networks are available for public use.
-   **Association:** Process of connecting a wireless device to an AP.
-   **SSID (Service Set Identifier):** A 32-alphanumeric-character unique identifier for a WLAN. Devices must use the same SSID to connect.
-   **OFDM (Orthogonal Frequency-Division Multiplexing):** Digital modulation method splitting a signal into multiple orthogonal carrier frequencies.
-   **MIMO-OFDM (Multiple Input, Multiple Output-OFDM):** Influences spectral efficiency of 4G/5G, reduces interference, increases channel robustness.
-   **DSSS (Direct-Sequence Spread Spectrum):** Multiplies original data signal with a pseudo-random noise-spreading code to protect against interference.
-   **FHSS (Frequency-Hopping Spread Spectrum):** Rapidly switches a carrier among many frequency channels to decrease interception/jamming efficiency.

#### Types of Wireless Networks

-   **Extension to a Wired Network:** APs extend wired networks to wireless devices.
-   **Multiple Access Points:** Multiple APs used to cover a larger area, allowing roaming.
-   **LAN-to-LAN Wireless Network:** Interconnecting local area networks wirelessly using APs.
-   **3G/4G/5G Hotspot:** Provides Wi-Fi access to Wi-Fi-enabled devices via cellular networks.

#### Wireless Standards (IEEE 802.11 Amendments)

-   **802.11 (Wi-Fi):** Original standard (1997), 1-2 Mbps, 2.4 GHz.
-   **802.11a:** 5 GHz band, OFDM modulation, up to 54 Mbps.
-   **802.11b:** 2.4 GHz band, DSSS modulation, up to 11 Mbps.
-   **802.11g:** 2.4 GHz band, OFDM modulation, up to 54 Mbps.
-   **802.11n:** 2.4/5 GHz bands, MIMO-OFDM, up to 600 Mbps.
-   **802.11ac (Wi-Fi 5):** 5 GHz band, supports up to 9.6 Gbps.
-   **802.11ax (Wi-Fi 6):** 2.4/5 GHz bands, 1024-QAM, up to 2.4 Gbps.
-   **802.11be (Wi-Fi 7):** 2.4/5/6 GHz bands, QAM, up to 3 Gbps.
-   **802.15.1 (Bluetooth):** Personal Area Networks (WPAN), 2.4 GHz.
-   **802.15.4 (ZigBee):** Low-power, low-data rate wireless personal area networks.
-   **802.16 (WiMAX):** Wireless Metropolitan Area Networks (WMAN), long-range.

#### Wi-Fi Authentication Process

-   **Pre-shared Key (PSK) Mode (WPA-PSK or WPA2-PSK):** Uses a single shared password for all devices. Common for homes/small offices.
-   **Centralized Authentication Mode (RADIUS):** Uses a centralized authentication server (RADIUS) for enterprise-level authentication with unique user credentials (WPA2-Enterprise).

#### Types of Wireless Antennas

-   **Directional Antenna:** Transmits/receives radio waves from a single direction.
-   **Omnidirectional Antenna:** Transmits/receives radio waves in all directions (360° horizontal pattern).
-   **Parabolic Grid Antenna:** High-gain, long-range antenna.
-   **Yagi Antenna:** Directional antenna, high gain, long signal-to-noise ratio.
-   **Dipole Antenna:** Straight electrical conductor, half-wavelength.
-   **Reflector Antennas:** Concentrate EM energy that is radiated/received at a focal point.

### 2. Wireless Encryption Algorithms

Wireless encryption protects against eavesdropping and unauthorized access to wireless networks.

-   **WEP (Wired Equivalent Privacy):**
    -   An old, vulnerable encryption algorithm for 802.11 WLANs.
    -   Uses the RC4 stream cipher and a 24-bit Initialization Vector (IV).
    -   **Flaws:**
        -   No defined method for encryption key distribution.
        -   Weak PSK changes.
        -   RC4 can be used in a more randomized environment.
        -   Attackers can analyze traffic to compute the key.
        -   Key scheduling algorithms are vulnerable.
        -   CRC-32 checksum is a weak integrity check.
        -   IV reuse leads to plaintext attacks.
        -   Standard does not require unique IVs.
        -   RC4 is a one-time cipher.
        -   No replay protection.
        -   Supports only one-way authentication.
-   **WPA (Wi-Fi Protected Access):**
    -   A security protocol for 802.11 standard, designed to address WEP's weaknesses.
    -   Uses **TKIP (Temporal Key Integrity Protocol)** for encryption and **MIC (Message Integrity Check)**.
    -   **TKIP:** Uses 128-bit keys and a per-packet key mixing function to prevent replay attacks.
    -   **MIC:** Provides integrity check to prevent data tampering.
    -   **Weaknesses:** Still vulnerable to dictionary/password-cracking attacks if PSK is weak. Can be vulnerable to packet spoofing/decryption in certain scenarios.
-   **WPA2 (Wi-Fi Protected Access 2):**
    -   Security protocol used to safeguard wireless networks, mandating `IEEE 802.11i` standard.
    -   Uses **AES (Advanced Encryption Standard)** and **CCMP (Counter Mode Cipher Block Chaining Message Authentication Code Protocol)** for strong encryption.
    -   **Modes of Operation:**
        -   **WPA2-Personal (PSK):** Uses a pre-shared key (PSK) (256-bit ASCII or 64-hexadecimal characters).
        -   **WPA2-Enterprise:** Integrates EAP (Extensible Authentication Protocol) and RADIUS server for centralized authentication.
    -   **Issues:** Still vulnerable to weak passwords, Man-in-the-Middle (MITM), DoS, and KRACK (Key Reinstallation Attack) vulnerabilities. Predictability of Group Temporal Key (GTK).
-   **WPA3 (Wi-Fi Protected Access 3):**
    -   Advanced implementation of WPA2, announced in 2018.
    -   Uses **AES-GCM-256** encryption algorithm.
    -   **Modes of Operation:**
        -   **WPA3-Personal:** Uses **SAE (Simultaneous Authentication of Equals)** protocol (Dragonfly Key Exchange) for stronger password-based authentication, resistant to dictionary attacks and offline brute-force attacks.
        -   **WPA3-Enterprise:** Provides enhanced protection for sensitive data using advanced cryptographic algorithms (`GCMP-256`, `HMAC-SHA-384`).
    -   **Enhancements over WPA2:**
        -   **SAE:** Stronger password authentication.
        -   **Wi-Fi Easy Connect:** Simplifies device onboarding using QR codes.
        -   **OWE (Opportunistic Wireless Encryption):** Provides better data privacy in public hotspots (unauthenticated encryption).
        -   **Bigger session keys:** Increased key size.
    -   **Limitations:** Limited adoption, resource intensive, configuration errors can impact benefits, timing attacks, cache-based side-channel attacks, transition mode weaknesses (compatibility with older devices), hardware requirements.

### 3. Wireless Threats

Wireless networks are vulnerable to various attacks due to their nature.

#### Access Control Attacks

-   **MAC Spoofing:** Changing MAC address to impersonate an authorized device or bypass MAC filtering.
-   **AP Misconfiguration:** Misconfigured APs (e.g., default SSIDs, weak passwords, configuration errors) make networks vulnerable.
-   **Ad Hoc Associations:** Direct client-to-client connections bypassing APs, often unencrypted.
-   **Promiscuous Client:** A client in promiscuous mode can observe network traffic (passive sniffing).
-   **Client Mis-association:** Client intentionally/accidentally connects to a rogue AP or unapproved network.
-   **Unauthorized Association:** Attacker connects to a wireless network without authorization using various methods (e.g., creating a rogue AP).

#### Integrity Attacks

Attackers try to change or alter data during transmission.

-   **Data-Frame Injection:** Injecting forged 802.11 frames.
-   **WEP Injection:** Injecting crafted WEP encryption keys.
-   **Bit-Flipping Attacks:** Flipping bits in encrypted data to alter plaintext without knowing the key.
-   **Extensible AP Replay:** Replaying 802.1X Extensible Authentication Protocol (EAP) messages.
-   **Data Replay:** Replaying captured 802.11 data frames.
-   **Initialization Vector (IV) Replay:** Deriving the keystream by sending a plaintext message and replaying IVs.
-   **RADIUS Replay:** Replaying RADIUS Access-Accept or Reject messages.
-   **Wireless Network Viruses:** Malware designed to spread across wireless networks.

#### Confidentiality Attacks

These attacks intercept confidential information sent over a wireless network, regardless of encryption.

-   **Eavesdropping:** Capturing and decoding unprotected wireless traffic.
-   **Traffic Analysis:** Inferring information from observing network traffic characteristics.
-   **Cracking WEP Key:** Decrypting WEP keys.
-   **Evil Twin AP:** Attacker sets up a rogue AP with the same SSID as a legitimate AP to lure victims and steal credentials (phishing).
-   **Honeypot AP:** Setting up a decoy AP to gather attacker information.
-   **Session Hijacking:** Taking over an established wireless session.
-   **Masquerading:** Pretending to be an authorized user/device.
-   **MITM Attack:** Intercepting and potentially altering wireless communications.
-   **aLTEr Attack:** A virtual (fake) communication tower to intercept wireless communication, manipulate traffic, and redirect to malicious websites.

#### Availability Attacks

These attacks obstruct the delivery of wireless services to legitimate users (DoS).

-   **Access Point Theft:** Physically removing an AP.
-   **Disassociation Attacks:** Destroying connectivity between an AP and client.
-   **De-authentication Attacks:** Flooding clients with forged de-authentication messages to disconnect them from an AP.
-   **EAP-Failure:** Exploiting EAP to cause DoS.
-   **Beacon Flood:** Generating thousands of counterfeit 802.11 beacons to make it difficult to find a legitimate AP.
-   **Denial-of-Service (DoS):** Overwhelming the wireless network with traffic (e.g., jamming, signal flooding).
-   **Routing Attacks (Wormhole Attack, Sinkhole Attack):** Exploiting routing protocols to redirect traffic or create black holes.
-   **Authenticate Flood:** Sending forged authenticate messages to exhaust AP's association table.
-   **ARP Cache Poisoning Attacks:** Poisoning ARP cache on wireless devices.
-   **Power Saving Attacks:** Manipulating power-saving mechanisms to cause DoS.
-   **TKIP MIC Exploit:** Generating invalid TKIP data to suspend WLAN service.

#### Authentication Attacks

These attacks steal Wi-Fi client identities and login information to gain unauthorized access.

-   **PSK Cracking:** Recovering WPA PSK from captured key handshakes (brute-force/dictionary).
-   **LEAP Cracking:** Recovering user credentials from LEAP.
-   **VPN Login Cracking:** Cracking VPN credentials.
-   **Domain Login Cracking:** Recovering Windows domain login hashes.
-   **Key Reinstallation Attack (KRACK):** Exploiting vulnerabilities in the WPA2 four-way handshake to reinstall keys, allowing traffic decryption and injection.
-   **Identity Theft:** Capturing user identities from 802.1X traffic.
-   **Shared Key Guessing:** Cracking WEP keys.
-   **Password Speculation:** Guessing passwords based on 802.11 traffic.
-   **Application Login Theft:** Capturing user credentials from application protocols.

#### Wireless Specific Attacks

-   **Honeypot AP Attack:** Attacker creates a rogue AP masquerading as a legitimate one to lure victims and steal information.
-   **Wormhole Attack:** Exploiting routing protocols to create a "wormhole" tunnel, redirecting traffic through an attacker-controlled node.
-   **Sinkhole Attack:** Advertising a compromised node as the best possible route to the base station, attracting all traffic.
-   **Inter-Chip Privilege Escalation/Wireless Co-Existence Attack:** Exploiting vulnerabilities in wireless chips (e.g., Bluetooth/Wi-Fi combo chips) to gain privilege escalation.

### 4. Wireless Hacking Methodology

A systematic process to compromise a Wi-Fi network.

1.  **Wi-Fi Discovery / Wireless Network Footprinting:**
    
    -   Attacker starts by discovering Wi-Fi networks and locating/analyzing them.
    -   **Passive Footprinting:** Detecting APs and clients by sniffing existing traffic without injecting packets.
    -   **Active Footprinting:** Sending probe requests with spoofed SSIDs to gather responses from APs.
    -   **WarChalking:** Marking areas with Wi-Fi availability.
    -   **WarDriving:** Driving around with Wi-Fi-enabled laptops to map open wireless networks.
    -   **WarFlying:** Using drones to detect open wireless networks.
    -   **WPS (Wi-Fi Protected Setup) Enabled APs:** Identifying APs with WPS enabled, which is vulnerable to brute-force attacks.
    -   **Tools:** `inSSIDer`, `NetSurveyor`, `Wi-Fi Scanner`, `Acrylic Wi-Fi Heatmaps`, `WirelessMon`, `Ekahau Wi-Fi Heatmaps`, `NetSpot`, `AirMagnet Survey PRO`, `WiFi Analyzer`, `Opensignal`, `Network Signal Info Pro`, `Net Signal Pro:WiFi & 5G Meter`, `NetSpot WiFi Analyzer`, `WIFIman`, `Wash` (for WPS-enabled APs), `Airodump-ng`.
2.  **Wireless Traffic Analysis:**
    
    -   Capturing and analyzing wireless traffic to identify vulnerabilities, connected clients, and encryption methods.
    -   **Tools:** `Wireshark`, `Riverbed Packet Analyzer`, `OmniPeek Network Protocol Analyzer`, `CommView for Wi-Fi`, `Kismet`, `Acrylic Wi-Fi Analyzer`, `airgeddon`.
    -   **Choosing Optimal Wi-Fi Card:** Selecting a wireless card that supports packet injection and monitoring.
    -   **Spectrum Analysis:** Analyzing RF spectrum for interference and potential vulnerabilities. Tools: `RF Explorer`, `Chanalyzer`, `AirCheck G3 Pro`, `Spectraware S1000`, `RSA306B USB Spectrum Analyzer`, `Monics`, `Signal Hound`, `FIELDSENSE`.
3.  **Launch of Wireless Attacks:**
    
    -   **Aircrack-ng Suite:** A comprehensive suite of tools for Wi-Fi auditing and cracking (Airodump-ng, Aircrack-ng, Aireplay-ng, Airbase-ng, Airmon-ng, Airodump-ng, Airolib-ng, Airtun-ng).
    -   **Detection of Hidden SSIDs:** Using `airodump-ng` to discover hidden SSIDs.
    -   **MAC Spoofing Attack (AP MAC Spoofing):** Impersonating APs by changing MAC addresses. Tools: `Technitium MAC Address Changer`.
    -   **Wireless ARP Poisoning Attack:** Spoofing ARP packets on wireless networks to redirect traffic. Tools: `arpspoof`, `Ettercap`.
    -   **Rogue APs:** Setting up unauthorized APs to lure clients and steal data. Tools: MANA Toolkit (`hostapd-mana.conf`, `start-nat-simple.sh`).
    -   **Evil Twin Attack:** Creating a rogue AP with the same SSID as a legitimate one to trick users.
    -   **Key Reinstallation Attack (KRACK):** Exploiting WPA2 four-way handshake vulnerability.
    -   **Jamming Signal Attack:** Overloading wireless network frequencies to cause DoS. Tools: Wi-Fi jamming devices (e.g., CPB-4510 Jammer).
    -   **aLTEr Attack:** Virtual communication tower for MITM attacks on LTE/4G/5G.
4.  **Wi-Fi Encryption Cracking:** (Often part of 'Launch of Wireless Attacks') - focuses on breaking encryption keys.
    
5.  **Compromise the Wi-Fi Network:** (The ultimate goal after successful attacks).
    

### 5. Wireless Attack Countermeasures

Implementing multi-layered security measures is crucial.

#### Wireless Encryption & Authentication Countermeasures

-   **Use Strong Encryption (WPA2-Enterprise or WPA3):** Always prefer WPA3-Enterprise or WPA2-Enterprise with strong authentication (EAP-TLS, PEAP) and a RADIUS server.
-   **Strong Passwords for WPA2-Personal/WPA3-Personal:** Use complex, long pre-shared keys.
-   **Regular Key Rotation:** Change keys periodically.
-   **Enable MAC Address Filtering:** Restrict access to known MAC addresses (can be bypassed by spoofing).
-   **Disable SSID Broadcast:** Hiding the SSID makes network discovery slightly harder, but does not prevent determined attackers.
-   **Use Centralized Authentication (RADIUS/EAP):** For enterprise environments.
-   **Implement 802.1X:** Port-based network access control.

#### Network Configuration & Management

-   **Change Default Settings:** Change default SSIDs, passwords, and admin credentials on APs.
-   **Proper AP Placement:** Place APs strategically to avoid signal leakage outside the desired coverage area.
-   **Network Segmentation (VLANs):** Isolate wireless network traffic from the wired network.
-   **Firewalls and IDS/IPS:** Implement firewalls to filter wireless traffic and IDS/IPS to detect suspicious activity.
-   **Disable WPS:** WPS is vulnerable to brute-force attacks.
-   **Disable Unused Services on APs.**
-   **Physical Security:** Secure APs against physical tampering or theft.
-   **Regular Firmware Updates:** Keep APs and wireless devices updated.
-   **Monitor Wireless Logs:** For unusual activity.

#### Client-Side Countermeasures

-   **Disable Auto-Connect to Unknown Networks.**
-   **Verify AP Authenticity:** Be cautious of suspicious or unauthenticated APs (Evil Twins).
-   **Use VPNs (Virtual Private Networks):** Encrypt traffic over untrusted wireless networks.
-   **Keep OS and Client Software Updated:** Patch vulnerabilities in wireless drivers and OS.
-   **Personal Firewalls:** On client devices.
-   **User Awareness Training:** Educate users about wireless threats (Evil Twin, phishing).
-   **Strong Password for Wi-Fi Networks.**
-   **Disable Ad Hoc Mode on Clients:** Prevent unauthorized direct connections.
-   **Use Digital Certificates for Authentication.**

#### Countermeasures for Specific Attacks

-   **Against MAC Spoofing:** Implement 802.1X with centralized authentication, or use port security on switches (if AP is wired).
-   **Against Evil Twin:** Educate users to verify network names, use VPNs, and disable auto-connect. Use wireless IDS/IPS.
-   **Against KRACK:** Apply patches immediately to all Wi-Fi devices.
-   **Against Jamming:** Use spread spectrum technologies, signal hopping, and consider spectrum analysis tools.

#### Wireless Security Tools (Countermeasures/Detection)

-   **Wi-Fi Auditors:** (e.g., Aircrack-ng, inSSIDer, NetSurveyor).
-   **Wireless IDS/IPS:** (e.g., Cisco Wireless IPS, AirTight Networks, Wireless Guard).
-   **Wireless Security Gateways:** (e.g., SonicWall Wireless Network Security, FortiAP).
-   **Endpoint Protection:** On client devices (antivirus, host-based firewalls).

----------

## Key Terms for Last-Minute Revision

-   **Wireless Network (Wi-Fi):** Uses radio-frequency tech.
-   **Access Point (AP):** Connects wireless devices.
-   **SSID:** Wireless network identifier.
-   **BSSID:** MAC address of an AP.
-   **802.11 Standards:** Family of Wi-Fi standards (a, b, g, n, ac, ax, be).
-   **OFDM, DSSS, FHSS:** Wireless modulation/spread spectrum techniques.
-   **MIMO-OFDM:** Multiple Input, Multiple Output.
-   **WEP:** Wired Equivalent Privacy (old, vulnerable encryption).
-   **IV (Initialization Vector):** Used in WEP, often reused, making WEP crackable.
-   **RC4:** Stream cipher used in WEP.
-   **WPA:** Wi-Fi Protected Access (improves WEP).
-   **TKIP:** Temporal Key Integrity Protocol (used in WPA).
-   **MIC:** Message Integrity Check (used in WPA).
-   **WPA2:** Wi-Fi Protected Access 2 (stronger, uses AES/CCMP).
-   **AES (Advanced Encryption Standard):** Strong encryption standard.
-   **CCMP:** Counter Mode Cipher Block Chaining Message Authentication Code Protocol.
-   **WPA2-Personal (PSK):** Pre-shared Key mode.
-   **WPA2-Enterprise:** Uses EAP/RADIUS for authentication.
-   **EAP (Extensible Authentication Protocol):** Authentication framework.
-   **RADIUS:** Centralized authentication server.
-   **WPA3:** Wi-Fi Protected Access 3 (latest, uses SAE).
-   **SAE (Simultaneous Authentication of Equals):** Stronger PSK in WPA3.
-   **OWE (Opportunistic Wireless Encryption):** For public hotspots in WPA3.
-   **MAC Spoofing:** Changing MAC address.
-   **AP Misconfiguration:** Improperly configured AP.
-   **Evil Twin AP:** Rogue AP impersonating a legitimate one.
-   **De-authentication Attack:** Flooding clients with de-auth messages.
-   **Beacon Flood:** Flooding network with fake beacons.
-   **DoS (Denial-of-Service):** Making network resources unavailable.
-   **Jamming:** Overloading wireless frequencies.
-   **Wormhole Attack:** Exploiting routing protocols to create a tunnel.
-   **Sinkhole Attack:** Advertising a compromised node as the best route.
-   **KRACK (Key Reinstallation Attack):** WPA2 vulnerability.
-   **aLTEr Attack:** MITM on LTE/4G/5G.
-   **Wireless Footprinting:** Discovering and mapping wireless networks.
-   **WarDriving/WarChalking/WarFlying:** Methods of wireless discovery.
-   **WPS (Wi-Fi Protected Setup):** Vulnerable setup mechanism.
-   **Aircrack-ng Suite:** Wireless hacking tools (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng).
-   **inSSIDer/NetSurveyor:** Wi-Fi discovery tools.
-   **Wireshark:** Network protocol analyzer (for wireless traffic).
-   **VLANs:** Network segmentation for wireless security.
-   **VPN:** Virtual Private Network (for secure communication over insecure Wi-Fi).
-   **802.1X:** Port-based network access control.
-   **Wireless IDS/IPS:** Detects/prevents wireless attacks.
