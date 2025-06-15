## Module 11: Session Hijacking - Key Concepts and Notes

This module delves into session hijacking, an attack where an attacker takes over an active communication session by bypassing authentication. It covers concepts, techniques at both application and network levels, tools, and countermeasures.

### Learning Objectives

-   Summarize Session Hijacking Concepts.
-   Explain Application-Level Session Hijacking.
-   Explain Network-Level Session Hijacking.
-   Use Session Hijacking Tools.
-   Apply Session Hijacking Countermeasures.

### 1. Session Hijacking Concepts

What is Session Hijacking?

An attack where an attacker seizes control of a valid TCP communication session between two computers. Since most authentication occurs only at the start of a TCP session, this allows the attacker to gain unauthorized access to a machine once a session is in progress. The attacker steals a valid session ID (token) and uses it to authenticate themselves with the server.

-   **Session Token/ID:** A unique identifier sent by a web server to a client after successful authentication, differentiating multiple sessions.
-   Attackers can sniff traffic from established sessions to perform identity theft, information theft, fraud, etc.
-   Can be used to launch Man-in-the-Middle (MITM) and Denial-of-Service (DoS) attacks.

#### Why is Session Hijacking Successful?

-   **Absence of account lockout for invalid session IDs:** Allows brute-force attempts on session IDs without penalty.
-   **Weak session-ID generation algorithm or small session IDs:** Predictable or short IDs are easier to guess or brute-force.
-   **Insecure handling of session IDs:** Session IDs can be retrieved through DNS poisoning, Cross-Site Scripting (XSS), or browser bugs.
-   **Indefinite session timeout:** "Remember me" options or long session durations give attackers more time to exploit captured session IDs.
-   **Vulnerability of TCP/IP:** Design flaws inherent in TCP/IP make all machines running it vulnerable.
-   **Lack of Encryption:** Easy to sniff session IDs in plaintext if transport security (SSL/TLS) is not properly implemented.

#### Session Hijacking Process

1.  **Sniff:** Attacker places themselves between the victim and the target to sniff network traffic and capture session information (e.g., sequence numbers).
2.  **Monitor:** Monitor the flow of packets to predict sequence and acknowledgment numbers.
3.  **Session Desynchronization:** Break the legitimate connection between the victim and the server by injecting packets (e.g., sending null data to advance SEQ/ACK numbers, or RST/FIN flags to reset/close connection on server side).
4.  **Session ID Prediction:** Predict the next valid session ID or use the captured one to take over the session.
5.  **Command Injection:** Start injecting malicious packets to the target server, impersonating the legitimate user.

#### Types of Session Hijacking

-   **Passive Session Hijacking:** Attacker observes and records all traffic during the session without active interference. Used to obtain user IDs and passwords for later login. Difficult to detect.
-   **Active Session Hijacking:** Attacker takes over an existing session by breaking the connection of the legitimate user or actively participating in the conversation (MITM). More detectable.

#### Session Hijacking in OSI Model

-   **Network-Level Hijacking:** Intercepts packets during TCP or UDP sessions (e.g., TCP/IP hijacking, UDP hijacking). Does not require host access.
-   **Application-Level Hijacking:** Gains control over HTTP user sessions by obtaining session IDs. Focuses on web applications.

#### Spoofing vs. Hijacking

-   **Spoofing:** Attacker pretends to be another user or machine by forging credentials or IP/MAC addresses. Initiates a _new_ session using stolen credentials.
-   **Hijacking:** Attacker takes _control of an existing, active session_ after authentication has already occurred.

### 2. Application-Level Session Hijacking

This focuses on web application sessions, often by compromising the session token.

-   **Stealing Session IDs:** Attackers use various techniques to steal session IDs:
    -   **Sniffing:** Capturing session IDs from network traffic (if unencrypted).
    -   **Client-side attacks:** Using XSS (Cross-Site Scripting) or malicious JavaScript to steal cookies containing session IDs.
    -   **Malicious JavaScript Codes:** Injected scripts that capture tokens.
    -   **Trojans:** Malware that intercepts session data.
-   **Guessing Session IDs:** Attacker attempts to guess valid session IDs if the generation algorithm is weak or predictable (brute-force).
    -   **Sequential Tokens:** IDs are generated in a predictable sequence (e.g., 001, 002, 003).
    -   **Timestamp-based Tokens:** IDs include a timestamp, making them easier to predict.
    -   **Small Token Space:** A small number of possible tokens makes brute-forcing feasible.
    -   **Weak Random Number Generators (PRNG):** Predictable random numbers for session IDs.
-   **Compromising Session IDs using Man-in-the-Middle/Manipulator-in-the-Middle Attack:** Attacker intercepts and modifies communication between client and server.
-   **Compromising Session IDs using Man-in-the-Browser Attack:** Trojan horse intercepts and manipulates browser activity, affecting web transactions and potentially bypassing PKI/2FA.
-   **Compromising Session IDs using Client-side Attacks:**
    -   **Cross-Site Scripting (XSS):** Injecting malicious client-side scripts to steal cookies or session info.
    -   **Cross-Site Request Forgery (CSRF):** Tricks a user's browser into performing unwanted actions on a trusted site by exploiting implicit trust.
-   **Compromising Session IDs using Session Replay Attacks:** Captures an authentication token and replays it to gain unauthorized access.
-   **Compromising Session IDs using Session Fixation:** Attacker forces a user's browser to use a specific, known session ID. When the user logs in, that session ID becomes authenticated, allowing the attacker to hijack it.
-   **Session Hijacking using CRIME Attack:** (Compression Ratio Info-leak Made Easy) A client-side attack against TLS/SSL compression, exploiting vulnerabilities to decrypt session cookies and steal sensitive information.
-   **Session Hijacking using Forbidden Attack:** A MITM attack using a cryptographic nonce (random number) during the TLS handshake to inject malicious code and bypass security.
-   **Session Hijacking using Session Donation Attack:** Attacker donates their own session ID to the target user, lures them to log in, and then hijacks the now-authenticated session.

### 3. Network-Level Session Hijacking

Focuses on exploiting transport and Internet protocols (TCP/IP, UDP) at the network layer.

-   **TCP/IP Hijacking:** Attacker intercepts and takes over an established TCP connection between two communicating parties by spoofing packets. Involves sniffing, desynchronization, and command injection.
    -   **Blind Hijacking:** Attacker injects malicious data/commands without seeing the response from the server.
    -   **IP Spoofing (Source Routed Packets):** Attacker uses source routing to specify the path of packets, allowing them to hide their true IP and inject into a trusted host's session.
-   **RST Hijacking:** Attacker injects an authentic-looking RST packet with a spoofed source IP and predicted sequence/acknowledgment numbers to reset the victim's connection.
-   **UDP Hijacking:** Similar to TCP hijacking but for UDP sessions. More challenging due to stateless nature, but no sequence numbers make it less complex than TCP.
-   **MITM Attack using Forged ICMP and ARP Spoofing:** Attacker intercepts communication by forging ICMP redirect messages or ARP replies to reroute traffic through their machine.
-   **PetitPotam Hijacking:** Attack where attacker forces a domain controller to initiate authentication to their server, allowing them to relay NTLM credentials and gain admin privileges.

### 4. Session Hijacking Tools

-   **Hetty:** HTTP toolkit for security research, MITM proxy with logs.
-   **Caido:** Web security auditing toolkit for intercepting/testing HTTP requests.
-   **bettercap:** Framework for Wi-Fi, Bluetooth, network attacks, and reconnaissance.
-   **Burp Suite:** Web vulnerability scanner and interception proxy.
-   **OWASP ZAP:** Open-source web application security scanner.
-   **WebSploit Framework:** Penetration testing framework with various modules.
-   **sslstrip:** Tool for SSL stripping (downgrading HTTPS to HTTP).
-   **JHijack:** Session hijacking tool.

### 5. Session Hijacking Countermeasures

Protecting against session hijacking requires robust security practices across all layers.

#### Session Hijacking Detection Methods

-   **Manual Method:** Using packet sniffing software (Wireshark, SteelCentral Packet Analyzer) to monitor network traffic for suspicious patterns (repeated ARP updates, ACK storms, different MAC addresses for client/server).
-   **Automatic Method:** Using Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) to monitor incoming network traffic for attack signatures.

#### Protecting against Session Hijacking (General)

-   **Use Secure Shell (SSH) / OpenSSH:** To create secure communication channels.
-   **Pass authentication cookies over HTTPS connections:** Always use HTTPS.
-   **Implement log-out functionality:** For user to end the session properly.
-   **Generate Session IDs after successful login:** New ID after authentication.
-   **Encrypt data in transit:** Ensures data is encrypted during transmission.
-   **Use strong or long random numbers as session keys:** Makes session ID prediction difficult.
-   **Use different usernames and passwords for different accounts.**
-   **Educate employees:** Minimize remote access.
-   **Implement timeout mechanism:** Automatically expire inactive sessions.
-   **Avoid session ID in URL:** Don't include session IDs in the URL query string.
-   **Switch from a hub to a network switch:** (Hubs are outdated, but switches provide isolation).
-   **IDS products or ARPwatch:** For monitoring ARP cache poisoning.
-   **Firewalls and browser settings:** To confine cookies.
-   **Protect authentication cookies with Secure Sockets Layer (SSL).**
-   **Regularly update platform patches:** To fix TCP/IP vulnerabilities.
-   **Use IPsec:** To encrypt session information.
-   **Verify website authenticity:** Network notary services.
-   **Implement DNS-based authentication:** For named entities.
-   **Disable HTTP request compression.**
-   **Restrict Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF).**
-   **Upgrade web browsers to latest versions.**
-   **Vulnerability scanners:** To detect insecure HTTPS session settings.
-   **Enable HTTPOnly property:** Prohibit user scripts from accessing cookies.
-   **SSH file transfer protocol (SFTP), Applicability Statement 2 (AS2)-managed file transfer, or FTP Secure (FTPS):** Secure file transfers.
-   **Microsoft-based solution (SMB signing):** To enable traffic signing.
-   **Secure socket layer (SSL) or transport layer security (TLS):** To decrease chances of successful hijacks.
-   **Implement IPsec:** To secure IP communications.
-   **Encrypted virtual private networks (VPNs):** For remote connections.
-   **Multi-factor authentication (MFA):** To reduce chances of unauthorized access.
-   **Samesite cookie attribute:** To prevent sending cookies along with cross-site requests.
-   **Monitor unusual patterns:** For multiple simultaneous logins from different locations.
-   **Educate users on application logging and unique passwords.**
-   **Bind the session to the user's IP address.**

#### Approaches to Prevent Session Hijacking (Specifics)

-   **HTTP Strict Transport Security (HSTS):** Forces browsers to interact with HTTPS websites only, preventing MITM downgrade attacks.
-   **Token Binding:** Binds authentication tokens/cookies to the client's TLS session to prevent their theft or misuse.
-   **Prevent MITM Attacks:**
    -   **DNS over HTTPS (DoH):** Encrypts DNS queries to prevent DNS spoofing.
    -   **WPA3 Encryption:** For secure wireless networks.
    -   **VPN:** Encrypted tunnel for secure communication.
    -   **Two-Factor Authentication:** Adds a second layer of proof.
    -   **Password Manager:** Securely stores unique, complex passwords.
    -   **Zero-trust Principles:** Verify every user and device before granting access.
    -   **Public Key Infrastructure (PKI):** Manages digital certificates for secure communication.
    -   **Network Segmentation:** Divides network to limit attacker's ability to move laterally.
-   **IPsec (Internet Protocol Security):** A suite of protocols providing secure exchange of packets at the IP layer. Offers authentication, data integrity, confidentiality, and replay protection.
    -   **Transport Mode:** Encrypts only the payload.
    -   **Tunnel Mode:** Encrypts the entire IP packet (payload + IP header), used for VPNs.

#### Session Hijacking Prevention Tools

-   **Checkmarx One SAST:** Source-code analysis for vulnerabilities.
-   **Fiddler:** Web debugging proxy to intercept and modify HTTP/HTTPS traffic.
-   **Nessus:** Vulnerability scanner.
-   **Invicti/Wapiti:** Web application security scanners.

#### Session Hijacking Detection Tools

-   **USM Anywhere (AT&T Cybersecurity):** Unified security management platform.
-   **Wireshark:** Network protocol analyzer.
-   **Quantum Intrusion Prevention System (Check Point).**
-   **SolarWinds Security Event Manager.**
-   **IBM Security Network Intrusion Prevention System.**
-   **LogRhythm.**

----------

## Key Terms for Last-Minute Revision

-   **Session Hijacking:** Seizing control of an active communication session.
-   **Session ID/Token:** Unique identifier for a user's session.
-   **TCP/IP Hijacking:** Taking over an active TCP connection.
-   **UDP Hijacking:** Taking over an active UDP session.
-   **Man-in-the-Middle (MITM):** Attacker intercepts and relays communication.
-   **Man-in-the-Browser (MITB):** Trojan-based MITM that modifies browser activity.
-   **Cross-Site Scripting (XSS):** Injecting malicious scripts to steal session IDs.
-   **Cross-Site Request Forgery (CSRF):** Tricking browser to perform unwanted actions.
-   **Session Replay Attack:** Replaying captured authentication tokens.
-   **Session Fixation:** Forcing a user to use a predictable session ID.
-   **CRIME Attack:** Exploits TLS/SSL compression to decrypt cookies.
-   **Forbidden Attack:** MITM using cryptographic nonce.
-   **Session Donation Attack:** Attacker gives a victim a session ID and then hijacks it.
-   **PetitPotam Hijacking:** Exploits MS-EFSRPC to gain admin privileges.
-   **HSTS (HTTP Strict Transport Security):** Forces HTTPS communication.
-   **Token Binding:** Binds tokens to TLS session to prevent misuse.
-   **DNS over HTTPS (DoH):** Encrypts DNS queries.
-   **IPsec:** Suite of protocols for secure IP communication (Transport & Tunnel modes).
-   **2FA/MFA:** Two-Factor/Multi-Factor Authentication.
-   **IDS/IPS:** Intrusion Detection/Prevention Systems (detection).
-   **Wireshark:** Packet sniffing tool.
-   **Honeypots:** Decoy systems for detection.
-   **Egress/Ingress Filtering:** Network traffic control.
-   **Port Security:** Switch security feature.
-   **VLAN Hopping:** Bypassing VLAN segmentation.
