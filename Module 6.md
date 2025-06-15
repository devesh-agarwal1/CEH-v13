## Module 06: System Hacking - Key Concepts and Notes

This module focuses on the tools and techniques attackers use to hack target systems, building upon information acquisition methods like footprinting, scanning, enumeration, and vulnerability analysis.

### Learning Objectives

-   Explain techniques to gain access to a system.
-   Apply privilege escalation techniques.
-   Explain techniques to gain and maintain remote access to a system.
-   Describe different types of rootkits.
-   Explain steganography and steganalysis techniques.
-   Apply techniques to hide evidence of compromise.
-   Apply various system hacking countermeasures.

### Gaining Access

Attackers use various techniques to gain access to a target system, including password cracking, exploiting buffer overflows, and exploiting identified vulnerabilities.

### Microsoft Authentication

Windows authenticates users using mechanisms/protocols:

#### 1. Security Accounts Manager (SAM) Database

-   Windows stores user passwords in the SAM database or Active Directory database in hashed format (one-way hash).
    
-   Passwords are never stored in clear text.
    
-   The SAM database is implemented as a registry file.
    
-   The Windows kernel maintains an exclusive filesystem lock on the SAM file, preventing direct copying while Windows is running.
    
-   Attackers can dump the on-disk contents of the SAM file for offline brute-force attacks.
    
-   The SAM file uses an SYSKEY function (Windows NT 4.0+) to partially encrypt password hashes.
    
-   LM (LAN Manager) hashes are susceptible to cracking; newer Windows versions (Vista and later) disable them by default.
    
-   LM hashes cannot be calculated for passwords exceeding 14 characters; a "dummy" value is set instead.
    

#### 2. NTLM Authentication (NT LAN Manager)

-   A default authentication scheme using a challenge/response strategy.
    
-   Consists of NTLM authentication protocol and LAN Manager (LM) authentication protocol.
    
-   Uses different hash methodologies to store passwords in the SAM database.
    
-   NTLM includes LM, NTLMv1, and NTLMv2, differing primarily in encryption levels.
    
-   The client and server negotiate an authentication protocol via the Microsoft-negotiated Security Support Provider (SSP).
    

**NTLM Authentication Process** :

1.  Client enters username and password.
    
2.  Windows hashes the password.
    
3.  Client sends login request to the domain controller (DC).
    
4.  DC generates and sends a 16-byte random string ("nonce") to the client.
    
5.  Client encrypts the nonce with its password hash and sends it back to the DC.
    
6.  DC retrieves its stored password hash from SAM, encrypts the nonce, and compares the value with the client's response. A match authenticates the client.
    

#### 3. Kerberos Authentication

-   A network authentication protocol providing strong authentication for client/server applications using secret-key cryptography.
    
-   Provides mutual authentication (server and user verify each other).
    
-   Messages are protected against replay attacks and eavesdropping.
    
-   Employs a **Key Distribution Center (KDC)**, a trusted third party.
    
-   KDC has two parts: **Authentication Server (AS)** and **Ticket-Granting Server (TGS)**.
    
-   Uses "tickets" to prove a user's identity.
    
-   Microsoft has upgraded its default authentication protocol to Kerberos, offering stronger security than NTLM.
    
-   Kerberos provides a **Ticket-Granting Ticket (TGT)** for post-authentication access to services (Single Sign-On).
    

### Tools to Extract Password Hashes

-   **pwdump7**: Extracts LM and NTLM password hashes from NT's SAM database. Can dump protected files and extract passwords offline. Requires administrative privileges on the remote system.
    
-   **Mimikatz**: A post-exploitation tool that extracts plaintext passwords, Kerberos tickets, and NTLM hashes from LSASS process memory.
    
-   **DSInternals**: Tool for Active Directory.
-   **Hashcat**: Advanced password recovery tool.
-   **PyCrack**: Python-based password cracking tool.

### Password Cracking

Password cracking is the process of recovering passwords from transmitted data or stored hashes. It can be done offline or online.

#### Types of Password Attacks

-   **Non-Electronic Attacks**: Do not require technical knowledge to crack passwords. Examples include Social Engineering, Shoulder Surfing, and Dumpster Diving.
    
    -   **Social Engineering**: Tricking individuals into revealing credentials.
        
    -   **Shoulder Surfing**: Observing users enter credentials.
        
    -   **Dumpster Diving**: Searching discarded materials for sensitive information.
        
-   **Active Online Attacks**: Attackers directly communicate with the victim machine to gain access. Examples include Password Guessing, Dictionary Attack, Brute-Force Attack, Password Spraying, Mask Attack, Hash Injection, LLMNR/NBT-NS Poisoning, Kerberos Password Cracking (AS-REP Roasting, Kerberoasting), Pass-the-Hash, and Man-in-the-Middle Attack.
    
-   **Passive Online Attacks**: Attackers monitor or record data passing over the communication channel, then analyze it offline. Examples include Wire Sniffing, Man-in-the-Middle Attacks, and Replay Attacks.
    
-   **Offline Attacks**: Attackers try to recover cleartext passwords from a password hash dump (e.g., SAM file). Precomputed hashes are also used.
    

#### Active Online Attacks Explained

-   **Dictionary Attack**: Loads a dictionary of words into a cracking application to find passwords. It's effective against weak passwords. Can be improved by adding numbers/symbols or combining multiple dictionaries.
    
-   **Brute-Force Attack**: Tries every possible combination of characters until the correct password is found. Cryptographic algorithms make it difficult to prevent. It's a time-consuming process. Cryptanalysis is used to evaluate the strength of encryption.
    
-   **Rule-based Attack**: Uses information about the victim (e.g., birthdate, common patterns) to generate password guesses.
    
-   **Password Spraying Attack**: Attempts a single common password against multiple user accounts simultaneously to avoid account lockouts. Tools like `thc-hydra` are used for this.
    
-   **Hash Injection/Pass-the-Hash (PtH) Attack**: Uses a hash function to authenticate to a system without knowing the plaintext password. Attackers inject a compromised hash into a local session or use it to authenticate to network resources.
    
-   **LLMNR/NBT-NS Poisoning**: LLMNR (Link Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) are naming protocols. Attackers poison these services to resolve fake name queries, leading victims to send authentication requests to the attacker. Tools like `Responder` are used.
    
-   **Internal Monologue Attack**: Similar to Pass-the-Hash. Attackers extract plaintext passwords, Kerberos tickets, and NTLM hashes from LSASS process memory.
    
-   **Cracking Kerberos Password**: Exploiting vulnerabilities in Kerberos to crack passwords.
    
    -   **AS-REP Roasting (Cracking TGT)**: Attacks users configured not to require Kerberos preauthentication. Attackers request a Ticket Granting Ticket (TGT) for the user and decrypt it offline to obtain the password hash.
        
    -   **Kerberoasting (Cracking TGS)**: Attackers target service accounts (User Principal Names - UPNs) and obtain a service ticket from the TGS, then crack it offline to reveal the password.
        
-   **Pass the Ticket Attack**: Mimikatz can be used to pass Kerberos TGTs to authenticate to other computers without knowing the user's password.
    
-   **NTLM Relay Attack**: An attacker intercepts and relays NTLM authentication requests between a client and server to impersonate the client and gain unauthorized access.
    
-   **SSH Brute-Force Attack**: Uses tools like `ShellGPT` to perform dictionary or brute-force attacks against SSH services.
