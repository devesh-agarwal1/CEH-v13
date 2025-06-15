Here are notes and key terms from "CEHv13 - Module 07 - Malware Threats.pdf" to help you prepare for your CEH Certification exam:

## Module 07: Malware Threats - Key Concepts and Notes

This module provides knowledge about various types of malware, how they work and propagate, their symptoms, consequences, analysis techniques, and countermeasures.

### Learning Objectives

-   Explain Malware and Advanced Persistent Threat (APT) Concepts.
-   Explain Fileless Malware Concepts.
-   Explain AI-based Malware Concepts.
-   Demonstrate Malware Analysis Process.
-   Explain Malware Countermeasures.

### 1. Malware Concepts

**What is Malware?** Malicious software designed to damage or disable computer systems, or give limited/full control to the attacker for theft or fraud. It includes: viruses, worms, Trojans, rootkits, backdoors, botnets, ransomware, spyware, adware, crypters, keyloggers, etc.

**Malicious Activities of Malware:**

-   Attack browsers and track websites.
-   Slow down systems.
-   Cause hardware failure.
-   Steal personal information (contacts, financial data, credentials).
-   Erase valuable information.
-   Attack additional systems.
-   Send spam.
-   Spy on user activities and capture screenshots.
-   Make infected system part of a botnet.

#### Ways for Malware to Enter a System

-   **Instant Messenger Applications:** Via shared files (e.g., Facebook Messenger, WhatsApp).
-   **Portable Hardware Media/Removable Devices:** USB drives, memory cards (e.g., via Autorun feature).
-   **Browser and Email Software Bugs:** Exploiting vulnerabilities in outdated browsers or email clients.
-   **Insecure Patch Management:** Unpatched software is a high risk (e.g., Parse Server, Pandora FMS, WPVibes, Microsoft Edge vulnerabilities).
-   **Rogue/Decoy Applications:** Free, seemingly legitimate programs that contain malware.
-   **Untrusted Sites & Free Web Applications/Software:** Websites offering pirated or "underground" software, or professional-looking malicious sites.
-   **Downloading Files from the Internet:** Malicious files disguised as legitimate downloads (music players, movies, games, greeting cards, screensavers, malicious MS Word/Excel macros, embedded in audio/video/subtitle files).
-   **Email Attachments:** Most common medium, tricking victims into clicking malicious files.
-   **Network Propagation:** Exploiting network vulnerabilities (e.g., Blaster worm, SQL Slammer).
-   **File Sharing:** Exploiting open file-sharing ports (NetBIOS, FTP, SMB) to install malware.
-   **Installation by other Malware:** One malware installing another.
-   **Bluetooth and Wireless Networks:** Open Wi-Fi/Bluetooth networks used to capture user data.

#### Components of Malware

-   **Crypter:** Encrypts malware to evade antivirus detection.
-   **Downloader:** A Trojan that downloads other malware/malicious code.
-   **Dropper:** Installs malware covertly (often embeds malicious files).
-   **Exploit:** Code that takes advantage of a vulnerability.
-   **Injector:** Injects exploits or malicious code into running processes.
-   **Obfuscator:** Conceals malware code to make detection difficult.
-   **Packer:** Compresses malware to make it unreadable.
-   **Payload:** The malicious activity performed by the malware.
-   **Malicious Code:** The core harmful functionality of the malware.

#### Potentially Unwanted Applications (PUAs)

-   Also known as grayware/junkware.
-   Applications that pose security risks (e.g., adware, toolbars, privacy risks).
-   **Types of PUAs:**
    -   **Adware:** Displays unsolicited advertisements (pop-ups, banners).
    -   **Torrent:** Programs for downloading large files, often peer-to-peer file sharing.
    -   **Marketing:** Monitor online activities for targeted advertising.
    -   **Cryptomining:** Hijacks CPU to mine cryptocurrencies without user consent.
    -   **Dialers:** Programs that automatically call numbers (often premium rate numbers).

### 2. Advanced Persistent Threat (APT) Concepts

**What are APTs?** A type of network attack where an unauthorized person gains access to a network and stays there undetected for a long period.

-   **Advanced:** Uses sophisticated techniques, zero-days, custom tools.
-   **Persistent:** Long-term engagement within the target network.
-   **Threat:** Refers to the human element behind the attack.

**Characteristics of APTs:**

-   **Objectives:** Repeatedly obtain sensitive information, espionage.
-   **Timeliness:** Long-term presence.
-   **Resources:** Sophisticated tools and methods, highly skilled criminals.
-   **Risk Tolerance:** Remain undetected in target networks for long periods.
-   **Skills and Methods:** Social engineering, custom malware, evasion techniques.
-   **Actions:** Different types of cyber attacks over a long time.
-   **Attack Origin Points:** Multiple entry points to gain and launch further attacks.
-   **Numbers Involved:** Can involve many hosts.
-   **Knowledge Source:** Gathering information from various online sources.
-   **Multi-Phased:** Follows multiple phases (reconnaissance, access, discovery, data exfiltration).
-   **Tailored to Vulnerabilities:** Malicious code designed for specific targets.
-   **Multiple Points of Entries:** Establishes connections to multiple servers.
-   **Evading Signature-Based Detection Systems:** Uses zero-day exploits, rootkits, polymorphic malware.
-   **Specific Warning Signs:** Unusual user account activities, backdoor Trojans, unusual file transfers.
-   **Highly Targeted:** Meticulously planned against specific organizations or critical infrastructure.
-   **Long-term Engagement:** Long-term presence within the target network.
-   **Use of Advanced Techniques:** Spear-phishing, zero-day, rootkits, multi-stage malware.
-   **Complex Command and Control (C2) Infrastructure:** Sophisticated and often obfuscated C2 channels.

#### Advanced Persistent Threat Lifecycle (6 Phases)

1.  **Preparation:** Research target, acquire tools, define objective, identify trust for detection.
2.  **Initial Intrusion:** Enter target network (spear-phishing, exploiting vulnerabilities, compromised legitimate servers).
3.  **Expansion:** Expand access, obtain credentials, move laterally.
4.  **Persistence:** Maintain access, evade endpoint security, install backdoors.
5.  **Search and Exfiltration:** Gather data, exfiltrate data, use encryption.
6.  **Cleanup:** Remove evidence of presence, hide tracks.

### 3. Trojans

**What is a Trojan?** A Trojan (Trojan horse) is a program with malicious or harmful code disguised as legitimate software. It performs hidden malicious functions without the user's consent.

**How Hackers Use Trojans:**

-   Delete/replace OS critical files.
-   Generate fake traffic for DoS attacks.
-   Record screenshots, audio, video.
-   Spam victims.
-   Download spyware, adware, malicious files.
-   Disable firewalls and antivirus.
-   Gain remote access.
-   Act as a proxy server for relaying attacks.
-   Become part of a botnet for DDoS attacks.
-   Steal sensitive information (credit card, bank, web service passwords, account data).
-   Encrypt victim's machine/prevent access.

**Common Ports Used by Trojans:** Trojans often use specific ports for command and control or data transfer. The module provides a long list of specific Trojans and their corresponding ports (e.g., 2 (Death), 20/22/80/443 (Fireflotcker), 80 (NetMonitor), etc.). _For the exam, focus on understanding that Trojans utilize ports, rather than memorizing every single one._

#### Types of Trojans

1.  **Remote Access Trojans (RATs):** Provide full remote control over victim's system (e.g., Remcos RAT, Parallax RAT, AsyncRAT, Xeno RAT, MagicRAT).
2.  **Backdoor Trojans:** Bypass standard authentication/security to gain access (e.g., TinyTurla-NG, SmokeLoader).
3.  **Botnet Trojans:** Infect computers and make them part of a botnet for large-scale attacks (e.g., RDDos, Horabot, Satoni, Qakbot).
4.  **Rootkit Trojans:** Hide malicious programs and processes from detection (e.g., Reptile Rootkit, Fire Chili Rootkit).
5.  **E-Banking Trojans:** Target online banking credentials and financial data (e.g., Grandoreiro, Ursnif, IceID, Nexus, CHAFFCLOAK, Prilex).
6.  **Point-of-Sale (POS) Trojans:** Target POS systems to steal credit card data (e.g., Prilex POS, LockPOS, FastPOS).
7.  **Defacement Trojans:** Alter website content (e.g., Restorator).
8.  **Service Protocol Trojans:** Exploit vulnerable service protocols (VNC, HTTP/HTTPS, ICMP) to attack systems (e.g., VNC Trojans, HTTP RAT, ICMP Trojans).
9.  **Mobile Trojans:** Target mobile phones (e.g., Chameleon, Vultur).
10.  **IoT Trojans:** Attack Internet of Things devices (e.g., OpenSSH Trojan).
11.  **Security Software Disabler Trojans:** Stop the working of security programs (firewalls, IDS).
12.  **Destructive Trojans:** Designed to delete files and disrupt system operations (e.g., SilverRAT, HermeticWiper).
13.  **DDoS Attack Trojans:** Designed to launch Distributed Denial of Service attacks (e.g., Mirai botnet).
14.  **Command Shell Trojans:** Provide remote control via a command shell (e.g., Netcat, DNS Messenger, GCat).

#### How to Infect Systems Using a Trojan

Attackers use various techniques to propagate Trojans:

1.  **Create a Trojan:** Use construction kits (njRAT, Trojan Horse Construction Kit).
2.  **Employ a dropper/downloader:** Transmit the Trojan package to the victim's machine.
3.  **Employ a wrapper:** Binds the Trojan executable with legitimate applications.
4.  **Employ a crypter:** Encrypts the original binary code to evade antivirus.
5.  **Propagate the Trojan:** Through emails, covert channels, proxy servers, USB/Flash drives.
    -   **Overt vs. Covert Channels:** Overt is legitimate communication; covert is hidden, used for exfiltration.

**Techniques for Evading Antivirus Software (for Trojans):**

-   Breaking Trojan files into multiple pieces.
-   Embedding into applications with signatures that AV recognizes as legitimate.
-   Changing Trojan's syntax/extension (e.g., to VBScript, EXE, DLL).
-   Changing checksum and encrypting files.
-   Not downloading Trojans from untrusted web sources.
-   Using binder and splitter tools.
-   Perform code obfuscation or morphing.

### 4. Exploit Kits

**What are Exploit Kits?** Exploit kits (EKs) are toolkits used to exploit security loopholes in software applications. They are designed to automate the exploitation process.

**How Attackers Use Exploit Kits:**

1.  Identify a vulnerable service/application.
2.  Search for known exploits (e.g., on Exploit Database, VulDB).
3.  Download the exploit code.
4.  Modify if needed to suit environment.
5.  Execute the exploit against the target.
6.  Post-Exploitation activities (privilege escalation, data exfiltration, lateral movement).

**Various Exploit Sites:**

-   **Exploit Database (Exploit-db.com):** A large repository of pre-written exploit code.
-   **VulDB (vuldb.com):** Provides details on latest vulnerabilities and exploits, with exploitation probability ratings.
-   **OSV (osv.dev):** Vulnerability database for open-source projects.
-   **MITRE CVE (cve.org):** Database of vulnerabilities with CVE IDs.
-   **Windows Exploit Suggester - Next Generation (WES-NG):** Python tool to find exploits for Windows OS by comparing systeminfo.exe output to a CVE database.

### 5. Metasploit Framework

**What is Metasploit Framework?** A penetration-testing toolkit, exploit development platform, and research tool. It includes hundreds of working remote exploits for various platforms. It automates exploitation of web servers by abusing known vulnerabilities.

**Features for Web Server Attacks:**

-   Closed loop vulnerability validation.
-   Phishing simulations.
-   Social engineering.
-   Manual brute forcing.
-   Manual exploitation.
-   Evade-leading defensive solutions.

**Metasploit Architecture:**

-   **Libraries:** Rex, Framework-Core, Framework-Base.
-   **Interfaces:** msfconsole, msfvenom, msfrpc, msfrpcd, Armitage.
-   **Security Tools:** Web Services, Integration.
-   **Modules:** Auxiliary, Encoders, Evasion, Exploits, NOPs, Payloads, Post-exploitation.

#### Metasploit Modules Explained

-   **Metasploit Exploit Module:** Basic module used to encapsulate a single exploit, targeting multiple platforms.
    -   **Steps to exploit a system:** Configure active exploit, verify options, select target, select payload, launch exploit.
-   **Metasploit Payload Module:** An exploit carries a payload that executes on the system.
    -   **Singles:** Self-contained, complete.
    -   **Stagers:** Sets up a network connection, downloads stages.
    -   **Stages:** Downloaded by stager modules.
-   **Metasploit Auxiliary Module:** Performs arbitrary, one-off actions like port scanning, network discovery, fuzzing, DoS.
-   **Metasploit NOPs Module:** No-operation generators used for blocking out buffers.
-   **Metasploit Encoder Modules:** Encodes payloads to evade AV, IDS.
    -   **Key Functions:** Obfuscation, bypassing signature detection, polymorphism.
-   **Metasploit Evasion Modules:** Designed to modify payload behavior/characteristics to bypass AV, IDS, endpoint security.
-   **Metasploit Post-exploitation Modules:** Used after successfully compromising a target system.
    -   **Windows Gather Modules:** Enumerate users, collect credentials.
    -   **Linux Gather Modules:** Collect configuration files, dump password hashes.
    -   **Network Pivoting Modules:** Add routes to target network through compromised system.

### 6. AI-Powered Vulnerability Exploitation Tools

AI/ML is being used to enhance and automate vulnerability exploitation.

-   **Nebula:** AI-powered vulnerability exploitation tool.
    -   **Key Features:** AI-driven vulnerability detection/exploitation, automated threat analysis, real-time security monitoring, adaptive learning, leveraging NLP, command search engine.
-   **DeepExploit:** AI tool for automated vulnerability identification and exploitation.
    -   Utilizes a deep learning model to automate vulnerability identification and exploit vulnerabilities.
    -   **Workflow:** Data Collection, Neural Network Training, Payload Execution, Model Updating, Fully Automated Vulnerability Identification & Exploitation, Continuous Learning & Optimization.

### 7. Buffer Overflow Exploitation

**What is Buffer Overflow?** A buffer is an area of adjacent memory locations allocated to a program or application for runtime data. A buffer overflow occurs when an application attempts to write more data into a buffer than it was allocated, leading to overwriting neighboring memory. This can lead to system crashes, memory access errors, or malicious code execution.

**Why Programs and Applications are Vulnerable to Buffer Overflows:**

-   Boundary checks are not performed.
-   Outdated programming languages.
-   Unsafe/unusable functions.
-   Programmers fail to set proper filtering and validation.
-   Systems execute code present in the stack segment.
-   Improper memory allocation or insufficient input sanitization.

#### Types of Buffer Overflow

-   **Stack-Based Buffer Overflow:** Occurs in static memory allocation (stack), using LIFO (Last-In, First-Out) order. Overwriting data on the stack can change the program's execution flow.
    -   Stack memory includes: EBP (Extended Base Pointer), ESP (Extended Stack Pointer), EIP (Extended Instruction Pointer), ESI (Extended Source Index), EDI (Extended Destination Index).
-   **Heap-Based Buffer Overflow:** Occurs in dynamic memory allocation (heap). More complex to exploit as memory is allocated dynamically. Leads to overwriting dynamic object pointers.

#### Windows Buffer Overflow Exploitation Steps

1.  **Perform Spiking:** Send crafted TCP or UDP packets to the vulnerable server to crash it and identify buffer overflow vulnerabilities. Netcat is a tool used for this.
2.  **Perform Fuzzing:** Send a large amount of random data to the target server to crash it. Fuzzing helps determine the number of bytes needed to crash the server and the exact location of the EIP register.
3.  **Identify the Offset:** Determine the exact number of bytes needed to overwrite the EIP register. `pattern_create.rb` (Metasploit) is used to generate unique bytes.
4.  **Overwrite the EIP Register:** Overwrite the EIP register with a controlled value, redirecting execution.
5.  **Identify Bad Characters:** Find characters that break the shellcode.
6.  **Identify the Right Module:** Find a memory address (JMP ESP address) within the vulnerable process that allows jumping to shellcode.
7.  **Generate Shellcode and Gain Shell Access:** Use `msfvenom` (Metasploit) to generate shellcode and inject it to gain remote access.

### 8. Viruses and Worms

#### Viruses

**What is a Virus?** A self-replicating malicious program that attaches itself to other executable files or documents (host program) and spreads. It requires human interaction (e.g., running an infected file) to propagate.

**Characteristics of Viruses:**

-   Infects other programs.
-   Transforms itself (polymorphic, metamorphic).
-   Encrypts itself.
-   Alters data.
-   Corrupts files and programs.
-   Replicates itself.

**Purpose of Creating Viruses:**

-   Inflict damage on competitors.
-   Realize financial benefits.
-   Vandalize intellectual property.
-   Play pranks.
-   Conduct research.
-   Engage in cyber-terrorism.
-   Distribute political messages.
-   Damage networks or computers.
-   Gain remote access.

**Indications of Virus Attack:** Slow performance, system crashes, strange pop-ups, missing files, disabled antivirus, unusual network activity, unexpected reboots, etc.

**Stages of Virus Lifecycle:**

1.  **Design:** Development of virus code.
2.  **Replication:** Virus replicates itself and spreads.
3.  **Launch:** Virus activated and performs malicious actions.
4.  **Infection Phase:** Attaches to executable files, boot sectors, or scripts.
5.  **Attack Phase:** Performs intended malicious activities (data deletion, system slowdown).

**How a Computer Gets Infected by Viruses:**

-   Downloads from malicious websites.
-   Email attachments.
-   Pirated software.
-   Failing to install security software/updates.
-   Outdated browsers.
-   Firewall misconfiguration.
-   Pop-ups.
-   Removable media (USB).
-   Network access.
-   Malicious online ads.
-   Social media.

**Types of Viruses:**

-   **System or Boot Sector Virus:** Infects Master Boot Record (MBR) or DOS boot record.
-   **File Extension Virus:** Infects files with specific extensions (COM, EXE, SYS, OVL).
-   **Multipartite Virus:** Infects both boot sectors and executable files.
-   **Macro Virus:** Infects Microsoft Word/Excel documents using macros.
-   **Cluster Viruses:** Modify directory table entries to point to virus instead of legitimate program.
-   **Stealth/Tunneling Virus:** Evades detection by antivirus, hides itself.
-   **Encryption Viruses:** Encrypt their code to avoid detection.
-   **Sparse Infector Viruses:** Infests only occasionally, attempting to hide their presence.
-   **Polymorphic Viruses:** Mutate their code with each infection, making signatures harder to detect.
-   **Metamorphic Viruses:** Rewrite their code completely, making each instance unique.
-   **Overwriting File or Cavity Viruses:** Overwrite part of a host file.
-   **Companion/Camouflage Viruses:** Create a new executable with same name as legitimate program, running the virus instead.
-   **Shell Viruses:** The virus code forms a shell around the target host program's code.
-   **FAT Viruses:** Infect the File Allocation Table.
-   **Logic Bomb Virus:** Triggers at a specific date/time or event.
-   **Web Scripting Virus:** Exploits vulnerabilities in web browsers (XSS).
-   **Email Viruses:** Spread via email attachments.
-   **Armored Viruses:** Designed to confuse or trick antivirus software, difficult to trace.
-   **Add-on Viruses:** Add their code to the host code without making changes to the latter.
-   **Intrusive Viruses:** Overwrite the host code.
-   **Direct Action or Transient Viruses:** Load into memory, execute, then unload.
-   **Terminate and Stay Resident (TSR) Viruses:** Remain in memory after execution, controlling the system.

**Virus Hoaxes & Fake Antivirus:** False alarms claiming viruses or offering fake security software.

#### Worms

**What is a Worm?** A standalone malicious program that replicates itself and spreads across networks independently without human intervention. Consumes network bandwidth and system resources.

**How a Worm is Different from a Virus:**

Feature

Virus

Worm

**Infection Method**

Infects a system by inserting itself into a file/executable program.

Exploits vulnerabilities in OS/applications, replicates itself.

**Modification**

Can delete/alter files, change file location.

Typically does not modify stored programs; only exploits CPU/memory.

**User Consent/Interaction**

Operates without knowledge/consent of user.

Consumes network bandwidth, system memory, overloads servers.

**Spread**

Cannot spread to other computers unless infected file is replicated/sent.

Replicates and spreads rapidly via IRC, Outlook, email, etc.

**Propagation**

Spreads at a uniform rate, as programmed.

Spreads more rapidly than a virus.

**Removal**

Difficult to remove.

Can be removed easily.

Export to Sheets

**How to Infect Systems Using a Worm:**

1.  Create a worm using tools (e.g., Internet Worm Maker Thing, Batch Worm Generator).
2.  Deploy via phishing emails, malicious websites, network shares, USB drives.
3.  Victim clicks the phishing link or downloads a file.
4.  Worm scans for other vulnerable devices on the network.
5.  Worm copies itself to identified vulnerable devices.
6.  Worm installs backdoors/alters system settings, exfiltrates data.

### 9. Fileless Malware Concepts

**What is Fileless Malware?** Malware that operates in memory, without writing to disk. It's harder to detect using traditional antivirus based on file signatures. Often uses legitimate software and applications.

**Reasons for Fileless Malware Attacks:**

-   **Stealth:** Extremely difficult to detect.
-   **LOL (Living off the land):** Exploits tools already installed on the system (e.g., PowerShell, WMI).
-   **Trustworthiness:** Uses trusted system tools for malicious activities.
-   **Persistence:** Achieves persistence without storing files on disk (e.g., modifying registry).
-   **Simplifying Infection:** Simple phishing emails lead to memory-based infection.
-   **Increased Success Rate:** Evades traditional AV/IDS.
-   **Complicating Forensics:** Leaves minimal traces, making analysis harder.

#### Fileless Propagation Techniques Used by Attackers

-   **Phishing Emails/Malicious Documents:** Embeds malicious macros, links.
-   **Legitimate Applications:** Exploits legitimate programs (Word, Java, JavaScript, PowerShell).
-   **Native Applications:** Uses pre-installed system tools (WMI, PowerShell).
-   **Infection through Lateral Movement:** Moves laterally in memory.
-   **Malicious Websites:** Exploits browser vulnerabilities to run malicious code.
-   **Registry Manipulation:** Injects code into the Windows Registry for persistence.
-   **Memory Code Injection:** Injects malicious code into running processes.
-   **Script-Based Injection:** Obfuscated scripts embedded in documents.
-   **Reflective DLL Injection:** Loads a DLL directly into memory.
-   **Exploiting Non-Malicious Files:** Uses legitimate files (PDFs, shortcuts) to run malicious scripts.

#### Taxonomy of Fileless Malware Threats

Categorized by entry point:

-   **Type 1: No File Activity Performed:** Malware never writes to disk.
-   **Type 2: Indirect File Activity:** Requires files for operation but doesn't write directly (e.g., modifies registry for persistence).
-   **Type 3: Required Files to Operate:** Requires files to execute payloads (e.g., documents with embedded macros).

#### How Fileless Malware Works (Stages)

1.  **Point of Entry:** Initial access via exploit or compromised legitimate business.
2.  **Code Execution:** Injects code into processes or uses script-based execution.
3.  **Persistence:** Maintains access (e.g., Windows Registry, WMI, Scheduled Task).
4.  **Achieving Objectives:** Credential harvesting, data exfiltration, cyber espionage.

### 10. AI-Based Malware Concepts

**What is AI-Based Malware?** Malware that utilizes Artificial Intelligence (AI) or Machine Learning (ML) to enhance its capabilities.

**How AI-Based Malware Works:**

-   **Autonomous Operation:** Learns and adapts to evade detection and spread.
-   **Polymorphic Behavior:** Changes its code using AI to bypass signature-based detection.
-   **Evasion Techniques:** AI helps malware learn and adapt to security measures.
-   **Targeted Attacks:** AI identifies vulnerable targets and customizes attacks.
-   **Automated Reconnaissance:** AI automates data collection for targets.
-   **Decision-Making:** AI chooses optimal attack paths.
-   **Advanced Social Engineering:** AI creates highly convincing phishing attacks.
-   **Swarm Intelligence:** Multiple AI-powered malware instances coordinate attacks.

### 11. Malware Analysis Process

**What is Malware Analysis?** The process of understanding the functionality, origin, and potential impact of a given malware sample.

#### Types of Malware Analysis

-   **Static Malware Analysis:**
    
    -   Examines the malware without executing it.
    -   Looks at the code, resources, metadata.
    -   **Techniques:** Antivirus Scanning, Hashing, String Search, File Identification, Feature Extraction, Disassembly, Debugging.
    -   **Tools:** Virustotal, PeStudio, CFF Explorer, BinText, Strings, UPX, IDA Pro, OllyDbg, Ghidra, Bytecode Viewer.
    -   **Limitations:** Can be time-consuming, may miss hidden functionalities, not suitable for polymorphic/metamorphic malware, doesn't interact with systems.
-   **Dynamic Malware Analysis:**
    
    -   Executes the malware in a controlled, isolated environment (sandbox, virtual machine).
    -   Observes its behavior, system changes, network activity.
    -   **Techniques:** System Monitoring, Network Monitoring, Process Monitoring, Registry Monitoring, File System Monitoring, Memory Analysis.
    -   **Tools:** Process Monitor, Wireshark, Regshot, Process Explorer, ApateDNS, SysAnalyzer, Cuckoo Sandbox, Any.Run, Hybrid Analysis, VMRay, Joe Sandbox.
    -   **Limitations:** Risk of malware escape, requires isolated environment, might not uncover all functionalities (e.g., time-delayed payloads), some malware can detect sandboxes.

#### Malware Analysis Environment

-   **Virtual Machine (VM):** Essential for safe dynamic analysis. Allows isolation and snapshotting.
-   **Sandbox:** Automated analysis environment that executes malware and records its behavior.
-   **Network Configuration:** Isolated network setup to prevent malware propagation.
-   **Tools:** Windows OS with necessary tools (Process Monitor, Wireshark), Linux OS (Remnux) for additional tools.

#### Sandbox Evasion Techniques by Malware

-   **Checking for Human Activity:** Malware checks for mouse movements, keyboard input.
-   **Checking for Malware Analysis Tools:** Detects presence of debuggers, network monitors.
-   **Checking for VM Artifacts:** Looks for virtual machine drivers, specific registry keys.
-   **Environmental Detections:** Checks for specific CPU core counts, memory size, disk space.
-   **Time-Based Triggers:** Delays execution until a specific date/time.
-   **User Interaction Triggers:** Requires user clicks or specific actions.
-   **Network Connectivity Checks:** Waits for internet access or specific server responses.
-   **Obfuscation and Encryption:** Hides malicious code until executed.
-   **Anti-Debugging/Anti-Disassembly:** Techniques to hinder analysis.

### 12. Malware Countermeasures

#### Antivirus Software

-   Detects and removes malware.
-   **Detection Techniques:** Signature-based, Heuristic-based, Behavior-based, Sandboxing, Data Mining.

#### Anti-Malware Solutions

-   Provide protection beyond traditional antivirus.
-   **Key Features:** Real-time protection, behavior monitoring, cloud-based analysis, advanced threat detection.

#### Mobile Malware Countermeasures

-   Use official app stores.
-   Review app permissions.
-   Keep OS/apps updated.
-   Use mobile security solutions.
-   Be wary of unknown links/attachments.

#### Ransomware Countermeasures

-   Regular backups.
-   Email security (spam filters, attachment scanning).
-   Endpoint protection (AV, EDR).
-   Network segmentation.
-   Patch management.
-   User awareness training.
-   Incident response plan.

#### Endpoint Protection Platforms (EPP) and Endpoint Detection and Response (EDR)

-   **EPP:** Preventative controls on endpoints (antivirus, firewall, DLP).
-   **EDR:** Detects, investigates, and responds to threats on endpoints (continuous monitoring, behavioral analysis, threat hunting).

#### Other Countermeasures

-   **Security Best Practices:** Regular patching, strong passwords, network segmentation, firewall rules.
-   **Network Security Devices:** Firewalls, IDS/IPS.
-   **Data Loss Prevention (DLP):** Prevents sensitive data exfiltration.
-   **Sandboxing:** Running suspicious files in isolated environments.
-   **User Awareness Training:** Educating users about malware risks.
-   **Incident Response Plan:** Defined procedures for handling security incidents.

----------

## Key Terms for Last-Minute Revision

-   **Malware:** Malicious Software
-   **Trojans:** Disguised malicious programs
-   **Backdoors:** Bypasses security for persistent access
-   **Rootkits:** Hides malicious processes
-   **Ransomware:** Encrypts data, demands ransom
-   **Adware:** Displays unwanted ads
-   **Crypter:** Encrypts malware to evade AV
-   **Dropper:** Installs malware covertly
-   **Exploit Kit (EK):** Automates vulnerability exploitation
-   **APT (Advanced Persistent Threat):** Long-term, sophisticated, targeted attack
-   **CVSS:** Vulnerability scoring system
-   **CVE:** Publicly known vulnerabilities
-   **SAM Database:** Windows password hash storage
-   **NTLM:** Challenge/response authentication protocol
-   **Kerberos:** Ticket-based network authentication protocol
-   **KDC (Key Distribution Center):** Kerberos component (AS + TGS)
-   **TGT (Ticket-Granting Ticket):** Kerberos authentication ticket
-   **RAT (Remote Access Trojan):** Full remote control
-   **POS Trojan:** Targets Point-of-Sale systems
-   **Fileless Malware:** Operates in memory, no disk writes
-   **LOL (Living Off the Land):** Using legitimate system tools for malicious activities
-   **Static Malware Analysis:** Analysis without execution
-   **Dynamic Malware Analysis:** Analysis by executing in a controlled environment
-   **Sandbox:** Isolated environment for dynamic analysis
-   **Polymorphic Malware:** Changes code to avoid detection
-   **Metamorphic Malware:** Rewrites code completely for each infection
-   **Worm:** Self-replicating malware, spreads independently
-   **Virus:** Self-replicating malware, needs host program/user interaction to spread
-   **AI-Based Malware:** Uses AI/ML for enhanced capabilities
-   **EPP (Endpoint Protection Platform):** Preventative endpoint security
-   **EDR (Endpoint Detection and Response):** Detects, investigates, responds to endpoint threats
-   **DLP (Data Loss Prevention):** Prevents sensitive data exfiltration
