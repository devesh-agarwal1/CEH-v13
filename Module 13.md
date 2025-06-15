## Module 13: Hacking Web Servers - Key Concepts and Notes

This module focuses on the vulnerabilities and attack techniques against web servers, which are critical components of web infrastructure. It also covers the methodologies, tools, and countermeasures for web server security.

### Learning Objectives

-   Summarize Web Server Concepts.
-   Demonstrate Different Web Server Attacks.
-   Explain Web Server Attack Methodology.
-   Explain Web Server Attack Countermeasures.

### 1. Web Server Concepts

What is a Web Server?

A computer system that stores, processes, and delivers web pages and other web content (photos, videos) to global clients via HTTP. It responds to client HTTP requests by retrieving information from data storage or application servers.

-   **Client-Server Model:** Web server acts as the server, browser as the client.
-   **Hosting:** A single web server can host multiple websites.
-   **Common Web Server Software:** Apache, Microsoft IIS, Nginx, Google, Tomcat.

#### Components of a Web Server

-   **Document Root:** The root file directory storing HTML files and other web page content (e.g., `/admin/web/certroot`).
-   **Server Root:** The top-level directory for web server configuration files, log files, and executables (e.g., `conf`, `logs`, `cgi-bin` subdirectories).
-   **Virtual Document Tree:** Provides storage on a different machine or disk, allowing object-level security.
-   **Virtual Hosting:** Hosting multiple domains or websites on the same physical server (Name-based, IP-based, Port-based hosting).
-   **Web Proxy:** A server located between the web client and web server, passing requests and responses. Used for IP blocking prevention and anonymity.

#### Web Server Security Issues

Web servers are highly vulnerable because they are accessible from anywhere via the Internet.

**Why Web Servers are Compromised:**

-   Improper file and directory permissions.
-   Unnecessary default, backup, or sample files.
-   Misconfigurations in web server, OS, and network settings.
-   Bugs in server software, OS, and web applications.
-   Administrative or debugging functions enabled/accessible.
-   Use of self-signed or misconfigured SSL certificates, default certificates.
-   Not using a dedicated server for web services.
-   Excessive privileges granted to users or processes.
-   Lack of security policy, procedures, and maintenance.

**Impact of Web Server Attacks:**

-   Compromise of user accounts.
-   Website defacement (changing appearance).
-   Secondary attacks launched from the compromised website.
-   Root access to other applications or servers.
-   Data tampering (altering/deleting data).
-   Data theft (sensitive credentials, financial records, source code).
-   Reputational damage to the company.

#### Levels of Organizational Security (Stack View)

-   Stack 1: Security (IPS/IDS)
-   Stack 2: Network (Router/Switch)
-   Stack 3: Operating System (Windows/Linux/macOS)
-   Stack 4: Database (Oracle/MySQL/MS SQL)
-   Stack 5: Web Server (Apache/Microsoft IIS)
-   Stack 6: Third-party Components (Open Source/Commercial)
-   Stack 7: Custom Web Applications (Business Logic Flaws)

#### Common Goals of Web Server Hacking

-   Stealing credit card details/sensitive credentials (phishing).
-   Integrating the server into a botnet for DoS/DDoS attacks.
-   Compromising a database.
-   Obtaining closed-source applications.
-   Hiding and redirecting traffic.
-   Escalating privileges.
-   Curiosity, intellectual challenge, damaging reputation.

### 2. Web Server Attacks

#### DNS Server Hijacking

-   Attacker compromises a DNS server and changes its mapping settings to redirect users to a rogue DNS server or malicious website.

#### DNS Amplification Attack

-   Attacker instructs compromised hosts (bots) to make DNS queries with spoofed source IPs (victim's IP). DNS servers then respond to the victim, amplifying traffic and causing a DDoS.

#### Directory Traversal Attacks

-   Exploiting vulnerabilities (e.g., using `../` sequences) to access restricted directories and execute commands outside the web server's root directory.

#### Website Defacement

-   Unauthorized changes to a website's appearance by replacing original data with different visuals or messages.

#### Web Server Misconfiguration

-   Exploiting weaknesses in web infrastructure due to improper configuration (e.g., verbose error messages, anonymous/default users/passwords, sample configuration files, remote administration enabled).

#### HTTP Response-Splitting Attack

-   Attacker injects new lines into HTTP response headers, allowing them to split a single HTTP response into two, leading to client-side attacks (XSS, CSRF, SQL Injection, Web Cache Poisoning).

#### Web Cache Poisoning Attack

-   Attacker injects malicious content into a web cache, causing it to serve poisoned content to legitimate users. Often involves HTTP Response Splitting.

#### SSH Brute Force Attack

-   Attacker uses SSH protocols to access an encrypted SSH tunnel by brute-forcing login credentials. Uses tools like Nmap (port 22 scan) and Ncrack.

#### FTP Brute Force with AI

-   Leverages AI-powered technologies (e.g., ChatGPT, `hydra`) to automate brute-force attacks against FTP servers.

#### HTTP/2 Continuation Flood Attack

-   Exploits handling of HTTP/2 CONTINUATION frames to exhaust Apache server resources, leading to DoS.

#### Frontjacking Attack

-   Attacker manipulates the front-end components of a web application to hijack the execution flow or user interactions. Often targets Nginx reverse proxy servers and combines CRLF injection, HTTP request header injection, and XSS.

#### Other Web Server Attacks (Summary)

-   **Web Server Password Cracking:** Using brute-force, dictionary, hybrid attacks against passwords (e.g., via SMTP, FTP, SSH, web shares). Tools: Hashcat, THC Hydra.
-   **DoS/DDoS Attacks:** Overloading the web server with traffic to make it unavailable. Refer to Module 10.
-   **Man-in-the-Middle (MITM) Attacks:** Intercepting and altering communication. Refer to Module 11.
-   **Phishing Attacks:** Tricking users into revealing credentials via fake websites. Refer to Module 09.
-   **Web Application Attacks:**
    -   **Server-Side Request Forgery (SSRF):** Attacker forces server to make requests to internal/external resources.
    -   **Parameter/Form Tampering:** Manipulating parameters exchanged between client and server.
    -   **Cookie Tampering:** Modifying cookie contents.
    -   **Unvalidated Input and File Injection Attacks:** Injecting malicious files or input.
    -   **Session Hijacking:** Taking over an active session. Refer to Module 11.
    -   **SQL Injection Attacks:** Exploiting SQL vulnerabilities.
    -   **Directory Traversal:** Accessing unauthorized directories.
    -   **Denial-of-Service (DoS):** Exhausting web server resources.
    -   **Cross-Site Scripting (XSS) Attacks:** Injecting client-side scripts.
    -   **Buffer Overflow Attacks:** Writing too much data into a buffer.
    -   **Cross-Site Request Forgery (CSRF) Attack:** Tricking users into unwanted actions.
    -   **Command Injection Attacks:** Altering HTML content to execute commands.
    -   **Source Code Disclosure:** Revealing sensitive source code.

### 3. Web Server Attack Methodology

A systematic approach to compromising a web server.

1.  **Information Gathering:** Collect as much information as possible about the target web server (whois, DNS lookup, public IPs, domain information).
    -   Tools: `who.is`, `Whois Lookup`, `Domain Dossier`, `Subdomain Finder`.
    -   **robots.txt file:** Contains directives for web crawlers, can reveal hidden directories.
2.  **Web Server Footprinting/Banner Grabbing:** Gather system-level data (OS, server software, versions, database schema) by analyzing HTTP headers.
    -   Tools: `Netcat`, `Telnet`, `httprecon`, `Uniscan`, `Nmap`, `WhatWeb`, `Nikto`, `Shodan` (for IIS info).
    -   **Web Server Footprinting with AI:** Use AI (e.g., ChatGPT) for automated footprinting.
3.  **Website Mirroring:** Copying a website and its content for offline browsing and analysis.
4.  **Vulnerability Scanning:** Identify vulnerabilities and misconfigurations in the web server or network.
    -   Tools: `Acunetix Web Vulnerability Scanner`, `OpenText Fortify WebInspect`, `Tenable.io`, `ImmuniWeb`, `Invicti`.
    -   **Nginx Vulnerability Scanning:** Using tools like `Nginxpwner` (Python-based tool).
    -   **Finding Exploitable Vulnerabilities with AI:** Leverage AI to identify and search for exploits (e.g., using ChatGPT, `exploitdb`, `searchsploit`).
5.  **Session Hijacking:** Perform session hijacking to gain unauthorized access.
    -   Tools: `Burp Suite`, `JHijack`, `Ettercap`. (Refer to Module 11).
6.  **Web Server Passwords Hacking:** Employ password cracking techniques (guessing, dictionary, brute-force, hybrid attacks).
    -   Tools: `Hashcat`, `THC Hydra`, `Ncrack`, `Rainbow crack`, `Wfuzz`, `Wireshark`.
    -   **Using Application Server as a Proxy:** Web servers configured as reverse proxy can be used to connect to vulnerable servers.
    -   **Path Traversal via Misconfigured NGINX Alias:** Exploiting misconfigurations in Nginx to gain access to sensitive files. Tool: `Kyubi`.

### 4. Web Server Attack Countermeasures

A well-informed web server security posture involves a combination of technical controls, policies, and continuous monitoring.

#### General Countermeasures

-   **Separate Secure Server Security Segment:** Divide the network into segments (Internet, secure server segment, DMZ, internal network).
-   **Patches and Updates:** Regularly scan for vulnerabilities, apply hotfixes and security patches, ensure consistency across domains, establish a recovery plan, disable unused extensions, avoid default configurations, conduct risk assessments, maintain inventory, automate patch management, reduce third-party risks, validate updates, standardize processes.
-   **Protocols and Accounts:**
    -   Block unnecessary ports, ICMP traffic.
    -   Harden TCP/IP stack.
    -   Secure insecure protocols (Telnet, SMTP, FTP) with encryption (IPsec, SSL/TLS).
    -   Encrypt traffic through tunneling.
    -   Use secure communication (Transport Layer Security (TLS)/SSL).
    -   Ensure unidentified FTP servers are in separate directories.
    -   Ensure HTTP service banner properly configured.
    -   Isolate supporting servers (LDAP, mail, DB) behind firewalls.
    -   Ensure file transfers are encrypted.
    -   Redirect HTTP to HTTPS.
    -   Use HSTS headers.
    -   Automate SSL/TLS certificate renewal.
    -   Implement rate-limiting for DDoS attacks on SSL/TLS handshake.

#### Countermeasures: Accounts

-   Remove all unused modules/extensions.
-   Disable unused default user accounts.
-   Grant least privilege access (NTFS permissions).
-   Eliminate unnecessary database users.
-   Use secure web permissions (NTFS permissions, .NET Framework access control mechanisms).
-   Slow brute-force attacks with strong password policies and lockout.
-   Run processes with least privileged accounts.
-   Limit administrator/root access.
-   Maintain logs of user activity.
-   Disable non-interactive accounts.
-   Use secure VPNs for remote access.
-   Use password managers.
-   Enable Separation of Duties (SoD).
-   Periodically change passwords.
-   Enable user account locking.
-   Implement 2FA/MFA.
-   Use CAPTCHA challenges.
-   Use security questions with unpredictable answers.
-   Use strong hashing algorithms (bcrypt, scrypt, Argon2).
-   Design secure account recovery processes.

#### Web Server Security Tools

-   **Immunity's CANVAS:** Penetration testing and exploitation framework.
-   **OpenVAS:** Vulnerability scanner.
-   **THC Hydra:** Brute-forcing tool.
-   **HULK:** HTTP Unbearable Load King (DoS tool).
-   **MPack:** Exploit kit.
-   Various commercial firewalls (Cisco Secure Firewall ASA, FortiGate, Check Point, Juniper, Microsoft Defender, Comodo, Norton, McAfee, Palo Alto, SonicWall, Zyxel, DrayTek).
-   Various open-source firewalls (pfSense, IPFire).
-   Web application firewalls (WAFs).

----------

## Key Terms for Last-Minute Revision

-   **Web Server:** System hosting websites, responds to HTTP requests.
-   **Document Root:** Directory storing web page files.
-   **Server Root:** Directory storing server configuration and logs.
-   **Virtual Hosting:** Hosting multiple sites on one server.
-   **Web Proxy:** Intermediary server between client and web server.
-   **Website Defacement:** Unauthorized alteration of a website's appearance.
-   **Misconfiguration:** Improper server settings leading to vulnerabilities.
-   **DNS Server Hijacking:** Redirecting domains to malicious IPs.
-   **DNS Amplification Attack:** DDoS using DNS queries for traffic amplification.
-   **Directory Traversal:** Accessing unauthorized directories.
-   **HTTP Response-Splitting:** Injecting newlines into HTTP headers to create multiple responses.
-   **Web Cache Poisoning:** Injecting malicious content into web cache.
-   **SSH Brute Force:** Guessing SSH login credentials.
-   **HTTP/2 Continuation Flood:** DoS attack on HTTP/2 by sending excessive CONTINUATION frames.
-   **Frontjacking:** Manipulating front-end components to hijack execution.
-   **SSRF (Server-Side Request Forgery):** Server making requests to internal resources.
-   **Parameter/Form Tampering:** Modifying HTTP request parameters.
-   **Cookie Tampering:** Modifying cookie values.
-   **Unvalidated Input:** Input not properly validated.
-   **SQL Injection:** Injecting malicious SQL queries.
-   **XSS (Cross-Site Scripting):** Injecting client-side scripts.
-   **CSRF (Cross-Site Request Forgery):** Tricking user into unwanted actions.
-   **Source Code Disclosure:** Leaking sensitive source code.
-   **Footprinting:** Gathering information about the target.
-   **Banner Grabbing:** Obtaining server/service version info.
-   **Website Mirroring:** Copying a website for offline analysis.
-   **Vulnerability Scanning:** Identifying flaws in systems/applications.
-   **Session Hijacking:** Taking over an active session (Module 11).
-   **Password Cracking:** Recovering passwords from hashes or network traffic.
-   **robots.txt:** File providing directives for web crawlers, can leak info.
-   **NginxPwner:** Tool for Nginx vulnerability scanning.
-   **Exploit Database:** Repository of exploits.
-   **Acunetix:** Web vulnerability scanner.
-   **Immunity Canvas:** Penetration testing framework.
-   **THC Hydra:** Brute-forcing tool.
-   **Hashcat:** Password cracking tool.
-   **DMZ (Demilitarized Zone):** Perimeter network segment.
-   **HSTS (HTTP Strict Transport Security):** Forces HTTPS.
-   **2FA/MFA:** Two-Factor/Multi-Factor Authentication.
-   **WAF (Web Application Firewall):** Protects web applications.
-   **NGFW (Next-Generation Firewall):** Advanced firewall with integrated security features.
-   **BITS (Background Intelligent Transfer Service):** Windows service exploited for data transfer.
