## Module 14: Hacking Web Applications - Key Concepts and Notes

This module familiarizes you with various web applications and web attack vectors, and how to protect an organization's information resources from them. It describes the general web application hacking methodology, web API, and webhook concepts.

### Learning Objectives

-   Describe web application concepts.
-   Perform various web application attacks.
-   Describe the web application hacking methodology.
-   Use different web application hacking tools.
-   Explain web API and webhook concepts.
-   Understand how to hack web applications via web API.
-   Adopt countermeasures against web application attacks.
-   Use different web application security testing tools.

### 1. Web Application Concepts

What are Web Applications?

Software programs that run on web browsers, acting as an interface between users and web servers. They allow users to request, submit, and retrieve data from a database over the Internet using a graphical user interface (GUI).

-   **How They Work:** Users enter a URL, request goes to web server, if server-side processing is needed (e.g., PHP, ASP), it passes to a web application server. The web app server then interacts with the database and sends results back to the web server for display in the browser.
-   **Advantages:** OS independent, accessible anytime/anywhere, customizable UI, device compatibility, centralized data storage (better physical security), flexible core technologies (scalable).

#### Web Application Architecture (Three Layers)

1.  **Client or Presentation Layer:**
    -   Includes user devices (laptops, smartphones) with OS and browsers.
    -   Users send requests by entering URLs.
    -   Displays the web page.
2.  **Business Logic Layer:**
    -   **Web-Server Logic Layer:** Handles HTTP requests, firewall, proxy caching, authentication/login, resource handling (e.g., IIS, Apache).
    -   **Business Logic Layer:** Contains the functional logic using technologies like .NET, Java, middleware. Defines data flow and integrates legacy applications.
3.  **Database Layer:**
    -   Consists of cloud services, B2B layer (commercial transactions), and database server (MS SQL, MySQL).
    -   Stores an organization's production data in structured form.

#### Web Services

-   An application/software deployed over the Internet using standard messaging protocols (e.g., SOAP) for communication between applications on different platforms.
-   Integrated with SOAP, UDDI, WSDL, and REST.

**Web Service Architecture (Roles and Operations):**

-   **Roles:**
    -   **Service Provider:** Offers and publishes web services.
    -   **Service Requester:** Client application seeking/invoking a service.
    -   **Service Registry:** Where providers publish and requesters discover service descriptions (e.g., UDDI).
-   **Operations:**
    -   **Publish:** Provider publishes service descriptions to registry.
    -   **Find:** Requester discovers/obtains service descriptions from registry.
    -   **Bind:** Requester establishes communication with services during runtime.
-   **Artifacts:**
    -   **Service:** The software module offered.
    -   **Service Description:** Provides interface details, operations, network locations.

**Characteristics of Web Services:**

-   **XML-based:** Use XML for data representation.
-   **Coarse-grained service:** Large amount of functionality, less fine-grained.
-   **Loosely coupled:** Systems interact via web API.
-   **Asynchronous and synchronous support:** For communications.
-   **RPC support:** Remote procedure calls.

**Types of Web Services:**

-   **SOAP Web Services:** Uses XML format, often with WSDL (Web Services Description Language).
-   **RESTful Web Services (REST):** Uses HTTP concepts, more lightweight.

#### Vulnerability Stack (7 Layers of Organizational Security in context of Web Apps)

-   **Layer 7: Custom Web Applications:** Business Logic Flaws.
-   **Layer 6: Third-party Components:** Open Source/Commercial vulnerabilities.
-   **Layer 5: Web Server:** Apache/Microsoft IIS (misconfigurations, known vulnerabilities).
-   **Layer 4: Database:** Oracle/MySQL/MS SQL (data access flaws).
-   **Layer 3: Operating System:** Windows/Linux/macOS (OS vulnerabilities).
-   **Layer 2: Network:** Router/Switch (network device vulnerabilities).
-   **Layer 1: Security:** IPS/IDS (evasion techniques).

### 2. Web Application Threats (OWASP Top 10 2021)

**OWASP Top 10:** A regularly updated list of the top 10 most critical web application security risks.

-   **A01:2021 - Broken Access Control:** Improperly enforced restrictions on authenticated users. Leads to unauthorized access, viewing sensitive files, modifying data. (e.g., Directory Traversal, Hidden Field Manipulation).
-   **A02:2021 - Cryptographic Failures / Sensitive Data Exposure:** Sensitive data (financial, PII) not properly protected. (e.g., Cookie Snooping, weak crypto, RC4 NOMORE, Same-Site Attack, Pass-the-Cookie Attack).
-   **A03:2021 - Injection:** Untrusted data sent to an interpreter as part of a command or query. (e.g., SQL Injection, Command Injection, LDAP Injection, XSS, Buffer Overflow).
-   **A04:2021 - Insecure Design:** Design flaws leading to vulnerabilities, even if implementation is correct. (e.g., Business Logic Bypass, Web-based Timing Attacks, CAPTCHA Attacks, Platform Exploits).
-   **A05:2021 - Security Misconfiguration:** Security misconfigurations at any level of the stack. (e.g., default settings, open S3 buckets, HTTP headers, verbose error messages, unpatched components, XML External Entity (XXE), Unvalidated Redirects and Forwards, Directory Traversal, Hidden Field Manipulation).
-   **A06:2021 - Vulnerable and Outdated Components:** Using components (libraries, frameworks) with known vulnerabilities.
-   **A07:2021 - Identification and Authentication Failures / Broken Authentication:** Incorrectly implemented authentication or session management. (e.g., CSRF, Cookie/Session Poisoning, password spraying, automated attacks, session ID prediction).
-   **A08:2021 - Software and Data Integrity Failures:** Applications relying on plugins, dependencies, or libraries from untrusted sources, or not validating data integrity. (e.g., Insecure Deserialization, Watering Hole Attack, DoS, Web Service Attacks).
-   **A09:2021 - Security Logging and Monitoring Failures:** Insufficient logging or monitoring, making detection difficult. (e.g., Insufficient logging, improper neutralization for logs, exclusion of security-relevant information).
-   **A10:2021 - Server-Side Request Forgery (SSRF):** Server forced to make requests to an attacker-controlled system, potentially compromising internal resources.

#### Specific Web Application Attack Techniques

-   **Directory Traversal:** Accessing restricted directories using `../` sequences.
-   **Hidden Field Manipulation:** Modifying hidden form fields (e.g., price in e-commerce).
-   **Pass-the-Cookie Attack:** Using a cloned cookie to access a user's web services without authentication.
-   **Same-Site Attack:** Exploiting subdomains of a trusted organization to redirect users to attacker-controlled pages.
-   **SQL Injection:** Injecting malicious SQL queries through input fields.
-   **Command Injection:** Injecting OS commands through input fields.
-   **LDAP Injection:** Exploiting LDAP queries to manipulate directory services.
-   **Server-Side JS Injection:** Injecting JavaScript that executes on the server.
-   **Server-Side Template Injection:** Injecting malicious code into server-side templates.
-   **HTML Injection:** Injecting HTML tags or scripts into a target website.
-   **CRLF Injection:** Injecting Carriage Return and Line Feed characters to split HTTP responses/requests.
-   **Cross-Site Scripting (XSS):** Injecting client-side scripts (HTML, JavaScript, VBScript) into web pages viewed by other users.
    -   **Techniques to Evade XSS Filters:** Encoding characters (ASCII, Hex), embedding whitespaces, manipulating tags, using invalid characters, changing checksum, using bind/splitter tools.
-   **Web-based Timing Attacks:** Inferring sensitive information (e.g., passwords) by measuring response time (Direct Timing, Cross-site Timing, Browser-based Timing, Video-parsing, Cache Storage Timing).
-   **XML External Entity (XXE) Attack:** Exploiting XML parsers to include external entities, potentially leading to file disclosure, SSRF, RCE, DoS.
-   **Unvalidated Redirects and Forwards:** Redirecting users to malicious sites via legitimate URLs. (e.g., Session Fixation, Malicious File Execution).
-   **Magecart Attack:** Web skimming (supply chain attacks) injecting malicious code into e-commerce sites to steal payment card data.
-   **Watering Hole Attack:** Attacker identifies frequently visited websites and injects malicious code, waiting for victims to visit and get infected.
-   **Cross-Site Request Forgery (CSRF):** Tricks a user's browser into performing unwanted actions on a trusted site where they are already authenticated.
-   **Cookie/Session Poisoning:** Modifying contents of a cookie/session ID to gain unauthorized access or manipulate data.
-   **Insecure Deserialization:** Injecting malicious code into deserialized data to execute arbitrary code.
-   **Web Service Attack:** Exploiting vulnerabilities in web services (SOAP, REST).
    -   **Web Service Footprinting:** Gathering info about web services via UDDI (Universal Description, Discovery, and Integration).
    -   **Web Service XML Poisoning:** Injecting malicious XML code into SOAP requests.
-   **DNS Rebinding Attack:** Attacker uses DNS to bypass the Same-Origin Policy (SOP), making a malicious web page communicate with arbitrary hosts on local domains.
-   **Clickjacking Attack:** Masking a web page element with a transparent malicious web page element, tricking users into clicking the malicious element (e.g., complete transparent overlay, hidden overlay).
-   **MarioNet Attack:** Browser-based attack running malicious code inside the browser, persisting even after closing the browser. Leverages Service Workers API.
-   **Cookie Snooping:** Observing victims' surfing habits.
-   **RC4 NOMORE Attack:** Exploits RC4 stream cipher vulnerability to decrypt encrypted web session cookies.
-   **Buffer Overflow:** Overwriting buffer memory.
-   **Business Logic Bypass Attack:** Exploiting flaws in an application's design or workflow.
-   **CAPTCHA Attacks:** Bypassing CAPTCHA mechanisms.
-   **Platform Exploits:** Exploiting vulnerabilities in underlying platforms.
-   **Denial-of-Service (DoS):** Overloading web application resources.
-   **H2C Smuggling Attack:** Exploiting HTTP/2 connections to bypass security controls.
-   **JavaScript Hijacking:** JSON hijacking where attackers can capture sensitive data.
-   **Cross-Site WebSocket Hijacking (CSWH):** Hijacking WebSocket connections.
-   **Obfuscation:** Hiding malicious code.
-   **Network Access Attacks:** Affecting basic HTTP application methods.
-   **DMZ Protocol Attacks:** Compromising DMZ to access internal systems.

### 3. Web Application Hacking Methodology

A structured approach for ethical hackers to assess an organization's security against web app attacks.

1.  **Footprint Web Infrastructure:** Server discovery, detecting firewalls/proxies, hidden content discovery, load balancer detection.
    -   **Server Discovery:** Whois lookup, DNS interrogation, Banner Grabbing.
    -   **Detecting Web App Firewalls & Proxies:** Analyze HTTP headers, cookies. Use `wafw00f` for WAF detection.
    -   **Hidden Content Discovery:** Recover backup files, explore default files/directories (robots.txt, sitemap.xml), discover unlinked content.
    -   **Detect Load Balancers:** Use `dig`, `nslookup` (for multiple IPs).
2.  **Analyze Web Applications:** Understand the application's functionality.
3.  **Bypass Client-Side Controls:** (e.g., JavaScript validation bypass).
4.  **Attack Authentication Mechanisms:** (e.g., brute-force, credential stuffing).
5.  **Attack Authorization Schemes:** (e.g., privilege escalation, horizontal/vertical privilege escalation).
6.  **Attack Access Controls:** (e.g., directory traversal, broken access control).
7.  **Attack Session Management Mechanisms:** (e.g., session hijacking, session fixation, cookie manipulation).
8.  **Perform Injection Attacks:** (e.g., SQL Injection, XSS, Command Injection).
9.  **Attack Application Logic Flaws:** (e.g., business logic bypass).
10.  **Attack Shared Environments:** (e.g., misconfigurations in shared hosting).
11.  **Attack Database Connectivity:** (e.g., SQL Injection, database password cracking).
12.  **Attack Web App Clients:** (e.g., browser exploits, client-side attacks).
13.  **Attack Web Services:** (e.g., SOAP/REST vulnerabilities, XML attacks).

### 4. Web API and Webhooks

#### Web API (Application Programming Interface)

-   A set of defined rules that allows different applications to communicate with each other.
-   Enables integration between systems without direct knowledge of their internal workings.
-   **Features:** Communication via HTTP, structured data (JSON, XML), RESTful principles, authentication mechanisms (API keys, OAuth, JWT).
-   **Common Vulnerabilities:** Injection (SQL, Command), Broken Authentication/Access Control, Insecure Design, Insecure Deserialization, SSRF, Logging/Monitoring Failures, Misconfiguration, Vulnerable Components, XSS, DoS, Rate Limiting bypass.

#### Webhooks

-   User-defined HTTP callbacks triggered by events in a system.
-   Allow applications to send real-time notifications to other applications.
-   **How it Works:** Source application (sender) registers a webhook URL with the destination application (receiver). When an event occurs, the source sends an HTTP POST request to the webhook URL.
-   **Vulnerabilities:** Unauthenticated webhooks, lack of input validation, SSRF, replay attacks, disclosure of sensitive information.

#### Hacking Web APIs

-   **Information Gathering:** Reconnaissance to understand API endpoints, methods, parameters.
-   **API Key/Authentication Bypass:** Test for weak API keys, token validity, broken authentication.
-   **Injection Attacks:** Test for SQL, Command, XSS, LDAP injection in API parameters.
-   **Parameter Tampering:** Modify API request parameters.
-   **Broken Access Control:** Test for horizontal/vertical privilege escalation.
-   **Insecure Direct Object References (IDOR):** Modify object IDs to access unauthorized data.
-   **Mass Assignment:** Sending extra parameters to modify unintended data.
-   **Rate Limiting Bypass:** Flood API to bypass rate limits.
-   **Schema Validation Bypass:** Send malformed requests to bypass validation.
-   **DoS/DDoS Attacks:** Overwhelm API endpoints.

### 5. Web Application Security Techniques (Countermeasures)

-   **Input Validation:** Strict validation of all user input (data type, length, format) to prevent injection attacks.
-   **Output Encoding:** Encode output to prevent XSS (e.g., HTML entity encoding).
-   **Implement Strong Authentication and Session Management:**
    -   **Strong Passwords:** Enforce complexity, length.
    -   **Multi-Factor Authentication (MFA).**
    -   **Secure Session IDs:** Generate long, random, unpredictable IDs; regenerate after login.
    -   **Session Timeout:** Implement strict session timeouts.
    -   **HTTPOnly and Secure flags for cookies.**
    -   **CSRF Tokens:** Implement unique, unpredictable tokens to protect against CSRF.
-   **Error Handling and Logging:**
    -   **Generic Error Messages:** Avoid verbose error messages that reveal system details.
    -   **Comprehensive Logging:** Log all security-relevant events (failed logins, access violations).
    -   **Centralized Logging and Monitoring (SIEM).**
-   **Access Control:**
    -   **Least Privilege:** Grant minimum necessary permissions.
    -   **Role-Based Access Control (RBAC):** Define roles and assign permissions accordingly.
    -   **Secure Coding Practices:** Follow OWASP secure coding guidelines.
-   **Patch Management:** Regularly update web server, OS, and application components.
-   **Web Application Firewall (WAF):** Provides a layer of defense against common web attacks (SQLi, XSS, CSRF).
-   **Network Segmentation:** Isolate web servers in DMZ.
-   **Secure File Uploads:** Validate file types, scan for malware, store outside web root.
-   **Protect against Brute-Force Attacks:** Account lockout, CAPTCHA, rate limiting.
-   **Secure Configuration:** Harden web servers and applications (disable unnecessary features, remove default files).
-   **Data Encryption:** Encrypt sensitive data at rest and in transit (TLS/SSL).
-   **Content Security Policy (CSP):** Mitigate XSS attacks by restricting sources of content.
-   **Regular Security Audits & Penetration Testing.**
-   **Threat Modeling:** Proactively identify and mitigate threats during design.
-   **Automated Security Testing:** Use SAST (Static Application Security Testing) and DAST (Dynamic Application Security Testing) tools.
-   **API Security Best Practices:**
    -   **Authentication & Authorization:** Strong API key management, OAuth/JWT.
    -   **Input Validation & Output Encoding.**
    -   **Rate Limiting:** Protect against DoS/brute-force.
    -   **Monitor API Traffic:** For anomalies.
    -   **Error Handling:** Generic API error messages.
    -   **API Gateway:** Centralized control, security, and traffic management.
-   **Webhook Security Best Practices:**
    -   **Authentication:** Require authentication for webhook endpoints.
    -   **Payload Validation:** Validate incoming webhook payloads.
    -   **HTTPS:** Use HTTPS for all webhook communication.
    -   **Secret/Signature Verification:** Use shared secrets and HMAC signatures to verify origin.
    -   **Idempotency:** Handle duplicate webhook deliveries gracefully.
    -   **Rate Limiting:** Protect webhook endpoints.

----------

## Key Terms for Last-Minute Revision

-   **Web Application:** Software running in a browser, interface to web server/DB.
-   **Web Server:** Delivers web content.
-   **Web Application Server:** Processes server-side scripts.
-   **Web Service:** Application/software deployed over internet, uses standard messaging.
-   **SOAP:** XML-based web service protocol.
-   **REST:** Architectural style for web services, often uses HTTP.
-   **UDDI:** Universal Description, Discovery, and Integration (web service registry).
-   **WSDL:** Web Services Description Language (describes web services).
-   **OWASP Top 10:** List of top web application security risks.
-   **Broken Access Control:** Improper authorization.
-   **Cryptographic Failures:** Weak encryption or sensitive data exposure.
-   **Injection:** Untrusted data executed as code (SQL, Command, LDAP, XSS).
-   **Insecure Design:** Flaws in application architecture.
-   **Security Misconfiguration:** Improper setup of components.
-   **Vulnerable & Outdated Components:** Using insecure third-party software.
-   **Identification & Authentication Failures:** Weak login/session management.
-   **Software & Data Integrity Failures:** Lack of validation for software/data.
-   **Security Logging & Monitoring Failures:** Insufficient logging.
-   **Server-Side Request Forgery (SSRF):** Server making unintended requests.
-   **Directory Traversal:** Accessing unauthorized file system paths.
-   **Hidden Field Manipulation:** Modifying hidden input fields.
-   **Pass-the-Cookie Attack:** Using a cloned cookie.
-   **Same-Site Attack:** Exploiting subdomains for malicious redirects.
-   **XSS (Cross-Site Scripting):** Client-side code injection.
-   **CSRF (Cross-Site Request Forgery):** Forcing unwanted actions on trusted sites.
-   **Cookie/Session Poisoning:** Modifying session cookies.
-   **Insecure Deserialization:** Executing code via malformed deserialized data.
-   **XML External Entity (XXE):** Exploiting XML parser vulnerabilities.
-   **Unvalidated Redirects and Forwards:** Redirecting to malicious sites.
-   **Magecart Attack:** Web skimming for payment card data.
-   **Watering Hole Attack:** Infecting frequented websites.
-   **DNS Rebinding Attack:** Bypassing Same-Origin Policy via DNS manipulation.
-   **Clickjacking:** Tricking users into clicking masked elements.
-   **MarioNet Attack:** Browser-based attack using Service Workers for persistence.
-   **Web API:** Interface for applications to communicate.
-   **Webhook:** HTTP callback triggered by events.
-   **WAF (Web Application Firewall):** Protects web apps from common attacks.
-   **SAST (Static Application Security Testing):** Code analysis without execution.
-   **DAST (Dynamic Application Security Testing):** Black-box testing by executing application.
-   **HSTS (HTTP Strict Transport Security):** Forces HTTPS.
-   **HTTPOnly/Secure Flags:** Cookie attributes for security.
-   **CSRF Tokens:** Anti-CSRF protection.
-   **Input Validation:** Essential for preventing injection attacks.
-   **Output Encoding:** Essential for preventing XSS.
-   **Threat Modeling:** Proactive security design.
-   **Least Privilege:** Granting minimum necessary permissions.
-   **RBAC (Role-Based Access Control):** Assigning permissions based on roles.
-   **MFA (Multi-Factor Authentication):** Enhanced login security.
-   **SIEM (Security Information and Event Management):** Centralized logging.
