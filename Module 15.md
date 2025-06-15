## Module 15: SQL Injection - Key Concepts and Notes

This module discusses SQL injection attacks, tools, and techniques used by attackers to compromise data-driven web applications. It also covers IDS evasion techniques and countermeasures.

### Learning Objectives

-   Summarize SQL Injection Concepts.
-   Demonstrate Various Types of SQL Injection Attacks.
-   Explain SQL Injection Methodology.
-   Demonstrate Different Evasion Techniques.
-   Explain SQL Injection Countermeasures.
-   Use different SQL Injection detection tools.

### 1. SQL Injection Concepts

What is SQL Injection?

A technique that takes advantage of unsanitized input vulnerabilities to pass SQL commands through a web application for execution by a backend database. Attackers inject malicious SQL queries into user input forms to gain unauthorized access or retrieve information directly from the database. It is a flaw in web applications, not in the database or web server.

Why Bother About SQL Injection? (Impacts)

SQL injection is a major issue for database-driven websites and can lead to:

-   **Authentication Bypass:** Log in without valid credentials, gain administrative privileges.
-   **Authorization Bypass:** Alter authorization information stored in the database.
-   **Information Disclosure:** Obtain sensitive information (user IDs, passwords, credit card numbers).
-   **Compromised Data Integrity:** Deface web pages, insert malicious content, alter database contents.
-   **Compromised Availability of Data:** Delete database information, logs, or audit information (DoS).
-   **Remote Code Execution:** Compromise the host operating system.

**How SQL Injection Works:**

1.  Programmers use sequential SQL commands with client-supplied parameters.
2.  Attackers inject malicious SQL queries into user input fields (e.g., username, password).
3.  If the application does not properly validate or filter the input, the injected query modifies the original SQL statement.
4.  The modified SQL query is executed by the database, performing the attacker's desired action.
    -   **Code Analysis Example:** Using `blah' OR 1=1 --` in a username field makes the WHERE clause always true, bypassing authentication. The `--` indicates a comment, ignoring the rest of the original query.

### 2. Various Types of SQL Injection Attacks

SQL injection attacks vary based on how data is retrieved or how the attack impacts the application.

#### In-band SQL Injection

Attackers use the same communication channel to perform the attack and retrieve the results. This is the most common and easiest type to exploit.

-   **Error-based SQL Injection:** Attacker intentionally triggers database error messages to reveal sensitive information about the database structure (e.g., table names, column names).
-   **UNION SQL Injection:** Uses the `UNION SELECT` statement to combine the results of a malicious query with a legitimate query, allowing attackers to retrieve data from other tables or databases.
-   **System Stored Procedure:** Exploiting vulnerabilities in stored procedures to gain unauthorized access or perform malicious actions.
-   **Illegal/Logically Incorrect Query:** Injecting logically incorrect statements to deduce information from error messages or application behavior.
-   **Tautology:** Injecting conditions that are always true (e.g., `OR 1=1`), bypassing authentication.
-   **End-of-Line Comment:** Using comment characters (`--` or `#`) to ignore the rest of the original SQL query, making the injected query execute.
-   **Inline Comment:** Similar to end-of-line comments, but comments are inserted within the query.
-   **Piggybacked Query:** Injecting additional SQL queries (separated by a semicolon `;`) that are executed alongside the original query. This can lead to data manipulation, DoS, or remote code execution.

#### Blind/Inferential SQL Injection

Attackers do not receive direct feedback from the database. They infer information by observing application behavior, response times, or generic error messages. This type of attack is often time-consuming.

-   **Boolean-based Blind SQL Injection:** Sends SQL queries that return a TRUE or FALSE result. Attackers infer information by observing whether the application's response changes (e.g., page content, error message).
-   **Time-based Blind SQL Injection:** Sends SQL queries that cause the database to delay its response based on the result of a logical condition (e.g., `IF(condition, BENCHMARK(delay, 1))`). Attackers infer information by measuring the time taken for the response.
-   **Heavy Query:** Performing computationally intensive queries to consume database resources and observe delays for inference.
-   **Double Blind SQL Injection:** A more sophisticated time-based blind SQL injection that doesn't provide direct feedback or error messages.

#### Out-of-band SQL Injection

Attackers use different communication channels (e.g., DNS, HTTP, SMB) to send query results or perform file writing functions. This is useful when direct in-band communication is blocked.

-   **DNS Exfiltration using SQL Injection:** Using SQL queries to force the database to perform DNS lookups to an attacker-controlled domain, effectively exfiltrating data via DNS requests.
-   **MongoDB Injection / NoSQL Injection:** While not SQL, similar injection attacks target NoSQL databases (e.g., MongoDB, using JavaScript syntax) to bypass authentication or extract data.

#### Other Injection Attacks

-   **PL/SQL Exploitation:** Exploiting vulnerabilities in PL/SQL (Procedural Language/SQL) stored procedures to manipulate user data or gain control.
-   **HTTP Header-Based SQL Injection:** Injecting malicious SQL into HTTP headers (e.g., `User-Agent`, `X-Forwarded-For`, `Referer`, `Cookie`) if they are used in SQL queries without proper sanitization.
-   **Creating Server Backdoors using SQL Injection:** Using functions like `xp_cmdshell` (MSSQL) or `LOAD_FILE`/`INTO OUTFILE` (MySQL) to execute OS commands or write files (e.g., web shells) to the server, establishing a backdoor.

### 3. SQL Injection Methodology

A systematic approach used by attackers to compromise a web application via SQL injection.

1.  **Information Gathering and SQL Injection Vulnerability Detection:**
    
    -   **Target Information:** Gather details about the target database (name, version, users, privileges, OS).
    -   **Identify Data Entry Paths:** Find all input fields (GET/POST requests, hidden fields, cookies) that interact with the database. Tools: Burp Suite, Tamper Dev.
    -   **Extract Information through Error Messages:** Trigger database errors to reveal sensitive information (e.g., database type, version, OS level).
    -   **SQL Injection Vulnerability Detection:** Test various SQL injection strings to see if the application is vulnerable.
    -   **Source Code Review:** Analyze application source code (manual or using SAST tools like Veracode, SonarQube, Fortify) for SQL injection vulnerabilities.
    -   **Function Testing (Black Box):** Send crafted inputs to observe application behavior.
    -   **Fuzz Testing (Black Box):** Send large amounts of random data to discover coding errors and security loopholes. Tools: BeSTORM, Burp Suite, AppScan Standard.
    -   **SQL Injection Black Box Pen Testing:** Systematically test input fields for SQL injection issues (detecting input sanitization, truncation, SQL modification).
    -   **Detecting SQL Modification:** Observe how long strings of single quotes or brackets affect the query.
2.  **Launch SQL Injection Attacks:** Once vulnerabilities are detected, the attacker proceeds with exploitation.
    
    -   **Perform Error Based SQL Injection:** Exploit error messages for data extraction.
    -   **Perform UNION SQL Injection:** Use `UNION SELECT` to retrieve data from other tables/columns.
    -   **Perform Blind SQL Injection:** Use Boolean or time-based techniques to infer information character by character.
    -   **Perform Out-of-Band SQL Injection:** Exfiltrate data via alternative channels (e.g., DNS).
    -   **Exploiting Second-Order SQL Injection:** Attacks where the injected payload from a previous request is stored and then executed in a later, different operation.
3.  **Advanced SQL Injection (Compromising the Entire Network):**
    
    -   **Bypassing Website Logins using SQL Injection:** Using `OR 1=1` or similar techniques to bypass login forms.
    -   **PL/SQL Exploitation:** Gaining control over PL/SQL procedures.
    -   **Creating Server Backdoors:** Writing web shells or executing OS commands.
    -   **HTTP Header-Based SQL Injection:** Injecting through HTTP headers.
    -   **DNS Exfiltration using SQL Injection:** Exfiltrating data via DNS queries.
    -   **MongoDB/NoSQL Injection:** Targeting NoSQL databases.
    -   **Grabbing SQL Server Hashes:** Extracting password hashes from database system tables.
    -   **Transfer Database to Attacker's Machine:** Using `OPENROWSET` (MSSQL) or other methods to transfer entire databases.
    -   **Interacting with the Operating System:** Executing OS commands via `xp_cmdshell` (MSSQL) or `sys_exec`/`sys_eval` (MySQL).
    -   **Interacting with the File System:** Reading (`LOAD_FILE`) or writing (`INTO OUTFILE`) files on the server.
    -   **Network Reconnaissance Using SQL Injection:** Using SQL queries to perform network reconnaissance (e.g., `xp_cmdshell` with `ping`, `nmap`, `netstat`).
    -   **Finding and Bypassing Admin Panel:** Using Google Dorks or SQL injection to find and access hidden admin login pages.

### 4. SQL Injection Evasion Techniques

Attackers try to bypass WAFs and IDS/IPS using various methods to obfuscate or modify their SQLi payloads.

-   **Normalization Method:** Altering the structure of the SQL query to bypass WAFs that normalize inputs.
-   **HPP Technique (HTTP Parameter Pollution):** Injecting HTTP GET/POST parameters multiple times to alter/override HTTP requests and bypass WAFs.
-   **HPP Technique (HTTP Parameter Fragmentation):** Breaking HTTP parameters into fragments.
-   **Blind SQL Injection (Evasion):** Leveraging the blind nature to avoid detection by WAFs that rely on direct error messages or responses.
-   **Signature Bypass:** Modifying the signature of SQL queries to bypass signature-based firewalls (e.g., using comments, different syntax).
-   **Buffer Overflow Method:** Sending oversized SQL injection payloads that crash the firewall or application.
-   **CRLF Technique:** Injecting Carriage Return and Line Feed characters to bypass firewalls by splitting HTTP requests.
-   **Integration Method:** Using different bypassing techniques together (e.g., combining `UNION` with fragmentation or other obfuscation).
-   **Bypassing WAF using JSON-based SQL Injection:** Manipulating JSON input parameters to inject SQL commands.

### 5. SQL Injection Countermeasures

Protecting against SQL injection is primarily about rigorous input validation and secure coding practices.

#### Web Application Countermeasures

-   **Input Validation:** The most crucial defense. Validate all user input (data type, length, format, characters) before processing.
    -   **Whitelist Validation:** Allow only known good input.
    -   **Blacklist Validation:** Block known bad input (less effective).
-   **Use Prepared Statements with Parameterized Queries:** This is the most effective defense. SQL code is defined first, and then parameters are passed separately. The database engine treats parameters as data, not executable code, preventing injection.
-   **Stored Procedures:** Use stored procedures that do not concatenate user input directly into SQL queries. Input parameters should be explicitly defined and validated.
-   **Principle of Least Privilege:** Grant database users only the minimum necessary permissions. The web application's database account should only have access to specific data required by the application.
-   **Disable Default Database Accounts:** Remove or disable default/sample database accounts.
-   **Strong Password Policies:** Enforce complex and regularly changed passwords for database accounts.
-   **Error Handling:** Implement custom, generic error messages. Do not display detailed database error messages to users, as these can reveal sensitive information.
-   **Regular Patching and Updates:** Keep database servers, web servers, and application frameworks patched.
-   **Database Security Audits:** Regularly audit database configurations and security settings.
-   **Web Application Firewall (WAF):** Deploy a WAF to filter malicious web traffic and block common SQL injection patterns.
-   **IDS/IPS:** Use Intrusion Detection/Prevention Systems to monitor and alert on suspicious SQL injection attempts.
-   **Encrypt Data:** Encrypt sensitive data in the database.
-   **Database Activity Monitoring (DAM):** Monitor real-time database activity for suspicious queries.
-   **Limit Network Access:** Restrict database access only to necessary application servers.
-   **Use Secure Coding Best Practices:** Train developers on secure coding standards (e.g., OWASP Secure Coding Principles).
-   **Web Application Security Testing:** Regularly perform penetration testing, vulnerability scanning (SAST/DAST), and code reviews.
-   **Configure Database Specific Hardening Settings:** Implement specific security features for MySQL, MS SQL, Oracle, etc.
-   **Monitor for SQLi Detection Tools:** Monitor for the presence or use of SQLi detection tools against the application.

#### SQL Injection Detection Tools

-   **sqlmap:** Open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws. Supports1 various types of SQLi (blind, error-based, union, out-of-band).
-   **Mole:** Automated SQL injection exploitation tool, supports MySQL, PostgreSQL, SQL Server, and Oracle.
-   **Havij:** Automated SQL injection tool.
-   **NoSQLMap:** Tool for NoSQL database enumeration and injection.
-   **Metasploit:** Can be used for SQL injection exploits.
-   **Burp Suite:** Web application testing tool with intruder/repeater for manual SQLi testing.
-   **OWASP ZAP:** Open-source web application security scanner.
-   **BeSTORM:** Fuzzing tool for finding SQL injection vulnerabilities.
-   **AppScan Standard:** Commercial web application security scanner.
-   **Static Code Analysis Tools (SAST):** Veracode, SonarQube, PV-Studio, Coverity Scan, Fortify.
-   **Dynamic Analysis Tools (DAST):** Invicti, Acunetix, IBM AppScan.

#### Discovering SQL Injection Vulnerabilities with AI

Attackers can leverage AI-powered technologies (e.g., ChatGPT combined with `sqlmap`) to automate network-scanning tasks and effortlessly perform SQL injections.

----------

## Key Terms for Last-Minute Revision

-   **SQL Injection (SQLi):** Injecting malicious SQL queries into input fields.
-   **Unsanitized Input:** Input not properly filtered or validated.
-   **Authentication Bypass:** Gaining access without proper credentials.
-   **Authorization Bypass:** Altering permissions.
-   **Information Disclosure:** Leaking sensitive data.
-   **Compromised Data Integrity:** Altering/deleting data.
-   **Remote Code Execution (RCE):** Executing OS commands.
-   **In-band SQLi:** Attack and retrieve results via same channel.
    -   **Error-based SQLi:** Using error messages to extract info.
    -   **UNION SQLi:** Combining queries with `UNION SELECT`.
    -   **Piggybacked Query:** Injecting multiple queries using semicolons.
-   **Blind SQLi:** No direct feedback, infer results from application behavior.
    -   **Boolean-based Blind SQLi:** Inferring based on true/false responses.
    -   **Time-based Blind SQLi:** Inferring based on response delays.
-   **Out-of-band SQLi:** Exfiltrating data via alternative channels (e.g., DNS, HTTP, SMB).
-   **PL/SQL Exploitation:** Attacking Oracle's PL/SQL procedures.
-   **HTTP Header-Based SQLi:** Injecting through HTTP headers.
-   **Backdoor (SQLi):** Creating persistent access to the server/database.
-   **xp_cmdshell:** MSSQL extended stored procedure for OS command execution.
-   **LOAD_FILE/INTO OUTFILE:** MySQL functions for file operations.
-   **SQLmap:** Automated SQL injection tool.
-   **Mole:** SQL injection exploitation tool.
-   **Burp Suite:** Web application testing proxy.
-   **OWASP ZAP:** Open-source web application scanner.
-   **Prepared Statements:** Most effective countermeasure, separates code from data.
-   **Parameterized Queries:** Similar to prepared statements, treats input as data.
-   **Input Validation:** Crucial for preventing SQLi.
-   **Least Privilege:** Granting minimum necessary permissions.
-   **WAF (Web Application Firewall):** Filters web traffic to block SQLi.
-   **IDS/IPS:** Detects/prevents intrusion attempts.
-   **Normalization Method (Evasion):** Changing query structure to bypass WAF.
-   **HPP (HTTP Parameter Pollution):** Sending multiple parameters to confuse WAF.
-   **CRLF Injection (SQLi Evasion):** Using CR/LF to split HTTP requests/responses.
-   **Signature Bypass:** Modifying payload to evade signature-based detection.
-   **Database Activity Monitoring (DAM):** Real-time monitoring of database queries.
