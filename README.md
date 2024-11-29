# DEPI-Final_Project
Digital Egypt Pioneers Initiative Final Project in " Cyber Security Incident Response Analyst " Track 

--------------------------------------------------------------------------------------------------------------------------------------------------------------------
1. Pulling Plain Text Passwords & Chrome Passwords Using Mimikatz
Overview:
This report details the use of Mimikatz, a powerful penetration testing tool, to extract sensitive credentials from a Windows system. The document highlights two main tasks: retrieving plain text passwords stored in the Local Security Authority Subsystem Service (LSASS) memory and extracting saved passwords from Google Chrome. It explains the technical steps, the risks involved, and the mitigation strategies organizations can adopt.

Key Points:
Purpose of Mimikatz: Mimikatz is primarily used to demonstrate vulnerabilities in Windows authentication mechanisms by extracting sensitive data like plain text passwords, password hashes, and Kerberos tickets.

LSASS Memory Extraction: Windows temporarily stores user credentials in the LSASS memory. Mimikatz can retrieve this data in plain text form, bypassing the intended protections.

Steps:
Disable antivirus software (to avoid detection).
Launch mimikatz.exe with administrative privileges.
Enable debug privileges using privilege::debug.
Execute sekurlsa::logonpasswords to dump credentials from LSASS memory.
Chrome Password Extraction: Chrome saves passwords in an encrypted SQLite database called Login Data. Mimikatz can decrypt these passwords.

Steps:
Locate the database at %LocalAppData%\Google\Chrome\User Data\Default\.
Use the command dpapi::chrome /in:"path\to\Login Data" to extract credentials.
Risks & Mitigation:

Risks:
Unauthorized use of Mimikatz can lead to severe security breaches.
Plain text storage of passwords creates a critical vulnerability.
Mitigation:
Disable WDigest authentication to prevent plain text password storage.
Enable Credential Guard to protect LSASS memory.
Avoid storing sensitive passwords in browsers; use a dedicated password manager.
Conduct regular security audits.
Use Case & Screenshots: The report includes visual documentation of:

Installing Mimikatz in a virtualized environment (Windows 7 on VirtualBox).
Successfully extracting Chrome passwords.
Conclusion: The document concludes by emphasizing the critical nature of securing credentials and implementing best practices to defend against tools like Mimikatz.
--------------------------------------------------------------------------------------------------------------------------------------------------------------------
2. Investigating a PCAP File Using SNORT
Overview:
This cybersecurity incident response report focuses on analyzing network traffic captured in a PCAP (Packet Capture) file using Snort, a popular open-source Network Intrusion Detection System (NIDS). The analysis investigates potential threats, anomalies, and malicious activities in the captured traffic and provides recommendations to enhance network security.

Key Points:
Purpose of Analysis: The goal is to examine the PCAP file for evidence of suspicious or malicious activities, assess the security posture of the network, and recommend actionable mitigations.

Methodology:

Environment Setup:
Operating System: Ubuntu 20.04.2 LTS.
Snort Version: 2.9.7.0 GRE.
Default configuration and community rules were used without modification.
Analysis Process:
Load the PCAP File: The file named mx-1.pcap was analyzed using Snort.
Generate Alerts: Snort was configured to detect threats and anomalies by matching packets against predefined rules.
Review Logs: The alert and log files were analyzed to extract meaningful insights.
Findings:

Incident 1: ICMP Ping Behavior:

Description: Multiple ICMP Echo Requests and Replies were observed between a source IP and two destination IPs.
Significance: This behavior indicates reconnaissance activity, likely using tools to map active hosts in the network.
Recommendation: Implement IP filtering for suspicious IPs, limit ICMP traffic, and monitor for unusual patterns.
Incident 2: Repeated ICMP Traffic Patterns:

Description: Sequential ICMP requests with identical payloads and timing intervals suggested the use of automated reconnaissance tools.
Significance: This could indicate early stages of an attack.
Recommendation: Disable unnecessary ICMP responses, implement custom Snort rules for advanced detection, and enhance network monitoring.
Conclusion:

The detected ICMP traffic patterns highlight the importance of monitoring reconnaissance activities. Though the threats were classified as low severity, addressing them proactively strengthens network defenses.
Recommendations included implementing stricter ICMP filtering, using advanced Snort rules, and keeping Snort’s rule set updated.
Screenshots & Logs: The report includes:

Visuals of Snort environment setup.
Screenshots of detected alerts and logs generated from the PCAP analysis.
Summary
Both documents showcase advanced cybersecurity techniques:

Password Extraction with Mimikatz: Highlights vulnerabilities in Windows authentication mechanisms and browser password storage.
Network Analysis with Snort: Demonstrates the use of a NIDS to detect reconnaissance and potential threats in network traffic.
