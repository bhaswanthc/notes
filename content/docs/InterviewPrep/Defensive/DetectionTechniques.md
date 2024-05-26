---
author: "fireblood"
date: 2024-05-25
linktitle: Detection Techniques
menu:
  main:
    parent: InterviewPrep

title: Detection Techniques
weight: 1
---

# Based on Cyber Kill Chain

## 1. Reconnaissance

1. **Hunting for Open Ports using PowerShell:**
    - **Technique**: Attackers scan for open ports as initial reconnaissance to discover services they can exploit.
    - **Detection**: Develop scripts to log and analyze port scanning activities and alert on anomalies compared to baseline port usage.
    - **Response**: Block or limit access to unused ports, implement network segmentation, and regularly audit network services.
2. **Hunting Network Connections:**
    - **Technique**: Monitoring connections can reveal attempts to reach known bad domains or unusual external systems, indicating reconnaissance or data exfiltration attempts.
    - **Detection**: Use network traffic analysis tools to flag new, unexpected, or unauthorized connections.
    - **Response**: Block connections to known malicious IPs and domains, and implement network whitelisting.
3. **Hunting Metasploit:**
    - **Technique**: Using Metasploit for initial scanning and probing.
    - **Detection**: Detect signatures of Metasploit payloads and modules in network traffic, and monitor for suspicious endpoint behavior that correlates with common Metasploit tactics.
    - **Response**: Isolate and investigate systems showing signs of Metasploit activity, and update defenses to mitigate known Metasploit exploits.
4. **Hunting for Common Enumeration Techniques:**
    - **Technique**: Attackers use tools like Nmap and Nessus to enumerate network services and vulnerabilities.
    - **Detection**: Monitor for high volumes of network traffic and unusual patterns indicative of enumeration tools.
    - **Response**: Conduct regular internal vulnerability assessments to understand the attack surface and apply necessary patches.
5. **Hunting DNS Requests:**
    - **Technique**: Attackers often use DNS requests to resolve command and control servers or gather information about the network.
    - **Detection**: Analyze DNS query logs for unusual domain lookups and patterns that deviate from normal behavior.
    - **Response**: Block suspicious domains, implement DNS filtering solutions, and configure alerting for high-risk domain queries.
6. **Hunting Social Media and Public Data Leaks:**
    - **Technique**: Attackers gather information from social media profiles and public data sources.
    - **Detection**: Monitor social media and public forums for mentions of your organization, and use digital risk protection services.
    - **Response**: Educate employees on safe social media practices, and take down exposed sensitive information from public sites.
7. **OSINT Gathering:**
    - **Technique**: Collecting information from publicly available sources about the target organization.
    - **Detection**: Monitor social media, public forums, and other platforms for mentions of the organization or key personnel.
    - **Response**: Educate employees about the risks of oversharing information and implement policies to minimize exposure.
8. **DNS Reconnaissance:**
    - **Technique**: Querying DNS records to gather information about the target’s infrastructure.
    - **Detection**: Monitor DNS query logs for patterns indicative of reconnaissance activities.
    - **Response**: Implement DNS security measures such as DNSSEC, and regularly audit DNS records for unnecessary exposure.

## 2. Weaponization & Delivery

1. **Detecting File Creation:**
    - **Technique**: Delivery of malware via document downloads or email attachments.
    - **Detection**: Implement file integrity monitoring to detect the creation of new files, especially executable or script types, and scan them with antivirus software.
    - **Response**: Quarantine suspicious files immediately, alert relevant teams, and conduct a thorough scan of the affected system.
2. **Detecting Malicious Email Attachments:**
    - **Technique**: Embedding malicious code in email attachments.
    - **Detection**: Use email security gateways and sandboxing to analyze attachments for malicious behavior.
    - **Response**: Block emails with malicious attachments, educate users on the dangers of opening unknown attachments, and update email filtering rules.
3. **Detecting Malicious Links:**
    - **Technique**: Sending links to malicious websites that host exploit kits or malware.
    - **Detection**: Implement URL filtering and threat intelligence to block known malicious domains.
    - **Response**: Train users to recognize and avoid clicking on suspicious links, and use browser isolation techniques.
4. **Detecting Exploit Kits:**
    - **Technique**: Use of exploit kits to deliver malware through vulnerabilities in web browsers or plugins.
    - **Detection**: Monitor for indicators of exploit kit activity, such as unusual web traffic patterns or known exploit kit signatures.
    - **Response**: Patch vulnerable software promptly, use virtual patching for web applications, and employ intrusion prevention systems (IPS).
5. **Spear-Phishing Attachments:**
    - **Technique**: Crafting tailored emails with malicious attachments targeting specific individuals.
    - **Detection**: Use advanced email security solutions to scan attachments for malicious content and employ sandboxing techniques.
    - **Response**: Train employees to recognize and report suspicious emails, and configure email filters to block malicious attachments.
6. **Drive-By Downloads:**
    - **Technique**: Compromising websites to deliver malware when a user visits the site.
    - **Detection**: Implement web filtering solutions to block access to known malicious websites and use browser security settings to prevent automatic downloads.
    - **Response**: Regularly update web browsers and plugins to patch vulnerabilities, and educate users on the risks of visiting untrusted websites.

## 3. Exploitation

1. **Detecting Mimikatz:**
    - **Technique**: Extracting plaintext passwords, hash values, and Kerberos tickets from memory.
    - **Detection**: Monitor access to the LSASS process and detect typical Mimikatz command patterns or memory access behaviors.
    - **Response**: Implement endpoint protection solutions, restrict access to sensitive processes, and immediately isolate affected systems for forensic analysis.
2. **Hunting Abnormal LSASS Behavior and Detecting LSASS Behavior with PowerShell:**
    - **Technique**: Unusual interaction with the LSASS process indicating credential dumping attempts.
    - **Detection**: Implement rules in SIEM systems to alert on atypical accesses to LSASS, and use PowerShell scripts to check LSASS process integrity and behavior.
    - **Response**: Investigate and remediate abnormal behavior, update security policies to restrict LSASS access, and educate users on secure password handling.
3. **Detecting Exploits Against Web Applications:**
    - **Technique**: Exploiting vulnerabilities in web applications to gain unauthorized access or execute malicious code.
    - **Detection**: Use web application firewalls (WAFs) to detect and block malicious requests, and monitor application logs for signs of exploitation.
    - **Response**: Regularly update and patch web applications, conduct security assessments, and implement secure coding practices.
4. **Detecting Brute Force Attacks:**
    - **Technique**: Repeatedly trying different passwords to gain unauthorized access.
    - **Detection**: Monitor for excessive login attempts and failed authentication requests.
    - **Response**: Implement account lockout policies, use MFA, and analyze login patterns to identify and block brute force attempts.
5. **Exploitation of User Credentials:**
    - **Technique**: Using stolen credentials to gain unauthorized access.
    - **Detection**: Monitor for unusual login attempts, particularly from unfamiliar locations or devices.
    - **Response**: Enforce strong password policies, implement multi-factor authentication (MFA), and reset compromised credentials immediately.

## 4. Installation

1. **Hunting Malware:**
    - **Technique**: Installation of executables, DLLs, or scripts to maintain attacker presence.
    - **Detection**: Regular scans with updated antivirus definitions, anomaly detection for new processes or service installations, and behavioral analysis for known malware tactics.
    - **Response**: Quarantine detected malware, conduct a root cause analysis to understand how it was installed, and enhance defenses to prevent recurrence.
2. **Hunting RATS and C2 Servers:**
    - **Technique**: RATs establish persistence and facilitate remote access.
    - **Detection**: Monitor outbound connections for traffic to known C2 infrastructure, unusual periodic traffic patterns, or unrecognized encryption protocols.
    - **Response**: Block known C2 IP addresses and domains, isolate affected systems, and perform a full security audit to identify and close entry points.
3. **Hunting for Common Back Connect Ports with PowerShell:**
    - **Technique**: Specific network ports used by malware for outbound connections.
    - **Detection**: Use PowerShell to scan for and log connections on suspicious ports, with real-time alerts for unexpected activity.
    - **Response**: Block unauthorized ports, review firewall rules, and implement network segmentation to limit lateral movement.
4. **Detecting Malicious Scheduled Tasks:**
    - **Technique**: Using scheduled tasks to execute malicious code at specific times.
    - **Detection**: Monitor for the creation of new scheduled tasks and changes to existing tasks.
    - **Response**: Review and delete unauthorized scheduled tasks, and audit task creation policies.
5. **Detecting Startup Persistence Mechanisms:**
    - **Technique**: Modifying startup settings to ensure malware runs when the system starts.
    - **Detection**: Monitor startup folders, registry keys, and system services for changes.
    - **Response**: Remove unauthorized startup entries, reinforce access controls, and educate users on avoiding actions that enable persistence.
6. **Fileless Malware:**
    - **Technique**: Using legitimate system tools to execute malicious activities without writing files to disk.
    - **Detection**: Monitor system behavior for anomalies, such as unusual use of PowerShell or WMI.
    - **Response**: Implement application whitelisting and restrict the use of system tools to authorized personnel.
7. **Malicious Browser Extensions:**
    - **Technique**: Installing browser extensions that perform malicious actions.
    - **Detection**: Monitor for the installation of unauthorized browser extensions and unusual browser activity.
    - **Response**: Educate users on the risks of installing untrusted extensions, and implement browser security policies to control extension installations.

## 5. Command and Control (C2)

1. **Persistence:**
    - **Hunting Startup Persistence:**
        - **Technique**: Techniques involving registry keys, startup folder items, scheduled tasks, or services to reload malware after restarts.
        - **Detection**: Monitor and audit startup directories, task scheduler, service list, and registry startup keys for unexpected entries.
        - **Response**: Remove unauthorized startup entries, reinforce access controls, and educate users on avoiding actions that enable persistence.
	 - **Hunting Registry Key Persistence:**
	    - **Technique**: Using the registry to maintain persistence or configure software in a way that benefits the attacker.
	    - **Detection**: Regularly audit registry keys commonly used for persistence and use tools to detect hidden or obfuscated keys.
	    - **Response**: Remove malicious registry keys, update policies to prevent unauthorized changes, and monitor registry activities for suspicious behavior.
2. **Hunting for Command and Control (C2) Traffic:**
    - **Technique**: Establishing communication channels with compromised systems.
    - **Detection**: Monitor network traffic for known C2 patterns, beaconing behavior, and traffic to suspicious domains.
    - **Response**: Block identified C2 traffic, isolate compromised systems, and conduct a thorough investigation to identify and remove malware.
3. **Detecting DNS Tunneling:**
    - **Technique**: Using DNS queries to exfiltrate data or establish C2 channels.
    - **Detection**: Analyze DNS traffic for unusual query patterns and payload sizes.
    - **Response**: Implement DNS filtering and response policies, and block or sinkhole malicious domains.
4. **Domain Generation Algorithms (DGAs):**
    - **Technique**: Using algorithms to generate a large number of domain names for C2 communication.
    - **Detection**: Monitor DNS traffic for patterns indicative of DGAs and use threat intelligence feeds to identify known malicious domains.
    - **Response**: Block identified domains at the firewall, and implement DNS filtering solutions to prevent communication with DGA-generated domains.
5. **Beaconing:**
    - **Technique**: Regularly sending signals to a C2 server to check for instructions.
    - **Detection**: Use network monitoring tools to identify beaconing patterns, such as regular, periodic outbound connections.
    - **Response**: Investigate and block the source of beaconing traffic, and update firewall rules to prevent future connections.

## 6. Actions on Objectives

1. **Data Exfiltration:**
    - **Technique**: Stealing sensitive data from compromised systems.
    - **Detection**: Monitor for large, unusual data transfers and use Data Loss Prevention (DLP) solutions to detect and block unauthorized data movements. Analyze outbound traffic for abnormal patterns.
    - **Response**: Identify and isolate the source of exfiltration, mitigate the leak, review and enhance data access policies, and conduct a post-incident analysis to understand the breach and prevent recurrence.
2. **Detecting Evasion Techniques:**
    - Hunting Alternate Data Streams (ADS):
        - **Technique**: Hiding files/data from normal file browsing tools.
        - **Detection**: Scan file systems for hidden streams and monitor file system API calls for signs of ADS creation.
        - **Response**: Remove hidden streams, reinforce file system monitoring, and educate users on secure file handling practices.
    - **Detecting Remote Threads:**
        - **Technique**: Injecting code into other processes via remote threads.
        - **Detection**: Monitor for unexpected thread creation, especially from external processes into critical system processes.
        - **Response**: Terminate malicious threads, isolate affected processes, and perform a security review to prevent future injection attempts.
    - **Detecting Evasion Techniques with PowerShell:**
        - **Technique**: Using PowerShell to execute code directly in memory, modify system logs, or alter security settings.
        - **Detection**: Log and monitor PowerShell execution policies, command line inputs, and scripts run, focusing on encoded or obfuscated commands.
        - **Response**: Restrict PowerShell usage, implement logging and monitoring for all PowerShell activities, and update security policies to mitigate risks.
3. **Privilege Escalation:**
    - **Technique**: Gaining elevated access to perform unauthorized actions.
    - **Detection**: Monitor for abnormal behavior such as the creation of new admin accounts or changes to existing accounts. Use behavioral analytics to detect deviations from normal user activity.
    - **Response**: Immediately remove elevated access, investigate the source of the escalation, and apply security patches to prevent the exploit from being reused.
4. **Impact and Sabotage:**
    - **Technique**: Disrupting services, deleting data, or otherwise causing harm to the organization.
    - **Detection**: Monitor system logs for unusual deletion activities, service disruptions, or unauthorized configuration changes.
    - **Response**: Isolate affected systems, restore from backups, conduct a thorough incident review, and enhance monitoring and protection mechanisms to prevent recurrence.

# Based on Unified Kill Chain

## 1. Reconnaissance

1. **Hunting for Open Ports using PowerShell:**
    - **Technique**: Attackers scan for open ports to discover services they can exploit.
    - **Detection**: Develop scripts to log and analyze port scanning activities and alert on anomalies compared to baseline port usage.
    - **Response**: Block or limit access to unused ports, implement network segmentation, and regularly audit network services.

2. **Hunting Network Connections:**
    - **Technique**: Monitoring connections to reveal attempts to reach known bad domains or unusual external systems.
    - **Detection**: Use network traffic analysis tools to flag new, unexpected, or unauthorized connections.
    - **Response**: Block connections to known malicious IPs and domains, and implement network whitelisting.

3. **Hunting Metasploit:**
    - **Technique**: Using Metasploit for initial scanning and probing.
    - **Detection**: Detect signatures of Metasploit payloads and modules in network traffic, and monitor for suspicious endpoint behavior.
    - **Response**: Isolate and investigate systems showing signs of Metasploit activity, and update defenses to mitigate known Metasploit exploits.

4. **Hunting for Common Enumeration Techniques:**
    - **Technique**: Attackers use tools like Nmap and Nessus to enumerate network services and vulnerabilities.
    - **Detection**: Monitor for high volumes of network traffic and unusual patterns indicative of enumeration tools.
    - **Response**: Conduct regular internal vulnerability assessments to understand the attack surface and apply necessary patches.

5. **Hunting DNS Requests:**
    - **Technique**: Attackers use DNS requests to resolve command and control servers or gather information about the network.
    - **Detection**: Analyze DNS query logs for unusual domain lookups and patterns that deviate from normal behavior.
    - **Response**: Block suspicious domains, implement DNS filtering solutions, and configure alerting for high-risk domain queries.

6. **Hunting Social Media and Public Data Leaks:**
    - **Technique**: Attackers gather information from social media profiles and public data sources.
    - **Detection**: Monitor social media and public forums for mentions of your organization, and use digital risk protection services.
    - **Response**: Educate employees on safe social media practices, and take down exposed sensitive information from public sites.

7. **OSINT Gathering:**
    - **Technique**: Collecting information from publicly available sources about the target organization.
    - **Detection**: Monitor social media, public forums, and other platforms for mentions of the organization or key personnel.
    - **Response**: Educate employees about the risks of oversharing information and implement policies to minimize exposure.

8. **DNS Reconnaissance:**
    - **Technique**: Querying DNS records to gather information about the target’s infrastructure.
    - **Detection**: Monitor DNS query logs for patterns indicative of reconnaissance activities.
    - **Response**: Implement DNS security measures such as DNSSEC, and regularly audit DNS records for unnecessary exposure.

## 2. Resource Development

1. **Hunting for Credential Dumping Tools:**
    - **Technique**: Using tools like Mimikatz to extract passwords and hashes from memory.
    - **Detection**: Monitor for execution of known credential dumping tools and abnormal access to sensitive processes like LSASS.
    - **Response**: Implement endpoint protection solutions, restrict access to sensitive processes, and isolate affected systems for forensic analysis.

2. **Detecting Malware Compilers:**
    - **Technique**: Development and compilation of custom malware.
    - **Detection**: Monitor for the use of common compilers and development environments used to create malware.
    - **Response**: Isolate development environments from production networks and monitor for suspicious compilations.

3. **Detecting Malicious Email Campaigns:**
    - **Technique**: Crafting and distributing phishing emails to gather credentials or deliver malware.
    - **Detection**: Use email security solutions to detect and block phishing attempts and monitor for unusual email patterns.
    - **Response**: Educate users on phishing threats and implement email filtering rules.

4. **Detecting Rogue Infrastructure:**
    - **Technique**: Setting up command and control servers and other malicious infrastructure.
    - **Detection**: Use threat intelligence to identify and monitor rogue domains and IP addresses.
    - **Response**: Block access to known malicious infrastructure and monitor for attempts to connect to suspicious domains.

5. **Hunting Malicious Code Repositories:**
    - **Technique**: Storing and sharing malicious code through public or private repositories.
    - **Detection**: Monitor for access to known malicious repositories and inspect repositories for suspicious code.
    - **Response**: Block access to malicious repositories and implement code review policies.

6. **Hunting Compromised Accounts:**
    - **Technique**: Using compromised accounts to gain further access or distribute malware.
    - **Detection**: Monitor for unusual login attempts and access patterns.
    - **Response**: Reset compromised credentials and implement multi-factor authentication.

7. **Hunting for Exploit Kits:**
    - **Technique**: Developing or purchasing exploit kits to deliver malware.
    - **Detection**: Monitor for traffic indicative of exploit kit use and analyze suspicious files.
    - **Response**: Patch vulnerable software and block known exploit kit domains.

## 3. Delivery

1. **Detecting Malicious Email Attachments:**
    - **Technique**: Embedding malicious code in email attachments.
    - **Detection**: Use email security gateways and sandboxing to analyze attachments for malicious behavior.
    - **Response**: Block emails with malicious attachments and educate users on the dangers of opening unknown attachments.

2. **Detecting Malicious Links:**
    - **Technique**: Sending links to malicious websites that host exploit kits or malware.
    - **Detection**: Implement URL filtering and threat intelligence to block known malicious domains.
    - **Response**: Train users to recognize and avoid clicking on suspicious links and use browser isolation techniques.

3. **Drive-By Downloads:**
    - **Technique**: Compromising websites to deliver malware when a user visits the site.
    - **Detection**: Implement web filtering solutions to block access to known malicious websites and use browser security settings to prevent automatic downloads.
    - **Response**: Regularly update web browsers and plugins to patch vulnerabilities and educate users on the risks of visiting untrusted websites.

4. **Watering Hole Attacks:**
    - **Technique**: Compromising a site likely to be visited by the target to deliver malware.
    - **Detection**: Monitor for unusual activity on commonly visited sites and use threat intelligence to identify compromised sites.
    - **Response**: Block access to compromised sites and educate users on safe browsing practices.

5. **USB-Based Malware:**
    - **Technique**: Using infected USB drives to deliver malware.
    - **Detection**: Monitor for new USB device connections and scan for malware.
    - **Response**: Educate users on the risks of using untrusted USB devices and implement USB usage policies.

6. **Malvertising:**
    - **Technique**: Using malicious advertisements to deliver malware.
    - **Detection**: Use ad blockers and monitor for unusual web activity.
    - **Response**: Block access to known malvertising networks and educate users on the risks of clicking on ads.

7. **Supply Chain Attacks:**
    - **Technique**: Compromising a third-party supplier to deliver malware.
    - **Detection**: Monitor for unusual activity from third-party software and services.
    - **Response**: Conduct security assessments of suppliers and implement monitoring for third-party services.

8. **Spear-Phishing Attachments:**
    - **Technique**: Crafting tailored emails with malicious attachments targeting specific individuals.
    - **Detection**: Use advanced email security solutions to scan attachments for malicious content and employ sandboxing techniques.
    - **Response**: Train employees to recognize and report suspicious emails and configure email filters to block malicious attachments.

## 4. Social Engineering

1. **Pretexting:**
    - **Technique**: Creating a fabricated scenario to obtain information or access.
    - **Detection**: Educate employees on social engineering tactics and monitor for unusual requests for sensitive information.
    - **Response**: Implement verification processes for sensitive requests and conduct regular social engineering awareness training.

2. **Baiting:**
    - **Technique**: Offering something enticing to lure victims into a trap.
    - **Detection**: Monitor for suspicious offers or emails and educate users on the risks of accepting unknown offers.
    - **Response**: Block known baiting attempts and reinforce policies against engaging with unknown offers.

3. **Quid Pro Quo:**
    - **Technique**: Offering a service or benefit in exchange for information.
    - **Detection**: Monitor for unusual requests for information and educate users on the risks of exchanging information for services.
    - **Response**: Implement strict information sharing policies and verify all requests for information.

4. **Tailgating:**
    - **Technique**: Following someone into a secure area without proper authorization.
    - **Detection**: Use physical security measures like badge access and educate employees on the importance of not allowing tailgating.
    - **Response**: Implement policies for reporting tailgating incidents and reinforce physical security measures.

5. **Vishing:**
    - **Technique**: Using phone calls to deceive individuals into revealing information.
    - **Detection**: Monitor for unusual phone activity and educate users on the risks of sharing information over the phone.
    - **Response**: Implement verification processes for sensitive information shared over the phone and conduct regular awareness training.

6. **Smishing:**
    - **Technique**: Using SMS messages to deceive individuals into revealing information.
    - **Detection**:

 Monitor for suspicious SMS messages and educate users on the risks of sharing information via SMS.
    - **Response**: Block known malicious SMS senders and reinforce policies against sharing sensitive information via SMS.

7. **Shoulder Surfing:**
    - **Technique**: Observing someone’s screen to gather information.
    - **Detection**: Educate employees on the risks of shoulder surfing and monitor for unusual behavior in workspaces.
    - **Response**: Implement privacy screens and conduct awareness training on securing screens in public areas.

8. **Impersonation:**
    - **Technique**: Pretending to be someone else to gain access or information.
    - **Detection**: Educate employees on impersonation tactics and monitor for unusual requests for access or information.
    - **Response**: Implement verification processes for identity and conduct regular awareness training.

## 5. Exploitation

1. **Exploiting Vulnerabilities in Web Applications:**
    - **Technique**: Using known vulnerabilities to gain unauthorized access or execute malicious code.
    - **Detection**: Use web application firewalls (WAFs) to detect and block malicious requests and monitor application logs for signs of exploitation.
    - **Response**: Regularly update and patch web applications, conduct security assessments, and implement secure coding practices.

2. **Exploiting Software Vulnerabilities:**
    - **Technique**: Using vulnerabilities in software to gain access or escalate privileges.
    - **Detection**: Monitor for signs of exploitation and use intrusion detection systems (IDS) to detect suspicious activity.
    - **Response**: Patch software promptly and use virtual patching to mitigate vulnerabilities.

3. **Exploiting Configuration Weaknesses:**
    - **Technique**: Taking advantage of weak or misconfigured settings to gain access.
    - **Detection**: Conduct regular security assessments and monitor for configuration changes.
    - **Response**: Implement secure configuration policies and regularly audit configurations.

4. **Exploiting Insecure APIs:**
    - **Technique**: Using vulnerabilities in APIs to gain unauthorized access.
    - **Detection**: Monitor API traffic for signs of exploitation and use API gateways to enforce security policies.
    - **Response**: Secure APIs with authentication and authorization controls and regularly test for vulnerabilities.

5. **Exploiting Buffer Overflows:**
    - **Technique**: Using buffer overflow vulnerabilities to execute arbitrary code.
    - **Detection**: Monitor for signs of buffer overflow attacks and use security solutions to detect and block them.
    - **Response**: Apply patches and updates to vulnerable software and use security coding practices to prevent buffer overflows.

6. **Exploiting Weak Authentication:**
    - **Technique**: Using weak or compromised authentication mechanisms to gain access.
    - **Detection**: Monitor for unusual login attempts and use multi-factor authentication (MFA).
    - **Response**: Implement strong authentication policies and regularly review and update them.

7. **Exploiting Privilege Escalation Vulnerabilities:**
    - **Technique**: Using vulnerabilities to gain elevated privileges.
    - **Detection**: Monitor for signs of privilege escalation and use security solutions to detect and block them.
    - **Response**: Apply patches and updates to vulnerable software and use security best practices to prevent privilege escalation.

8. **Exploiting Credential Reuse:**
    - **Technique**: Using stolen credentials to gain unauthorized access.
    - **Detection**: Monitor for unusual login attempts and use MFA.
    - **Response**: Implement strong password policies and educate users on the risks of credential reuse.

## 6. Persistence

1. **Hunting Malware:**
    - **Technique**: Installation of executables, DLLs, or scripts to maintain attacker presence.
    - **Detection**: Regular scans with updated antivirus definitions, anomaly detection for new processes or service installations, and behavioral analysis for known malware tactics.
    - **Response**: Quarantine detected malware, conduct a root cause analysis to understand how it was installed, and enhance defenses to prevent recurrence.

2. **Hunting RATS and C2 Servers:**
    - **Technique**: RATs establish persistence and facilitate remote access.
    - **Detection**: Monitor outbound connections for traffic to known C2 infrastructure, unusual periodic traffic patterns, or unrecognized encryption protocols.
    - **Response**: Block known C2 IP addresses and domains, isolate affected systems, and perform a full security audit to identify and close entry points.

3. **Hunting for Common Back Connect Ports with PowerShell:**
    - **Technique**: Specific network ports used by malware for outbound connections.
    - **Detection**: Use PowerShell to scan for and log connections on suspicious ports, with real-time alerts for unexpected activity.
    - **Response**: Block unauthorized ports, review firewall rules, and implement network segmentation to limit lateral movement.

4. **Detecting Malicious Scheduled Tasks:**
    - **Technique**: Using scheduled tasks to execute malicious code at specific times.
    - **Detection**: Monitor for the creation of new scheduled tasks and changes to existing tasks.
    - **Response**: Review and delete unauthorized scheduled tasks, and audit task creation policies.

5. **Detecting Startup Persistence Mechanisms:**
    - **Technique**: Modifying startup settings to ensure malware runs when the system starts.
    - **Detection**: Monitor startup folders, registry keys, and system services for changes.
    - **Response**: Remove unauthorized startup entries, reinforce access controls, and educate users on avoiding actions that enable persistence.

6. **Fileless Malware:**
    - **Technique**: Using legitimate system tools to execute malicious activities without writing files to disk.
    - **Detection**: Monitor system behavior for anomalies, such as unusual use of PowerShell or WMI.
    - **Response**: Implement application whitelisting and restrict the use of system tools to authorized personnel.

7. **Malicious Browser Extensions:**
    - **Technique**: Installing browser extensions that perform malicious actions.
    - **Detection**: Monitor for the installation of unauthorized browser extensions and unusual browser activity.
    - **Response**: Educate users on the risks of installing untrusted extensions, and implement browser security policies to control extension installations.

8. **Hunting Registry Key Persistence:**
    - **Technique**: Using the registry to maintain persistence or configure software in a way that benefits the attacker.
    - **Detection**: Regularly audit registry keys commonly used for persistence and use tools to detect hidden or obfuscated keys.
    - **Response**: Remove malicious registry keys, update policies to prevent unauthorized changes, and monitor registry activities for suspicious behavior.

## 7. Defense Evasion

1. **Hunting Alternate Data Streams (ADS):**
    - **Technique**: Hiding files/data from normal file browsing tools.
    - **Detection**: Scan file systems for hidden streams and monitor file system API calls for signs of ADS creation.
    - **Response**: Remove hidden streams, reinforce file system monitoring, and educate users on secure file handling practices.

2. **Detecting Remote Threads:**
    - **Technique**: Injecting code into other processes via remote threads.
    - **Detection**: Monitor for unexpected thread creation, especially from external processes into critical system processes.
    - **Response**: Terminate malicious threads, isolate affected processes, and perform a security review to prevent future injection attempts.

3. **Detecting Evasion Techniques with PowerShell:**
    - **Technique**: Using PowerShell to execute code directly in memory, modify system logs, or alter security settings.
    - **Detection**: Log and monitor PowerShell execution policies, command line inputs, and scripts run, focusing on encoded or obfuscated commands.
    - **Response**: Restrict PowerShell usage, implement logging and monitoring for all PowerShell activities, and update security policies to mitigate risks.

4. **Detecting Obfuscated Files or Information:**
    - **Technique**: Using obfuscation techniques to hide malicious code or data.
    - **Detection**: Use static and dynamic analysis tools to detect obfuscation techniques in files and scripts.
    - **Response**: Deobfuscate and analyze suspicious files, and update detection rules to recognize new obfuscation methods.

5. **Detecting Process Injection:**
    - **Technique**: Injecting malicious code into legitimate processes.
    - **Detection**: Monitor for abnormal memory modifications and the creation of new threads in existing processes.
    - **Response**: Investigate and terminate malicious processes, and update security measures to prevent future injections.

6. **Hunting for Rootkits:**
    - **Technique**: Using rootkits to hide malicious activities and maintain persistence.
    - **Detection**: Use rootkit detection tools and monitor for signs of rootkit activity, such as hidden files and processes.
    - **Response**: Remove detected rootkits, conduct a full system scan, and update security policies to prevent rootkit installations.

7. **Detecting Anti-Forensics Techniques:**
    - **Technique**: Using techniques to prevent or hinder forensic analysis.
    - **Detection**: Monitor for the use of anti-forensics tools and techniques, such as data wiping and encryption.
    - **Response**: Investigate and counteract anti-forensics measures, and update policies to detect and prevent their use.

8. **Detecting Log Manipulation:**
    - **Technique**: Altering or deleting logs to cover tracks.
    - **Detection**: Monitor for unusual log activity and implement tamper-evident logging solutions.
    - **Response**: Investigate and restore altered or deleted logs, and reinforce logging policies to ensure integrity.

## 8. Command & Control (C2)

1. **Hunting for Command and Control (C2) Traffic:**
    - **Technique**: Establishing communication channels with compromised systems.
    - **Detection**: Monitor network traffic for known C

2 patterns, beaconing behavior, and traffic to suspicious domains.
    - **Response**: Block identified C2 traffic, isolate compromised systems, and conduct a thorough investigation to identify and remove malware.

2. **Detecting DNS Tunneling:**
    - **Technique**: Using DNS queries to exfiltrate data or establish C2 channels.
    - **Detection**: Analyze DNS traffic for unusual query patterns and payload sizes.
    - **Response**: Implement DNS filtering and response policies, and block or sinkhole malicious domains.

3. **Domain Generation Algorithms (DGAs):**
    - **Technique**: Using algorithms to generate a large number of domain names for C2 communication.
    - **Detection**: Monitor DNS traffic for patterns indicative of DGAs and use threat intelligence feeds to identify known malicious domains.
    - **Response**: Block identified domains at the firewall, and implement DNS filtering solutions to prevent communication with DGA-generated domains.

4. **Beaconing:**
    - **Technique**: Regularly sending signals to a C2 server to check for instructions.
    - **Detection**: Use network monitoring tools to identify beaconing patterns, such as regular, periodic outbound connections.
    - **Response**: Investigate and block the source of beaconing traffic, and update firewall rules to prevent future connections.

5. **Detecting C2 Over HTTPS:**
    - **Technique**: Using HTTPS to encrypt C2 traffic and evade detection.
    - **Detection**: Monitor for unusual HTTPS traffic patterns and use SSL inspection to analyze encrypted traffic.
    - **Response**: Block identified malicious HTTPS traffic and implement SSL inspection policies.

6. **Detecting C2 Over Social Media:**
    - **Technique**: Using social media platforms to communicate with C2 servers.
    - **Detection**: Monitor for unusual social media activity and use threat intelligence to identify malicious accounts.
    - **Response**: Block access to known malicious social media accounts and reinforce social media usage policies.

7. **Detecting C2 Over P2P Networks:**
    - **Technique**: Using peer-to-peer networks for C2 communication.
    - **Detection**: Monitor for unusual P2P traffic patterns and use threat intelligence to identify malicious P2P nodes.
    - **Response**: Block identified malicious P2P traffic and implement P2P usage policies.

8. **Detecting C2 Over Custom Protocols:**
    - **Technique**: Using custom protocols to evade detection.
    - **Detection**: Monitor for unusual traffic patterns and use deep packet inspection (DPI) to analyze traffic.
    - **Response**: Block identified malicious custom protocol traffic and update firewall rules to prevent future connections.

## 9. Pivoting

1. **Detecting Lateral Movement:**
    - **Technique**: Moving laterally within the network to gain access to additional systems.
    - **Detection**: Monitor for unusual login attempts and access patterns, and use endpoint detection and response (EDR) solutions.
    - **Response**: Isolate affected systems, reset credentials, and conduct a full security audit.

2. **Detecting Pass-the-Hash Attacks:**
    - **Technique**: Using stolen hash values to authenticate without knowing the actual password.
    - **Detection**: Monitor for unusual authentication attempts and use multi-factor authentication (MFA).
    - **Response**: Reset compromised credentials and implement strong password policies.

3. **Detecting Pass-the-Ticket Attacks:**
    - **Technique**: Using stolen Kerberos tickets to authenticate.
    - **Detection**: Monitor for unusual Kerberos ticket activity and use MFA.
    - **Response**: Reset compromised credentials and implement strong authentication policies.

4. **Detecting Remote Desktop Protocol (RDP) Usage:**
    - **Technique**: Using RDP to move laterally within the network.
    - **Detection**: Monitor for unusual RDP activity and use endpoint security solutions.
    - **Response**: Restrict RDP usage and implement network segmentation.

5. **Detecting SMB Relay Attacks:**
    - **Technique**: Using the Server Message Block (SMB) protocol to relay authentication requests.
    - **Detection**: Monitor for unusual SMB activity and use network security solutions.
    - **Response**: Block identified malicious SMB traffic and implement network segmentation.

6. **Detecting Remote File Copy:**
    - **Technique**: Copying files remotely to facilitate lateral movement.
    - **Detection**: Monitor for unusual file copy activity and use data loss prevention (DLP) solutions.
    - **Response**: Block identified malicious file copy attempts and implement network segmentation.

7. **Detecting Windows Management Instrumentation (WMI) Usage:**
    - **Technique**: Using WMI to execute commands on remote systems.
    - **Detection**: Monitor for unusual WMI activity and use endpoint security solutions.
    - **Response**: Restrict WMI usage and implement network segmentation.

8. **Detecting PowerShell Remoting:**
    - **Technique**: Using PowerShell to execute commands on remote systems.
    - **Detection**: Monitor for unusual PowerShell remoting activity and use endpoint security solutions.
    - **Response**: Restrict PowerShell remoting usage and implement network segmentation.

## 10. Discovery

1. **Detecting Network Scanning:**
    - **Technique**: Scanning the network to discover devices and services.
    - **Detection**: Monitor for unusual network scanning activity and use intrusion detection systems (IDS).
    - **Response**: Block identified malicious scanning attempts and implement network segmentation.

2. **Detecting Account Enumeration:**
    - **Technique**: Enumerating user accounts to identify targets.
    - **Detection**: Monitor for unusual account enumeration activity and use endpoint security solutions.
    - **Response**: Block identified malicious enumeration attempts and implement strong authentication policies.

3. **Detecting Group Policy Enumeration:**
    - **Technique**: Enumerating group policies to understand security settings.
    - **Detection**: Monitor for unusual group policy enumeration activity and use endpoint security solutions.
    - **Response**: Block identified malicious enumeration attempts and implement strong security policies.

4. **Detecting File Share Enumeration:**
    - **Technique**: Enumerating file shares to identify potential targets.
    - **Detection**: Monitor for unusual file share enumeration activity and use endpoint security solutions.
    - **Response**: Block identified malicious enumeration attempts and implement strong access controls.

5. **Detecting Software Inventory:**
    - **Technique**: Enumerating installed software to identify vulnerabilities.
    - **Detection**: Monitor for unusual software inventory activity and use endpoint security solutions.
    - **Response**: Block identified malicious inventory attempts and implement strong security policies.

6. **Detecting System Information Discovery:**
    - **Technique**: Gathering information about the system to identify targets.
    - **Detection**: Monitor for unusual system information discovery activity and use endpoint security solutions.
    - **Response**: Block identified malicious discovery attempts and implement strong security policies.

7. **Detecting Network Topology Discovery:**
    - **Technique**: Mapping the network topology to identify targets.
    - **Detection**: Monitor for unusual network topology discovery activity and use network security solutions.
    - **Response**: Block identified malicious discovery attempts and implement network segmentation.

8. **Detecting Active Directory Enumeration:**
    - **Technique**: Enumerating Active Directory to identify targets.
    - **Detection**: Monitor for unusual Active Directory enumeration activity and use endpoint security solutions.
    - **Response**: Block identified malicious enumeration attempts and implement strong security policies.

## 11. Privilege Escalation

1. **Detecting Mimikatz:**
    - **Technique**: Extracting plaintext passwords, hash values, and Kerberos tickets from memory.
    - **Detection**: Monitor access to the LSASS process and detect typical Mimikatz command patterns or memory access behaviors.
    - **Response**: Implement endpoint protection solutions, restrict access to sensitive processes, and immediately isolate affected systems for forensic analysis.

2. **Hunting Abnormal LSASS Behavior and Detecting LSASS Behavior with PowerShell:**
    - **Technique**: Unusual interaction with the LSASS process indicating credential dumping attempts.
    - **Detection**: Implement rules in SIEM systems to alert on atypical accesses to LSASS, and use PowerShell scripts to check LSASS process integrity and behavior.
    - **Response**: Investigate and remediate abnormal behavior, update security policies to restrict LSASS access, and educate users on secure password handling.

3. **Detecting Exploits Against Web Applications:**
    - **Technique**: Exploiting vulnerabilities in web applications to gain unauthorized access or execute malicious code.
    - **Detection**: Use web application firewalls (WAFs) to detect and block malicious requests, and monitor application logs for signs of exploitation.
    - **Response**: Regularly update and patch web applications, conduct security assessments, and implement secure coding practices.

4. **Detecting Brute Force Attacks:**
    - **Technique**: Repeatedly trying different passwords to gain unauthorized access.
    - **Detection**: Monitor for excessive login attempts and failed authentication requests.
    - **Response**: Implement account lockout policies, use MFA, and analyze login patterns to identify and block brute force attempts.

5. **Exploitation of User Credentials:**
    - **Technique**: Using stolen credentials to gain unauthorized access.
    - **Detection**: Monitor for unusual login attempts, particularly from unfamiliar locations or devices.
    - **Response**: Enforce strong password policies, implement multi-factor authentication (MFA), and reset compromised credentials immediately.

6. **Detecting Kerberoasting:**
    - **Technique**: Extracting Kerberos service tickets to crack offline and retrieve plaintext passwords.
    - **Detection**: Monitor

 for unusual Kerberos ticket requests and use honeypots to detect Kerberoasting attempts.
    - **Response**: Enforce strong password policies, implement monitoring for Kerberos activity, and update security policies.

7. **Detecting Token Impersonation:**
    - **Technique**: Using stolen tokens to impersonate users and gain unauthorized access.
    - **Detection**: Monitor for unusual token usage and access patterns.
    - **Response**: Reset compromised tokens and implement strong authentication policies.

8. **Detecting Exploits for Privilege Escalation:**
    - **Technique**: Using known exploits to gain elevated privileges.
    - **Detection**: Monitor for signs of privilege escalation exploits and use endpoint security solutions.
    - **Response**: Patch vulnerable software and implement strong security policies.

## 12. Execution

1. **Detecting Malicious Scripts:**
    - **Technique**: Using scripts to execute malicious actions.
    - **Detection**: Monitor for unusual script activity and use endpoint security solutions.
    - **Response**: Block identified malicious scripts and implement script execution policies.

2. **Detecting Exploit Kits:**
    - **Technique**: Using exploit kits to deliver malware through vulnerabilities in web browsers or plugins.
    - **Detection**: Monitor for indicators of exploit kit activity, such as unusual web traffic patterns or known exploit kit signatures.
    - **Response**: Patch vulnerable software promptly, use virtual patching for web applications, and employ intrusion prevention systems (IPS).

3. **Detecting Malicious Macros:**
    - **Technique**: Using macros in documents to execute malicious actions.
    - **Detection**: Monitor for unusual macro activity and use endpoint security solutions.
    - **Response**: Block identified malicious macros and implement macro execution policies.

4. **Detecting Scheduled Tasks:**
    - **Technique**: Using scheduled tasks to execute malicious actions at specific times.
    - **Detection**: Monitor for unusual scheduled task activity and use endpoint security solutions.
    - **Response**: Block identified malicious scheduled tasks and implement task scheduling policies.

5. **Detecting PowerShell Execution:**
    - **Technique**: Using PowerShell to execute malicious actions.
    - **Detection**: Monitor for unusual PowerShell activity and use endpoint security solutions.
    - **Response**: Block identified malicious PowerShell scripts and implement PowerShell execution policies.

6. **Detecting Command Line Execution:**
    - **Technique**: Using command line tools to execute malicious actions.
    - **Detection**: Monitor for unusual command line activity and use endpoint security solutions.
    - **Response**: Block identified malicious command line activity and implement command line execution policies.

7. **Detecting WMI Execution:**
    - **Technique**: Using WMI to execute malicious actions.
    - **Detection**: Monitor for unusual WMI activity and use endpoint security solutions.
    - **Response**: Block identified malicious WMI scripts and implement WMI execution policies.

8. **Detecting Exploit Modules:**
    - **Technique**: Using exploit modules to execute malicious actions.
    - **Detection**: Monitor for unusual exploit module activity and use endpoint security solutions.
    - **Response**: Block identified malicious exploit modules and implement exploit execution policies.

## 13. Credential Access

1. **Detecting Credential Dumping:**
    - **Technique**: Using tools like Mimikatz to extract passwords and hashes from memory.
    - **Detection**: Monitor for unusual process activity and access to sensitive processes like LSASS.
    - **Response**: Block identified credential dumping attempts and implement endpoint security solutions.

2. **Detecting Keylogging:**
    - **Technique**: Using keyloggers to capture keystrokes and obtain credentials.
    - **Detection**: Monitor for unusual process activity and use endpoint security solutions.
    - **Response**: Block identified keyloggers and implement strong security policies.

3. **Detecting Credential Harvesting:**
    - **Technique**: Using phishing or other methods to obtain credentials.
    - **Detection**: Monitor for unusual login attempts and use endpoint security solutions.
    - **Response**: Block identified credential harvesting attempts and implement strong authentication policies.

4. **Detecting Password Spraying:**
    - **Technique**: Using a single password against multiple accounts to gain access.
    - **Detection**: Monitor for unusual login attempts and use endpoint security solutions.
    - **Response**: Block identified password spraying attempts and implement strong password policies.

5. **Detecting Brute Force Attacks:**
    - **Technique**: Repeatedly trying different passwords to gain access.
    - **Detection**: Monitor for unusual login attempts and use endpoint security solutions.
    - **Response**: Block identified brute force attempts and implement strong authentication policies.

6. **Detecting Pass-the-Hash Attacks:**
    - **Technique**: Using stolen hash values to authenticate without knowing the actual password.
    - **Detection**: Monitor for unusual authentication attempts and use endpoint security solutions.
    - **Response**: Block identified pass-the-hash attempts and implement strong authentication policies.

7. **Detecting Pass-the-Ticket Attacks:**
    - **Technique**: Using stolen Kerberos tickets to authenticate.
    - **Detection**: Monitor for unusual Kerberos ticket activity and use endpoint security solutions.
    - **Response**: Block identified pass-the-ticket attempts and implement strong authentication policies.

8. **Detecting Credential Reuse:**
    - **Technique**: Using stolen credentials to gain unauthorized access.
    - **Detection**: Monitor for unusual login attempts and use endpoint security solutions.
    - **Response**: Block identified credential reuse attempts and implement strong authentication policies.

## 14. Lateral Movement

1. **Detecting Remote Desktop Protocol (RDP) Usage:**
    - **Technique**: Using RDP to move laterally within the network.
    - **Detection**: Monitor for unusual RDP activity and use endpoint security solutions.
    - **Response**: Block identified malicious RDP activity and implement strong RDP usage policies.

2. **Detecting SMB Relay Attacks:**
    - **Technique**: Using the Server Message Block (SMB) protocol to relay authentication requests.
    - **Detection**: Monitor for unusual SMB activity and use endpoint security solutions.
    - **Response**: Block identified malicious SMB activity and implement strong SMB usage policies.

3. **Detecting Remote File Copy:**
    - **Technique**: Copying files remotely to facilitate lateral movement.
    - **Detection**: Monitor for unusual file copy activity and use endpoint security solutions.
    - **Response**: Block identified malicious file copy activity and implement strong file copy policies.

4. **Detecting Windows Management Instrumentation (WMI) Usage:**
    - **Technique**: Using WMI to execute commands on remote systems.
    - **Detection**: Monitor for unusual WMI activity and use endpoint security solutions.
    - **Response**: Block identified malicious WMI activity and implement strong WMI usage policies.

5. **Detecting PowerShell Remoting:**
    - **Technique**: Using PowerShell to execute commands on remote systems.
    - **Detection**: Monitor for unusual PowerShell remoting activity and use endpoint security solutions.
    - **Response**: Block identified malicious PowerShell remoting activity and implement strong PowerShell remoting policies.

6. **Detecting Pass-the-Hash Attacks:**
    - **Technique**: Using stolen hash values to authenticate without knowing the actual password.
    - **Detection**: Monitor for unusual authentication attempts and use endpoint security solutions.
    - **Response**: Block identified pass-the-hash attempts and implement strong authentication policies.

7. **Detecting Pass-the-Ticket Attacks:**
    - **Technique**: Using stolen Kerberos tickets to authenticate.
    - **Detection**: Monitor for unusual Kerberos ticket activity and use endpoint security solutions.
    - **Response**: Block identified pass-the-ticket attempts and implement strong authentication policies.

8. **Detecting Credential Reuse:**
    - **Technique**: Using stolen credentials to gain unauthorized access.
    - **Detection**: Monitor for unusual login attempts and use endpoint security solutions.
    - **Response**: Block identified credential reuse attempts and implement strong authentication policies.

## 15. Collection

1. **Detecting Data Staging:**
    - **Technique**: Preparing data for exfiltration.
    - **Detection**: Monitor for unusual data staging activity and use endpoint security solutions.
    - **Response**: Block identified data staging attempts and implement strong data staging policies.

2. **Detecting Data Archiving:**
    - **Technique**: Archiving data to facilitate exfiltration.
    - **Detection**: Monitor for unusual data archiving activity and use endpoint security solutions.
    - **Response**: Block identified data archiving attempts and implement strong data archiving policies.

3. **Detecting Data Compression:**
    - **Technique**: Compressing data to facilitate exfiltration.
    - **Detection**: Monitor for unusual data compression activity and use endpoint security solutions.
    - **Response**: Block identified data compression attempts and implement strong data compression policies.

4. **Detecting Data Encryption:**
    - **Technique**: Encrypting data to facilitate exfiltration.
    - **Detection**: Monitor for unusual data encryption activity and use endpoint security solutions.
    - **Response**: Block identified data encryption attempts and implement strong data encryption policies.

5. **Detecting Data Transfer:**
    - **Technique**: Transferring data to a remote location to facilitate exfiltration.
    - **Detection**: Monitor for unusual data transfer activity and use endpoint security solutions.
    - **Response**: Block identified data transfer attempts and implement strong data transfer policies.

6. **Detecting Data Collection Tools:**
    - **Technique**: Using tools

 to collect data for exfiltration.
    - **Detection**: Monitor for unusual data collection tool activity and use endpoint security solutions.
    - **Response**: Block identified data collection tools and implement strong data collection policies.

7. **Detecting Data Collection Scripts:**
    - **Technique**: Using scripts to collect data for exfiltration.
    - **Detection**: Monitor for unusual data collection script activity and use endpoint security solutions.
    - **Response**: Block identified data collection scripts and implement strong data collection policies.

8. **Detecting Data Collection from Network Shares:**
    - **Technique**: Collecting data from network shares for exfiltration.
    - **Detection**: Monitor for unusual data collection from network shares activity and use endpoint security solutions.
    - **Response**: Block identified data collection from network shares and implement strong data collection policies.

## 16. Exfiltration

1. **Data Exfiltration via HTTP/HTTPS:**
    - **Technique**: Using HTTP or HTTPS to exfiltrate data.
    - **Detection**: Monitor for unusual HTTP/HTTPS traffic and use data loss prevention (DLP) solutions.
    - **Response**: Block identified data exfiltration attempts and implement strong HTTP/HTTPS usage policies.

2. **Data Exfiltration via FTP:**
    - **Technique**: Using FTP to exfiltrate data.
    - **Detection**: Monitor for unusual FTP traffic and use data loss prevention (DLP) solutions.
    - **Response**: Block identified data exfiltration attempts and implement strong FTP usage policies.

3. **Data Exfiltration via Email:**
    - **Technique**: Using email to exfiltrate data.
    - **Detection**: Monitor for unusual email activity and use data loss prevention (DLP) solutions.
    - **Response**: Block identified data exfiltration attempts and implement strong email usage policies.

4. **Data Exfiltration via Removable Media:**
    - **Technique**: Using removable media to exfiltrate data.
    - **Detection**: Monitor for unusual removable media activity and use data loss prevention (DLP) solutions.
    - **Response**: Block identified data exfiltration attempts and implement strong removable media usage policies.

5. **Data Exfiltration via Cloud Storage:**
    - **Technique**: Using cloud storage to exfiltrate data.
    - **Detection**: Monitor for unusual cloud storage activity and use data loss prevention (DLP) solutions.
    - **Response**: Block identified data exfiltration attempts and implement strong cloud storage usage policies.

6. **Data Exfiltration via DNS:**
    - **Technique**: Using DNS to exfiltrate data.
    - **Detection**: Monitor for unusual DNS activity and use data loss prevention (DLP) solutions.
    - **Response**: Block identified data exfiltration attempts and implement strong DNS usage policies.

7. **Data Exfiltration via P2P Networks:**
    - **Technique**: Using peer-to-peer networks to exfiltrate data.
    - **Detection**: Monitor for unusual P2P network activity and use data loss prevention (DLP) solutions.
    - **Response**: Block identified data exfiltration attempts and implement strong P2P network usage policies.

8. **Data Exfiltration via Custom Protocols:**
    - **Technique**: Using custom protocols to exfiltrate data.
    - **Detection**: Monitor for unusual custom protocol activity and use data loss prevention (DLP) solutions.
    - **Response**: Block identified data exfiltration attempts and implement strong custom protocol usage policies.

## 17. Impact

1. **Detecting Data Destruction:**
    - **Technique**: Destroying data to cause harm.
    - **Detection**: Monitor for unusual data deletion activity and use endpoint security solutions.
    - **Response**: Block identified data destruction attempts and implement strong data deletion policies.

2. **Detecting Data Corruption:**
    - **Technique**: Corrupting data to cause harm.
    - **Detection**: Monitor for unusual data corruption activity and use endpoint security solutions.
    - **Response**: Block identified data corruption attempts and implement strong data corruption policies.

3. **Detecting Data Encryption for Ransom:**
    - **Technique**: Encrypting data and demanding ransom for decryption.
    - **Detection**: Monitor for unusual data encryption activity and use endpoint security solutions.
    - **Response**: Block identified data encryption attempts and implement strong data encryption policies.

4. **Detecting Service Disruption:**
    - **Technique**: Disrupting services to cause harm.
    - **Detection**: Monitor for unusual service disruption activity and use endpoint security solutions.
    - **Response**: Block identified service disruption attempts and implement strong service disruption policies.

5. **Detecting System Reboot:**
    - **Technique**: Rebooting systems to cause disruption.
    - **Detection**: Monitor for unusual system reboot activity and use endpoint security solutions.
    - **Response**: Block identified system reboot attempts and implement strong system reboot policies.

6. **Detecting System Shutdown:**
    - **Technique**: Shutting down systems to cause disruption.
    - **Detection**: Monitor for unusual system shutdown activity and use endpoint security solutions.
    - **Response**: Block identified system shutdown attempts and implement strong system shutdown policies.

7. **Detecting Service Sabotage:**
    - **Technique**: Sabotaging services to cause harm.
    - **Detection**: Monitor for unusual service sabotage activity and use endpoint security solutions.
    - **Response**: Block identified service sabotage attempts and implement strong service sabotage policies.

8. **Detecting Financial Impact:**
    - **Technique**: Causing financial harm through cyber attacks.
    - **Detection**: Monitor for unusual financial activity and use endpoint security solutions.
    - **Response**: Block identified financial impact attempts and implement strong financial security policies.

## 18. Objectives

1. **Detecting Strategic Data Theft:**
    - **Technique**: Stealing data to achieve strategic objectives.
    - **Detection**: Monitor for unusual data access activity and use endpoint security solutions.
    - **Response**: Block identified data theft attempts and implement strong data access policies.

2. **Detecting Intellectual Property Theft:**
    - **Technique**: Stealing intellectual property to gain competitive advantage.
    - **Detection**: Monitor for unusual data access activity and use endpoint security solutions.
    - **Response**: Block identified intellectual property theft attempts and implement strong data access policies.

3. **Detecting Industrial Espionage:**
    - **Technique**: Conducting espionage to gain industrial advantage.
    - **Detection**: Monitor for unusual data access activity and use endpoint security solutions.
    - **Response**: Block identified industrial espionage attempts and implement strong data access policies.

4. **Detecting Financial Theft:**
    - **Technique**: Stealing financial data to gain monetary advantage.
    - **Detection**: Monitor for unusual financial activity and use endpoint security solutions.
    - **Response**: Block identified financial theft attempts and implement strong financial security policies.

5. **Detecting Political Espionage:**
    - **Technique**: Conducting espionage to gain political advantage.
    - **Detection**: Monitor for unusual data access activity and use endpoint security solutions.
    - **Response**: Block identified political espionage attempts and implement strong data access policies.

6. **Detecting Military Espionage:**
    - **Technique**: Conducting espionage to gain military advantage.
    - **Detection**: Monitor for unusual data access activity and use endpoint security solutions.
    - **Response**: Block identified military espionage attempts and implement strong data access policies.

7. **Detecting Personal Data Theft:**
    - **Technique**: Stealing personal data to gain advantage.
    - **Detection**: Monitor for unusual data access activity and use endpoint security solutions.
    - **Response**: Block identified personal data theft attempts and implement strong data access policies.

8. **Detecting Trade Secret Theft:**
    - **Technique**: Stealing trade secrets to gain competitive advantage.
    - **Detection**: Monitor for unusual data access activity and use endpoint security solutions.
    - **Response**: Block identified trade secret theft attempts and implement strong data access policies.