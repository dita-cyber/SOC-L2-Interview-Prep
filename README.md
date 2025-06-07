**SOC Analyst Level 2 interview preparation 2025**

I have been reviewing some materials for an interview for a Level 2 SOC Analyst position, leveraging both technical knowledge and practical experience from my time as a SOC Level 1 Analyst. I found this approach to be a valuable way to organize my concepts and reference them as needed. The content I've compiled mainly comes from my GCIH certification materials and various cybersecurity articles from leading companies. Additionally, I used AI to gain further insights. As I prepare for the interview, I'm guessing the questions would be more about real-life scenarios. Getting a good review on these key concepts would work more like a guide and should help me explain the scenarios given and share examples confidently.

The material is mainly focused for a MSSP environment and as an L2, I should be familiar with answering the common investigative questions for endpoint related incidents, like:

•	How something got to the asset - Initial Access Vector<br/>
•	Is it still there? - Persistence<br/>
•	Where did they go? - Lateral Movement<br/>
•	Prove that something was taken - Data Exfiltration<br/>

Those topics above where a very good start to guide me thorough what to review. Additionally, I added more topics as I was reviewing and remembering content that I already knew but needed a refresh or a more structure understanding to be able to explain. 

____


**Persistence**

____

**Lateral Movement **

____

**Data Exfiltration **

____

**Binary Analysis**

____

**Malware Analysis**

____

**SMB**

____

**DNS**

Domain Name System analysis is a crucial aspect of network security monitoring because DNS is a fundamental protocol that translates human-readable domain names into IP addresses, enabling communication over the internet. However, attackers can exploit DNS for malicious purposes, including C2 communication and data exfiltration. 

DNS Tunneling:
•	Attackers can use DNS tunneling to encapsulate data or commands within DNS queries and responses. This allows them to bypass traditional network defenses by disguising traffic as legitimate DNS queries.
•	To avoid detection and DNS caching, attackers often generate numerous unique subdomains for their C2 channels. A high volume of unique subdomains can be a strong IOC.

DNS for Network Communication:
•	DNS is essential for translating domain names into IP addresses. Analyzing DNS logs can provide insights into network traffic patterns and identify unusual or malicious activity.

DNS Analysis Techniques

•	Top DNS queries and abnormal queries: Identify the most frequently queried domains. Sudden spikes or unusual patterns in DNS queries can indicate malicious activity.
•	Identify High volume FQDN logs: Investigate FQDNs that appear frequently or that are associated with known malicious activity. 
•	Narrow down which host sent DNS requests: Determine which internal hosts are making suspicious DNS requests. 
•	Identify failed DNS Lookups logs: Monitor failed DNS lookups, as they may indicate attempts to contact non-existent or newly registered domains.

____


**LOLBAS**

____

**PUPs**

____

**PowerShell**  

PowerShell is a powerful scripting language and command-line shell used extensively in Windows environments for task automation, configuration management, and system administration. While it provides significant capabilities for legitimate users, it is also a tool that attackers commonly exploit for malicious activities 

Indicators of suspicious PowerShell activity  

• Encoded Commands: Attackers may use the -EncodedCommand parameter to obfuscate their scripts, making it harder to detect malicious intent.<br/> 
• External Script Downloads: Scripts that download and execute external executables from malicious URLs are a common. **Invoke-WebRequest** or **Invoke-Expression** used with URLs.<br/>
• Hidden Windows: Scripts that use **-WindowStyle Hidden** or **Start-Process** with hidden window options can indicate attempts to avoid detection.<br/>
• String manipulation and concatenation: Malicious scripts often break down commands into strings and use concatenation to evade detection by static analysis tools.<br/>
• External Command Execution: PowerShell scripts that call external command-line utilities (e.g., cmd.exe, net.exe) can signify attempts to leverage system utilities for malicious purposes.<br/>
• Registry Interrogation: Monitoring registry queries and modifications can reveal attempts to establish persistence or gather system information.<br/>
• Unusual Scheduled Tasks: Creation of unusual or suspicious scheduled tasks can indicate persistence attempts. Check task properties and the last run time for anomalies.<br/>
• Log Analysis: Use **Get-WinEvent** to review unusual log entries, especially those related to PowerShell script block logging (Event ID 4104) and pipeline execution (Event ID 4103).<br/>

Sysinternals Tools for Process and System Analysis
Process Explorer: Provides detailed information about running processes, including open handles and loaded DLLs. Useful for identifying suspicious processes.<br/>
Process Monitor: Offers real-time monitoring of file system, registry, process, and network activity. It is valuable for identifying abnormal behavior and forensic analysis.<br/>
TCPView: Displays active TCP and UDP connections, helping identify unauthorized network communication.<br/>
Autoruns: Lists auto-start extensibility points (ASEPs), allowing you to identify unusual programs configured to run at startup.<br/>
Sysmon: Provides detailed logging of system events, including process creation, network connections, and file modifications. It is useful for feeding data into SIEM systems for comprehensive monitoring.<br/>
ProcDump: Captures process memory dumps, aiding in malware analysis and understanding the behavior of suspicious processes.<br/>

____

**Tcpdump**

____

**Nmap**

____

**Hashcat**

____

**Netcat**

____

**Cyber Kill Chain** 

The Cyber Kill Chain was developed by Lockheed Martin and it models the stages of a cyberattack. The seven stages of the cyber kill model demonstrate a specific goal along with a threat actor's path. It is focused more in the progression of attacks:

1.	Reconnaissance: The attacker gathers information about the target, such as network structure, vulnerabilities, and personnel details.<br/>
2.	Weaponization: The attacker creates malware tailored to exploit specific vulnerabilities identified during reconnaissance.<br/>
3.	Delivery: The attacker delivers the malware to the target, often via phishing emails, malicious websites, or infected USB drives.<br/>
4.	Exploitation: The malware exploits a vulnerability in the target system, allowing the attacker to execute code.<br/>
5.	Installation: The malware is installed on the target system, establishing a foothold.<br/>
6.	Command and Control: The attacker establishes communication with the compromised system, allowing remote control.<br/>
7.	Actions on Objectives: The attacker achieves their goals, such as data exfiltration, system disruption, or further propagation within the network.<br/>

____

**MITRE ATT&CK**  

https://attack.mitre.org/

The MITRE ATT&CK framework is a comprehensive and continuously updated knowledge base of tactics, techniques, and procedures (TTPs) used by attackers. It provides detailed information on how adversaries operate, allowing defenders to better anticipate and respond to threats. Focused more for detection and defense.

Complete list of categories:

•	Reconnaissance<br/>
•	Resource Development<br/>
•	Initial Access<br/>
•	Execution<br/>
•	Persistence<br/>
•	Privilege Escalation<br/>
•	Defense Evasion<br/>
•	Credential Access<br/>
•	Discovery<br/>
•	Lateral Movement<br/>
•	Collection<br/>
•	Command and Control<br/>
•	Exfiltration<br/>
•	Impact<br/>

From the categories I listed the ones I am focusing to understand the examples better:

| Persistence            | Privilege Escalation                | Lateral Movement                     | Command and Control                |
|-----------------------------------|-------------------------------------|--------------------------------------|------------------------------------|
| Account Manipulation              | Abuse Elevation Control Mechanism   | Exploitation of Remote Services      | Application Layer Protocol         |
| BITS Jobs                         | Access Token Manipulation           | Internal Spearphishing               | Communication Through Removable Media |
| Boot or Logon Autostart Execution | Account Manipulation                | Lateral Tool Transfer                | Content Injection                  |
| Boot or Logon Initialization Scripts | Boot or Logon Autostart Execution | Remote Service Session Hijacking     | Data Encoding                      |
| Cloud Application Integration     | Boot or Logon Initialization Scripts| Remote Services                      | Data Obfuscation                   |
| Compromise Host Software Binary   | Create or Modify System Process     | Replication Through Removable Media  | Dynamic Resolution                 |
| Create Account                    | Domain or Tenant Policy Modification| Software Deployment Tools            | Encrypted Channel                  |
| Create or Modify System Process   | Escape to Host                      | Taint Shared Content                 | Fallback Channels                  |
| Event Triggered Execution         | Event Triggered Execution           | Use Alternate Authentication Material| Hide Infrastructure                |
| Exclusive Control                 | Exploitation for Privilege Escalation|                                      | Ingress Tool Transfer              |
| External Remote Services          | Hijack Execution Flow               |                                      | Multi-Stage Channels               |
| Hijack Execution Flow             | Process Injection                   |                                      | Non-Application Layer Protocol     |
| Implant Internal Image            | Scheduled Task/Job                  |                                      | Non-Standard Port                  |
| Modify Authentication Process     | Valid Accounts                      |                                      | Protocol Tunneling                 |
| Modify Registry                   |                                     |                                      | Proxy                              |
| Office Application Startup        |                                     |                                      | Remote Access Tools                |
| Power Settings                    |                                     |                                      | Traffic Signaling                  |
| Pre-OS Boot                       |                                     |                                      | Web Service                        |
| Scheduled Task/Job                |                                     |                                      |                                    |
| Server Software Component         |                                     |                                      |                                    |
| Software Extensions               |                                     |                                      |                                    |
| Traffic Signaling                 |                                     |                                      |                                    |
| Valid Accounts                    |                                     |                                      |                                    |

 



____








