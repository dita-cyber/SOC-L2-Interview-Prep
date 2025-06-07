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

**Lateral Movement**

____

**Data Exfiltration**

____

**Binary Analysis**

____

**Malware Analysis**

**Static Malware Analysis**

Static analysis involves examining malware without executing it. This method focuses on analyzing the file's structure, code, and metadata to understand its functionality and potential impact.

**•	File Hashing:** Calculate hashes (e.g., MD5, SHA-256) for the malware file to check against known malware databases.<br/>
**•	Disassembly:** Use tools like IDA Pro or Ghidra to disassemble the code and understand its logic.<br/>
**•	String Analysis**<br/>
**•	Metadata Examination:** Analyze the file's metadata, such as PE headers in Windows executables, to identify compilation details and potential anomalies.<br/>

In PowerShell, you can calculate hashes using:
```
Get-FileHash -Algorithm SHA256 -Path $filePath
```
In Linux, you can use built-in commands to calculate file hashes:
```
md5sum
sha1sum
sha256sum
md5sum /path/to/your/file
```

**Dynamic Malware Analysis**

Dynamic analysis involves executing the malware in a controlled environment (sandbox) to observe its behavior and interactions with the system.

**•	Sandboxing:**  Use sandbox environments like Cuckoo Sandbox or Any.Run to safely execute the malware and monitor its behavior.<br/>
**•	Network Monitoring:**  Observe network connections made by the malware using tools like Wireshark or Fiddler.<br/>
**•	Process Monitoring:**  Use tools like Process Monitor (Procmon) to track file, registry, and process activities.<br/>
**•	API Monitoring:**  Use tools like API Monitor to track system calls made by the malware.<br/>

IOCs for Dynamic Analysis:<br/>
**•	Network Connections:**  Unexpected outbound connections to known malicious domains or IP addresses.<br/>
**•	File and Registry Changes:**  Creation of new files or registry keys, especially in startup locations.<br/>
**• Process Activity:**  Unusual processes spawned by the malware, often with suspicious names or paths.<br/>

**Other techniques:**

**•	VM Snapshot:** Primarily used in dynamic malware analysis. It allows analysts to quickly revert to a clean state of a virtual machine, which is useful for observing the behavior of malware without permanent changes to the system.<br/>

**•	Regshot:** Used in dynamic malware analysis. It takes snapshots of the registry before and after running a program, allowing analysts to compare changes and understand what modifications the malware makes to the system registry.<br/>

**•	Process Monitor:** Used in dynamic malware analysis. It monitors and logs real-time system activity, such as file system, registry, and process operations, helping analysts observe the behavior of malware as it executes.<br/>

**•	IDA Pro:** Used in static malware analysis. It is a disassembler and debugger that helps reverse engineers analyze the code structure and logic of a binary without executing it, enabling them to understand the functionality of malware.<br/>

**•	Ghidra:** Also used in static malware analysis. It is a reverse engineering tool that provides capabilities for disassembling, decompiling, and analyzing binaries to understand the code's behavior and logic without execution.<br/>
____

**SMB**

____

**DNS**

Domain Name System analysis is a crucial aspect of network security monitoring because DNS is a fundamental protocol that translates human-readable domain names into IP addresses, enabling communication over the internet. However, attackers can exploit DNS for malicious purposes, including C2 communication and data exfiltration. 

**DNS Tunneling:**<br/>
•	Attackers can use DNS tunneling to encapsulate data or commands within DNS queries and responses. This allows them to bypass traditional network defenses by disguising traffic as legitimate DNS queries.<br/>
•	To avoid detection and DNS caching, attackers often generate numerous unique subdomains for their C2 channels. A high volume of unique subdomains can be a strong IOC.<br/>

**DNS for Network Communication:**<br/>
•	DNS is essential for translating domain names into IP addresses. Analyzing DNS logs can provide insights into network traffic patterns and identify unusual or malicious activity.<br/>

**DNS Analysis Techniques**<br/>

•	Top DNS queries and abnormal queries: Identify the most frequently queried domains. Sudden spikes or unusual patterns in DNS queries can indicate malicious activity.<br/>
•	Identify High volume FQDN logs: Investigate FQDNs that appear frequently or that are associated with known malicious activity. <br/>
•	Narrow down which host sent DNS requests: Determine which internal hosts are making suspicious DNS requests. <br/>
•	Identify failed DNS Lookups logs: Monitor failed DNS lookups, as they may indicate attempts to contact non-existent or newly registered domains.<br/>

____


**LOLBAS**

Living Off the Land Binaries And Scripts is a technique used by attackers to exploit legitimate system tools and executables to perform malicious activities. This approach allows attackers to bypass security mechanisms such as application whitelisting, intrusion detection systems, and antivirus solutions, as these tools are typically trusted and not flagged as malicious. Attackers use pre-installed system binaries and scripts to execute attacks. These tools are part of the operating system or commonly installed applications, making them less likely to be scrutinized by security systems. 

https://lolbas-project.github.io/   

Commonly Used LOLBAS Tools: 

| Tool             | Path                                                                 | Abuse Technique                                      |
|------------------|----------------------------------------------------------------------|------------------------------------------------------|
| powershell.exe   | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe            | Execute payloads, download malware, bypass AV        |
| certutil.exe     | C:\Windows\System32\certutil.exe                                     | Download files using: certutil -urlcache -f          |
| mshta.exe        | C:\Windows\System32\mshta.exe                                        | Execute malicious HTML apps or remote scripts        |
| regsvr32.exe     | C:\Windows\System32\regsvr32.exe                                     | Load and execute remote/local DLLs                   |
| rundll32.exe     | C:\Windows\System32\rundll32.exe                                     | Execute DLLs or scripts to evade detection           |
| wmic.exe         | C:\Windows\System32\wbem\wmic.exe                                    | Execute commands, gather system info                 |
| bitsadmin.exe    | C:\Windows\System32\bitsadmin.exe                                    | Download/upload files silently                       |
| msbuild.exe      | C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe            | Execute malicious C# code in project files           |
| installutil.exe  | C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe        | Run code during .NET assembly install                |
| schtasks.exe     | (Path not fully visible)                                             | Create scheduled tasks for persistence               |

Summary of each tool:

**• certutil.exe:** A command-line utility for managing and manipulating certificates, certificate services, and keys in Windows. It is often used for tasks like importing, exporting, and verifying certificates.<br/> 

**• mshta.exe:** A tool that executes Microsoft HTML Applications (HTA) files. HTA files are HTML-based applications that can run scripts, making mshta.exe a common vector for executing scripts on Windows.<br/> 

**• regsvr32.exe:** A command-line utility used to register and unregister DLLs and ActiveX controls in the Windows Registry. It is frequently used in application installation and configuration processes.<br/> 

**• rundll32.exe:** A system utility that allows the execution of DLL functions from the command line. It is often used to call specific functions within DLLs, enabling the automation of various tasks.<br/>

**• wmic.exe:** The Windows Management Instrumentation Command-line (WMIC) utility provides a command-line interface for accessing WMI data. It allows users to query system information, manage tasks, and interact with the Windows environment.<br/> 

**• bitsadmin.exe:** A command-line tool for managing Background Intelligent Transfer Service (BITS), which facilitates asynchronous file transfers between machines. It is often used for downloading or uploading files in the background.<br/> 

**• msbuild.exe:** Microsoft's build platform for building applications. It is used to compile, package, and deploy software projects based on configuration files and scripts.<br/> 

**• installutil.exe:** A command-line utility for installing and uninstalling .NET Framework applications and components. It is commonly used to register and configure services and applications.<br/> 

**•schtasks.exe:** A command-line utility for creating, deleting, querying, changing, running, or ending scheduled tasks on a Windows system. It is used to automate tasks and manage the Task Scheduler.<br/> 
____

**PowerShell**  

PowerShell is a powerful scripting language and command-line shell used extensively in Windows environments for task automation, configuration management, and system administration. While it provides significant capabilities for legitimate users, it is also a tool that attackers commonly exploit for malicious activities 

Indicators of suspicious PowerShell activity  

**• Encoded commands:** Attackers may use the -EncodedCommand parameter to obfuscate their scripts, making it harder to detect malicious intent.<br/> 
**• External script downloads:** Scripts that download and execute external executables from malicious URLs are a common. **Invoke-WebRequest** or **Invoke-Expression** used with URLs.<br/>
**• Hidden windows:** Scripts that use **-WindowStyle Hidden** or **Start-Process** with hidden window options can indicate attempts to avoid detection.<br/>
**• String manipulation and concatenation:** Malicious scripts often break down commands into strings and use concatenation to evade detection by static analysis tools.<br/>
**• External command execution:** PowerShell scripts that call external command-line utilities (e.g., cmd.exe, net.exe) can signify attempts to leverage system utilities for malicious purposes.<br/>
**• Registry interrogation:** Monitoring registry queries and modifications can reveal attempts to establish persistence or gather system information.<br/>
**• Unusual scheduled tasks:** Creation of unusual or suspicious scheduled tasks can indicate persistence attempts. Check task properties and the last run time for anomalies.<br/>
**• Log analysis:** Use **Get-WinEvent** to review unusual log entries, especially those related to PowerShell script block logging (Event ID 4104) and pipeline execution (Event ID 4103).<br/>

Sysinternals Tools for process and system analysis<br/>
**Process Explorer:** Provides detailed information about running processes, including open handles and loaded DLLs. Useful for identifying suspicious processes.<br/>
**Process Monitor:** Offers real-time monitoring of file system, registry, process, and network activity. It is valuable for identifying abnormal behavior and forensic analysis.<br/>
**TCPView:** Displays active TCP and UDP connections, helping identify unauthorized network communication.<br/>
**Autoruns:** Lists auto-start extensibility points (ASEPs), allowing you to identify unusual programs configured to run at startup.<br/>
**Sysmon:** Provides detailed logging of system events, including process creation, network connections, and file modifications. It is useful for feeding data into SIEM systems for comprehensive monitoring.<br/>
**ProcDump:** Captures process memory dumps, aiding in malware analysis and understanding the behavior of suspicious processes.<br/>
____

**PUPs**

Potentially Unwanted Programs are a category of software that, while not overtly malicious like traditional malware, often exhibit behaviors that users find undesirable or intrusive. These programs typically installed alongside legitimate software, usually without explicit user consent. This bundling tactic is common in free software downloads, where users might overlook additional programs being installed. 

PUPs are often rated as highly malicious in OSINT platforms like VirusTotal for several reasons. While PUPs are not designed to be overtly harmful like traditional malware, their behaviors and characteristics can trigger high threat ratings like:<br/> 

**• Behavioral similarity to malware:** Some PUPs exhibit behaviors similar to malware, such as installing without explicit consent, modifying system settings, or persisting in ways that make them difficult to remove.<br/> 

**• Bundled with malware:**	PUPs are often distributed through software bundling, and in some cases, they may be bundled with actual malware or serve as a delivery mechanism for more harmful software.<br/>

**• Privacy violations:** PUPs often collect user data without clear consent, which can be considered a significant privacy violation. This behavior is sometimes flagged as malicious due to its potential for misuse or data leakage.<br/> 

**• Persistence and evasion techniques:** The use of persistence mechanisms and evasion techniques to avoid detection and removal can cause PUPs to be rated more severely. Techniques such as modifying the registry or creating scheduled tasks are often associated with malicious intent.<br/> 

**• Reputation and history:** If a particular PUP has a history of being linked to malicious activities or has been used in conjunction with malicious campaigns, OSINT platforms may rate its hashes more critically.<br/> 

**• Aggressive advertising and monetization:** PUPs that aggressively monetize through intrusive ads or redirect users to potentially harmful sites can be rated as highly malicious due to their negative impact on user experience and potential security risks.<br/> 

**• Previous reports and community feedback:** Community feedback and previous reports of negative experiences with a PUP can influence its rating. If users frequently report issues or associate the PUP with malicious behavior. Additionally, VirusTotal aggregates results from multiple antivirus vendors. If a PUP is detected by a majority of these vendors as having malicious characteristics, its overall threat rating will be higher.<br/> 

PUP common behaviors:<br/> 
**• Adware:** Displays intrusive advertisements, often redirecting users to specific websites.<br/> 
**• Browser hijackers:** Modify browser settings, such as the default search engine or homepage, to redirect traffic to specific sites.<br/> 
**• Spyware:** Collects user data without explicit consent, potentially leading to privacy violations.<br/> 
**•	Dialers:** Automatically dial phone numbers, often resulting in high charges, though less common today with the decline of dial-up internet.<br/> 

____

**Cyber Kill Chain** 

The Cyber Kill Chain was developed by Lockheed Martin and it models the stages of a cyberattack. The seven stages of the cyber kill model demonstrate a specific goal along with a threat actor's path. It is focused more in the progression of attacks:

**1.	Reconnaissance:** The attacker gathers information about the target, such as network structure, vulnerabilities, and personnel details.<br/>
**2.	Weaponization:** The attacker creates malware tailored to exploit specific vulnerabilities identified during reconnaissance.<br/>
**3.	Delivery:** The attacker delivers the malware to the target, often via phishing emails, malicious websites, or infected USB drives.<br/>
**4.	Exploitation:** The malware exploits a vulnerability in the target system, allowing the attacker to execute code.<br/>
**5.	Installation:** The malware is installed on the target system, establishing a foothold.<br/>
**6.	Command and Control:** The attacker establishes communication with the compromised system, allowing remote control.<br/>
**7.	Actions on Objectives:** The attacker achieves their goals, such as data exfiltration, system disruption, or further propagation within the network.<br/>

____

**MITRE ATT&CK**  

https://attack.mitre.org/

The MITRE ATT&CK framework is a comprehensive and continuously updated knowledge base of tactics, techniques, and procedures (TTPs) used by attackers. It provides detailed information on how adversaries operate, allowing defenders to better anticipate and respond to threats. Focused more for detection and defense.

Complete list of categories:

**•	Reconnaissance<br/>
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
•	Impact<br/>**

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

**Tcpdump**

Command-line packet analysis tool that allows users to capture and examine network traffic. It's widely used by network administrators and security professionals for troubleshooting, network performance analysis, and security auditing. 
____

**Nmap**

Nmap (Network Mapper) is a widely-used open-source tool for network discovery and security auditing.  It includes network discovery and mapping, port scanning, service version detection, and operating system detection capabilities. 

**Host Discovery Techniques**<br/>

**Default Host Discovery:** Before initiating a port scan, Nmap performs host discovery to determine which hosts are up. By default, it may use methods like ICMP echo requests, TCP SYN to port 443, and TCP ACK to port 80.<br/>

**ARP Scanning:** On a local network, Nmap uses ARP (Address Resolution Protocol) to map IP addresses to MAC addresses. ARP scans are fast and reliable since ARP requests are not filtered by firewalls on the local subnet.<br/>

**ARP Review:** ARP is used to map IP addresses to physical MAC addresses on a local network. It broadcasts an ARP request for a specific IP, and the device with that IP responds with its MAC address. The mapping is stored in an ARP cache to speed up future requests. ARP is vulnerable to spoofing attacks, where an attacker sends fake ARP messages to associate their MAC address with another IP address, potentially intercepting or disrupting traffic.

____

**Hashcat**

Password cracking tool through various attack methods. It's known for its speed and flexibility, supporting a wide range of hashing algorithms and running efficiently on both CPU and GPU hardware. 

____

**Netcat**

Netcat is a versatile utility used for reading, writing, and transferring data across network connections. It operates in both client and server modes, enabling a wide range of functions from simple data transfers to complex network debugging and security testing.

**•	Client Mode:** Netcat can initiate connections to remote hosts, making it useful for testing server responses and sending data.<br/>
**•	Listen Mode:** It can listen for incoming connections, turning your machine into a server, which is helpful for receiving data or setting up a basic TCP/UDP server.<br/>
**•	Data Transfer:**	Netcat can transfer files and data streams between hosts, making it useful for simple file transfers or as a rudimentary backup solution.<br/>
**•	Port Scanning:** Although not as sophisticated as dedicated port scanners like Nmap, Netcat can scan open ports on a target host, providing a quick overview of available services.<br/>

Additional information related to security info

**•	Backdoors and Relays:**<br/>
Attackers can use Netcat to create backdoors by setting it to listen mode on a target system, allowing them to connect back at any time.<br/>
It can also be used to create relays, which are one-way connections that bypass firewalls and make it difficult to trace the origin of an attack or connection.<br/>
A single Netcat relay can be used to pivot through multiple hosts, helping attackers move laterally within a network.<br/>
**•	Named Pipes:**<br/>
In Windows environments, attackers may use named pipes with Netcat to obtain responses from a target. Named pipes allow inter-process communication, which can be exploited to relay data between processes on a compromised host. <br/>





