SOC Analyst Level 2 interview preparation 2025

I have been reviewing some materials for an interview for a Level 2 SOC Analyst position, leveraging both technical knowledge and practical experience from my time as a SOC Level 1 Analyst. I found this approach to be a valuable way to organize my concepts and reference them as needed. The content I've compiled mainly comes from my GCIH certification materials and various cybersecurity articles from leading companies. Additionally, I used AI to gain further insights. As I prepare for the interview, I'm guessing the questions would be more about real-life scenarios. Getting a good review on these key concepts would work more like a guide and should help me explain the scenarios given and share examples confidently.

The material is mainly focused for a MSSP environment and as an L2, I should be familiar with answering the common investigative questions for endpoint related incidents, like:

•	How something got to the asset - Initial Access Vector<br/>
•	Is it still there? - Persistence<br/>
•	Where did they go? - Lateral Movement<br/>
•	Prove that something was taken - Data Exfiltration<br/>

Those topics above where a very good start to guide me thorough what to review. Additionally, I added more topics as I was reviewing and remembering content that I already knew but needed a refresh or a more structure understanding to be able to explain. 

____


Persistence 

____

Lateral Movement 

____

Data Exfiltration 

____

Binary Analysis

____

Malware Analysis

____

SMB

____

DNS

____


LOLBAS  

____

PUPs  

____

PowerShell  

____

Tcpdump

____

Nmap

____

Hashcat

____

Netcat

____

Cyber Kill Chain 

The Cyber Kill Chain was developed by Lockheed Martin and it models the stages of a cyberattack. The seven stages of the cyber kill model demonstrate a specific goal along with a threat actor's path. It is focused more in the progression of attacks:

1.	Reconnaissance: The attacker gathers information about the target, such as network structure, vulnerabilities, and personnel details.<br/>
2.	Weaponization: The attacker creates malware tailored to exploit specific vulnerabilities identified during reconnaissance.<br/>
3.	Delivery: The attacker delivers the malware to the target, often via phishing emails, malicious websites, or infected USB drives.<br/>
4.	Exploitation: The malware exploits a vulnerability in the target system, allowing the attacker to execute code.<br/>
5.	Installation: The malware is installed on the target system, establishing a foothold.<br/>
6.	Command and Control: The attacker establishes communication with the compromised system, allowing remote control.<br/>
7.	Actions on Objectives: The attacker achieves their goals, such as data exfiltration, system disruption, or further propagation within the network.<br/>

____

MITRE ATT&CK  

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








