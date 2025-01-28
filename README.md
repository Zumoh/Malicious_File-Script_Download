# Malicious File/Script Download

This investigation focused on analyzing malicious file behavior and endpoint logs to identify a Malicious File/Script Download Attempt, uncovering the embedded VBA macros, potential C2 communication, and the threat’s delivery mechanism, as well as completing a challenge provided by LetsDefend.io.

#

<img width="650" alt="Screenshot 2025-01-19 203716" src="https://github.com/user-attachments/assets/9b90444a-246b-4813-8697-b8fa22ec35af" />


## Objective

The objective of this investigation is to analyze and determine the details surrounding a potential malicious file/script download attempt detected on the endpoint ‘**NicolasPRD**’. The investigation aims to identify critical information such as the source address, file name, file hash, and associated URLs. By reviewing logs, performing file analysis using VirusTotal, and using tools like ExifTool, oleid, and olevba, the goal is to verify the file’s malicious nature, assess its potential impact, and determine whether it successfully executed any harmful payloads. Additionally, by examining network activity, endpoint behavior, and command-and-control (C2) communications, the investigation seeks to identify the scope of the threat, ensure proper containment and mitigation, and provide recommendations for enhancing the organization’s security posture.

#

### Skills Learned

- **Threat Analysis and Detection**:
   - Identifying malicious files, scripts, and behaviors, such as embedded macros.
      - Understanding protocols like HTTP, RDP, and TCP/IP is essential for identifying attack patterns like brute force attempts and unauthorized access. This skill is critical for detecting threats and vulnerabilities in network communication.
- **Utilizing Security Tools:**
   - Mastering tools like VirusTotal, ExifTool, OLE tools (oleid, olevba), and EDR solutions for threat analysis.
      - Performing sandboxed analyses using Kali Linux or other isolated environments.
- **Incident Response Processes:**
   - Following playbooks to systematically assess, contain, and mitigate threats.
      - Documenting findings and taking appropriate steps to address incidents.
- **Log Analysis:**
   - Searching logs for evidence of suspicious activities, such as file executions or network communications.
      - Verifying whether C2 servers were contacted or other endpoints were affected.
- **Threat Intelligence Integration:**
   - Leveraging external sources like VirusTotal to cross-reference malicious activity and validate threats.
- **Secure File Handling:**
   - Using tools like the wipe command to securely delete malicious files, ensuring no residual risks.
- **Communication and Documentation:**
   - Writing clear, detailed reports and notes for ticket closure to aid in future investigations.
      - Communicating findings with team members for coordinated responses.  
#

### 🛠️ Tools Used

- **VirusTotal**: For scanning file hashes and checking for known malicious files across multiple security vendors.
- **Kali Linux (Sandboxed Environment)**: For performing static analysis in an isolated environment to safely examine potentially malicious files and behavior without risking system compromise.
- **ExifTool**: For extracting metadata from documents to understand their origin and properties.
- **oleid**: For analyzing files for embedded macros, links, and other suspicious content in Microsoft Office documents.
- **olevba**: For extracting and analyzing embedded VBA macros within Microsoft Office files to detect potential security threats.
- **EDR Tool**: For reviewing endpoint status, logs, and quarantine actions related to detected malicious files.
- **Wipe Command**: For securely deleting files to prevent any potential recovery or accidental re-execution of malicious code.

#

<img width="614" alt="Screenshot 2025-01-27 at 3 29 40 PM" src="https://github.com/user-attachments/assets/054afd3f-7d76-42d8-a214-cf45799d2270" />

#

### Alert Information

- EventID : 76 
- Event Time : Mar, 14, 2021, 07:15 PM
- Rule : SOC137 - Malicious File/Script Download Attempt
- Level : Security Analyst
- Source Address : 172.16.17.37
- Source Hostname : NicolasPRD
- File Name : INVOICE PACKAGE LINK TO DOWNLOAD.docm
- File Hash : f2d0c66b801244c059f636d08a474079
- File Size : 16.66 Kb
- Device Action : Blocked
- File (Password:infected) : https[:]//files-ld[.]s3[.]us-east-2[.]amazonaws[.]com[/]f2d0c66b801244c059f636d08a474079.zip

#

To get the investigation started, we need to create a case and take ownership of the ticket. This helps other SOC analysts know that someone is already working on it, which prevents duplicate efforts. Assigning ownership keeps the investigation organized and ensures no unnecessary work is done.

#

<img width="727" alt="Screenshot 2025-01-27 at 3 36 45 PM" src="https://github.com/user-attachments/assets/e17d2a9f-260c-4c25-93f4-4f61a62fbfdf" />

<img width="728" alt="Screenshot 2025-01-27 at 3 37 22 PM" src="https://github.com/user-attachments/assets/f7059bc6-e981-40a4-9dab-d67ebb4e2e62" />

#

Upon detection of a security event, we are prompted to start the playbook. The playbook offers a clear, step-by-step guide to help us assess the situation, contain the threat, escalate when necessary, eliminate the threat, restore the system, and document the process. This organized approach ensures we address the incident effectively, minimizing potential damage or further compromise.

<img width="726" alt="Screenshot 2025-01-27 at 3 38 47 PM" src="https://github.com/user-attachments/assets/4b9a6021-a571-4f3f-a4d1-52ce5a5a9cf3" />

#

### _Playbook Prompt (1). Check If The Malware Is Quarantined/Cleaned?_

<img width="726" alt="Screenshot 2025-01-28 at 12 40 32 PM" src="https://github.com/user-attachments/assets/b0ef57d7-f630-4587-ad45-0bc888cb90f5" />

#

The playbook first prompts us to check if the malware has been quarantined or cleaned. To do this, we access the EDR tool, search for the affected endpoint ‘**NicolasPRD**’, and review its status and logs. The logs will provide detailed information about any malicious activity detected, as well as any actions taken.

#

<img width="727" alt="Screenshot 2025-01-27 at 3 48 55 PM" src="https://github.com/user-attachments/assets/f3f2ed29-7f9a-4d1a-ba34-a30b747c913d" />

#

Despite conducting a thorough review of all the analysis tabs, we did not find any suspicious activity or indicators of compromise. The endpoint did not display any unexpected network connections, processes, or interactions with malicious IP addresses or domains.

<img width="728" alt="Screenshot 2025-01-27 at 3 50 12 PM" src="https://github.com/user-attachments/assets/f8c6f65b-f63b-4fb6-8b3e-32dd3fa26d8e" />

#

After confirming that the initial endpoint showed no suspicious activity, we extended our investigation to other endpoints within the network to check for the presence of the same file hash. This helps ensure no other systems are affected and gives us a better idea of the threat's scope.

<img width="727" alt="Screenshot 2025-01-27 at 3 53 38 PM" src="https://github.com/user-attachments/assets/fcaa1671-70dc-41ca-acf1-20846af450cd" />

Our search across the network verified that no other endpoints contained the malicious file. This indicates that the threat was successfully quarantined on the affected endpoint, and no further instances of the file were found in the environment. This provides reassurance that the malicious file was contained, and there is no evidence of widespread compromise.

#

### _Playbook Prompt (2). Analyze Malware._

<img width="727" alt="Screenshot 2025-01-28 at 12 56 59 PM" src="https://github.com/user-attachments/assets/5152557a-ea5c-498b-9207-f24288de35f0" />

#

The playbook then requires analyzing the file to determine whether it is malicious. Since we have already been provided with the hash value of the file, we will use this hash to perform a quick scan on VirusTotal. By submitting the file hash to VirusTotal, we can quickly check if the file has been flagged as malicious by any security vendor. This step allows us to gain insight into the file’s reputation across multiple threat intelligence sources, helping us assess its risk and decide on further actions based on the results.

A total of forty security vendors identified the file as malicious. The macro, named 'AutoOpen,' uses the shell function to execute a PowerShell command that retrieves a file from a specified URL. This behavior is commonly associated with malicious activity, as it allows attackers to download and execute additional harmful payloads on the target machine. By leveraging PowerShell, the macro can silently carry out these actions without the user's knowledge, making it a common tactic used in the delivery of malware such as ransomware, trojans, or other forms of malicious software. This type of activity further confirms the file's malicious intent and its potential to compromise the system.

<img width="728" alt="Screenshot 2025-01-27 at 3 56 00 PM" src="https://github.com/user-attachments/assets/2dd03120-6b32-42dd-96bd-acd8857fb740" />

#

We examine the **Relations** tab to identify the callback IP address(es) of the Command and Control (C2) server associated with the trojan. This tab helps track the file’s communication patterns, revealing the IPs it contacts to receive commands or send data. By identifying these IP addresses, we can further investigate the infection scope and monitor for ongoing malicious activity, check for any other systems that might be communicating with these IPs which helps to mitigate the threat if any.

<img width="728" alt="Screenshot 2025-01-27 at 3 57 12 PM" src="https://github.com/user-attachments/assets/67a58595-4a3c-4226-8171-47fd3794ca06" />

#

Reviewing the **MITRE ATT&CK** section allows us to gather information on the attacker's tactics and techniques. It reveals that the file contains embedded VBA macros that trigger malicious code execution when interacted with. This can result in various harmful activities, such as downloading additional payloads, data theft, or remote control of the infected system. VBA macros are commonly used to deliver and execute malicious code within documents.

<img width="729" alt="Screenshot 2025-01-27 at 3 58 15 PM" src="https://github.com/user-attachments/assets/c581c9ff-05e4-4513-ac33-3f47ddaeb010" />

#

<img width="728" alt="Screenshot 2025-01-27 at 4 01 50 PM" src="https://github.com/user-attachments/assets/2ceb3916-5ead-4a29-bf37-e80896177932" />

#

### Static Analysis using a Sand-boxed Environment. 

To perform a static analysis, we can use OLE tools in an isolated environment. This approach allows us to examine the file's properties such as embedded macros, links, and other potentially harmful content without the risk of executing the file or causing harm to the system. Conducting this analysis in a sandboxed or isolated environment ensures that any malicious behavior is contained while we assess the file's risks.

To install Oletools, run the following command: ```sudo -H pip install -U oletools[full]```. This ensures that the full package, including all optional dependencies, is installed. Using ```-H``` ensures the home directory is correctly set for the superuser, and ```-U``` upgrades any existing version of Oletools.

<img width="732" alt="Screenshot 2025-01-28 at 1 00 15 PM" src="https://github.com/user-attachments/assets/929c7f8c-c95b-4a86-bd37-24316b654b68" />

#

Ensure that your virtual machine's network adapter is set to 'Custom: Specific Virtual Network’ to create a sandboxed environment. This setup places the virtual machine in its own isolated network, preventing it from communicating with the host machine or external networks, which enhances security.

<img width="725" alt="Screenshot 2025-01-28 at 1 11 32 PM" src="https://github.com/user-attachments/assets/a5e59b16-e960-4e27-87c3-249d5df8a22f" />

#

The first tool we used is called ExifTool. This tool is used to gather metadata about the document. Metadata includes information like the document’s creation date, the software used to create it, and any modifications that have been made. From the results, we can see the MIME type, which indicates that the document has macros enabled, and other details like the document's author, title, and last modified date. This metadata helps us understand the origin and nature of the document, which is crucial for further analysis.

<img width="727" alt="Screenshot 2025-01-28 at 1 13 35 PM" src="https://github.com/user-attachments/assets/f5459af7-df25-4dda-ba69-cc8a7ee5b87f" />

#




