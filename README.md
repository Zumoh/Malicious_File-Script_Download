# Malicious File/Script Download

<img width="750" alt="Screenshot 2025-01-19 203716" src="https://github.com/user-attachments/assets/9b90444a-246b-4813-8697-b8fa22ec35af" />


## Objective

The objective of this investigation is to analyze and determine the details surrounding a potential malicious file/script download attempt detected on the endpoint ‘**NicolasPRD**’. The investigation aims to identify critical information such as the source address, file name, file hash, and associated URLs. By reviewing logs, performing file analysis using VirusTotal, and using tools like ExifTool, oleid, and olevba, the goal is to verify the file’s malicious nature, assess its potential impact, and determine whether it successfully executed any harmful payloads. Additionally, by examining network activity, endpoint behavior, and command-and-control (C2) communications, the investigation seeks to identify the scope of the threat, ensure proper containment and mitigation, and provide recommendations for enhancing the organization’s security posture.

---

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
---

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

### _Playbook Prompt (1). Check If The Malware Is Quarantined/Cleaned._

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

Ensure that your virtual machine's network adapter is set to '**Custom: Specific Virtual Network**’ to create a sandboxed environment. This setup places the virtual machine in its own isolated network, preventing it from communicating with the host machine or external networks, which enhances security.

<img width="725" alt="Screenshot 2025-01-28 at 1 11 32 PM" src="https://github.com/user-attachments/assets/a5e59b16-e960-4e27-87c3-249d5df8a22f" />

#

The first tool we used is called **ExifTool**. This tool is used to gather metadata about the document. Metadata includes information like the document’s creation date, the software used to create it, and any modifications that have been made. From the results, we can see the MIME type, which indicates that the document has macros enabled, and other details like the document's author, title, and last modified date. This metadata helps us understand the origin and nature of the document, which is crucial for further analysis.

<img width="727" alt="Screenshot 2025-01-28 at 1 13 35 PM" src="https://github.com/user-attachments/assets/f5459af7-df25-4dda-ba69-cc8a7ee5b87f" />

#

To gather more information about the document, we used a tool called ‘oleid’, which analyzes files for properties such as embedded macros, links, and other potentially suspicious content. The results confirmed that the file format is Microsoft Word, the file is not encrypted, and it contains VBA macros, which are commonly used to automate tasks but can also pose security risks if malicious.

<img width="624" alt="Screenshot 2025-01-28 at 2 59 05 PM" src="https://github.com/user-attachments/assets/05fba0e1-7ec6-4027-ada2-88abf02825b4" />

#

The tool ‘oleid’ recommended using another tool called ‘olevba’ to gather more info on suspicious keywords. The ‘olevba’ tool is specifically designed to examine Microsoft Office documents such as Word, Excel, and PowerPoint files for VBA macros. It works by extracting the embedded VBA code from these files and evaluating it for potential security threats. This includes detecting suspicious function calls, obfuscated code, and other indicators of malicious behavior.

By using the ‘olevba’ command and pointing it to a specific file, the tool extracts any VBA code within the document, evaluates it for potential threats, and displays the findings in its output. This process helps identify and assess the security risks associated with the analyzed file.

From the output, it was clear that the file was designed to automatically execute a system command or run an executable in the background once opened. The malicious file will then exeecute a PowerShell command to potentially download malicious payload(s) from the URL: ```https://filetransfer[.]io[/]data-package[/]UR2whuBv[/]download```

The code is obfuscated, making it difficult to determine the exact purpose of the downloaded file.

<img width="728" alt="Screenshot 2025-01-28 at 3 01 28 PM" src="https://github.com/user-attachments/assets/e3b436f8-1eff-4430-8602-a495c6a2c3ed" />

#

After analyzing the malicious file in our sandboxed environment, it is crucial to securely delete the file to prevent any accidental interaction or potential spread of malware. To do this we used the ‘**wipe**’ command to securely delete the file. The ‘**wipe**’ command ensures that data cannot be recovered by overwriting it with random data multiple times before deleting it. This method is much more secure than a standard way of deleting, which typically only removes file references without erasing the actual data on the disk.

<img width="725" alt="Screenshot 2025-01-28 at 3 02 22 PM" src="https://github.com/user-attachments/assets/335e4e3e-c8ec-4f60-a00e-59939705d65b" />

#

### _Playbook Prompt (3). Check If Someone Requested the C2 (Command & Control Server)._

<img width="726" alt="Screenshot 2025-01-28 at 3 04 31 PM" src="https://github.com/user-attachments/assets/b84d0571-3d6b-4600-a746-b5940f6f5ed2" />

Following the playbook, we are asked whether the C2 (Command and Control) address was accessed. This information is crucial as it helps us determine the scope of the incident. By searching for the C2 address(es) in our logs, we can assess whether the file was executed and identify if other endpoints were affected.

#

<img width="727" alt="Screenshot 2025-01-28 at 3 05 49 PM" src="https://github.com/user-attachments/assets/e6247818-beaf-4bcd-9c91-57b179441d7f" />

When we reviewed the logs for the Command and Control (C2) addresses identified on VirusTotal, there were no indications of those addresses being accessed. This suggests that the file was not accessed, and the system did not connect to the malicious servers.

#

<img width="727" alt="Screenshot 2025-01-28 at 3 07 31 PM" src="https://github.com/user-attachments/assets/12712184-a078-4d92-a1ad-56ba7165419f" />

#

When prompted by the playbook to define the Threat Indicator, we selected 'Other' because none of the available options adequately described the nature of the threat. Since the threat did not match a specific predefined category, 'Other' was the most appropriate choice to ensure accurate tracking and classification of the incident. This allows for further investigation and proper documentation for future reference.

<img width="628" alt="Screenshot 2025-01-28 at 3 08 43 PM" src="https://github.com/user-attachments/assets/688457a0-a3a2-4596-a101-018db3802332" />

#

We are then prompted to provide the artifacts gathered during the investigation. These artifacts may include files, logs, or other relevant data collected throughout the analysis process. Submitting these artifacts is crucial because it allows for a thorough review of the incident, helping to identify key details that can aid in detecting and remediating the threat, ultimately improving the organization's security posture. It also ensures that all necessary information is available for a comprehensive investigation and any future actions that may be required.

<img width="628" alt="Screenshot 2025-01-28 at 3 09 22 PM" src="https://github.com/user-attachments/assets/526efcba-ff22-4d13-8bbd-2fe7e71c4d94" />

#

The analyst’s notes when closing a ticket play a key role in recording findings, offering context for future investigations, and facilitating knowledge sharing. They create an audit trail for compliance, support post-incident reviews for process enhancement, and ensure the investigation is fully resolved and mitigated. This step involves ensuring that all findings, actions taken, and any recommendations for future monitoring or prevention are thoroughly documented.

<img width="628" alt="Screenshot 2025-01-28 at 3 10 08 PM" src="https://github.com/user-attachments/assets/5e427f38-d100-41e9-acd8-12106ac12126" />

#

After providing our notes, it is now time to close the ticket. Proper closure of the ticket ensures the investigation is formally concluded, and all necessary information is available for review or future reference.

<img width="626" alt="Screenshot 2025-01-28 at 3 11 08 PM" src="https://github.com/user-attachments/assets/69e28ed8-ef4e-4cfa-b6fb-637a0b3ce8b9" />

#

After analyzing the file, we determined it to be malicious. It contained embedded code designed to potentially communicate with a Command and Control (C2) server and download additional harmful payloads. This conclusion was supported by findings from VirusTotal, where multiple security vendors flagged the file as malicious. Based on this evidence, we confirmed that the alert was a True Positive, indicating a legitimate security threat that required action.

<img width="606" alt="Screenshot 2025-01-28 at 3 12 06 PM" src="https://github.com/user-attachments/assets/17013c46-6f12-4079-95af-2d6f9abe0a18" />

#

By navigating to the 'Closed Alerts' tab, we can access a complete list of all previously closed investigations. This feature allows us to review resolved cases, analyze past incidents, and reference documented findings for future use. It ensures that all historical investigations are easily accessible for auditing, knowledge sharing, or process improvement.

<img width="626" alt="Screenshot 2025-01-28 at 3 13 07 PM" src="https://github.com/user-attachments/assets/21613bcd-9e30-4a99-b6c2-e91f31a086bd" />

