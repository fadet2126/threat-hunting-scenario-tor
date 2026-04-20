# Official [Flo Cyber Security Lab](http://fadet2126.tech/cyber-range) Project

<img width="400" src="SOC - Lab Portfolio/tor-browser-icon.jpg" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/fadet2126/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

1.	The DeviceFileEvents table was searched to see if any table has the string ‘tor’ in it, it was discovered that the user ‘flo’ downloaded ‘tor installer’ which resulted in copying many tor-related files..to the desktop and a file named ‘tor-shopping-list’ being created and downloaded to the desktop. The events started at 13 Apr 2026 14:58:32

**Query used to locate events:**

```kql
//check device for a vm
DeviceFileEvents
| where DeviceName == "flovmreal"
| where InitiatingProcessAccountName == "flo"
| where FileName contains "tor"
| where Timestamp >= datetime(13 Apr 2026 14:58:45)
| order by Timestamp desc 
|project Timestamp, DeviceId, DeviceName, ActionType, FileName, SHA256, InitiatingProcessAccountName 

<img width="1508" src="SOC - Lab Portfolio/threatHuntingStep1-Image.png" alt="image of Advanced Hunting query result">

---

### 2. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

//To check if the tor browser was launched:
The search carried out on the DeviceProcessEvents table indicated that the user “flo” opened the tor browser. Evidence revealed that the tor browser was opened at 13 Apr 2026 15:11:14 . There were other aftermath instances of firefox.exe (Tor) as well as tor.exe spawned.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName  == "flovmreal"
| where FileName has_any ("firefox.exe", "tor.exe", "tor-browser.exe", "start-tor-browser.exe", "torbrowser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath,SHA256, ProcessCommandLine
| order by Timestamp desc 

```
<img width="1508" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f" alt="Advanced Hunting query result screenshot">

---


### 3. Searched the `DeviceProcessEvents` Table

Investigating the DeviceProcessEvents table to see if the file was executed:
A search for any ProcessCommandLline that contained the string “
tor-browser-windows-x86_64-portable-15.0.9.exe  /S” was carried out. The returned logs at 
13 Apr 2026 15:09:20, it was discovered that the device flovmreal was used by ‘flo’ was used to run the file tor-browser-windows-x86_64-portable-15.0.9.exe from their Downloads folder with a command that silently triggered the installation. 

**Query used to locate event:**

```kql

//check to know if the file was executed
DeviceProcessEvents
| where DeviceName == "flovmreal"
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"
|project Timestamp, DeviceId, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1508" src="SOC - Lab Portfolio/threatHuntingStep2-Image.png" alt="Advanced Hunting query result screenshot">

---


### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections
	//To check if the tor browser was used to browse.
The Search on DeviceNetworkEvents to know whether the tor browser was used to browse, as well as used to browse on the normal internet indicated that the Tor software on the computer (flovmreal by user “flo”)  connected to another Tor server on the internet. The file path shows that it came from a Tor browser installation on the desktop with the IP address 57.131.42.77 Port 9001. The connection was initiated by the process tor.exe, located in the folder c:\users\flo\desktop\tor browser\browser\torbrowser\tor\tor.exe. A couple of other connections were made to sites over port 443.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "flovmreal"
| where InitiatingProcessAccountName != "system"
|where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "9151, 80, 443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
|order by Timestamp desc


```
<img width="1508" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb" alt="Advanced Hunting query result screenshot">

---

## Chronological Event Timeline 

### 1.Initial TOR File Activity (Download & Staging)

- **Timestamp:** 13 Apr 2026 14:58:32 – ~15:05:28 
- **Event:** The user "flo" downloaded a file named tor-browser-windows-x86_64-portable-15.0.9.exe and initiated TOR-related file activity. 
- **Action:** : File download and staging detected; multiple TOR-related files were created/copied to the Desktop, including additional artifacts such as “tor-shopping-list”. 
- **File Path:** C:\Users\Flo\Downloads\tor-browser-windows-x86_64-portable-15.0.9.exe 

### 2.TOR Installer Execution (Silent Installation)

- **Timestamp:** `13 Apr 2026 15:09:20`
- **Event:** The user "flo" executed the TOR installer using a silent command. 
- **Action:** Process creation detected with silent installation flag (/S), indicating background installation without user prompts. 
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\Flo\Downloads\tor-browser-windows-x86_64-portable-15.0.9.exe` 

### 3. TOR Browser Launch

- **Timestamp:** 13 Apr 2026 15:09:20 
- **Event:** The user "flo" launched the TOR Browser. 
- **Action:** Process execution detected; TOR-related processes (firefox.exe and tor.exe) were spawned. 
- **File Path:** `C:\Users\Flo\Desktop\tor browser\browser\ `

### 4. TOR Network Connection Established

- **Timestamp:** `13 Apr 2026 (post 15:12)`
- **Event:** The TOR Browser was used to generate outbound encrypted network traffic. 
- **Action:** CMultiple connections detected over TOR-related ports (e.g., 9001) and encrypted web traffic over port 443. 
- **Process:** `tor.exe`
- **File Path:** `C:\Users\Flo\Desktop\tor browser\browser\torbrowser\tor\tor.exe `

### 5. TOR Network Activity (Browsing Behavior)

- **Timestamps:**
  - `13 Apr 2026 (post 15:12) ` .
- **Event:** The TOR Browser was used to generate outbound encrypted network traffic. 
- **Action:** Multiple connections detected over TOR-related ports (e.g., 9001) and encrypted web traffic over port 443.
- **File Path:** `C:\Users\Flo\Desktop\tor browser\browser\torbrowser\tor\tor.exe` 

### 6. Continued TOR Usage (Subsequent Activity)

- **Timestamp:** 16 Apr 2026 ~14:05 `
- **Event:** The user "flo" reopened and used the TOR Browser. 
- **Action:** Additional TOR-related processes (firefox.exe, tor.exe) were executed, indicating continued usage. 
- **File Path:** `C:\Users\Flo\Desktop\tor browser\browser\ `

---

## Summary of Events

•	The user "flo" downloaded and staged the TOR Browser installer. 
•	The installer was executed using a silent installation method, avoiding user prompts. 
•	TOR Browser was launched shortly after installation, confirming successful setup. 
•	The system established connections to the TOR network, indicating active anonymized browsing. 
•	Additional encrypted network traffic confirms TOR was used for browsing activity. 
•	TOR usage persisted over multiple days, demonstrating continued and intentional use. 

---

## Final Assessment
The activity shows intentional installation and use of TOR Browser on the workstation flovmreal.
The use of silent installation combined with successful TOR network connections and repeated usage suggests deliberate attempts to bypass standard network monitoring and controls.

---

## Response Taken

TOR usage was confirmed on the endpoint flovmreal by the user flo. The device should be isolated, and the user's direct manager should be notified.

---
