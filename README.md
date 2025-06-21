<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/TechTomy/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for ANY file that had the string “tor” in it and discovered what looks like the user “employee” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and creation of a file called `tor-shopping-list.txt` on the desktop at `2025-06-20T21:43:19.8442977Z`. These events began at: `2025-06-20T21:32:55.4458245Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceId == "27e66b4fea05c3f811e5ff3db86255436b5f3424"
| where InitiatingProcessAccountName == "employee"
| where Timestamp >= datetime(2025-06-20T21:32:55.4458245Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/4558eeb2-e04c-4be8-8f44-11496d41dcab">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string `tor-browser-windows-x86_64-portable-14.5.3.exe`. Based on the logs returned, `2025-06-20T21:34:35.6464742Z`, an employee on the `tee-threat-hunt` device ran the file `tor-browser-windows-x86_64-portable-14.5.3.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceId == "27e66b4fea05c3f811e5ff3db86255436b5f3424"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/5843d989-384e-488e-bec1-d3a463731cc2">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceId == "27e66b4fea05c3f811e5ff3db86255436b5f3424"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/5843d989-384e-488e-bec1-d3a463731cc2">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-06-20T21:35:46.6803501Z`, a successful connection was made from a device named `tee-threat-hunt`. The connection originated from the IP address `178.254.20.235` and used port `9001`. The process was initiated by a user account named `employee` running the file `tor.exe` located at `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe` There were a few other connections over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceId == "27e66b4fea05c3f811e5ff3db86255436b5f3424"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9150", "9040", "9051")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/070dd1c6-1c2c-435d-841d-f684a5c8f211">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025‑06‑20T21:32:55.4458245Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.3.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025‑06‑20T21:34:35.6464742Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.3.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025‑06‑20T21:35:03.9403808Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025‑06‑20T21:35:38.6803501Z`
- **Event:** A network connection to IP `178.254.20.235` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025‑06‑20T21:43:19.8442977Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "tee-threat-hunt" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `tee-threat-hunt` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
