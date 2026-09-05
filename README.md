<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/whsiano/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "wilsonuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-09-04T20:21:15.8686801Z`. These events began at ` 2026-09-04T20:03:49.5836932Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "vm-wilson-tor-l"
| where InitiatingProcessAccountName == "wilsonuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-09-04T20:03:49.5836932Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, SHA256, Account = InitiatingProcessAccountName 
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/edb01599-29b0-4a8c-bdda-a3f732bd2a30">


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `2026-09-04T20:07:00.4327069Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-15.0.21.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "vm-wilson-tor-l"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/f0a8e998-c5c0-4b27-86fe-3f0526946178">


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2026-09-04T20:07:29.3198778Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "vm-wilson-tor-l"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc  
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/802bf1e0-86b2-4f6d-8c4b-aa395d20f054">


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-09-04T20:08:09.0189457Z`, an employee on the "vm-wilson-tor-l" device successfully established a connection to the remote IP address `84.234.21.32` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\wilsonuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "vm-wilson-tor-l"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe") 
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/f4b86f02-cc8f-4a31-97d7-dbe46e5e98f5">


---

## Chronological Timeline
 
| Time (Sep 4, 2026) | Event Type | Details |
|---|---|---|
| 1:03:49 PM | FileRenamed | `tor-browser-windows-x86_64-portable-15.0.21.exe` renamed in the Downloads folder — consistent with a browser finalizing a download (temp file → final filename). |
| 1:03:56 PM | FileDeleted | `tor-browser-windows-x86_64-portable-15.0.21.exe` — a same-named file record deleted seconds later, consistent with cleanup of a temporary/partial download artifact rather than the final installer itself. |
| 1:04:01 PM | ProcessCreated | Installer launched interactively, no command-line arguments (`tor-browser-windows-x86_64-portable-15.0.21.exe`) — the user double-clicked the downloaded file, opening the NSIS setup wizard. |
| 1:07:00 PM | ProcessCreated | Installer re-invoked itself with `/S` (silent flag) — the standard behavior for this installer once the user selects a destination and clicks "Install" in the wizard; it re-launches itself silently to perform the actual extraction. |
| 1:07:09 PM | FileCreated (×4) | `tor.exe`, `tor.txt`, `Torbutton.txt`, `Tor-Launcher.txt` extracted to `Desktop\Tor Browser\Browser\TorBrowser\Tor` — core Tor Browser files unpacked. |
| 1:07:14 PM | FileCreated | `Tor Browser.lnk` — desktop shortcut created, marking install completion. |
| 1:07:29 PM | ProcessCreated (×2) | `firefox.exe` launched with no arguments — Tor Browser opened for the first time. |
| 1:07:39 PM | FileCreated | `storage.sqlite` — Firefox profile database created as the browser initializes. |
| 1:07:40 – 1:07:43 PM | ProcessCreated (×6) | Multiple `firefox.exe` child processes spawned (GPU, RDD, utility, and content processes) — normal Firefox multi-process startup sequence. |
| 1:07:43 PM | FileCreated | `storage-sync-v2.sqlite` — additional Firefox profile file created. |
| 1:07:45 PM | ProcessCreated | `tor.exe` launched with its `torrc` config: `SocksPort 127.0.0.1:9150`, `ControlPort 127.0.0.1:9151`, `DisableNetwork 1` — the Tor daemon starting up under the browser's control, network initially disabled pending connection setup. |
| 1:08:05 PM | ConnectionSuccess | → `176.65.149.96:443` (`z6zqwn7sc3t53o4ver.com`) — first Tor relay connection, disguised as ordinary HTTPS traffic. |
| 1:08:09 PM | ConnectionSuccess (×3) | → `144.76.188.91:9001` (`52udxmyldzyucdrjd5bmgsnhg.com`) and `192.42.116.173:443` — additional relay hops, consistent with building a 3-hop Tor circuit. |
| 1:08:12 PM | ConnectionSuccess | `firefox.exe` → `127.0.0.1:9150` — the browser itself connects to Tor's local SOCKS proxy, confirming browsing traffic is actively being routed through Tor. |
| 1:08:25 PM | ConnectionFailed | → `178.239.17.187:9001` — a relay connection attempt failed; normal background noise during Tor circuit building, not inherently suspicious. |
| 1:10:13 PM | ConnectionSuccess (×2) | → `192.42.116.25:443` (`hwtbtd4w.com`) |
| 1:10:30 PM | ProcessCreated | `firefox.exe` content process spawned ("11 tab") — a new browser tab opened. |
| 1:11:11 PM | ConnectionSuccess | → `84.234.21.32:9001` — relay/circuit maintenance traffic (no associated URL). |
| 1:12:10 PM | ConnectionSuccess | → `84.234.21.32:9001` (`fy4y465z4gh5cwit.com`) |
| 1:12:50 PM | ProcessCreated | `firefox.exe` content process spawned ("12 tab"). |
| 1:13:28 PM | ConnectionSuccess | → `192.42.116.173:443` (`yuqlqh35zmqc.com`) |
| 1:14:30 – 1:16:24 PM | ProcessCreated (×7) | `firefox.exe` content processes continue spawning in sequence ("13 tab" through "20 tab") — a sustained, active browsing session with the tab count climbing steadily. |
| 1:21:15 PM | FileCreated (×2) | `tor-shopping-list.txt` and `tor-shopping-list.lnk` created on the Desktop — a text file (and its shortcut) saved roughly 5 minutes after the last observed browsing activity. |
 
---

## Summary

Between **1:03 PM and 1:21 PM on September 4, 2026**, the user **wilsonuser** downloaded the Tor Browser portable installer to the Downloads folder on **vm-wilson-tor-l**, launched it interactively, and completed a standard (self-silencing) install to their Desktop. Tor Browser was opened immediately after installation, and the underlying `tor.exe` process successfully bootstrapped a working Tor circuit — confirmed by multiple successful outbound connections to known Tor relay ports (443 and 9001) and by Firefox connecting to Tor's local SOCKS proxy on `127.0.0.1:9150`, which verifies the browser was actively routing traffic through the Tor network rather than merely running.
 
Over the following ~13 minutes, the browser's content-process count climbed steadily from roughly 11 to 20, indicating an extended, hands-on browsing session with many tabs open. The session ended with the creation of a file named **`tor-shopping-list.txt`** (plus its shortcut) directly on the Desktop.
 
**Assessment:** All activity in this dataset is self-contained — a single user, on a single device, downloading, installing, and personally using Tor Browser, with no evidence in these exports of lateral movement, external tooling, or automated/scripted behavior. The interactive install (double-click before the silent re-launch) and the steadily climbing tab count point to manual, hands-on-keyboard use rather than malware or a scripted process. The resulting file name ("shopping list") suggests the user may have been browsing and noting items from anonymized/dark-web sites, though the actual file contents are not present in the provided logs and cannot be confirmed from this data alone. Whether this constitutes a policy violation depends on your organization's acceptable-use policy regarding anonymization tools — Tor usage itself is not inherently malicious, but unsanctioned installation of anonymizing software on a corporate endpoint typically warrants a policy/HR follow-up.
---

## Response Taken

TOR usage was confirmed on the endpoint `vm-wilson-tor-l` by the user `wilsonuser`. The device was isolated, and the user's direct manager was notified.

---
