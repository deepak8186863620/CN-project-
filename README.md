# Basic Firewall Implementation using Python
### Computer Networks (CN) Course Project & Laboratory Demonstration

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![GUI-Tkinter](https://img.shields.io/badge/GUI-Tkinter%2FTTK-green.svg)](https://docs.python.org/3/library/tkinter.html)
[![Networking-Scapy](https://img.shields.io/badge/Packet%20Engine-Scapy-red.svg)](https://scapy.net/)
[![Tests-Passed](https://img.shields.io/badge/Tests-21%20Passed-brightgreen.svg)](tests/)

---

## 1. Project Title & Overview

**Basic Firewall Implementation using Python** is an educational, application-layer packet-filtering firewall and network traffic inspection system. It demonstrates the fundamental networking principles behind statutory packet filters, Access Control Lists (ACLs), transport protocol multiplexing, and state-agnostic rule evaluation.

The system empowers Computer Networks students to observe how incoming datagram headers are dissected, matched sequentially against configured rule policies, and classified into **ALLOWED** or **BLOCKED** verdicts with comprehensive audit logging and graphical analytics.

---

## 2. Problem Statement

Modern enterprise and edge networks rely on firewalls as the frontline defense against unauthorized access, malicious port scans, and denial-of-service attempts. However, commercial production firewalls (e.g., Linux iptables/nftables, Cisco ASA, Windows Advanced Firewall) operate deep within the operating system kernel or dedicated ASIC hardware. This makes their internal rule-matching algorithms, packet dissecting logic, and fallback policies opaque to students studying Computer Networks.

There is a critical educational need for a self-contained, transparent, and completely safe software firewall simulator that:
1. Dissects layer-3 (IP) and layer-4 (TCP/UDP/ICMP) headers in real time.
2. Demonstrates the strict **First-Matching-Rule-Wins** priority evaluation algorithm.
3. Provides an interactive GUI to inspect packets, simulate arbitrary traffic, reorder policies, and review audit logs.
4. Operates without altering operating system kernel configurations or risking disruption to the student's actual host internet connectivity.

---

## 3. Project Objectives

- **Educational Packet Inspection**: Provide complete visibility into IP datagram headers (source IP, destination IP) and transport protocol headers (protocol number, source port, destination port).
- **Rule Matching Engine**: Implement a deterministic packet evaluation engine based on Access Control List (ACL) priority ordering (first matching rule wins).
- **Dynamic Rule Management**: Allow users to dynamically create, edit, toggle, reorder, and persist firewall rules in a portable JSON format.
- **Traffic Simulator**: Provide an interactive laboratory testbed to inject synthetic TCP, UDP, and ICMP datagrams with instantaneous visual decision banners (**ALLOWED** in Green, **BLOCKED** in Red).
- **Optional Live Packet Sniffing**: Integrate Scapy for live network interface packet capture and layer-by-layer inspection, with a zero-privilege synthetic generator fallback for restricted lab environments.
- **Comprehensive Audit Trail**: Maintain an append-only log file (`firewall.log`) recording timestamps, 5-tuple attributes, decision verdicts, and matching rationale.
- **Visual Analytics**: Deliver a responsive Tkinter GUI featuring KPI metric cards and custom Canvas-rendered traffic distribution charts.

---

## 4. Key Features

| Feature | Description |
| :--- | :--- |
| **Real-Time Dashboard** | Displays firewall status (`RUNNING` / `STOPPED`), metric counters (processed, allowed, blocked), and an animated Tkinter Canvas comparative chart. |
| **Rule Management (ACLs)** | Interactive table supporting full CRUD operations, priority reordering (`Move Up` / `Move Down`), and instant toggle (`Enable` / `Disable`). |
| **Packet Simulator** | Laboratory workspace with single-click presets (HTTP, HTTPS, Telnet, DNS, ICMP Ping, SSH) and custom 5-tuple inputs. |
| **Scapy Packet Crafting** | Synthesizes true Scapy packet objects layer-by-layer (`IP() / TCP() / Raw()`), enabling inspection of raw hex summaries and flags. |
| **Live Packet Capture & Demo**| Sniffs network traffic using Scapy's `sniff()`, with graceful detection of Windows Npcap privileges and a built-in synthetic traffic streamer. |
| **Audit Logger (`firewall.log`)**| Thread-safe, standardized audit logging with in-GUI search, decision filtering (`ALL`, `ALLOWED`, `BLOCKED`), and export options. |
| **Input Validation & Safety** | Validates IPv4 addresses, CIDR notation (e.g., `192.168.1.0/24`), wildcards (`ANY`), and port numbers (0–65535). Never crashes on bad input. |

---

## 5. Technology Stack

- **Programming Language**: Python 3.8+ (Tested on Python 3.13)
- **Networking Library**: [Scapy](https://scapy.net/) (for packet creation, header extraction, and live capture)
- **Graphical User Interface**: Standard Python `tkinter` & `ttk` (native, cross-platform, zero heavy GUI dependencies)
- **Rule Storage**: Portable JSON (`data/rules.json`)
- **Logging Subsystem**: Thread-safe Python file I/O (`firewall.log`)
- **Testing Framework**: Python standard `unittest` suite (21 automated unit tests)

---

## 6. Important Safety & Architectural Design

> [!IMPORTANT]
> **Educational Firewall Guarantee**: This software operates strictly within user space as an educational simulator and packet-filtering demonstration. It **does NOT** modify host operating system kernel routing tables, network adapter bindings, or native Windows Firewall / Linux iptables settings.
> 
> Testing network traffic through this application will **never disrupt your host computer's real internet connection**.

---

## 7. System Requirements

- **Operating System**: Windows 10/11, Linux (Ubuntu/Debian/Fedora), or macOS.
- **Python**: Python 3.8 or higher.
- **Privileges**: Standard user privileges are sufficient for the Dashboard, Rule Management, Packet Simulator, and Audit Logs.
  - *Note on Live Capture*: Sniffing promiscuous packets directly from physical network interfaces on Windows requires [Npcap](https://npcap.com/) and Administrator privileges. If Npcap or admin rights are absent, the application automatically provides the **Live Synthetic Stream Generator**, ensuring 100% demonstration capability without elevated rights.

---

## 8. Installation & Setup

### Step 1: Clone or Navigate to Project Directory

```bash
git clone https://github.com/deepak8186863620/CN-project-.git
cd CN-project-
```

### Step 2: Create a Python Virtual Environment

**On Windows (PowerShell / Command Prompt):**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Required Dependencies

```bash
pip install -r requirements.txt
```

*(Note: Scapy will be installed. Tkinter is bundled by default with official Python distributions on Windows and macOS).*

---

## 9. How to Run

### Graphical User Interface (Default)

Launch the full interactive GUI application:

```bash
python main.py
```

### Terminal CLI Demonstration Mode (Optional / Headless)

To demonstrate packet filtering decisions directly in the terminal without opening a GUI:

```bash
python main.py --cli
```

---

## 10. How Firewall Rules Work

### The 5-Tuple Network Header

A packet filtering firewall examines the headers of layer-3 (Network) and layer-4 (Transport) protocols. In this project, each packet is characterized by its **5-tuple**:

1. **Source IP**: Originating host IP address (e.g., `192.168.1.10` or wildcard `ANY`).
2. **Destination IP**: Target host IP address (e.g., `142.250.190.46` or wildcard `ANY`).
3. **Protocol**: Transport protocol (`TCP`, `UDP`, or `ICMP`).
4. **Source Port**: Ephemeral port assigned by client operating system (e.g., `54321` or `ANY`).
5. **Destination Port**: Service port corresponding to target application (e.g., `80` for HTTP, `443` for HTTPS, `23` for Telnet).

### Matching Algorithm (First-Match-Wins)

```mermaid
flowchart TD
    Start([Incoming Packet Header]) --> CheckRunning{Firewall Running?}
    CheckRunning -- No --> Bypass[Bypass Filter: ALLOWED]
    CheckRunning -- Yes --> FetchRules[Load Active Rules in Order]
    
    FetchRules --> CheckRule{Next Rule Available?}
    CheckRule -- No --> DefaultPolicy[Apply Default Policy: BLOCK / ALLOW]
    CheckRule -- Yes --> MatchProto{Protocol Matches?}
    
    MatchProto -- No --> NextRule[Advance to Next Rule]
    MatchProto -- Yes --> MatchSrcIP{Source IP Matches?}
    
    MatchSrcIP -- No --> NextRule
    MatchSrcIP -- Yes --> MatchDstIP{Dest IP Matches?}
    
    MatchDstIP -- No --> NextRule
    MatchDstIP -- Yes --> MatchPorts{Ports Match? (or ICMP)}
    
    MatchPorts -- No --> NextRule
    MatchPorts -- Yes --> ApplyAction[Apply Rule Action: ALLOWED / BLOCKED]
    
    NextRule --> CheckRule
    ApplyAction --> LogDecision[Write to firewall.log & Update UI]
    DefaultPolicy --> LogDecision
    Bypass --> LogDecision
    LogDecision --> End([Return Evaluation Result])
```

1. **Sequential Evaluation**: Active rules are checked strictly in top-to-bottom priority order.
2. **Field Comparison**: A rule matches a packet if and only if **all 5 criteria match**:
   - Protocol matches (or rule protocol is `ANY`).
   - Source IP matches (exact IP, CIDR subnet, or `ANY`).
   - Destination IP matches (exact IP, CIDR subnet, or `ANY`).
   - Source Port matches (or rule source port is `ANY`).
   - Destination Port matches (or rule destination port is `ANY`; automatically bypassed for ICMP).
3. **Termination**: The **first rule that matches determines the verdict** (`ALLOW` $\to$ `ALLOWED`, `BLOCK` $\to$ `BLOCKED`). Evaluation halts immediately.
4. **Fallback / Default Policy**: If no active rule matches the packet headers, the configured **Default Policy** (default: `BLOCK`) is applied.
5. **Audit Logging**: Every decision is written to `firewall.log` and dispatched to GUI listener callbacks.

---

## 11. Initial Default Sample Rules

The application ships with 5 standard educational rules configured in `data/rules.json`:

| ID | Name | Protocol | Source IP | Src Port | Destination IP | Dst Port | Action | Purpose |
| :-: | :--- | :-: | :-: | :-: | :-: | :-: | :-: | :--- |
| **1** | Allow Web HTTP | TCP | ANY | ANY | ANY | 80 | **ALLOW** | Permits unencrypted web browsing |
| **2** | Allow Web HTTPS | TCP | ANY | ANY | ANY | 443 | **ALLOW** | Permits secure SSL/TLS web traffic |
| **3** | Block Insecure Telnet | TCP | ANY | ANY | ANY | 23 | **BLOCK** | Prevents plaintext remote terminal access |
| **4** | Allow DNS Queries | UDP | ANY | ANY | ANY | 53 | **ALLOW** | Permits domain name resolution queries |
| **5** | Block ICMP Ping | ICMP | ANY | ANY | ANY | ANY | **BLOCK** | Shields network from ICMP echo discovery |

---

## 12. Project Directory Structure

```
basic_firewall/
│
├── main.py                     # Main application entry point (GUI & CLI modes)
├── requirements.txt           # Python dependency specifications (Scapy)
├── README.md                  # Comprehensive setup & user documentation
├── PROJECT_REPORT.md          # 21-section academic Computer Networks project report
├── firewall.log               # Live append-only audit trail
│
├── core/                      # Core networking and firewall business logic
│   ├── __init__.py            # Core package exports
│   ├── firewall_engine.py     # Decision engine, statistics, and callback pipeline
│   ├── rule_manager.py        # Rule CRUD, validation, JSON I/O, and matching helpers
│   ├── packet_parser.py       # PacketData definition, Scapy packet crafting & parsing
│   └── logger.py              # Thread-safe log writer and log file reader
│
├── gui/                       # Tkinter & TTK graphical user interface views
│   ├── __init__.py            # GUI package exports
│   ├── dashboard.py           # Dashboard tab with KPI cards, Canvas chart, and live stream
│   ├── rules_view.py          # Rule management table, Add/Edit modal, priority reordering
│   ├── packet_simulator.py    # Packet testbed, preset injection, and result banner
│   ├── logs_view.py           # Log viewer with keyword search, decision filter, and export
│   └── live_capture_view.py   # Scapy sniffer & synthetic stream generator demonstration
│
├── data/                      # Persistent storage directory
│   └── rules.json             # Firewall rules database in JSON format
│
└── tests/                     # Automated unit and integration testing suite
    ├── __init__.py            # Tests package init
    ├── test_firewall_engine.py# 10 core automated test requirements
    ├── test_rule_manager.py   # Rule validation, CIDR matching, and persistence tests
    └── test_viva_demonstration.py # End-to-end 11-step viva walkthrough test
```

---

## 13. Automated Testing

The project includes 21 comprehensive unit tests covering all required evaluation criteria:

### Running the Test Suite

Execute the following command from the project root:

```bash
python -m unittest discover -s tests -v
```

### Verified Test Cases

1. `test_01_tcp_port_80_allow`: Verifies HTTP packet on TCP :80 evaluates to **ALLOWED**.
2. `test_02_tcp_port_443_allow`: Verifies HTTPS packet on TCP :443 evaluates to **ALLOWED**.
3. `test_03_tcp_port_23_block`: Verifies Telnet packet on TCP :23 evaluates to **BLOCKED**.
4. `test_04_udp_port_53_allow`: Verifies DNS query on UDP :53 evaluates to **ALLOWED**.
5. `test_05_icmp_block`: Verifies ICMP Ping echo evaluates to **BLOCKED**.
6. `test_06_unknown_packet_default_policy`: Verifies unmatched traffic triggers the Default Policy (`BLOCK` / `ALLOW`).
7. `test_07_wildcard_ip_matching`: Tests IP matching with wildcards (`ANY`) and subnet CIDR masks (`192.168.50.0/24`).
8. `test_08_invalid_rule_input`: Verifies strict validation rejects malformed IPs, ports > 65535, and invalid protocols.
9. `test_09_rule_ordering_first_match_wins`: Proves rule prioritization by testing conflicting rules and verifying first-match wins.
10. `test_10_logging_verification`: Validates `firewall.log` write format and parser reconstruction.
11. `test_full_demonstration_scenario`: Executes the full 11-step viva examination sequence end-to-end.

---

## 14. Step-by-Step Viva Examination Walkthrough

Follow this 11-step sequence during your project evaluation or lab viva:

1. **Launch Application**: Run `python main.py`. The window opens on the **Dashboard** tab.
2. **Examine Dashboard**: Note the status badge showing **RUNNING**, metrics initialized, and the comparative Canvas chart.
3. **Inspect Rules**: Switch to the **Rule Management** tab. Show the 5 initial rules, explaining the priority order (Rules 1 to 5).
4. **Test Allowed Traffic (HTTPS)**: Switch to **Packet Simulator**. Click the `HTTPS Secure (TCP :443)` preset. Click **CHECK PACKET**.
   - Result: Bright green **ALLOWED** banner with rule rationale.
5. **Test Blocked Traffic (Telnet)**: Click the `Telnet Insecure (TCP :23)` preset. Click **CHECK PACKET**.
   - Result: Bright red **BLOCKED** banner explaining that Rule #3 matched.
6. **Verify Audit Logs**: Switch to the **Firewall Logs** tab. Show both packets logged with exact timestamps and 5-tuple attributes.
7. **Modify Rule / Demonstrate Priority**: Switch to **Rule Management**.
   - Select Rule #3 (`Block Insecure Telnet`).
   - Click `🔘 Toggle Enable/Disable` to disable the rule, or click `✏️ Edit Rule` to change its action to `ALLOW`.
8. **Retest Telnet Packet**: Return to **Packet Simulator** and click **CHECK PACKET** again.
   - Result: Show that the decision has now dynamically flipped!
9. **Send Traffic Burst**: Click `⚡ Send 15 Mixed Packets Burst` to populate realistic network traffic.
10. **Demonstrate Live Sniffing**: Switch to **Live Capture / Demo**. Select `Live Synthetic Stream Generator` and click **Start Live Capture**. Watch real-time packets flow across the table.
11. **Review Final Statistics**: Return to **Dashboard** to view updated packet counts, allowance percentages, and the rendered distribution chart.

---

## 15. Limitations & Future Scope

### Limitations
- **Stateless Inspection**: Inspects each packet independently without tracking TCP 3-way handshake states (SYN, SYN-ACK, ESTABLISHED).
- **Deep Packet Inspection (DPI)**: Filtering is performed on layer-3 and layer-4 headers; payload contents (layer 7 application data) are not decrypted or signature-scanned.
- **Operating System Kernel Interception**: As an educational tool, packets are filtered inside the Python runtime rather than intercepting OS-level kernel network drivers.

### Future Scope
- **Stateful Inspection**: Implementing a Connection State Table to track TCP connection life cycles and allow related/established traffic.
- **Dynamic Intrusion Detection (IDS)**: Rate limiting and automatic blocking of source IPs generating excessive SYN packets (SYN Flood protection).
- **Geo-IP Filtering**: Integrating MaxMind GeoLite databases to filter traffic based on geographic country of origin.

---

## 16. Author & Academic Context

- **Course**: Computer Networks (Undergraduate CS / IT)
- **Project Topic**: Application-Layer Packet-Filtering Firewall Implementation
- **Implementation Language**: Python 3
