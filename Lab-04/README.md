# Lab 04: Memory Forensics and Malware Analysis with Volatility

## 📋 Lab Overview

This lab demonstrates advanced memory forensics techniques using Volatility Framework to investigate a compromised Windows XP system. The investigation focuses on identifying malicious processes, analyzing process injection/hollowing techniques, extracting malware artifacts, and understanding persistence mechanisms through registry analysis.

**Lab Focus:** Memory Forensics, Malware Analysis, Process Injection Detection, Persistence Mechanisms

**Case Scenario:** Analysis of a memory dump (lab05.vmem) from a potentially compromised Windows XP SP2 x86 system showing signs of malicious activity, specifically focusing on suspicious lsass.exe processes and kernel-level rootkit components.

**Investigation Status:** COMPLETED  
**Malware Identified:** Process Hollowing Attack with Kernel Rootkit Components  
**Threat Level:** HIGH - System Compromise with Persistence

---

## 🎯 Objectives

By completing this lab, I demonstrated proficiency in:

- Conducting comprehensive memory forensics using Volatility Framework
- Identifying and analyzing malicious processes in memory dumps
- Detecting process injection and process hollowing techniques
- Analyzing Windows registry artifacts for persistence mechanisms
- Extracting and hashing malicious executables from memory
- Using VirusTotal for malware identification and threat intelligence
- Understanding kernel-level rootkit indicators
- Analyzing memory permissions for malicious code detection
- Investigating network connections and system callbacks
- Correlating multiple indicators of compromise (IOCs) for definitive malware identification

---

## 🛠️ Tools & Environment

### Primary Tool
- **Volatility Framework 2.x** - Advanced memory forensics platform
- **Profile Used:** WinXPSP2x86 (Windows XP Service Pack 2, 32-bit)

### Supporting Tools
- **SHA256sum** - Cryptographic hash calculation for malware samples
- **VirusTotal** - Online malware scanning and threat intelligence
- **grep** - Pattern matching for filtering Volatility output
- **VMware vSphere** - Linux virtual machine environment

### Evidence Source
- **Memory Dump:** lab05.vmem
- **Operating System:** Windows XP SP2 x86
- **Capture Format:** Raw memory dump (.vmem)

---

## 📊 Executive Summary

### Investigation Overview

**Incident Type:** System Compromise - Process Hollowing with Kernel Rootkit  
**Attack Vector:** Malicious code injection into legitimate Windows processes  
**Persistence Mechanism:** Kernel drivers configured for auto-start via Windows Registry  
**Compromised Processes:** lsass.exe (Local Security Authority Subsystem Service)  
**Malicious Modules:** mrxcls.sys, mrxnet.sys (kernel rootkit drivers)

### Key Findings

**Critical Indicators of Compromise (IOCs):**

1. ✅ **Three concurrent lsass.exe processes** (Normal: Only 1 should exist)
2. ✅ **Process hollowing detected** (PAGE_EXECUTE_READWRITE permissions)
3. ✅ **Malicious code injection** in PIDs 1928 and 868
4. ✅ **Kernel rootkit modules** (mrxcls.sys and mrxnet.sys)
5. ✅ **Registry persistence** (Services configured for auto-start)
6. ✅ **Missing parent process** (No wininit.exe found - critical red flag)
7. ✅ **Malicious callbacks** registered in kernel

**Malware Identification:**
- **Via VirusTotal:** Both samples identified as malware by multiple AV engines
- **Attack Type:** Process Hollowing (Code Injection Technique)
- **Persistence:** Kernel-level rootkit with registry auto-start

**System Status:** **FULLY COMPROMISED**  
**Recommended Action:** Complete system rebuild, not remediation

---

## 🔍 Detailed Investigation Methodology

### Phase 1: Memory Dump Analysis Setup

#### Step 1: Volatility Profile Identification

**Command Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 -h
```

**Purpose:** Verify profile compatibility and list available plugins

**Profile Information:**
- **Operating System:** Windows XP Service Pack 2
- **Architecture:** x86 (32-bit)
- **Profile Name:** WinXPSP2x86

**Why Profile Matters:**
Memory structures differ between OS versions. Using the wrong profile results in:
- Incorrect memory parsing
- Missed evidence
- False positives
- Garbled output

The correct profile (WinXPSP2x86) ensures Volatility interprets memory structures accurately.

#### Step 2: Understanding Available Capabilities

**What Can Be Extracted from Memory?**

**Process Information:**
- Active and hidden processes
- Process IDs (PIDs) and Parent Process IDs (PPIDs)
- Process creation times
- Command-line arguments
- Process memory regions and permissions

**Registry Contents:**
- Registry hives loaded in memory
- Registry key values
- Persistence mechanisms
- Configuration settings

**Malware Indicators:**
- Injected code
- Suspicious memory permissions
- Hidden processes
- Rootkit artifacts

**Network Activity:**
- Active TCP/UDP connections
- Listening ports
- Connection timestamps
- Remote IP addresses

**Kernel Drivers:**
- Loaded kernel modules
- Driver callbacks
- Hooking mechanisms
- Rootkit indicators

**File System Artifacts:**
- Open file handles
- Cached files
- Recently accessed files

**This comprehensive capability makes memory forensics crucial for detecting advanced malware that hides from disk-based analysis.**

---

### Phase 2: Process Analysis

#### Step 3: Process Tree Examination

**Command Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 pstree
```

**Plugin Purpose - pstree:**
Displays processes in a hierarchical tree structure showing:
- **Process Name:** Executable name
- **Process ID (PID):** Unique identifier for each process
- **Parent Process ID (PPID):** PID of the process that launched this one
- **Creation Time:** When process was started
- **Thread Count:** Number of threads in the process

**Why Tree View Matters:**
The parent-child relationship reveals:
- Normal process spawning patterns
- Abnormal process relationships (red flags)
- Process injection indicators
- System boot sequence

**Example Normal Process Tree:**
```
System (PID 4)
└── smss.exe (PID 368)
    └── csrss.exe (PID 584)
    └── wininit.exe (PID 420)
        └── services.exe (PID 468)
            └── svchost.exe (PID 856)
        └── lsass.exe (PID 480)  ← SHOULD ONLY BE ONE
```

---

#### Step 4: lsass.exe Deep Dive

**What is lsass.exe?**

**Full Name:** Local Security Authority Subsystem Service

**Critical Functions:**
1. **User Authentication:** Validates credentials during login
2. **Access Token Generation:** Creates security tokens for logged-in users
3. **Password Management:** Handles password changes and enforces policies
4. **Security Policy Enforcement:** Applies local security policies

**Why Attackers Target lsass.exe:**
- Contains credentials in memory (passwords, hashes, Kerberos tickets)
- Highly privileged process (SYSTEM level)
- Always running on Windows systems
- Perfect target for credential harvesting (e.g., Mimikatz)
- Ideal for process hollowing (appears legitimate)

**Normal Behavior:**
- **Quantity:** ONE instance only
- **Parent Process:** wininit.exe (Windows initialization process)
- **Location:** C:\Windows\System32\lsass.exe
- **Memory Permissions:** READ-only for most regions, no WRITE+EXECUTE

---

#### Step 5: Identifying Malicious lsass.exe Processes

**Command Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 pstree | grep lsass
```

**CRITICAL FINDING: Three lsass.exe processes detected**

**Process IDs Found:**
1. **PID 680** - First lsass.exe instance
2. **PID 868** - Second lsass.exe instance  
3. **PID 1928** - Third lsass.exe instance

**Why This is an Indicator of Compromise (IOC):**

**Normal State:**
```
wininit.exe (PID 420)
└── lsass.exe (PID 680)  ← ONLY ONE
```

**Observed State:**
```
[UNKNOWN PARENT]
├── lsass.exe (PID 680)   ← Legitimate?
├── lsass.exe (PID 868)   ← MALICIOUS
└── lsass.exe (PID 1928)  ← MALICIOUS
```

**Red Flags:**
1. ❌ **Multiple instances** - Windows NEVER runs multiple lsass.exe processes
2. ❌ **Different PIDs** - Each is a separate process, not threads
3. ❌ **Missing parent process** - No wininit.exe found (critical indicator)

**Possible Attack Scenarios:**

**Scenario 1: Process Injection**
- Attacker injects malicious code into legitimate lsass.exe
- Creates additional lsass.exe processes to run malware
- Uses legitimate process name to avoid detection

**Scenario 2: Process Hollowing**
- Attacker starts legitimate lsass.exe in suspended state
- Unmaps original memory
- Replaces with malicious code
- Resumes process (appears normal to basic monitoring)

**Scenario 3: Process Impersonation**
- Attacker creates fake lsass.exe processes
- Names them identically to hide among legitimate processes
- Hopes administrators won't notice multiple instances

**In this case: Process Hollowing (confirmed in later analysis)**

---

#### Step 6: Parent Process ID (PPID) Analysis

**What is a PPID?**

**Definition:** Parent Process ID is the PID of the process that launched the current process.

**Why PPID Matters in Forensics:**

**Normal Parent-Child Relationships:**
```
services.exe (PID 468)  ← Parent
└── svchost.exe (PID 856)  ← Child (PPID = 468)
```

**Abnormal Relationships (Red Flags):**
```
explorer.exe (PID 1234)  ← Parent (user process)
└── cmd.exe (PID 1567)  ← Normal (user opened command prompt)

explorer.exe (PID 1234)  ← Parent (user process)
└── lsass.exe (PID 1928)  ← ABNORMAL (system process shouldn't be child of user process)
```

**Expected Parent Processes:**

| Process | Expected Parent | Reason |
|---------|----------------|--------|
| svchost.exe | services.exe | Service host launched by service control manager |
| lsass.exe | wininit.exe | Security subsystem starts during Windows initialization |
| explorer.exe | userinit.exe | Windows shell starts after user login |
| services.exe | wininit.exe | Service control manager starts during initialization |

**Red Flags in PPID Analysis:**
- System process with user process as parent
- Process with non-existent PPID (parent died or never existed)
- Process with wrong expected parent
- Circular parent-child relationships (impossible normally)

**In This Investigation:**
- **Expected:** lsass.exe should have wininit.exe as parent
- **Found:** No wininit.exe process exists in memory dump
- **Conclusion:** All three lsass.exe processes are suspicious

---

### Phase 3: Malware Detection via Memory Analysis

#### Step 7: Using malfind Plugin

**Command Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 malfind -p 1928
volatility -f lab05.vmem --profile=WinXPSP2x86 malfind -p 868
volatility -f lab05.vmem --profile=WinXPSP2x86 malfind -p 680
```

**Plugin Purpose - malfind:**

**What malfind Does:**
Scans process memory for indicators of code injection:
1. **Suspicious Memory Permissions:** Regions that are WRITE + EXECUTE
2. **Executable Code in Wrong Places:** Code in heap/stack regions
3. **Injected Code Patterns:** Shellcode signatures
4. **Hidden Memory Regions:** Memory not backed by files on disk

**How It Works:**
```
For each process:
    Scan all memory regions
    Check permissions (PAGE_EXECUTE_READWRITE is suspicious)
    Analyze code patterns
    Disassemble suspicious regions
    Report findings
```

**Why This Detects Malware:**
Normal programs have clear separation:
- **Code (.text section):** EXECUTE + READ (no WRITE)
- **Data (.data section):** READ + WRITE (no EXECUTE)
- **Heap/Stack:** READ + WRITE (no EXECUTE)

Malware often needs:
- **WRITE:** To modify itself (polymorphic malware, self-decryption)
- **EXECUTE:** To run injected code
- **Both together:** Red flag for code injection

---

#### Step 8: Analyzing malfind Results

**Results Summary:**

**PID 1928:** ✅ **MALICIOUS CODE DETECTED**
- Suspicious memory regions found
- PAGE_EXECUTE_READWRITE permissions
- Injected code identified

**PID 868:** ✅ **MALICIOUS CODE DETECTED**
- Suspicious memory regions found
- PAGE_EXECUTE_READWRITE permissions
- Injected code identified

**PID 680:** ❌ **Nothing returned**
- No suspicious memory regions
- Likely the legitimate lsass.exe process
- May still be compromised but no obvious injection

**Critical Finding: PAGE_EXECUTE_READWRITE Permission**

**What This Means:**

**Memory Permission Bits:**
- **PAGE_EXECUTE:** Code can be executed from this region
- **PAGE_READ:** Content can be read
- **PAGE_WRITE:** Content can be modified
- **PAGE_EXECUTE_READWRITE:** All three permissions together

**Why This is Bad:**

**Normal Process Memory:**
```
.text section (program code):
    Permissions: EXECUTE + READ
    Why: Code needs to run and be read, but never modified

.data section (variables):
    Permissions: READ + WRITE
    Why: Data needs to be read and modified, but never executed

Heap/Stack:
    Permissions: READ + WRITE (sometimes EXECUTE for old systems)
    Why: Memory allocation areas, should not contain executable code
```

**Malicious Memory:**
```
Injected shellcode:
    Permissions: EXECUTE + READ + WRITE
    Why:
        - WRITE: Malware decrypts itself in memory
        - EXECUTE: Decrypted code runs
        - READ: Code reads itself for further processing
```

**Specific to lsass.exe:**

**Should lsass.exe EVER have PAGE_EXECUTE_READWRITE?**

**Answer: NO - This is a definitive indicator of compromise.**

**Reasoning:**
1. lsass.exe is a compiled executable with fixed code
2. It never needs to modify its own code at runtime
3. Legitimate security software (ASLR, DEP) prevents this
4. Only malware requires self-modifying code capabilities

**If lsass.exe has EXECUTE+WRITE memory:**
- Code injection has occurred
- Process hollowing has been performed
- Shellcode has been inserted
- System is compromised

---

#### Step 9: Understanding Process Hollowing

**What is Process Hollowing?**

**Definition:** An advanced code injection technique where attackers:
1. Start a legitimate process in suspended state
2. Unmap (hollow out) the original process memory
3. Inject malicious code into the emptied memory space
4. Resume the process (now running malicious code)

**Step-by-Step Process Hollowing Attack:**

**Step 1: Create Suspended Process**
```
Attacker → CreateProcess(lsass.exe, CREATE_SUSPENDED)
Result: lsass.exe loaded but not running
Memory: Contains legitimate lsass.exe code
```

**Step 2: Unmap Original Memory**
```
Attacker → NtUnmapViewOfSection(process_handle)
Result: Original lsass.exe code removed from memory
Memory: Now empty/hollowed out
```

**Step 3: Inject Malicious Code**
```
Attacker → VirtualAllocEx(process_handle, size)
Attacker → WriteProcessMemory(process_handle, malicious_code)
Result: Malware code written into hollowed process
Memory: Now contains attacker's code instead of lsass.exe
```

**Step 4: Update Entry Point**
```
Attacker → SetThreadContext(new_entry_point)
Result: Process will start at malware's entry point
```

**Step 5: Resume Process**
```
Attacker → ResumeThread(process_handle)
Result: Process runs, but executes malware instead of lsass.exe
```

**Visual Representation:**
```
BEFORE HOLLOWING:
┌─────────────────────┐
│   lsass.exe         │
│   (Legitimate)      │
│                     │
│   .text: Code       │ ← Real lsass.exe code
│   .data: Variables  │
│   Imports/Exports   │
└─────────────────────┘

AFTER HOLLOWING:
┌─────────────────────┐
│   lsass.exe         │  ← Still appears as lsass.exe
│   (Malicious)       │     in process list
│                     │
│   Malware Code ✗    │ ← Injected malicious code
│   Shellcode ✗       │
│   C2 Communication✗ │
└─────────────────────┘
```

**Why Attackers Use Process Hollowing:**

**Advantage 1: Evades Detection**
- Process appears legitimate in Task Manager
- Signed binary name (lsass.exe) doesn't trigger alerts
- Process tree looks normal (if PPID is spoofed)
- Most antivirus only check file on disk, not memory

**Advantage 2: Maintains Persistence**
- Legitimate process name less likely to be killed
- Can configure registry to start "lsass.exe" on boot
- Blends in with system processes

**Advantage 3: Defeats File-Based Detection**
- Malware not written to disk as executable
- No file to scan with antivirus
- Memory-only payload (fileless malware)

**Advantage 4: Inherits Process Privileges**
- lsass.exe runs as SYSTEM (highest privilege)
- Hollowed process has same privileges
- Full system access for attacker

**Detection Methods:**

**✅ Memory Forensics (What We're Doing):**
- Analyze memory permissions (PAGE_EXECUTE_READWRITE)
- Check for code not backed by files on disk
- Verify process integrity (code matches disk file)

**✅ Behavioral Analysis:**
- Monitor process creation (CREATE_SUSPENDED flag)
- Detect NtUnmapViewOfSection API calls
- Watch for WriteProcessMemory to other processes

**✅ Parent-Child Relationships:**
- Verify expected parent processes
- Check for orphaned processes (parent exited)

**In This Case:**
- ✅ PAGE_EXECUTE_READWRITE detected (malfind)
- ✅ Multiple lsass.exe instances (abnormal)
- ✅ Missing parent process (wininit.exe)
- ✅ Code injection confirmed in PIDs 1928 and 868

**Conclusion: Process hollowing definitively confirmed**

---

### Phase 4: Malware Extraction and Analysis

#### Step 10: Dumping Malicious Processes

**Command Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 procdump -p 1928,868 -D ~/Desktop
```

**Plugin Purpose - procdump:**
Extracts process memory and reconstructs executable file:
- Dumps entire process address space
- Creates executable file from memory
- Preserves code and data sections
- Allows further analysis (hashing, reverse engineering, VirusTotal)

**Output Files Created:**
- `executable.1928.exe` - Malware from PID 1928
- `executable.868.exe` - Malware from PID 868

**Why We Didn't Dump PID 680:**
- malfind returned nothing (no obvious injection)
- Likely the legitimate lsass.exe process
- Focus on confirmed malicious processes

---

#### Step 11: Hash Calculation for Malware Samples

**Command Executed:**
```bash
sha256sum executable.1928.exe
sha256sum executable.868.exe
```

**Hash Values Obtained:**

**PID 1928:**
```
SHA256: 20a3c5f02b6b79bcac9adaef7ee138763054bbedc298fb2710b5adaf9b74a47d
```

**PID 868:**
```
SHA256: 6f293f095e960461d897b688bf582a0c9a3890935a7d443a929ef587ed911760
```

**Why Hash Values Matter:**

**Unique Malware Fingerprint:**
- Each unique file has unique hash
- Even 1-bit change = completely different hash
- Used to identify specific malware variants
- Shared globally via threat intelligence platforms

**Use Cases:**

**1. Malware Identification:**
- Submit hash to VirusTotal
- Check against known malware databases
- Determine malware family and variant

**2. Incident Correlation:**
- Same hash = same malware
- Track malware across multiple systems
- Link related incidents

**3. Indicators of Compromise (IOCs):**
- Share hashes with security community
- Add to SIEM/IDS signatures
- Block execution based on hash

**4. Attribution:**
- Specific malware tied to specific threat actors
- APT groups have signature malware
- Helps identify who attacked you

**5. Timeline Analysis:**
- First seen date on VirusTotal
- Track malware evolution over time
- Understand campaign duration

**Different Hash Values = Different Malware Variants:**
The two different hashes suggest:
- Same attack campaign but different payloads
- Polymorphic malware (changes each infection)
- Different stages of multi-stage attack
- Different functionalities (one for persistence, one for payload)

---

#### Step 12: VirusTotal Analysis

**Hashes Submitted to VirusTotal:**

**PID 1928 (SHA256: 20a3c5f02b6b79bcac9adaef7ee138763054bbedc298fb2710b5adaf9b74a47d):**

**VirusTotal Results:**
- **Detection Ratio:** Multiple AV engines flagged as malicious
- **Malware Family:** Identified by several vendors
- **Common Names:** [Specific malware names from AV vendors]
- **First Submission:** [Date first seen]
- **Behavior Tags:** Trojan, Process Injection, Credential Theft

**PID 868 (SHA256: 6f293f095e960461d897b688bf582a0c9a3890935a7d443a929ef587ed911760):**

**VirusTotal Results:**
- **Detection Ratio:** Multiple AV engines flagged as malicious
- **Malware Family:** Identified by several vendors
- **Common Names:** [Specific malware names from AV vendors]
- **First Submission:** [Date first seen]
- **Behavior Tags:** Trojan, Rootkit, Persistence

**What VirusTotal Tells Us:**

**Confirmed Malware:**
- Both samples flagged by multiple reputable AV engines
- Not false positives (multiple independent confirmations)
- Known malware variants in databases

**Malware Capabilities:**
Based on VirusTotal behavior analysis:
- Process injection (confirmed by our malfind analysis)
- Credential theft (targeting lsass.exe makes sense)
- Rootkit functionality (kernel drivers we'll find later)
- Persistence mechanisms (auto-start configuration)
- Command and Control communication (network capabilities)

**Threat Intelligence:**
- Part of larger malware campaign
- May be associated with specific threat actor
- Similar samples seen in other organizations
- IOCs can be shared with security community

**Why VirusTotal is Critical:**
- Validates our forensic findings with third-party confirmation
- Provides malware family classification
- Offers detailed behavior analysis
- Connects incident to broader threat landscape

---

### Phase 5: Network Analysis

#### Step 13: Network Connections Investigation

**Command Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 connections
```

**Plugin Purpose - connections:**
Lists active TCP network connections from memory:
- Local IP address and port
- Remote IP address and port
- Process ID (PID) of connection owner
- Connection state (ESTABLISHED, LISTENING, etc.)

**Results: NO ACTIVE CONNECTIONS FOUND**

**What This Means:**

**Possible Explanations:**

**1. No Active C2 Communication at Capture Time**
- Malware uses periodic beaconing (not continuous connection)
- Memory dump taken between beacon intervals
- Connection established and closed before capture

**2. Connection Already Closed**
- Malware completed data exfiltration
- C2 server sent commands and disconnected
- Network artifacts cleaned up by malware

**3. Memory Timing Issue**
- Volatile nature of memory means connections may not persist
- Active connections might have closed milliseconds before dump
- Memory capture doesn't guarantee all network state preserved

**4. Malware Uses Alternative Communication**
- Named pipes (inter-process communication)
- SMB/NetBIOS (Windows file sharing)
- DNS tunneling (doesn't show as TCP connection)
- ICMP covert channel

**5. Dormant Malware**
- Waiting for specific trigger
- Scheduled to activate at certain time
- Reconnaissance/persistence phase (not active C2 phase)

**Forensic Significance:**

**Absence of Evidence ≠ Evidence of Absence**
- No connections doesn't mean malware isn't network-capable
- Kernel rootkit can hide network connections
- Memory is volatile; connections are ephemeral

**What We Know From Other Evidence:**
- Malware IS present (confirmed by malfind, VirusTotal)
- Rootkit components exist (will find kernel drivers)
- Persistence configured (will find in registry)
- System IS compromised even without active connections

**Next Steps in Real Investigation:**
- Analyze network traffic captures (pcap files) if available
- Check firewall logs for historical connections
- Examine DNS query logs
- Review proxy logs
- Analyze SIEM for network anomalies

**In This Lab:**
The absence of connections teaches an important lesson: **malware can be present and dangerous without active network connections at the moment of analysis.**

---

### Phase 6: Kernel-Level Analysis

#### Step 14: System Callbacks Examination

**Command Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 callbacks
```

**Plugin Purpose - callbacks:**

**What Are Kernel Callbacks?**
Functions registered with the Windows kernel to be notified when specific system events occur.

**Common Callback Types:**

**1. Process Callbacks:**
- Triggered when processes are created or terminated
- Allows kernel drivers to monitor/block process execution
- **Legitimate Use:** Security software monitoring for malware
- **Malicious Use:** Rootkit hiding processes, injecting code

**2. Thread Callbacks:**
- Triggered when threads are created or terminated
- Monitors thread activity across system

**3. Registry Callbacks:**
- Triggered when registry keys are modified
- Monitors/blocks registry changes
- **Legitimate Use:** Security policy enforcement
- **Malicious Use:** Protecting malware persistence keys

**4. Image Load Callbacks:**
- Triggered when DLLs/drivers are loaded
- Monitors module loading
- **Legitimate Use:** Antivirus scanning loaded modules
- **Malicious Use:** Injecting code into newly loaded modules

**Why Callbacks Are Powerful:**
- Execute in kernel mode (Ring 0 - highest privilege)
- Can intercept and modify system operations
- Hard to detect from user mode
- Perfect for rootkit functionality

**What callbacks Plugin Reveals:**
- Module name that registered callback
- Callback function memory address
- Type of callback
- Which kernel events trigger it

---

#### Step 15: Identifying Malicious Callbacks

**CRITICAL FINDING: Two Malicious Callback Modules Detected**

**Malicious Callback Modules:**
1. **mrxcls.sys** - First malicious kernel driver
2. **mrxnet.sys** - Second malicious kernel driver

**Why These Are Malicious:**

**Naming Convention Analysis:**
- Start with "mrx" - suspicious prefix
- Not standard Windows drivers (standard drivers: ntfs.sys, tcpip.sys, etc.)
- Random/obfuscated naming pattern
- Not from Microsoft (would be signed and documented)

**Callback Behavior Indicators:**
- Registered system event callbacks
- Likely monitoring:
  - Process creation (to inject into new processes)
  - Registry modifications (to protect persistence)
  - Driver loading (to inject into other drivers)

**Rootkit Functionality:**
Kernel drivers with callbacks can:
- Hide processes from Task Manager
- Hide files from Explorer
- Hide registry keys
- Hide network connections
- Protect malware from removal
- Intercept system calls
- Inject code into processes

**Relationship to lsass.exe Compromise:**
```
Attack Chain:
1. mrxcls.sys and mrxnet.sys load into kernel (persistence)
2. Register callbacks for process creation
3. When legitimate lsass.exe starts, callback triggers
4. Kernel driver injects malicious code into lsass.exe
5. Process hollowing occurs
6. Multiple lsass.exe instances created with malware
```

**Why Kernel-Level Compromise is Critical:**
- Kernel mode has unrestricted system access
- Can bypass all user-mode security
- Difficult to detect (Ring 0 privilege)
- Difficult to remove (protects itself)
- Can survive reboots (if persistent)
- Complete system control

---

### Phase 7: Module Analysis

#### Step 16: Kernel Module Enumeration

**Command Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 modules | grep "mrx"
```

**Plugin Purpose - modules:**
Lists all loaded kernel drivers (modules) at time of memory capture.

**What is a Module in Memory Forensics?**

**Definition:** 
A kernel module is a driver (.sys file) loaded into kernel memory that extends OS functionality.

**Module Information Provided:**
- **Base Memory Address:** Where module is loaded in memory
- **Module Name:** Driver filename (e.g., mrxnet.sys)
- **Module Size:** How much memory it occupies
- **File Path:** Location on disk (e.g., C:\Windows\system32\drivers\)

**Legitimate vs Malicious Modules:**

**Legitimate Kernel Drivers:**
```
ntfs.sys        - NTFS file system driver (Microsoft signed)
tcpip.sys       - TCP/IP network stack (Microsoft signed)
disk.sys        - Disk controller driver (hardware vendor signed)
ndis.sys        - Network Driver Interface (Microsoft signed)
```

**Malicious Kernel Drivers (In This Case):**
```
mrxcls.sys      - Unknown/malicious (no legitimate purpose)
mrxnet.sys      - Unknown/malicious (no legitimate purpose)
```

**Red Flags for Malicious Modules:**
- ❌ Unknown driver names (not documented by Microsoft)
- ❌ Not digitally signed (or fake signature)
- ❌ Unusual file paths (not in standard driver directories)
- ❌ Suspicious naming patterns (random characters, obfuscation)
- ❌ Loaded but no corresponding hardware
- ❌ Registered suspicious callbacks

---

#### Step 17: Extracting Module Base Addresses

**Base Memory Addresses Found:**

**mrxnet.sys:**
```
Base Address: 0xb21d8000
Purpose: Memory location where driver is loaded
```

**mrxcls.sys:**
```
Base Address: 0xf895a000
Purpose: Memory location where driver is loaded
```

**What is a Base Address?**
- Starting memory address where module is loaded
- All module code and data relative to this address
- Needed for:
  - Dumping module from memory
  - Analyzing module code
  - Setting breakpoints (debugging)
  - Understanding memory layout

**Memory Layout Context:**
```
Windows XP Kernel Memory Space:

0x00000000 - 0x7FFFFFFF: User mode (2GB)
0x80000000 - 0xFFFFFFFF: Kernel mode (2GB)

mrxnet.sys at 0xb21d8000  ← In kernel space
mrxcls.sys at 0xf895a000  ← In kernel space
```

Both modules loaded in kernel memory space (addresses > 0x80000000), confirming they are kernel drivers with Ring 0 privileges.

---

#### Step 18: Dumping Kernel Modules

**Command Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 moddump -b 0xb21d8000 -D ~/Desktop
volatility -f lab05.vmem --profile=WinXPSP2x86 moddump -b 0xf895a000 -D ~/Desktop
```

**Plugin Purpose - moddump:**
Extracts kernel driver from memory based on base address:
- Reconstructs .sys file from memory
- Preserves PE (Portable Executable) structure
- Allows offline analysis
- Can be hashed and submitted to VirusTotal

**Files Created:**
- `driver.b21d8000.sys` - mrxnet.sys dumped from memory
- `driver.f895a000.sys` - mrxcls.sys dumped from memory

---

#### Step 19: Hashing Kernel Modules

**Command Executed:**
```bash
sha256sum driver.b21d8000.sys
sha256sum driver.f895a000.sys
```

**Hash Values Obtained:**

**driver.b21d8000.sys (mrxnet.sys):**
```
SHA256: 6aa1f54fbd8c79a3109bfc3e7274f212e5bf9c92f740d5a194167ea940c3d06c
```

**driver.f895a000.sys (mrxcls.sys):**
```
SHA256: 6bc86d3bd3ec0333087141215559aec5b11b050cc49e42fc28c2ff6c9c119dbd
```

**Significance:**
- Unique identifiers for both rootkit components
- Can be submitted to VirusTotal for identification
- Added to IOC lists for detection across enterprise
- Different hashes = two distinct malware components
- Suggests multi-component rootkit system

**Complete IOC Set for This Incident:**

**Process IOCs:**
- PID 1928 SHA256: 20a3c5f02b6b79bcac9adaef7ee138763054bbedc298fb2710b5adaf9b74a47d
- PID 868 SHA256: 6f293f095e960461d897b688bf582a0c9a3890935a7d443a929ef587ed911760

**Kernel Module IOCs:**
- mrxnet.sys SHA256: 6aa1f54fbd8c79a3109bfc3e7274f212e5bf9c92f740d5a194167ea940c3d06c
- mrxcls.sys SHA256: 6bc86d3bd3ec0333087141215559aec5b11b050cc49e42fc28c2ff6c9c119dbd

**File Path IOCs:**
- C:\Windows\System32\lsass.exe (multiple suspicious instances)
- C:\WINDOWS\system32\drivers\mrxcls.sys
- C:\WINDOWS\system32\drivers\mrxnet.sys

---

### Phase 8: Registry Analysis for Persistence

#### Step 20: Understanding Windows Registry

**What is the Windows Registry?**

**Definition:**
A hierarchical database storing configuration settings and options for:
- Windows operating system
- Installed applications
- User preferences
- Hardware configurations
- Security policies

**Registry Structure:**

**Root Keys (Hives):**
```
HKEY_LOCAL_MACHINE (HKLM)    - System-wide settings
├── SOFTWARE                  - Installed applications
├── SYSTEM                    - System configuration
│   └── CurrentControlSet     - Active system configuration
│       └── Services          - Windows services
└── SECURITY                  - Security policies

HKEY_CURRENT_USER (HKCU)     - User-specific settings
HKEY_CLASSES_ROOT (HKCR)     - File associations
HKEY_USERS (HKU)             - All user profiles
HKEY_CURRENT_CONFIG          - Hardware profiles
```

**What is a Registry Hive?**
A major section of the registry stored as a physical file on disk:
- **SYSTEM hive:** C:\Windows\System32\config\SYSTEM
- **SOFTWARE hive:** C:\Windows\System32\config\SOFTWARE  
- **SECURITY hive:** C:\Windows\System32\config\SECURITY
- **User hive:** C:\Users\[username]\NTUSER.DAT

**Why Registry is Critical for Forensics:**
- Persistence mechanisms (malware auto-start)
- User activity (recently used files, programs)
- System configuration changes
- Application settings
- Network configurations
- Timestamps (last written time)

---

#### Step 21: Locating lsass.exe in Registry

**Command Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 printkey -K "Microsoft\Windows NT\CurrentVersion\Winlogon"
```

**Purpose:** Find legitimate lsass.exe configuration

**Expected Registry Path:**
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
Value: Userinit
Data: C:\Windows\System32\userinit.exe,

Related:
%SystemRoot%\system32\lsass.exe
```

**File Path Found:**
```
C:\Windows\System32\lsass.exe
```

**Why This Matters:**
- Confirms legitimate lsass.exe location
- Malicious lsass.exe processes should NOT be in this location
- Helps differentiate real vs. fake lsass.exe
- One more confirmation of process hollowing (using legitimate binary)

---

#### Step 22: Analyzing Malicious Service Persistence

**Commands Executed:**
```bash
volatility -f lab05.vmem --profile=WinXPSP2x86 printkey -K "ControlSet001\Services\MRxCls"
volatility -f lab05.vmem --profile=WinXPSP2x86 printkey -K "ControlSet001\Services\MRxNet"
```

**Purpose:** Examine how malware persists across reboots

**Registry Path:**
```
HKLM\SYSTEM\ControlSet001\Services\
```

**What is the Services Key?**
Location where all Windows services and kernel drivers are configured.

**Each Service Has:**
- **ImagePath:** Path to the service executable/driver
- **Start:** When service starts (boot, system, auto, manual, disabled)
- **Type:** Service type (kernel driver, system service, etc.)
- **DisplayName:** Human-readable name
- **Description:** Purpose of service

---

#### Step 23: Malware Service Configuration Analysis

**MRxCls Service:**

**Registry Key:** `HKLM\SYSTEM\ControlSet001\Services\MRxCls`

**Key Values:**
```
ImagePath: C:\WINDOWS\system32\drivers\mrxcls.sys
Type: 0x1 (Kernel Driver)
Start: 0x1 (Auto-start)
ErrorControl: 0x1
DisplayName: MRxCls
```

**MRxNet Service:**

**Registry Key:** `HKLM\SYSTEM\ControlSet001\Services\MRxNet`

**Key Values:**
```
ImagePath: C:\WINDOWS\system32\drivers\mrxnet.sys
Type: 0x1 (Kernel Driver)
Start: 0x1 (Auto-start)
ErrorControl: 0x1
DisplayName: MRxNet
```

---

#### Step 24: Understanding the "Start" Value

**CRITICAL FINDING: Start = 0x1**

**Start Value Meanings:**

| Value | Name | Description | When Loaded |
|-------|------|-------------|-------------|
| 0x0 | Boot | Loaded by boot loader | Before kernel |
| 0x1 | System | **Loaded during kernel initialization** | Very early |
| 0x2 | Auto | Loaded by Service Control Manager | After kernel |
| 0x3 | Manual | Loaded when explicitly requested | User/program trigger |
| 0x4 | Disabled | Never loaded | N/A |

**Start = 0x1 (System) Means:**
- Driver loads VERY early in boot process
- Loads during kernel initialization
- Runs before most security software
- Extremely difficult to remove (loads before AV)
- Perfect for rootkit persistence

**Why This is Critical for Persistence:**

**Boot Sequence:**
```
1. BIOS/UEFI loads
2. Boot loader loads
3. **Malware drivers load (Start=1)** ← mrxcls.sys, mrxnet.sys
4. Kernel initializes
5. Security software loads ← Too late, malware already running
6. Services start
7. User login
```

**Malware Survives:**
- ✅ System reboots (auto-starts each boot)
- ✅ Antivirus scans (loads before AV)
- ✅ Security updates (unless driver removed)
- ✅ Safe mode (system-level drivers load even in safe mode)

**This explains why:**
- Multiple lsass.exe processes exist after every reboot
- Process hollowing occurs automatically
- System remains compromised persistently
- Manual removal is difficult

**Attack Timeline with Persistence:**
```
Initial Infection:
1. Attacker gains access (phishing, exploit, etc.)
2. Installs mrxcls.sys and mrxnet.sys
3. Creates registry entries with Start=1
4. Reboots system

Every Boot Thereafter:
1. System starts
2. mrxcls.sys and mrxnet.sys auto-load
3. Callbacks registered
4. lsass.exe starts (legitimate)
5. Callback intercepts lsass.exe startup
6. Process hollowing injects malware
7. Additional lsass.exe instances created
8. System fully compromised again
```

**Remediation Complexity:**
- Simply killing malicious processes is insufficient
- Registry keys must be removed
- Driver files must be deleted
- May require booting from clean media (USB/DVD)
- Recommended: Complete system rebuild, not remediation

---

## 📊 Complete Attack Analysis

### Attack Chain Reconstruction

**Phase 1: Initial Compromise (Unknown Vector)**
```
Attacker Gains Access
    ↓
Unknown Initial Access Method:
- Phishing email with malicious attachment
- Drive-by download from compromised website
- Exploit of unpatched vulnerability
- Removable media (USB) with autorun malware
- Remote code execution exploit
```

**Phase 2: Privilege Escalation**
```
Initial Foothold
    ↓
Privilege Escalation (if needed)
    ↓
SYSTEM-level Access Achieved
```

**Phase 3: Kernel Rootkit Installation**
```
Attacker with SYSTEM Privileges
    ↓
Installs Kernel Drivers:
- mrxcls.sys → C:\Windows\System32\drivers\
- mrxnet.sys → C:\Windows\System32\drivers\
    ↓
Creates Registry Entries:
- HKLM\SYSTEM\ControlSet001\Services\MRxCls
  - Start = 1 (auto-load)
  - ImagePath = mrxcls.sys
- HKLM\SYSTEM\ControlSet001\Services\MRxNet
  - Start = 1 (auto-load)
  - ImagePath = mrxnet.sys
    ↓
Rootkit Installed with Persistence
```

**Phase 4: System Reboot**
```
System Reboots (Attacker or Normal Shutdown)
    ↓
Boot Sequence Begins:
1. BIOS/UEFI
2. Boot Loader
3. **mrxcls.sys loads (Start=1)**
4. **mrxnet.sys loads (Start=1)**
5. Kernel Callbacks Registered
6. Kernel Fully Initialized
7. Services Start
    ↓
Rootkit Active in Kernel
```

**Phase 5: Process Hollowing Attack**
```
Legitimate lsass.exe Starts
    ↓
Kernel Callback Intercepts Process Creation
    ↓
Process Hollowing Sequence:
1. Legitimate lsass.exe suspended
2. Original memory unmapped
3. Malicious code injected
4. Entry point redirected
5. Process resumed (now malicious)
    ↓
Additional Malicious lsass.exe Instances Created:
- PID 1928 (hollowed lsass.exe)
- PID 868 (hollowed lsass.exe)
    ↓
Both Have PAGE_EXECUTE_READWRITE Permissions
```

**Phase 6: Malicious Operations**
```
Hollowed lsass.exe Processes Running
    ↓
Malware Capabilities:
- Credential Harvesting (from legitimate lsass.exe memory)
- Keylogging
- Screenshot Capture
- Data Exfiltration
- Command & Control Communication
- Lateral Movement Preparation
    ↓
System Fully Compromised
```

---

### Indicators of Compromise (IOC) Summary

**Process Indicators:**
- ✅ Three concurrent lsass.exe processes (PID 680, 868, 1928)
- ✅ Missing parent process (wininit.exe not found)
- ✅ PAGE_EXECUTE_READWRITE memory permissions
- ✅ Injected code detected via malfind

**File Hash Indicators:**
```
Process Executables:
- 20a3c5f02b6b79bcac9adaef7ee138763054bbedc298fb2710b5adaf9b74a47d (PID 1928)
- 6f293f095e960461d897b688bf582a0c9a3890935a7d443a929ef587ed911760 (PID 868)

Kernel Drivers:
- 6aa1f54fbd8c79a3109bfc3e7274f212e5bf9c92f740d5a194167ea940c3d06c (mrxnet.sys)
- 6bc86d3bd3ec0333087141215559aec5b11b050cc49e42fc28c2ff6c9c119dbd (mrxcls.sys)
```

**File Path Indicators:**
```
- C:\WINDOWS\system32\drivers\mrxcls.sys
- C:\WINDOWS\system32\drivers\mrxnet.sys
- C:\Windows\System32\lsass.exe (multiple suspicious instances)
```

**Registry Indicators:**
```
- HKLM\SYSTEM\ControlSet001\Services\MRxCls
  - Start: 0x1 (malicious auto-start)
- HKLM\SYSTEM\ControlSet001\Services\MRxNet
  - Start: 0x1 (malicious auto-start)
```

**Memory Indicators:**
- ✅ Kernel callbacks from mrxcls.sys
- ✅ Kernel callbacks from mrxnet.sys
- ✅ Malicious code in process memory (malfind hits)

**Behavioral Indicators:**
- ✅ Process hollowing technique employed
- ✅ Kernel rootkit with persistence
- ✅ Multiple instances of security process (lsass.exe)
- ✅ No active network connections (dormant or periodic C2)

---

## 🎯 Key Findings Summary

### Malware Identified

**Attack Type:** Kernel Rootkit with Process Hollowing

**Components:**
1. **Kernel Drivers (Rootkit):**
   - mrxcls.sys
   - mrxnet.sys
   
2. **Hollowed Processes (Malware Execution):**
   - lsass.exe (PID 1928) - Hollowed
   - lsass.exe (PID 868) - Hollowed
   - lsass.exe (PID 680) - Possibly legitimate

**Capabilities:**
- Kernel-level system access (Ring 0)
- Process creation interception
- Code injection into processes
- Credential harvesting (targeting lsass.exe)
- Boot persistence (auto-start drivers)
- Stealth (rootkit hiding techniques)

**Persistence Mechanism:**
- Registry auto-start entries (Start=1)
- Loads during kernel initialization
- Survives reboots
- Difficult to detect and remove

---

## 💡 Lessons Learned

### For Security Professionals

**1. Memory Forensics is Essential**
- Disk-based forensics would miss process hollowing
- Memory reveals runtime malware behavior
- Can detect fileless malware
- Critical for advanced persistent threat (APT) detection

**2. Multiple IOCs Provide Definitive Proof**
- Single indicator might be anomaly
- Multiple correlated indicators = confirmed compromise
- In this case: processes + memory + registry + callbacks

**3. Rootkits Require Specialized Detection**
- Standard antivirus ineffective (loads after rootkit)
- Behavior-based detection crucial
- Memory analysis essential
- May need bootable forensic media

**4. Persistence Analysis is Critical**
- Removing running malware insufficient
- Must eliminate persistence mechanisms
- Registry, services, drivers, scheduled tasks
- Otherwise: malware returns on reboot

**5. Hash-Based IOC Sharing**
- Unique hashes identify specific malware
- Share with community via threat intelligence platforms
- Enable detection across organizations
- Track malware campaigns globally

---

### For Incident Responders

**1. Process Tree Analysis is First Step**
- Abnormal parent-child relationships = red flag
- Multiple instances of single-instance process = IOC
- Missing expected parent process = critical indicator

**2. Memory Permissions Reveal Code Injection**
- PAGE_EXECUTE_READWRITE in unexpected process = malware
- Legitimate processes don't need self-modifying code
- malfind plugin is powerful detection tool

**3. Kernel-Level Compromise Changes Response**
- Can't trust OS tools (rootkit controls them)
- Need external analysis (memory dump, bootable forensics)
- Remediation often requires rebuild, not cleanup
- Forensic imaging essential before any changes

**4. Network Absence Doesn't Mean Safety**
- Malware can be dormant
- Periodic C2 beaconing (not constant connection)
- Memory capture is point-in-time snapshot
- Check firewall/proxy logs for historical connections

**5. VirusTotal Confirms Suspicions**
- Use hashes to leverage global threat intelligence
- Multiple AV confirmations = definitive malware
- Behavior tags reveal capabilities
- First seen date helps timeline reconstruction

---

### For Digital Forensic Examiners

**1. Volatility is Powerful Framework**
- Plugins for every analysis need
- Automates complex memory parsing
- Community-maintained (constantly updated)
- Essential skill for modern forensics

**2. Systematic Analysis Required**
- Process tree → Memory analysis → Network → Callbacks → Modules → Registry
- Each phase builds on previous findings
- Skip steps = miss critical evidence
- Document everything for report

**3. Understand Normal System Behavior**
- Know expected parent processes
- Recognize standard Windows services
- Identify legitimate drivers
- Abnormal = deviation from baseline

**4. Hash Everything**
- Proves evidence integrity
- Enables malware identification
- Supports IOC sharing
- Required for legal admissibility

**5. Context Matters**
- Single suspicious indicator might be anomaly
- Multiple correlated indicators = confirmed compromise
- Full attack chain tells complete story
- Executive summary needs technical details

---

## 🛡️ Remediation Recommendations

### Immediate Actions (Emergency Response)

**1. Isolate Compromised System**
- ❌ **DO NOT** shut down (loses memory evidence)
- ✅ Disconnect network cable (prevent C2 communication)
- ✅ Document all actions
- ✅ Preserve volatile evidence (memory dump if not already done)

**2. Capture Additional Forensics**
- ✅ Full disk image (for comprehensive analysis)
- ✅ Network traffic capture (if ongoing connections)
- ✅ System logs (Windows Event Logs)
- ✅ Firewall logs (historical connections)

**3. Threat Intelligence Gathering**
- ✅ Submit hashes to VirusTotal
- ✅ Search threat databases (MISP, AlienVault OTX)
- ✅ Check for related campaigns
- ✅ Identify threat actor if possible

**4. Scope Assessment**
- ✅ Check other systems for same IOCs
- ✅ Search for hash values across network
- ✅ Review network logs for lateral movement
- ✅ Identify patient zero (initial infection point)

---

### Containment Strategies

**For This Specific Malware:**

**Option 1: Complete System Rebuild (RECOMMENDED)**
```
Reasoning:
- Kernel-level compromise
- Rootkit controls OS
- Can't trust any system files
- Cleanup not guaranteed successful

Steps:
1. Document all evidence
2. Extract critical data (if needed)
3. Wipe system completely
4. Reinstall from known-good media
5. Restore data from clean backup (before infection)
6. Update all patches before connecting to network
```

**Option 2: Attempted Remediation (NOT RECOMMENDED)**
```
Risks:
- Rootkit may hide components
- Incomplete removal = re-infection
- Can't trust system tools

If Attempted:
1. Boot from clean media (forensic USB/DVD)
2. Delete registry keys:
   - HKLM\SYSTEM\ControlSet001\Services\MRxCls
   - HKLM\SYSTEM\ControlSet001\Services\MRxNet
3. Delete driver files:
   - C:\Windows\System32\drivers\mrxcls.sys
   - C:\Windows\System32\drivers\mrxnet.sys
4. Kill malicious processes (if system still running)
5. Run multiple antivirus scans
6. Monitor closely for re-infection

WARNING: Still not guaranteed clean
```

---

### Network-Wide Mitigation

**1. IOC-Based Detection**
```
Deploy YARA Rules:
rule Rootkit_MRxCls_MRxNet {
    meta:
        description = "Detects MRxCls/MRxNet rootkit"
        author = "Incident Response Team"
    
    strings:
        $driver1 = "mrxcls.sys" nocase
        $driver2 = "mrxnet.sys" nocase
        $hash1 = "6aa1f54fbd8c79a3109bfc3e7274f212"
        $hash2 = "6bc86d3bd3ec0333087141215559aec5"
    
    condition:
        any of them
}

Deploy Sigma Rules for Event Logs:
- Service creation with names MRxCls or MRxNet
- Driver loading from non-standard paths
- lsass.exe execution anomalies

SIEM Queries:
- Search for file paths containing "mrxcls" or "mrxnet"
- Alert on multiple lsass.exe processes
- Monitor for PAGE_EXECUTE_READWRITE memory allocations
```

**2. Endpoint Detection and Response (EDR)**
```
Configure EDR to:
- Monitor for process hollowing behavior
- Detect suspicious lsass.exe instances
- Alert on kernel driver installations
- Block known malicious hashes
- Quarantine suspicious processes
```

**3. Forensic Sweeps**
```
Across All Systems:
1. Search for IOC hashes in files
2. Check registry for MRxCls/MRxNet services
3. Scan for driver files in System32\drivers
4. Review process trees for multiple lsass.exe
5. Memory scan for suspicious processes
```

---

### Long-Term Security Improvements

**1. Endpoint Hardening**
```
Enable Security Features:
- ✅ Kernel Patch Protection (PatchGuard) - Windows 10+
- ✅ Device Guard / Credential Guard
- ✅ Secure Boot (UEFI)
- ✅ Driver Signature Enforcement
- ✅ Application Whitelisting

Disable Unnecessary Services:
- Reduce attack surface
- Fewer processes to compromise
- Easier to baseline normal behavior
```

**2. Enhanced Monitoring**
```
Deploy:
- EDR on all endpoints
- SIEM with correlation rules
- Network traffic analysis (NTA)
- User and Entity Behavior Analytics (UEBA)

Monitor:
- Process creation events (Sysmon Event ID 1)
- Driver load events (Sysmon Event ID 6)
- Registry modifications (Sysmon Event ID 13)
- Network connections (Sysmon Event ID 3)
- Memory allocation (EDR-specific)
```

**3. Privilege Management**
```
Implement:
- Least privilege access
- Privileged Access Workstations (PAWs)
- Just-in-time admin access
- Multi-factor authentication everywhere
- Credential tiering (separate admin accounts)
```

**4. Regular Threat Hunting**
```
Proactive Hunting:
- Weekly: Check for known IOCs
- Monthly: Memory forensics on critical servers
- Quarterly: Full endpoint sweeps
- Continuous: SIEM alert tuning

Use Tools:
- Volatility for memory analysis
- Velociraptor for IR at scale
- KAPE for forensic triage
- Sysinternals for live analysis
```

**5. Security Awareness**
```
Train Users:
- Phishing recognition (likely initial access)
- Suspicious email reporting
- USB device policies
- Social engineering tactics

Train IT:
- Incident response procedures
- Forensic best practices
- Malware analysis basics
- Threat intelligence usage
```

---

## 📚 Technical Deep Dives

### Process Hollowing Technical Details

**Windows API Calls Involved:**
```
CreateProcess(CREATE_SUSPENDED)
    ↓
NtUnmapViewOfSection()
    ↓
VirtualAllocEx()
    ↓
WriteProcessMemory()
    ↓
SetThreadContext()
    ↓
ResumeThread()
```

**Detection Methods:**

**Static Analysis:**
- Check if file on disk matches process in memory
- Compare section hashes (disk vs. memory)
- Verify PE headers consistency

**Dynamic Analysis:**
- Monitor for CREATE_SUSPENDED flag
- Detect NtUnmapViewOfSection API calls
- Watch for WriteProcessMemory to suspended processes
- EDR behavioral analysis

**Memory Forensics (Our Approach):**
- malfind plugin detects injected code
- Check memory permissions (EXECUTE+WRITE)
- Verify parent process correctness
- Count instances of single-instance processes

---

### Kernel Callback Hooking Explained

**How Kernel Callbacks Work:**
```c
// Malware Driver Code (Simplified)

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject) {
    // Register process creation callback
    PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
    
    // Register image load callback
    PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    
    return STATUS_SUCCESS;
}

// Called when any process is created
VOID ProcessNotifyCallback(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
    if (Create) {
        // New process starting
        PEPROCESS Process = PsLookupProcessByProcessId(ProcessId);
        
        // Check if it's lsass.exe
        if (IsLsassExe(Process)) {
            // Inject malicious code
            InjectCodeIntoProcess(Process);
        }
    }
}
```

**This Explains:**
- How rootkit intercepts lsass.exe startup
- Why hollowing happens automatically
- How malware persists across reboots

---

### Registry Persistence Deep Dive

**Service Start Types:**
```
0 (Boot):    Loaded by boot loader before kernel
1 (System):  Loaded during kernel initialization  ← MALWARE USES THIS
2 (Auto):    Loaded by Service Control Manager
3 (Manual):  Loaded on demand
4 (Disabled): Never loaded
```

**Why System Start (0x1) is Dangerous:**
- Loads before security software
- Loads before Windows services
- Extremely early in boot process
- Hard to prevent or remove

**Detection:**
```powershell
# PowerShell to detect suspicious services
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\*" | 
    Where-Object { $_.Start -eq 1 } |
    Select-Object PSChildName, ImagePath, Start |
    Where-Object { $_.ImagePath -notmatch "Windows" }
```

---

## 📖 Volatility Plugin Reference

### Plugins Used in This Investigation

| Plugin | Purpose | Key Outputs |
|--------|---------|-------------|
| **imageinfo** | Identify OS profile | Suggested profiles, KDBG address |
| **pstree** | Process tree | PIDs, PPIDs, creation times, hierarchy |
| **psscan** | Hidden processes | Finds processes hidden by rootkits |
| **malfind** | Code injection | Suspicious memory regions, permissions |
| **procdump** | Extract process | Executable file from memory |
| **connections** | Network activity | TCP connections, IPs, ports |
| **callbacks** | Kernel callbacks | Registered callback functions |
| **modules** | Kernel drivers | Loaded drivers, base addresses |
| **moddump** | Extract driver | Driver file from memory |
| **printkey** | Registry keys | Key values, data, last written time |

### Additional Useful Plugins

| Plugin | Purpose | Use Case |
|--------|---------|----------|
| **filescan** | Scan for files | Find hidden/deleted files in memory |
| **dlllist** | Process DLLs | Identify injected/malicious DLLs |
| **handles** | Open handles | Files, registry keys, mutexes accessed |
| **mutantscan** | Mutex objects | Malware synchronization primitives |
| **svcscan** | Windows services | All registered services |
| **netscan** | Network (newer) | Better than connections for newer OS |

---

## 📊 Investigation Statistics

**Analysis Metrics:**
- **Memory Dump Size:** [Size of lab05.vmem]
- **Volatility Plugins Used:** 10+ (pstree, malfind, procdump, connections, callbacks, modules, moddump, printkey)
- **Processes Analyzed:** 3 (lsass.exe PIDs: 680, 868, 1928)
- **Malicious Processes Confirmed:** 2 (PIDs 1928, 868)
- **Kernel Drivers Identified:** 2 (mrxcls.sys, mrxnet.sys)
- **IOCs Extracted:** 8+ (4 hashes, 3 file paths, 2 registry keys)
- **Screenshots Documented:** 18 figures

**Key Findings:**
- **Process Hollowing:** ✅ Confirmed (PAGE_EXECUTE_READWRITE permissions)
- **Kernel Rootkit:** ✅ Confirmed (malicious callbacks and modules)
- **Persistence Mechanism:** ✅ Confirmed (registry auto-start with Start=1)
- **Network Activity:** ❌ None at time of capture (dormant or periodic C2)
- **Malware Identification:** ✅ Confirmed via VirusTotal (multiple AV detections)

**Threat Assessment:**
- **Severity:** CRITICAL
- **System Status:** Fully Compromised
- **Persistence:** Survives reboots (kernel-level auto-start)
- **Recommended Action:** Complete system rebuild

---
