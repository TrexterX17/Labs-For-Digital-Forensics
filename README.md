# Digital Forensics Portfolio

> A comprehensive collection of hands-on digital forensics investigations demonstrating expertise in evidence acquisition, malware analysis, incident response, and memory forensics.

**Author:** Faraz Ahmed  
**Focus:** Digital Forensics | Incident Response | Malware Analysis  
**Tools:** Autopsy, Volatility, Guymager, dc3dd, VirusTotal

---

## 📋 Portfolio Overview

This repository contains detailed documentation of **four advanced digital forensics labs** that demonstrate a complete investigative skillset from evidence acquisition through malware analysis. Each lab represents real-world scenarios encountered in professional forensic investigations, incident response, and security operations.

**Portfolio Highlights:**
- ✅ **100% success rate** across all investigations
- ✅ **25+ forensic tools** mastered and applied
- ✅ **Multiple evidence types** analyzed (disk images, memory dumps, emails, registry)
- ✅ **4 complete case studies** with professional documentation
- ✅ **Advanced techniques** including file carving, process hollowing detection, and kernel rootkit analysis

---

## 🎯 Core Competencies Demonstrated

### Technical Skills
- **Forensic Imaging:** Creating forensically sound evidence copies with hash verification
- **File System Analysis:** Deep examination of NTFS, HFS+, and APFS file systems
- **Memory Forensics:** Advanced memory dump analysis using Volatility Framework
- **Malware Analysis:** Detection and analysis of rootkits, process injection, and persistence mechanisms
- **Data Recovery:** File carving techniques to recover deleted evidence
- **Timeline Reconstruction:** Correlating evidence across multiple sources to build attack narratives

### Investigative Capabilities
- **Evidence Acquisition & Preservation:** Chain of custody, hash verification, forensic imaging
- **Incident Response:** Phishing investigation, data breach analysis, compromise assessment
- **Behavioral Analysis:** User activity profiling through digital artifacts
- **Attack Chain Reconstruction:** Understanding attacker methodology and techniques
- **IOC Extraction:** Identifying and documenting indicators of compromise

### Professional Skills
- **Executive Reporting:** Translating technical findings for non-technical stakeholders
- **Documentation:** Comprehensive case documentation with reproducible methodology
- **Tool Proficiency:** Autopsy, Volatility, Guymager, dc3dd, VirusTotal, Linux CLI
- **Regulatory Awareness:** Understanding of data breach notification and compliance requirements

---

## 📂 Lab Investigations

### Lab 01: Disk Imaging and Hash Verification
**Focus:** Evidence Acquisition & Chain of Custody  
**Tools:** Guymager, dc3dd, md5sum  
**Platform:** Linux

<details>
<summary><b>Investigation Summary</b></summary>

**Objective:** Master forensic imaging techniques and evidence integrity verification through hash values.

**Key Activities:**
- Created forensic disk images using both GUI (Guymager) and CLI (dc3dd) tools
- Compared dd (raw) format vs. Expert Witness Format (E01)
- Conducted hash verification experiments to understand file integrity
- Analyzed logical vs. physical acquisition methods
- Demonstrated proper chain of custody procedures

**Technical Achievements:**
- ✅ Generated MD5 hashes for all evidence (e134ced312b3511d88943d57ccd70c83)
- ✅ Verified image integrity through multiple hash calculations
- ✅ Created images in multiple formats (raw .dd and compressed .E01)
- ✅ Documented limitations of logical acquisition (misses deleted files, unallocated space)
- ✅ Demonstrated why mounting drives during investigation compromises evidence

**Key Learning:**
- Hash values prove evidence hasn't been modified (critical for court admissibility)
- Renaming files doesn't change hash, but modifying content does
- Forensic imaging preserves original evidence while allowing analysis on copies
- Command-line tools offer more control and automation capabilities

**Skills Demonstrated:**
- Forensic disk imaging (Guymager, dc3dd)
- Hash calculation and verification (MD5, SHA-256, SHA-512)
- File format analysis (dd vs E01)
- Evidence integrity documentation
- Understanding of write blockers and their importance

[📖 View Detailed Lab Report →](https://github.com/TrexterX17/Labs-For-Digital-Forensics/blob/master/Lab-01/HW%201-%20Lab%201.pdf)
</details>

**Impact:** Foundational skills for all digital forensics work—proper evidence acquisition is critical for legal admissibility and investigation integrity.

---

### Lab 02: Forensic Analysis and File Recovery with Autopsy
**Focus:** File System Analysis & Deleted File Recovery  
**Tools:** Autopsy, Guymager, File Carving  
**Platform:** Linux, MacOS (HFS+/APFS)

<details>
<summary><b>Investigation Summary</b></summary>

**Case Scenario:** Company president (Bob) requires recovery of accidentally deleted flower photos from MacOS drive while also identifying all bearcat images on primary system.

**Objective:** Conduct comprehensive forensic analysis, recover deleted files, and extract hidden evidence.

**Investigation Results:**
- **Bearcat Images Found:** 11 total
  - 9 active files (various formats and locations)
  - 2 deleted files (recovered via file carving)
- **Deleted Flower Photos Recovered:** 5 total
  - All from MacOS drive unallocated space
  - Formats: JPG, BMP, GIF, PNG, PCX

**Technical Achievements:**
- ✅ Multi-source investigation (primary Linux drive + secondary MacOS drive)
- ✅ File carving from unallocated space ($CarvedFiles directory)
- ✅ Located hidden files in various formats:
  - Compressed archives (tar.xz)
  - Email attachments (.eml)
  - Embedded in PDFs and presentations
  - Video frame extraction (MP4)
  - Hidden file attributes (leading dot)
- ✅ Hash verification to prove file uniqueness despite visual similarity
- ✅ 100% success rate—all requested evidence recovered

**Advanced Techniques:**
- File signature analysis (identifying files by content, not extension)
- Recursive extraction from nested containers
- Modified timestamp = 0 analysis (proving deletion)
- Multi-volume file system examination (vol0-vol11)
- Cross-platform forensics (Linux + MacOS)

**Key Findings:**
- Deleted files persist in unallocated space until overwritten
- Files can be hidden via compression, embedding, or file system attributes
- Extension mismatches reveal deliberate file concealment
- Hash values mathematically prove file uniqueness

**Skills Demonstrated:**
- Autopsy platform proficiency with ingest modules
- PhotoRec file carving for deleted file recovery
- Multi-format file extraction (archives, documents, email, video)
- File system artifact analysis
- Hash-based file differentiation

[📖 View Detailed Lab Report →](https://github.com/TrexterX17/Labs-For-Digital-Forensics/blob/master/Lab-02/HW%202-%20Lab%202.pdf)
</details>

**Impact:** Demonstrates ability to recover critical business data and conduct comprehensive system examinations—essential for corporate investigations and data recovery operations.

---

### Lab 03: Phishing Investigation and Incident Response
**Focus:** Incident Investigation & Behavioral Analysis  
**Tools:** Autopsy, Email Forensics, Browser History Analysis  
**Platform:** Windows XP

<details>
<summary><b>Investigation Summary</b></summary>

**Case Scenario:** Angela Carver's Housing suffered a data breach—employee PII posted on malicious website. Primary suspect: Josh Mosko (recently hired employee).

**Objective:** Determine if Josh was a malicious insider or phishing victim, reconstruct attack timeline, and provide recommendations.

**Investigation Timeline:**
- **March 20, 2025 23:51:41** - Phishing email received from acarver@gmail.com
- **March 20, 2025 22:35:48** - Josh searches "what is the price of a social security number"
- **March 20, 2025 22:36:16** - Josh searches "how much does an email sell for"
- **March 20, 2025 22:40:04** - Josh searches "can companies track things send from personal email"
- **March 20, 2025 22:42:44** - Josh searches "how to identify a phishing email" (AWARENESS CONFIRMED)
- **March 20, 2025 19:59:32** - Microsoft account locked (credentials changed by attacker)
- **March 21, 2025 00:31:11** - Josh replies confirming data upload (EXFILTRATION CONFIRMED)

**Final Determination:**
**Josh Mosko = VICTIM of sophisticated phishing attack, NOT malicious insider**

**Evidence Supporting Victim Classification:**
- ✅ Google search sequence shows genuine panic and self-education
- ✅ No evidence of premeditation or criminal planning
- ✅ Behavioral pattern consistent with social engineering victim
- ✅ No dark web access, encrypted communications, or counter-surveillance
- ✅ All evidence preserved on hard drive (no cover-up attempt)

**Accountability Distribution:**
- **80% Attacker** - Sophisticated phishing campaign
- **15% Josh** - Failed to verify request, failed to report incident
- **5% Organization** - No security awareness training, no email authentication controls

**Technical Achievements:**
- ✅ Complete email artifact analysis (headers, attachments, routing)
- ✅ Browser history behavioral profiling (psychological state tracking)
- ✅ Timeline reconstruction from multiple evidence sources
- ✅ Account compromise investigation (credential theft)
- ✅ Hash verification for all evidence (chain of custody)

**Comprehensive Recommendations Provided:**
- Immediate: Email filtering (SPF/DKIM/DMARC), MFA on all accounts, breach notification
- Short-term: Security awareness training, incident reporting procedures, DLP controls
- Long-term: Security culture development, phishing simulations, least privilege access

**Key Findings:**
- Browser searches revealed Josh's mental state progression (suspicion → awareness → panic)
- Reply email sent AFTER phishing awareness (poor judgment under stress)
- No IT reporting despite realization (critical procedural failure)
- Phishing email used authority impersonation and urgency tactics

**Skills Demonstrated:**
- Email forensics and header analysis
- Behavioral analysis from digital artifacts
- Timeline reconstruction across multiple sources
- Distinguishing victim from perpetrator
- Executive-level reporting and recommendations
- Incident response methodology

[📖 View Detailed Lab Report →](https://github.com/TrexterX17/Labs-For-Digital-Forensics/blob/master/Lab-03/HW%203-%20Lab%203.pdf)
</details>

**Impact:** Demonstrates incident response capabilities and ability to conduct investigations that inform both technical remediation and organizational policy—critical for IR teams and SOC analysts.

---

### Lab 04: Memory Forensics and Malware Analysis
**Focus:** Memory Analysis & Advanced Malware Detection  
**Tools:** Volatility Framework, VirusTotal, SHA256sum  
**Platform:** Windows XP SP2 x86

<details>
<summary><b>Investigation Summary</b></summary>

**Case Scenario:** Analysis of memory dump from compromised Windows XP system showing signs of malicious activity.

**Objective:** Identify malware, understand attack techniques, extract IOCs, and recommend remediation.

**Critical Findings:**

**1. Process Hollowing Attack Detected**
- **Indicator:** Three concurrent lsass.exe processes (normal: only 1 should exist)
- **PIDs:** 680, 868, 1928
- **Technique:** Legitimate process started in suspended state, memory hollowed out, malicious code injected
- **Evidence:** PAGE_EXECUTE_READWRITE memory permissions (definitive indicator)
- **Confirmed Malicious:** PIDs 1928 and 868

**2. Kernel Rootkit Components Identified**
- **Drivers:** mrxcls.sys, mrxnet.sys
- **Location:** C:\Windows\System32\drivers\
- **Capabilities:** System callbacks, process creation interception, code injection
- **Base Addresses:**
  - mrxnet.sys: 0xb21d8000
  - mrxcls.sys: 0xf895a000

**3. Persistence Mechanisms Confirmed**
- **Method:** Registry auto-start configuration
- **Keys:** HKLM\SYSTEM\ControlSet001\Services\MRxCls and MRxNet
- **Start Value:** 0x1 (system-level auto-start during kernel initialization)
- **Impact:** Malware loads BEFORE security software, survives reboots

**Attack Chain Reconstruction:**
```
Initial Compromise (Unknown Vector)
    ↓
Kernel Rootkit Installation (mrxcls.sys, mrxnet.sys)
    ↓
Registry Persistence Configuration (Start=1)
    ↓
System Reboot
    ↓
Rootkit Auto-Loads During Boot
    ↓
Kernel Callbacks Registered
    ↓
Legitimate lsass.exe Starts
    ↓
Callback Intercepts → Process Hollowing
    ↓
Multiple Malicious lsass.exe Instances Created
    ↓
System Fully Compromised
```

**IOCs Extracted:**

**Process Hashes (SHA256):**
- PID 1928: `20a3c5f02b6b79bcac9adaef7ee138763054bbedc298fb2710b5adaf9b74a47d`
- PID 868: `6f293f095e960461d897b688bf582a0c9a3890935a7d443a929ef587ed911760`

**Kernel Driver Hashes (SHA256):**
- mrxnet.sys: `6aa1f54fbd8c79a3109bfc3e7274f212e5bf9c92f740d5a194167ea940c3d06c`
- mrxcls.sys: `6bc86d3bd3ec0333087141215559aec5b11b050cc49e42fc28c2ff6c9c119dbd`

**File Paths:**
- C:\WINDOWS\system32\drivers\mrxcls.sys
- C:\WINDOWS\system32\drivers\mrxnet.sys

**Registry Keys:**
- HKLM\SYSTEM\ControlSet001\Services\MRxCls (Start=1)
- HKLM\SYSTEM\ControlSet001\Services\MRxNet (Start=1)

**Technical Achievements:**
- ✅ Memory forensics using Volatility Framework (10+ plugins)
- ✅ Process hollowing detection via memory permission analysis
- ✅ Kernel rootkit identification through callbacks and modules
- ✅ Malware extraction from memory (procdump, moddump)
- ✅ VirusTotal confirmation (multiple AV engine detections)
- ✅ Complete IOC documentation for enterprise deployment
- ✅ Persistence mechanism analysis (registry)

**Advanced Techniques:**
- Process tree analysis (PID/PPID relationships)
- Memory permission analysis (PAGE_EXECUTE_READWRITE as IOC)
- Kernel callback enumeration
- Driver extraction and hashing
- Registry forensics for persistence

**Why This Attack is Sophisticated:**
- Kernel-level compromise (Ring 0 privilege)
- Process hollowing evades basic detection
- Rootkit hides malicious activity
- Persistence survives security software installation
- Loads before antivirus during boot

**Remediation Recommendation:**
**COMPLETE SYSTEM REBUILD** (not remediation)
- Kernel-level compromise means OS cannot be trusted
- Rootkit controls system at deepest level
- Cleanup attempts may fail due to rootkit protection
- Only guaranteed solution: wipe and reinstall from known-good media

**Skills Demonstrated:**
- Volatility Framework proficiency
- Process hollowing detection
- Kernel rootkit analysis
- Memory permission analysis
- IOC extraction and documentation
- Persistence mechanism investigation
- Threat intelligence integration (VirusTotal)

[📖 View Detailed Lab Report →](https://github.com/TrexterX17/Labs-For-Digital-Forensics/blob/master/Lab-04/HW%204-%20Lab%204.pdf)
</details>

**Impact:** Demonstrates advanced malware analysis capabilities essential for threat hunting, malware analysis teams, and sophisticated incident response—this is expert-level forensics.

---

## 📊 Skills Matrix

### Tools & Technologies

| Category | Tools Mastered | Proficiency Level |
|----------|----------------|-------------------|
| **Forensic Imaging** | Guymager, dc3dd, FTK Imager (knowledge) | ⭐⭐⭐⭐⭐ |
| **Disk Forensics** | Autopsy, PhotoRec, File Carving | ⭐⭐⭐⭐⭐ |
| **Memory Forensics** | Volatility Framework 2.x | ⭐⭐⭐⭐⭐ |
| **Hash Verification** | md5sum, sha256sum, sha512sum | ⭐⭐⭐⭐⭐ |
| **Email Forensics** | Email header analysis, Thunderbird | ⭐⭐⭐⭐ |
| **Malware Analysis** | Static analysis, VirusTotal, IOC extraction | ⭐⭐⭐⭐⭐ |
| **Operating Systems** | Linux (Ubuntu), Windows XP/7/10 | ⭐⭐⭐⭐ |
| **File Systems** | NTFS, HFS+, APFS, FAT32 | ⭐⭐⭐⭐ |
| **Command Line** | Bash, Linux utilities, Windows CLI | ⭐⭐⭐⭐⭐ |

### Investigation Techniques

| Technique | Labs Applied | Expertise |
|-----------|--------------|-----------|
| **Evidence Acquisition** | Lab 01, 02 | Expert |
| **Hash Verification** | Lab 01, 02, 03, 04 | Expert |
| **File Carving** | Lab 02 | Advanced |
| **Timeline Reconstruction** | Lab 03, 04 | Expert |
| **Process Analysis** | Lab 04 | Advanced |
| **Memory Forensics** | Lab 04 | Expert |
| **Malware Detection** | Lab 04 | Advanced |
| **Registry Analysis** | Lab 03, 04 | Advanced |
| **Behavioral Analysis** | Lab 03 | Advanced |
| **IOC Extraction** | Lab 04 | Expert |

### Evidence Types Analyzed

- ✅ **Disk Images:** Raw (.dd), Expert Witness Format (.E01)
- ✅ **Memory Dumps:** Windows XP memory (.vmem)
- ✅ **Email Artifacts:** .eml files, headers, attachments
- ✅ **File Systems:** NTFS, HFS+, APFS
- ✅ **Registry Hives:** SYSTEM, SOFTWARE, SECURITY
- ✅ **Browser History:** Google Chrome, Internet Explorer
- ✅ **Deleted Files:** Unallocated space, $CarvedFiles
- ✅ **Process Memory:** Active processes, injected code
- ✅ **Kernel Drivers:** .sys files, rootkit components
- ✅ **Network Artifacts:** TCP connections, account access logs

---

## 🎯 Investigation Methodology

### Standard Operating Procedure Applied Across All Labs

**1. Evidence Acquisition & Preservation**
- Create forensic images (never work on original evidence)
- Calculate hash values for integrity verification
- Document chain of custody
- Preserve volatile data (memory) before non-volatile (disk)

**2. Initial Assessment**
- Identify operating system and file systems
- Configure appropriate forensic tools
- Plan investigation scope and objectives
- Establish timeline boundaries

**3. Comprehensive Analysis**
- Systematic examination of all evidence sources
- Multiple tool verification (don't rely on single tool)
- Document all findings with screenshots
- Extract and preserve critical artifacts

**4. Correlation & Timeline Reconstruction**
- Synchronize timestamps across evidence sources
- Build chronological narrative of events
- Identify relationships between artifacts
- Distinguish causation from correlation

**5. IOC Extraction & Documentation**
- Hash all malicious files
- Document file paths and registry keys
- Create detection signatures (YARA rules)
- Enable enterprise-wide threat hunting

**6. Reporting & Recommendations**
- Executive summary for stakeholders
- Technical details for peer review
- Actionable remediation steps
- Lessons learned and improvements

---

## 📈 Portfolio Metrics

### Investigation Statistics

**Total Labs Completed:** 4  
**Success Rate:** 100% (all objectives met)  
**Evidence Items Analyzed:** 40+  
**Screenshots Documented:** 50+  
**Hash Values Generated:** 15+  
**IOCs Extracted:** 10+  

### Complexity Progression

```
Lab 01 (Foundational)     ████░░░░░░  40% complexity
    ↓
Lab 02 (Intermediate)     ██████░░░░  60% complexity
    ↓
Lab 03 (Advanced)         ████████░░  80% complexity
    ↓
Lab 04 (Expert)           ██████████ 100% complexity
```

### Evidence Diversity

**File Formats Analyzed:**
- Image Files: PNG, JPEG, GIF, BMP, SVG, PCX
- Documents: PDF, DOCX, ODT, ODP
- Archives: TAR, XZ, ZIP
- Email: EML, MSG
- Video: MP4
- Executables: EXE, SYS, DLL
- Disk Images: DD, E01, VMEM

**Platforms Investigated:**
- Linux (Ubuntu-based forensic distributions)
- Windows XP SP2
- MacOS (HFS+/APFS file systems)

---

## 🏆 Key Achievements

### Technical Milestones

✅ **Zero False Positives** - All malware detections confirmed via multiple methods  
✅ **100% Data Recovery** - All requested deleted files successfully recovered  
✅ **Complete Attack Reconstruction** - Full attack chain documented from entry to persistence  
✅ **Multi-Platform Expertise** - Demonstrated across Linux, Windows, and MacOS  
✅ **Advanced Technique Mastery** - Process hollowing detection, kernel rootkit analysis  
✅ **Professional Documentation** - Executive-level reports suitable for stakeholders  

### Real-World Applications

**Corporate Investigations:**
- Data breach response (Lab 03)
- Insider threat vs. compromised user determination (Lab 03)
- Critical data recovery for executives (Lab 02)

**Malware Analysis:**
- Rootkit detection and analysis (Lab 04)
- Process injection identification (Lab 04)
- IOC extraction for threat hunting (Lab 04)

**Incident Response:**
- Timeline reconstruction (Lab 03, 04)
- Evidence preservation (Lab 01)
- Remediation recommendations (Lab 03, 04)

---

## 💼 Career Relevance

### Positions This Portfolio Qualifies For

**Digital Forensics Analyst**
- Evidence acquisition and analysis ✅
- Multiple tool proficiency ✅
- Professional reporting ✅
- Chain of custody understanding ✅

**Incident Response Specialist**
- Breach investigation ✅
- Timeline reconstruction ✅
- Remediation recommendations ✅
- Stakeholder communication ✅

**Malware Analyst**
- Memory forensics ✅
- Malware detection and analysis ✅
- IOC extraction ✅
- Threat intelligence integration ✅

**Security Operations Center (SOC) Analyst**
- Alert investigation ✅
- Evidence correlation ✅
- Threat hunting ✅
- Tool proficiency ✅

**Threat Hunter**
- Advanced malware detection ✅
- Behavioral analysis ✅
- IOC development ✅
- Proactive investigation ✅

---

## 🔍 Detailed Lab Documentation

Each lab includes comprehensive documentation with:

- **Executive Summary** - High-level overview for stakeholders
- **Detailed Methodology** - Step-by-step investigative process
- **Technical Analysis** - In-depth examination of findings
- **Screenshots & Evidence** - Visual documentation of all discoveries
- **Timeline Reconstruction** - Chronological event correlation
- **IOC Documentation** - Indicators of compromise for detection
- **Recommendations** - Actionable remediation and improvements
- **Lessons Learned** - Key takeaways and best practices

### Lab Structure

```
Lab-XX-Name/
├── README.md (comprehensive documentation)
├── lab.pdf (Detailed and practical report with evidence)
```

---

## 📚 Knowledge Areas

### Digital Forensics Fundamentals
- **Chain of Custody:** Documented evidence handling procedures
- **Evidence Integrity:** Hash verification and write-blocking
- **Legal Admissibility:** Court-ready documentation standards
- **Anti-Forensics Detection:** Identifying evidence tampering attempts

### Windows Internals
- **Process Management:** PIDs, PPIDs, parent-child relationships
- **Memory Architecture:** Kernel vs. user mode, memory permissions
- **Registry Structure:** Hives, keys, values, persistence mechanisms
- **Security Subsystems:** lsass.exe, authentication, access tokens

### Attack Techniques
- **Phishing:** Social engineering, email spoofing, urgency tactics
- **Process Hollowing:** Code injection, memory manipulation
- **Rootkits:** Kernel-level persistence, callback hooking
- **Credential Theft:** lsass.exe targeting, account takeover

### Incident Response
- **NIST Framework:** Preparation, Detection, Analysis, Containment, Eradication, Recovery
- **Timeline Analysis:** Event correlation and causation
- **Triage:** Rapid assessment and prioritization
- **Reporting:** Technical and executive communication

---

## 🛠️ Forensic Toolkit

### Essential Tools Demonstrated

**Acquisition & Imaging:**
- Guymager (GUI-based disk imaging)
- dc3dd (forensic dd with built-in hashing)
- Write blockers (hardware/software)

**Disk Forensics:**
- Autopsy (comprehensive forensic platform)
- PhotoRec (file carving)
- Sleuth Kit (file system analysis)

**Memory Forensics:**
- Volatility Framework (memory dump analysis)
- Process analysis plugins
- Registry extraction

**Hash & Verification:**
- md5sum, sha256sum, sha512sum
- File integrity verification
- Evidence chain of custody

**Malware Analysis:**
- VirusTotal (threat intelligence)
- Static analysis tools
- IOC extraction utilities

**Supporting Tools:**
- Linux CLI (bash, grep, find)
- Email clients (Thunderbird)
- Archive extractors (tar, 7zip)
- Document viewers (PDF, Office)

---

## 📖 Best Practices Applied

### Evidence Handling
✅ Always create forensic images before analysis  
✅ Calculate and verify hash values at every step  
✅ Never modify original evidence  
✅ Document all actions in investigation log  
✅ Maintain proper chain of custody  

### Analysis Methodology
✅ Use multiple tools to verify findings  
✅ Systematic examination (don't skip steps)  
✅ Correlate evidence across multiple sources  
✅ Document both positive and negative findings  
✅ Distinguish between correlation and causation  

### Professional Standards
✅ Reproducible methodology (others can verify)  
✅ Clear documentation (technical and non-technical)  
✅ Objective analysis (fact-based conclusions)  
✅ Comprehensive reporting (executive summaries + details)  
✅ Ethical considerations (privacy, legal requirements)  

---

## 🎓 Continuous Learning

### Areas of Ongoing Development

**Advanced Topics Explored:**
- File system forensics (NTFS, HFS+, APFS, ext4)
- Memory forensics (Windows, Linux, macOS)
- Malware reverse engineering
- Network forensics and packet analysis
- Cloud forensics (AWS, Azure, GCP)
- Mobile forensics (iOS, Android)

**Industry Certifications Preparation:**
- GCFA (GIAC Certified Forensic Analyst)
- GCFE (GIAC Certified Forensic Examiner)
- EnCE (EnCase Certified Examiner)
- CHFI (Computer Hacking Forensic Investigator)

**Emerging Technologies:**
- AI/ML for malware detection
- Container forensics (Docker, Kubernetes)
- Blockchain forensics
- IoT device forensics

---

## 📫 Contact & Portfolio

**GitHub:** [https://github.com/TrexterX17]  
**LinkedIn:** [https://www.linkedin.com/in/faraz-ahmed-5670931a7/]  
**Email:** [farazx789@gmail.com]  

---

## 🙏 Acknowledgments

This portfolio was developed through rigorous hands-on lab work in digital forensics education. Each investigation follows industry best practices and demonstrates real-world applicability of forensic techniques.

**Tools & Resources:**
- Autopsy Project (Sleuth Kit)
- Volatility Foundation
- SANS Digital Forensics & Incident Response
- NIST Computer Forensics Tool Testing Project

---

## 📜 License & Usage

This portfolio is intended for:
- Educational purposes
- Professional showcase
- Job application demonstrations
- Skill verification

All investigations were conducted in controlled lab environments with proper authorization. Techniques demonstrated should only be used for legitimate forensic investigations with appropriate legal authority.

---

## 🚀 Quick Navigation (Documents)

| Lab | Focus Area | Complexity | View Full Lab |
|-----|------------|------------|-------------|
| **Lab 01** | Disk Imaging & Hash Verification | ⭐⭐⭐ | [View →](https://github.com/TrexterX17/Labs-For-Digital-Forensics/tree/master/Lab-01) |
| **Lab 02** | File Recovery & Analysis | ⭐⭐⭐⭐ | [View →](https://github.com/TrexterX17/Labs-For-Digital-Forensics/tree/master/Lab-02) |
| **Lab 03** | Phishing Investigation | ⭐⭐⭐⭐ | [View →](https://github.com/TrexterX17/Labs-For-Digital-Forensics/tree/master/Lab-03) |
| **Lab 04** | Memory & Malware Analysis | ⭐⭐⭐⭐⭐ | [View →](https://github.com/TrexterX17/Labs-For-Digital-Forensics/tree/master/Lab-04) |

---

<div align="center">

**Digital Forensics Portfolio** | **Faraz Ahmed** | **2025**

*Demonstrating comprehensive expertise in digital forensics, incident response, and malware analysis through hands-on investigations*

</div>
