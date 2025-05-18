# Lab 01: Disk Imaging and Hash Verification

## 📋 Lab Overview

This lab demonstrates fundamental digital forensics skills in creating forensically sound disk images and verifying their integrity using cryptographic hash functions. The exercises cover both GUI-based and command-line imaging tools, comparing different acquisition methods and file formats used in professional forensic investigations.

**Lab Focus:** Evidence Acquisition, Data Integrity, Chain of Custody

---

## 🎯 Objectives

By completing this lab, I demonstrated proficiency in:

- Creating forensic disk images using multiple tools (Guymager and dc3dd)
- Understanding and comparing disk image formats (dd/raw vs Expert Witness Format)
- Implementing hash verification techniques to ensure evidence integrity
- Distinguishing between logical and physical acquisition methods
- Understanding the importance of write blockers in forensic investigations
- Utilizing both GUI and CLI tools for forensic imaging
- Maintaining proper chain of custody through documentation and hashing

---

## 🛠️ Tools & Environment

### Tools Used
- **Guymager** - GUI-based forensic imaging tool
- **dc3dd** - Enhanced forensic version of the dd command
- **md5sum** - Hash calculation and verification utility
- **Linux CLI** - Command-line operations and file management

### Operating System
- Linux (Ubuntu-based forensic distribution)

### File Formats Analyzed
- **Raw/dd format** (.dd) - Uncompressed bit-for-bit copies
- **Expert Witness Format** (.E01) - Compressed format with metadata

---

## 📊 Lab Exercises Summary

### Exercise 1: Using Guymager to Import and Verify Existing Disk Image

**Objective:** Learn to create forensic images using Guymager and verify integrity through hash values.

**Key Concepts Covered:**
- Difference between dd (raw) and Expert Witness Format (E01)
- Importance of hash verification in forensic investigations
- File size comparison between different formats

**Files Created:**
- `lab2image1.E01` - 3.7 kB (3,672 bytes)
- `lab2image1.info` - 6.0 kB (5,973 bytes)

**Hash Verification:**
- MD5 Hash: `e134ced312b3511d88943d57ccd70c83`
- MD5 Hash Verified Source: `e134ced312b3511d88943d57ccd70c83`
- **Result:** ✅ Hashes match - Data integrity confirmed

**Significance:** Matching hash values prove that the forensic image is an exact copy of the original evidence, with no data loss or modification during the imaging process.

---

### Exercise 2: Experimenting with Hashing

**Objective:** Understand how hash values respond to file modifications and the principles of cryptographic hashing.

#### Test 1: Renaming a File
**Action:** Renamed `helloworld.txt` to `goodbyeworld.txt` using `mv` command

**Result:** Hash value remained unchanged

**Analysis:** MD5 hash values are calculated based solely on file contents, not filenames or metadata. This demonstrates that:
- Hash functions are content-dependent
- Renaming files does not affect data integrity verification
- Forensic investigators must hash file contents, not rely on filenames

#### Test 2: Modifying File Contents
**Action:** Added "Goodbye!" to the file content

**Result:** Hash value changed completely

**Analysis:** Any modification to file contents, no matter how small, results in a completely different hash value. This demonstrates:
- The sensitivity of cryptographic hash functions
- How hash values detect tampering or alterations
- The importance of creating hashes before and after acquisition

**Key Takeaway:** Hash functions provide a reliable method to detect any changes to digital evidence, making them essential for maintaining chain of custody.

---

### Exercise 3: Creating a New Image with Guymager

**Objective:** Perform logical acquisition of specific files and understand its limitations.

**Acquisition Type:** Logical Acquisition (File-based)

**Method:** Used Guymager to image a specific file (`data.csv`) rather than the entire physical drive.

**Hash Values:**
- MD5 Hash: `1568c646682c442ac7df369a1512fc72`
- MD5 Hash Verified Source: `1568c646682c442ac7df369a1512fc72`
- MD5 Hash Verified Image: `1568c646682c442ac7df369a1512fc72`
- **Result:** ✅ All three hashes match - Complete integrity verification

**Logical Acquisition Analysis:**

*Advantages:*
- Faster than physical acquisition
- Smaller file sizes
- Targeted collection of specific files
- Useful for live systems or quick analysis

*Limitations:*
- Does not capture deleted files
- Misses unallocated space and slack space
- Cannot recover files in hidden or system areas
- Metadata modifications may go undetected
- Lost opportunity to analyze file system artifacts

**Critical Finding:** If a suspect modified file metadata or timestamps, logical acquisition might miss crucial evidence that could be recovered through physical acquisition methods.

---

### Exercise 4: Creating Image Using Command Line Interface (dc3dd)

**Objective:** Perform forensic imaging using CLI tools and understand why drives should not be mounted during acquisition.

#### Why Not Mount the Drive?

Mounting a drive during forensic acquisition is dangerous because:
- The operating system may write to the drive (timestamps, access logs)
- Metadata can be altered automatically
- Evidence integrity is compromised
- Chain of custody is broken
- Investigation becomes legally questionable

**Solution:** Use write blockers or work with unmounted drives to maintain forensic soundness.

#### dc3dd Command Analysis

**Command Executed:**
```bash
sudo dc3dd if=/dev/sdb of=/forensics/lab2image3.dd hash=md5 log=/forensics/lab2image3.txt
```

**Command Breakdown:**
- `sudo` - Execute with root privileges
- `dc3dd` - Forensic-enhanced version of dd with built-in hashing
- `if=/dev/sdb` - Input file (source device)
- `of=/forensics/lab2image3.dd` - Output file (destination image)
- `hash=md5` - Calculate MD5 hash during imaging
- `log=/forensics/lab2image3.txt` - Create log file with imaging details

**Why dc3dd Over Standard dd?**
- Built-in hash calculation (no separate step needed)
- Progress indicators during imaging
- Automatic logging of forensic details
- Better error handling
- Designed specifically for forensic investigations

**Files Created:**
- `lab2image3.dd` - Raw forensic image
- `lab2image3.txt` - Log file containing hash and imaging metadata

**MD5 Hash:** `6f42fa509942d28d08112c0e8d318785`

#### Hash Verification Methods

Two methods were used to verify the forensic image:

**Method 1: Using md5sum**
```bash
md5sum /forensics/lab2image3.dd
```
Compare output with hash in `lab2image3.txt`

**Method 2: Using dc3dd**
```bash
sudo dc3dd if=/forensics/lab2image3.dd hash=md5
```
Recalculate hash and verify against original

**Best Practice:** Always use multiple verification methods to ensure data integrity throughout the forensic process.

---

## 🔍 Advanced Concepts Explored

### Alternative Hashing Algorithms

While MD5 was used in this lab, modern forensic investigations often employ more secure algorithms:

**SHA-256:**
- 256-bit hash output
- Superior collision resistance compared to MD5
- Widely accepted in legal proceedings
- Recommended by NIST for federal agencies

**SHA-512:**
- 512-bit hash output
- Even stronger security than SHA-256
- Ideal for high-stakes investigations
- Better future-proofing against cryptographic advances

### Multi-Algorithm Verification Strategy

**Why use multiple hashing algorithms?**

1. **Reliability:** If one algorithm produces an error, others provide backup verification
2. **Cross-Validation:** Multiple matching hashes provide stronger evidence of integrity
3. **Legal Robustness:** Courts may require specific algorithms; having multiple satisfies various requirements
4. **Defense Against Vulnerabilities:** If one algorithm is compromised, others maintain evidence validity

**Recommended Practice:**
```bash
md5sum evidence.dd > evidence.md5
sha256sum evidence.dd > evidence.sha256
sha512sum evidence.dd > evidence.sha512
```

---

### Alternative Forensic Imaging Tools

**FTK Imager:**
- Industry-standard forensic imaging tool
- User-friendly GUI interface
- Creates multiple image formats (E01, dd, AFF)
- Built-in hash verification (MD5, SHA-1, SHA-256)
- Can mount images for preview
- Free for law enforcement and general use
- Excellent for creating court-admissible evidence

**Ddrescue:**
- Specialized in recovering data from damaged media
- Minimizes further data loss during acquisition
- Handles bad sectors intelligently
- Creates log files for tracking recovery progress
- Useful for physically damaged drives
- Open-source and command-line based

---

### Write Blockers in Digital Forensics

**Definition:** Hardware or software devices that prevent any write operations to storage media during forensic examination.

**Types:**

*Hardware Write Blockers:*
- Physical devices connected between evidence and forensic workstation
- Block all write commands at hardware level
- Faster and more reliable
- Court-preferred for high-profile cases

*Software Write Blockers:*
- Operating system-level write protection
- More affordable than hardware solutions
- Requires proper configuration
- May have edge cases where writes slip through

**Significance to Digital Forensics:**

1. **Preserves Data Integrity**
   - Prevents accidental modifications
   - Stops automatic OS operations (indexing, caching)
   - Maintains original timestamps and metadata

2. **Legal Admissibility**
   - Demonstrates proper forensic methodology
   - Satisfies chain of custody requirements
   - Shows evidence was not tampered with

3. **Professional Standards**
   - Required by many forensic certification bodies
   - Industry best practice
   - Protects investigator from allegations of evidence tampering

**Common Write Blocker Brands:**
- Tableau (hardware)
- WiebeTech (hardware)
- Microsoft Windows software write blockers
- Linux mount options (`-o ro,noload`)

---

## 📈 Key Findings & Analysis

### Disk Image Format Comparison

| Feature | dd (Raw) Format | Expert Witness Format (E01) |
|---------|----------------|----------------------------|
| Compression | None | Yes |
| Metadata Support | No | Yes (case info, examiner notes) |
| File Size | Larger | Smaller (compressed) |
| Tool Support | Universal | Wide (EnCase, FTK, Autopsy) |
| Hash Storage | Separate file | Embedded in format |
| Segmentation | Manual | Automatic (split large images) |
| Error Handling | Basic | Advanced with CRC checks |
| Legal Acceptance | High | Very High |

**Recommendation:** Use E01 format for professional investigations requiring documentation and compression; use raw dd format for maximum compatibility and simplicity.

---

### Hash Value Integrity Throughout Lab

All hash verifications in this lab successfully matched, demonstrating:
- Proper forensic imaging techniques
- No data corruption during acquisition
- Maintained chain of custody
- Forensically sound methodology

**Example Hash Verification Chain:**
```
Source → Hash A
Image → Hash B
Verification → Hash C

If A = B = C, integrity is confirmed
```

---

## 💡 Challenges & Solutions

### Challenge 1: Understanding Logical vs Physical Acquisition
**Issue:** Initial confusion about when to use each acquisition type

**Solution:** 
- Logical acquisition: Quick analysis, specific files, live systems
- Physical acquisition: Complete forensic investigation, deleted file recovery, maximum evidence collection

### Challenge 2: Why Mounting Drives is Problematic
**Issue:** Not immediately clear why mounting changes evidence

**Solution:** Learned that mounting triggers OS operations that write metadata, update access times, and potentially alter evidence

### Challenge 3: Command-Line Tool Complexity
**Issue:** Understanding dc3dd syntax and parameters

**Solution:** Broke down each parameter to understand its forensic purpose, realized CLI tools offer more control and automation capabilities

---

## 🎓 Key Takeaways & Lessons Learned

1. **Hash Verification is Non-Negotiable:** Every forensic image must be hashed before and after acquisition to prove integrity in court.

2. **Multiple Tools Provide Redundancy:** Using both GUI (Guymager) and CLI (dc3dd) tools ensures flexibility in different investigation scenarios.

3. **File Format Selection Matters:** Choose between dd and E01 based on case requirements, storage constraints, and legal expectations.

4. **Logical Acquisition Has Limits:** While faster, logical acquisition misses critical evidence like deleted files and unallocated space.

5. **Prevention is Key:** Write blockers and proper mounting procedures prevent accidental evidence contamination.

6. **Documentation is Evidence:** Log files, hash values, and metadata are as important as the disk image itself.

7. **Command-Line Proficiency is Essential:** Many forensic operations require CLI tools for automation and scripting.

8. **Chain of Custody Starts at Acquisition:** Proper imaging techniques are the foundation of legally admissible digital evidence.

---

## 🔐 Forensic Best Practices Demonstrated

✅ Used write-protected or unmounted drives during acquisition  
✅ Generated cryptographic hashes (MD5) for all images  
✅ Verified hash values match source and destination  
✅ Created detailed logs of all forensic operations  
✅ Compared multiple imaging tools and formats  
✅ Documented acquisition methods and limitations  
✅ Understood legal implications of forensic procedures  
✅ Maintained proper file handling and storage  

---

## 📚 Skills Demonstrated

**Technical Skills:**
- Disk imaging with Guymager and dc3dd
- Hash calculation and verification (MD5, SHA-256, SHA-512)
- Linux command-line operations
- File system navigation and management
- Understanding of forensic file formats

**Forensic Skills:**
- Chain of custody maintenance
- Evidence integrity verification
- Logical vs physical acquisition analysis
- Write blocker concepts and importance
- Forensic documentation and logging

**Analytical Skills:**
- Comparing imaging methodologies
- Evaluating acquisition method limitations
- Understanding hash function properties
- Problem-solving in evidence acquisition scenarios

---

## 🔗 References & Further Reading

- **NIST Guidelines:** Computer Forensics Tool Testing (CFTT) Program
- **File Format Specifications:** Expert Witness Format (EWF) documentation
- **Hashing Standards:** NIST FIPS 180-4 (SHA family)
- **Forensic Tools:** 
  - Guymager: https://guymager.sourceforge.io/
  - dc3dd: https://sourceforge.net/projects/dc3dd/
  - FTK Imager: AccessData Forensic Toolkit documentation

---