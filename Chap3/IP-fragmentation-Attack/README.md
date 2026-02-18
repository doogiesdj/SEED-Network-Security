# Chapter 3 – IP Fragmentation Based Attack

## 📌 Overview

This lab explores how IP fragmentation works and how attackers can manipulate fragmented packets to bypass detection systems.

Students will:

- Observe automatic IP fragmentation
- Construct manual IP fragments
- Perform overlapping fragment attacks
- Analyze IP reassembly behavior
- Investigate operating system reassembly policies

---

## 🎯 Learning Objectives

By the end of this lab, students will be able to:

- Explain how IP fragmentation works
- Interpret Fragment Offset and MF flag
- Understand how reassembly is performed
- Identify security risks related to overlapping fragments
- Analyze kernel reassembly statistics

---

## 🧪 Lab Components

### Documentation
- [Full Lab Guide](IP-fragmentation-Attack-lab.md)

### Python Scripts
Located in `lab-materials/`

- `manual_frag.py`
- `overlap_frag.py`

---

## 🛡 Security Insight

Overlapping fragment attacks historically allowed IDS evasion due to inconsistent reassembly policies between security devices and end hosts.

Modern Linux kernels detect overlaps and may drop such packets to prevent exploitation.

---

## 📂 Network Environment

| Role | IP |
|------|----|
| Attacker | 10.9.0.105 |
| Victim | 10.9.0.5 |
| Router | 10.9.0.11 |

Network: `10.9.0.0/24`

---

## 🔎 How to Check Reassembly Behavior

```bash
netstat -s | egrep -i 'frag|reasm|overlap'


