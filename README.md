# SIEM Lab: Ransomware Behavior & Mass File Modification Detection (Splunk)

An operational endpoint security monitoring architecture implemented within **Splunk Cloud (Dashboard Studio)**. This project creates detection rules to identify automated mass file modifications, rapid renaming, and potential ransomware execution patterns across corporate file systems.

---

## 🔍 Threat Vector & Detection Engineering

This deployment processes operating system and file server audit logs to isolate malicious encryption patterns and trigger immediate host isolation alerts:

1. **Process Monitoring**: Tracks host process executions and changes occurring inside critical directory file pathways.
2. **Volumetric Event Windowing**: Correlates file deletion and renaming rates executed by singular processes within tight temporal constraints.
3. **Anomaly Flagging**: Establishes an alert gate that flags an incident as highly suspicious if a non-system process alters multiple file extensions simultaneously.

---

## 💻 Core SPL Ransomware Detection Framework

```splunk
| makeresults count=120
| streamstats count as row
| eval time_offset = row * 2
| eval _time = _time - time_offset
| eval host = "finance-srv-01"
| eval process = case(row <= 100, "svchost.exe", 1=1, "unknown_script.exe")
| eval file_action = case(process=="unknown_script.exe", "rename", 1=1, "read")
| eval target_directory = "C:\Users\Finance\Documents"
| stats count(eval(file_action="rename")) as total_renames, count(eval(file_action="read")) as total_reads by host, process, target_directory
| where total_renames >= 15
| eval threat_indicator = "SUSPICIOUS MASS RENAMING ACTIVITY (POTENTIAL RANSOMWARE)"
| rename host as "Compromised Host", process as "Suspect Process", target_directory as "Target Directory", total_renames as "Mass Renamed Files", threat_indicator as "Incident Classification"
```

---

## 📊 Dashboard Engineering Details

- **Visual Dashboard Mode**: Dashboard Studio (Grid Layout Structure)
- **Primary Interface Theme**: SOC Dark Operational Standard
- **Core Visual Element**: Endpoint Threat Response Operational Grid Table
- **Monitored Indicators (IoCs)**: Endpoint Host Identity, Active Cryptographic Process Name, Target Corporate Directory, Modification Threshold Delta.
