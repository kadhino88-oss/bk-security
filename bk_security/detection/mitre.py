from __future__ import annotations

MITRE_MAP = {
    "powershell.exe": ["T1059.001"], "cmd.exe": ["T1059.003"], "wscript.exe": ["T1059.005"],
    "cscript.exe": ["T1059.005"], "mshta.exe": ["T1218.005"], "regsvr32.exe": ["T1218.010"],
    "rundll32.exe": ["T1218.011"], "certutil.exe": ["T1140"], "bitsadmin.exe": ["T1197"],
    "schtasks.exe": ["T1053.005"], "at.exe": ["T1053.002"],
}

def techniques_for_event(event) -> list[str]:
    process = str(event.data.get("process_name") or event.data.get("name") or event.process.get("name") or "").lower()
    result = list(MITRE_MAP.get(process, []))
    if event.data.get("beaconing"): result.append("T1071")
    if event.data.get("exfiltration"): result.append("T1041")
    if event.data.get("credential_access"): result.append("T1003")
    return sorted(set(result))
