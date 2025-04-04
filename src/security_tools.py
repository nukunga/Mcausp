import subprocess
import platform
import json
import re
import datetime
import psutil

try:
    import winreg  # Windows-specific module
except ImportError:
    winreg = None

try:
    import wmi  # Windows Management Instrumentation
except ImportError:
    wmi = None

from mcp.server.fastmcp import FastMCP

###############################################################################
# Tool: Windows Group Policy Scanner (scan_policies)
###############################################################################
def scan_policies() -> str:
    """
    Scans Windows Group Policies in read-only mode.
    Executes gpresult /z command and returns the policy results as text.
    """
    try:
        # Execute gpresult /z command (with shell=True, text mode)
        result = subprocess.run(
            ["gpresult", "/z"],
            capture_output=True,
            text=True,
            shell=True,
            timeout=30  # Setting timeout (if needed)
        )
        if result.returncode != 0:
            return f"Error occurred: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred while executing gpresult: {e}"

###############################################################################
# Tool: Registry and Firewall Check (check_registry_and_firewall)
###############################################################################
def check_registry_and_firewall() -> str:
    """
    Reads firewall and UAC settings from the registry and creates a report with OS information.
    - Firewall: SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy (e.g., EnableFirewall)
    - UAC: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System (EnableLUA)
    
    All operations are read-only.
    """
    os_info = platform.platform()
    report = {"os_info": os_info, "firewall": "N/A", "uac": "N/A"}
    
    if winreg is None:
        return "winreg module is not available in this environment."
    
    # Check if firewall is enabled
    try:
        fw_key_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, fw_key_path) as key:
            # Assuming 'EnableFirewall' value exists (key and value names may vary depending on environment)
            value, reg_type = winreg.QueryValueEx(key, "EnableFirewall")
            report["firewall"] = f"{value} (Expected: 1)"
    except Exception as e:
        report["firewall"] = f"Read failed: {e}"
    
    # Check UAC settings (EnableLUA)
    try:
        uac_key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uac_key_path) as key:
            value, reg_type = winreg.QueryValueEx(key, "EnableLUA")
            report["uac"] = f"{value} (Expected: 1)"
    except Exception as e:
        report["uac"] = f"Read failed: {e}"
    
    return json.dumps(report, indent=2)

###############################################################################
# Tool: Process Anomaly Detection (analyze_processes)
###############################################################################
def analyze_processes() -> str:
    """
    Collection: Gathers information about all currently running processes.
    
    Collected information:
    - Process name
    - PID
    - Parent process ID and name
    - CPU usage
    - Memory usage
    - Execution path
    - Creation time
    - Status
    
    Returns all process information to allow LLM to determine anomalies.
    Previous anomaly detection criteria are included for reference:
    - Process name not ending with ".exe" or containing special characters
    - Parent process is 'explorer.exe' but child is not a common application
    - CPU usage over 50% or memory usage over 80%
    
    Returns a JSON-formatted report of all processes.
    """
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'ppid', 'create_time', 'status']):
        try:
            info = proc.info
            pid = info.get("pid", -1)
            name = info.get("name", "").lower()
            cpu = info.get("cpu_percent", 0)
            mem = info.get("memory_percent", 0)
            ppid = info.get("ppid", -1)
            create_time = info.get("create_time", 0)
            status = info.get("status", "")
            
            # 추가 정보 수집
            process_info = {
                "pid": pid,
                "name": name,
                "cpu_percent": cpu,
                "memory_percent": mem,
                "parent_pid": ppid,
                "parent_name": "unknown",
                "exe_path": "unknown",
                "create_time": create_time,
                "status": status
            }
            
            # 부모 프로세스 이름 획득 시도
            try:
                parent = psutil.Process(ppid)
                process_info["parent_name"] = parent.name().lower()
            except Exception:
                pass
                
            # 실행 경로 획득 시도
            try:
                process_info["exe_path"] = proc.exe()
            except Exception:
                pass
                
            # 이상 징후 표시 (참고용)
            if not name.endswith(".exe") or re.search(r"[^a-z0-9_\-\. ]", name):
                process_info["possible_anomaly"] = "Process name anomaly (missing extension or contains special characters)"
            elif process_info["parent_name"] == "explorer.exe" and name not in {"notepad.exe", "cmd.exe", "explorer.exe"}:
                process_info["possible_anomaly"] = "Parent-child relationship anomaly (abnormal process under explorer.exe)"
            elif cpu > 50 or mem > 80:
                process_info["possible_anomaly"] = "Excessive resource usage"
            
            processes.append(process_info)
        except Exception as e:
            continue

    return json.dumps(processes, indent=2)

###############################################################################
# Tool: Security Event Log Analysis (check_security_events)
###############################################################################
def check_security_events() -> str:
    """
    Analyzes security event logs (Security) for the last 24 hours using wmi.
    
    Returns EventCode and message (up to 100 characters) for each event.
    All operations are read-only.
    """
    if wmi is None:
        return "wmi module is not available in this environment."
    
    # Calculate current time and 24 hours ago (WMI uses YYYYMMDDHHMMSS format)
    now = datetime.datetime.now()
    past = now - datetime.timedelta(days=1)
    past_str = past.strftime("%Y%m%d%H%M%S.000000+000")
    
    try:
        c = wmi.WMI()
        # Filter recent events from Security log using WMI query (TimeGenerated >= past_str)
        # Time comparison in WMI can be tricky, so get all Security events and filter in Python
        events = c.Win32_NTLogEvent(Logfile="Security")
        recent_events = []
        for event in events:
            try:
                # TimeGenerated is in string format: "YYYYMMDDHHMMSS.ffffff+ZZZ"
                event_time_str = event.TimeGenerated.split('.')[0]
                event_time = datetime.datetime.strptime(event_time_str, "%Y%m%d%H%M%S")
                if event_time >= past:
                    message = getattr(event, "Message", "") or ""
                    recent_events.append({
                        "EventCode": getattr(event, "EventCode", ""),
                        "TimeGenerated": event.TimeGenerated,
                        "Message": message[:100]  # Up to 100 characters
                    })
            except Exception:
                continue
        return json.dumps(recent_events, indent=2)
    except Exception as e:
        return f"Error occurred during security event log analysis: {e}"

###############################################################################
# Comprehensive Security Scan Tool (All Items Integrated)
###############################################################################
def scan_security() -> dict:
    """
    Comprehensive security scan tool that combines Windows policy scan,
    registry and firewall check, process anomaly detection, and security event log analysis.
    """
    return {
        "policies": scan_policies(),
        "registry_and_firewall": check_registry_and_firewall(),
        "process_anomalies": analyze_processes(),
        "security_events": check_security_events()
    }

###############################################################################
# Additional Tool: Security Vulnerability Severity Assessment
###############################################################################
def evaluate_vulnerabilities(scan_results: dict) -> dict:
    """
    Analyzes security scan results to evaluate vulnerability severity and recommended actions.
    
    Args:
        scan_results: Output from the scan_security tool
        
    Returns:
        Dictionary containing vulnerability assessment and recommended actions
    """
    vulnerabilities = []
    
    # Firewall analysis
    try:
        fw_data = json.loads(scan_results.get("registry_and_firewall", "{}"))
        if "firewall" in fw_data:
            firewall_status = fw_data["firewall"]
            if "0" in firewall_status or "Read failed" in firewall_status:
                vulnerabilities.append({
                    "area": "Firewall",
                    "issue": "Windows Firewall is disabled or status cannot be verified.",
                    "severity": "Critical",
                    "recommendation": "Immediately enable Windows Firewall and verify it's functioning properly."
                })
    except Exception:
        pass
    
    # UAC analysis
    try:
        if "uac" in fw_data:
            uac_status = fw_data["uac"]
            if "0" in uac_status or "Read failed" in uac_status:
                vulnerabilities.append({
                    "area": "User Account Control (UAC)",
                    "issue": "UAC is disabled or status cannot be verified.",
                    "severity": "High",
                    "recommendation": "Enable UAC to restore privilege elevation protection features."
                })
    except Exception:
        pass
    
    # Process anomaly analysis
    try:
        process_data = scan_results.get("process_anomalies", "")
        if process_data != "No process anomalies detected." and len(process_data) > 0:
            if not isinstance(process_data, list):
                try:
                    process_data = json.loads(process_data)
                except Exception:
                    process_data = []
            
            for anomaly in process_data:
                issue = anomaly.get("issue", "")
                name = anomaly.get("name", "Unknown")
                
                severity = "Medium"
                recommendation = f"Verify the legitimacy of process '{name}' and terminate if unnecessary."
                
                if "name anomaly" in issue:
                    severity = "High"
                    recommendation = f"Immediately investigate suspicious process '{name}' and verify if it's a legitimate program."
                elif "Parent-child relationship anomaly" in issue:
                    severity = "High"
                    recommendation = f"Process '{name}' with abnormal parent-child relationship may indicate malicious activity. Investigate immediately."
                
                vulnerabilities.append({
                    "area": "Processes",
                    "issue": f"Abnormal process detected: {name} - {issue}",
                    "severity": severity,
                    "recommendation": recommendation
                })
    except Exception:
        pass
    
    # Security event log analysis
    try:
        events_data = scan_results.get("security_events", "")
        if events_data and events_data != "wmi module is not available in this environment.":
            try:
                events = json.loads(events_data)
                # Map key security event IDs to severity
                critical_events = {
                    "4625": {"description": "Login failure", "severity": "Medium"},
                    "4648": {"description": "Login attempt with explicit credentials", "severity": "Medium"},
                    "4670": {"description": "Permission change", "severity": "Medium"},
                    "4672": {"description": "Special privilege assignment", "severity": "Low"},
                    "4720": {"description": "User account created", "severity": "Low"},
                    "4732": {"description": "Member added to security-enabled group", "severity": "Medium"},
                    "4738": {"description": "User account changed", "severity": "Low"},
                }
                
                # Filter important events
                for event in events:
                    event_id = str(event.get("EventCode", ""))
                    if event_id in critical_events:
                        info = critical_events[event_id]
                        message = event.get("Message", "")[:100]
                        
                        vulnerabilities.append({
                            "area": "Security Events",
                            "issue": f"{info['description']} (Event ID: {event_id}): {message}",
                            "severity": info["severity"],
                            "recommendation": "Verify the legitimacy of this security event and investigate for abnormal activity."
                        })
            except Exception:
                pass
    except Exception:
        pass
    
    # Calculate overall security score
    severity_scores = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }
    
    for vuln in vulnerabilities:
        severity_scores[vuln["severity"]] += 1
    
    # Apply weights by severity
    total_score = 100
    total_score -= severity_scores["Critical"] * 15
    total_score -= severity_scores["High"] * 10
    total_score -= severity_scores["Medium"] * 5
    total_score -= severity_scores["Low"] * 2
    
    # Limit score range (0-100)
    if total_score < 0:
        total_score = 0
    
    return {
        "vulnerabilities": vulnerabilities,
        "severity_summary": severity_scores,
        "security_score": total_score,
        "overall_status": (
            "Critical" if total_score < 60 else
            "High Risk" if total_score < 70 else
            "Caution" if total_score < 85 else
            "Good"
        )
    }
