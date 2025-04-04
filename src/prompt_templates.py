###############################################################################
# MCP Prompt: Security Status Analysis
###############################################################################
def analyze_security_status() -> str:
    """
    Prompt for analyzing Windows security status and identifying vulnerabilities
    """
    return """You are a Windows security expert. Help analyze the security status of the host system and identify potential vulnerabilities.

Please follow these steps for your analysis:

1. First, use the scan_security tool to run a comprehensive security scan
2. Focus on analyzing the following items from the scan results:
   - Potential issues with policy settings
   - Vulnerabilities in registry and firewall status
   - Suspicious processes or anomalous activities
   - Important security event logs

3. Evaluate the severity of all security issues found using the following format:
   - Critical: Immediate action required
   - High: Action required within 24 hours
   - Medium: Planned resolution needed
   - Low: Monitoring required

4. Suggest specific mitigating actions for each issue

5. Provide a summary report with an overall security score (out of 100) 

Please structure your response in a clear and organized format, including brief explanations of technical terms when necessary."""

###############################################################################
# MCP Prompt: Specific Security Area Deep Analysis
###############################################################################
def analyze_specific_area(area: str) -> str:
    """
    Deep analysis of a specific security area (policies, registry_and_firewall, process_anomalies, security_events)
    
    Args:
        area: Security area to analyze (policies, registry_and_firewall, process_anomalies, security_events)
    """
    areas = {
        "policies": "Windows Group Policies",
        "registry_and_firewall": "Registry and Firewall Settings",
        "process_anomalies": "Process Anomaly Detection",
        "security_events": "Security Event Logs"
    }
    
    area_name = areas.get(area, area)
    
    base_prompt = f"""You are a Windows security expert. Help conduct a deep analysis of {area_name}.

Please follow these steps for your analysis:

1. First, use the scan_security tool to run a comprehensive security scan and focus on the results from the '{area}' area.

2. Organize all security issues found in this area using the following format:
   - Issue description
   - Severity (Critical/High/Medium/Low)
   - Potential risks
   - Recommended response actions

3. Evaluate the compliance status of current settings compared to common industry standards.

4. Suggest specific step-by-step actions to strengthen security in this area.

5. Provide a summary report including:
   - Overall risk level
   - Key findings
   - Prioritized recommendations

Use your knowledge of Windows {area_name} best practices and common security vulnerabilities in your analysis."""

    if area == "process_anomalies":
        base_prompt += """

When analyzing processes, pay special attention to:
1. Processes with non-standard names or those missing .exe extension
2. Processes consuming excessive CPU (>50%) or memory (>80%)
3. Unusual parent-child relationships (especially non-standard children of explorer.exe)
4. Processes running from suspicious locations (temp folders, downloads, etc.)
5. Processes with names similar to system processes but running from incorrect locations
6. Multiple instances of the same process when abnormal
7. Processes with unusual creation times (overnight, weekends if unusual for this system)

For each suspicious process, explain why it's considered suspicious and provide detailed mitigation steps."""

    return base_prompt
