def prioritize(issues):
    """
    Ranks issues based on impact, severity, and exploitability.
    Ensures the 'Fix First' section is high-value for developers.
    """
    severity_rank = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }
    
    # 1. Exploit Chain first
    # 2. Severity
    # 3. REAL_RISK before WEAKNESS
    sorted_items = sorted(
        issues,
        key=lambda x: (
            1 if x.get("category") == "Exploit Chain" else 0,
            severity_rank.get(x.get("severity", "LOW").upper(), 0),
            1 if x.get("classification") == "REAL_RISK" else 0
        ),
        reverse=True
    )
    
    seen_names = set()
    unique_issues = []
    for i in sorted_items:
        name = i.get("name")
        if name not in seen_names:
            unique_issues.append(i)
            seen_names.add(name)
            
    return unique_issues
