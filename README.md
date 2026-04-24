# Vulnix SaaS Platform

## AI-Powered Web Vulnerability Scanner

Vulnix is an enterprise-grade cybersecurity SaaS platform designed to scan websites, detect real vulnerabilities, simulate attack paths, and provide AI-powered remediation guidance.

Unlike traditional scanners that only list vulnerabilities, Vulnix focuses on showing how attackers can actually exploit security weaknesses.

---

# Executive Overview

Vulnix helps users understand:

* What vulnerabilities exist
* How attackers can chain them together
* Which issues must be fixed first
* What the real business impact is
* How developers should properly remediate them

Example:

```text
Entry Point → XSS → Cookie Theft → Account Takeover
```

This transforms the platform from a simple scanner into a real security intelligence system.

---

# Core Workflow

## What Happens When a User Enters a URL

Example:

```text
https://example.com
```

The user clicks:

```text
Start Scan
```

Then the full security pipeline begins.

---

# Step-by-Step Scan Pipeline

## 1. URL Submission

The user submits a target URL from the dashboard.

This request is handled by:

```python
routes/scan.py
```

### Responsibilities

* Validate URL format
* Check user subscription tier (Free / Pro / Business)
* Apply rate limits
* Create scan job
* Save initial scan state in database

Then it calls:

```python
scanner.py
```

---

## 2. Scanner Engine

```python
scanner.py
```

This is the main scanning brain.

### Performs Basic Security Checks

* Content Security Policy (CSP)
* HSTS
* X-Frame-Options
* HTTPS enforcement
* HTTP downgrade detection
* Cookie security flags
* Security headers

---

## 3. Attack Simulation Engine

```python
services/attack_engine.py
```

This module simulates real attacker behavior.

### Detection Includes

* Reflected XSS
* Open Redirect
* Sensitive file exposure (.env / backups)
* Cookie weaknesses
* Session risks

This avoids fake security reports and focuses on real exploitability.

---

## 4. Exploit Chain Correlation

```python
services/exploit_chains.py
```

This system connects isolated vulnerabilities into real attack paths.

### Example

```text
XSS + Missing HttpOnly
↓
Session Hijacking
```

This creates high-value security intelligence instead of generic issue lists.

---

## 5. Proof of Concept Generation

```python
services/poc_generator.py
```

Generates developer-ready Proof of Concept payloads.

### Includes

* CURL commands
* Attack payloads
* Manual verification steps

This helps developers validate findings quickly.

---

## 6. Priority Engine

```python
services/priority_engine.py
```

This engine:

* Removes duplicates
* Sorts vulnerabilities by severity
* Prioritizes exploit chains first
* Pushes real risks above weak findings

Output example:

```text
FIX FIRST
TOP 1
TOP 2
TOP 3
```

---

## 7. Security Score Calculation

Back inside:

```python
scanner.py
```

The system calculates:

```text
Security Score
Threat Level
```

Example:

```text
83/100
Threat Level: Medium
```

Based on:

* HIGH vulnerabilities
* Exploit chains
* MEDIUM findings
* LOW findings

---

## 8. Database Storage

```python
models.py
```

Stores:

* Vulnerabilities
* Scan history
* Security score
* Threat level
* User tier
* AI summaries
* Subscription/payment data

---

## 9. Report Generation

```python
routes/report.py
```

When the user opens the report page:

The system loads:

* Scan results
* Priority engine output
* Security score
* Attack graph
* Premium upgrade locks

Then it sends findings to:

```python
ai_service.py
```

---

## 10. AI Intelligence Layer

```python
ai_service.py
```

This is the Gemini AI integration layer.

### Generates

* AI Intelligence Summary
* Risk explanation
* Business impact
* Developer remediation steps
* Chat with Scan assistant responses

### Protected By

```python
safe_generate()
validate_output()
```

These prevent:

* hallucinations
* fake breach claims
* unsupported “database takeover” outputs

The AI must remain realistic and evidence-based.

---

## 11. Final User Report

```python
templates/report.html
```

The user sees:

* Security Score
* Threat Level
* AI Intelligence Summary
* Fix First (Priority Engine)
* Intelligence Inventory
* Attack Visualization Graph
* AI Security Assistant
* Upgrade to Pro features

---

# Core Architecture

## Root Files

### app.py

Main Flask application entry point.

Handles:

* App initialization
* Blueprint registration
* Database setup
* Server startup

---

### scanner.py

Main scan orchestration engine.

Responsible for:

* Running security checks
* Calling modular attack services
* Calculating score
* Final issue output

---

### ai_service.py

Gemini AI integration layer.

Responsible for:

* AI summaries
* Chat assistant
* Validation
* Safe output generation

---

### models.py

SQLAlchemy database schemas.

Includes:

* Users
* ScanResults
* Payments
* Subscriptions

---

### config.py

Environment configuration loader.

Loads:

* API keys
* Flask secrets
* Database URIs

---

# Services

## attack_engine.py

Active vulnerability simulation.

## exploit_chains.py

Real exploit path detection.

## poc_generator.py

Proof-of-concept generation.

## priority_engine.py

Issue prioritization and deduplication.

## async_scan.py

Background task management.

## database.py

Persistence and database helpers.

---

# Monetization System

## Payment Flow

Supports:

* Free Tier
* Pro Tier
* Business Tier

Integration-ready for:

* Lemon Squeezy
* Stripe
* PayPal

### Premium Features

* Full exploit chains
* Advanced AI analysis
* Unlimited AI assistant
* Priority fix engine
* Full attack visualization

---

# Product Philosophy

Traditional scanners show:

```text
Missing Headers
Cookie Issues
XSS
```

Vulnix shows:

```text
How attackers use them
```

That is the difference.

---

# Final Summary

```text
URL
↓
Scan
↓
Attack Simulation
↓
Exploit Chains
↓
Priority Engine
↓
AI Explanation
↓
Final Security Report
```

---

# Mission

Vulnix is not just a vulnerability scanner.

It is:

## Attacker Simulation + AI Security Consultant

Built for modern SaaS security intelligence.
