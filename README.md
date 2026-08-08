# 🔎 Python Log Analyzer

A small Python-based security log analysis tool that reads application/server logs and detects useful patterns such as suspicious User-Agents, HTTP behavior, brute-force activity, and directory enumeration.

This project is being built incrementally as part of my journey learning **Python for cybersecurity, automation, and security engineering**.

The goal is not to build a production SIEM. The goal is to understand how security tooling works by **building one from scratch**, feature by feature.

---

## 🚀 Project Status

**Current version:** `In Development`

This project is actively being expanded as I learn new Python concepts and security techniques.

New functionality will be added over time rather than trying to build everything at once.

---

## 🎯 Goals

The main goals of this project are to:

* Strengthen Python programming through practical development.
* Learn how security tools process and analyze data.
* Practice working with files and logs.
* Build reusable Python classes and functions.
* Practice object-oriented programming.
* Learn how to identify suspicious patterns in logs.
* Automate common security-analysis tasks.
* Eventually turn the project into a more capable security-analysis utility.

---

# 🧠 What I've Practiced

This project has become a practical environment for applying Python concepts such as:

* Classes and objects
* Constructors
* Instance methods
* Lists
* Sets
* Loops
* Nested loops
* Conditional statements
* List comprehensions
* String manipulation
* `.split()`
* `.append()`
* `.count()`
* File handling
* Imports
* Helper modules
* Configuration modules
* Assertions
* Basic validation
* Returning values
* Working with external log files
* Writing reusable functions
* Writing tests
* Incremental refactoring

The project is intentionally developed while learning rather than being written all at once.

---

# 🛡️ Current Features

## 📄 Log File Loading

The analyzer can load a log file and store its contents for analysis.

Example:

```python
analyzer = LogAnalyzer("access.log")
analyzer.load_file()
```

---

## 📊 Basic Log Statistics

The analyzer can currently:

* Count total log entries.
* Count occurrences of specific keywords.
* Find logs containing a specific keyword.
* Count errors.
* Search for specific HTTP status codes.
* Determine the most common HTTP status code.
* Count HTTP request methods.
* Determine the most common HTTP method.

Examples:

```python
analyzer.count_lines()

analyzer.count_errors()

analyzer.count_keyword("ERROR")

analyzer.find_logs("FAILED LOGIN")

analyzer.count_status("404")

analyzer.find_status("403")

analyzer.top_method()
```

---

# 🌐 IP Analysis

The analyzer can extract IP addresses from logs.

It performs basic validation by checking that:

* The address contains four sections.
* Each section contains digits.
* Duplicate IP addresses are removed.

Example:

```python
analyzer.extract_ips()
```

The analyzer can also determine:

### IP request count

```python
analyzer.count_ip("192.168.1.10")
```

### Unique IPs

```python
analyzer.unique_ips()
```

### Most active IP

```python
analyzer.top_ip()
```

---

# 🤖 User-Agent Analysis

The analyzer can inspect User-Agent strings and identify potentially suspicious tools.

Examples of currently monitored User-Agents include tools such as:

* `curl`
* `python-requests`
* `sqlmap`
* `Burp`
* `Gobuster`
* `ffuf`
* `dirbuster`
* `nikto`
* `nmap`
* `masscan`
* `wpscan`

The suspicious User-Agent list is maintained separately in the configuration/helper area so that additional signatures can be added later.

Available functionality includes:

```python
analyzer.count_user_agent("sqlmap")

analyzer.find_user_agent("sqlmap")

analyzer.list_suspicious_agents()
```

---

# 🔐 HTTP Status Code Analysis

The analyzer can count and search for HTTP response codes.

Examples:

```python
analyzer.count_status("200")

analyzer.find_status("404")

analyzer.most_common_status()
```

Common status codes are maintained in the project configuration.

---

# 🌐 HTTP Request Method Analysis

The analyzer can work with common HTTP methods including:

```text
GET
POST
PUT
DELETE
OPTIONS
HEAD
```

Available functionality:

```python
analyzer.count_method("POST")

analyzer.find_method("GET")

analyzer.top_method()
```

---

# 🚨 Directory Busting Detection

The analyzer can detect potentially suspicious directory/path enumeration behavior.

The current approach looks for an IP address that accesses a large number of **different paths**.

For example:

```text
192.168.1.12 GET /admin
192.168.1.12 GET /.env
192.168.1.12 GET /.git
192.168.1.12 GET /backup.zip
192.168.1.12 GET /config.php
192.168.1.12 GET /phpinfo.php
192.168.1.12 GET /wp-admin
...
```

The current detector uses a configurable threshold:

```python
DIRECTORY_BUST_THRESHOLD = 15
```

An IP is flagged when it accesses at least 15 different paths.

Example:

```python
analyzer.detect_directory_busting()
```

Example result:

```python
[
    "192.168.1.12",
    "192.168.1.15"
]
```

### Why unique paths?

Repeatedly requesting the same endpoint should not automatically be considered directory enumeration.

For example:

```text
192.168.1.15 GET /admin
192.168.1.15 GET /admin
192.168.1.15 GET /admin
```

represents three requests but only **one unique path**.

The detector therefore focuses on the number of different paths accessed.

---

# 🗂️ Project Structure

```text
log-analyzer/
│
├── analyzer.py
│   └── Main LogAnalyzer class and analysis methods
│
├── config.py
│   └── Shared configuration such as HTTP methods
│      and status codes
│
├── helper.py
│   └── Reusable helper functions and security-related
│      configuration/signatures
│
├── access.log
│   └── Sample access log used for development/testing
│
├── login_logs.log
│   └── Login-related sample logs
│
├── user_agent.logs
│   └── User-Agent testing data
│
├── tests/
│   └── Test scripts for validating analyzer functionality
│
├── README.md
│   └── Project documentation
│
├── LICENSE
│   └── Project license
│
└── roadmap.txt
    └── Planned future features
```

---

# ⚙️ Current Log Format

The current analyzer is being developed around a simplified log format:

```text
IP METHOD PATH STATUS
```

Example:

```text
192.168.1.12 GET /admin 403
192.168.1.12 GET /.env 404
192.168.1.12 POST /login 401
```

This makes the project easier to develop and understand while learning.

One of the planned improvements is supporting more realistic log formats and creating a dedicated log parser instead of relying heavily on fixed positions such as:

```python
parts[0]
parts[2]
```

---

# ▶️ Running the Project

Clone the repository:

```bash
git clone https://github.com/cybernerddd/log-analyzer.git
```

Enter the project:

```bash
cd log-analyzer
```

Run the analyzer/test code:

```bash
python analyzer.py
```

Run the tests:

```bash
python tests/class_test.py
```

Depending on how the project develops, this usage structure may change.

---

# 🧪 Testing

The project contains test code under:

```text
tests/
```

Tests are updated as new functionality is introduced.

The goal is to make sure that adding a new feature does not silently break previously implemented functionality.

---

# 🏗️ Development Philosophy

This project is intentionally being built **incrementally**.

Instead of trying to create a complete security tool immediately, functionality is added as new Python and cybersecurity concepts are learned.

The development process generally looks like:

```text
Learn Python concept
       ↓
Understand the security problem
       ↓
Design the logic
       ↓
Implement the feature
       ↓
Test it
       ↓
Refactor
       ↓
Add documentation
       ↓
Move to the next feature
```

This means the code may evolve significantly over time.

Some implementations are intentionally simple because the primary goal is learning and understanding the underlying logic before introducing more advanced abstractions.

---

# 🔮 Roadmap

The project roadmap is maintained separately in:

```text
roadmap.txt
```

Planned areas include improvements to:

* Brute-force detection
* Directory enumeration detection
* Request behavior analysis
* IP reputation/behavior analysis
* Suspicious request detection
* Better log parsing
* More flexible log formats
* Time-based analysis
* Request-rate analysis
* Correlation between multiple indicators
* More automated security alerts
* Better testing
* CLI functionality
* Configuration options
* Performance improvements
* More advanced security detections

The roadmap will evolve as the project grows.

---

# 🧭 Long-Term Vision

The long-term goal is to turn this into a more complete Python security-analysis project.

Possible future capabilities include:

```text
Raw Logs
   │
   ▼
Log Parser
   │
   ▼
Normalized Events
   │
   ├── IP Analysis
   ├── User-Agent Analysis
   ├── HTTP Analysis
   ├── Authentication Analysis
   ├── Enumeration Detection
   ├── Brute-Force Detection
   └── Behavioral Analysis
            │
            ▼
      Suspicious Activity
            │
            ▼
       Security Report
```

Eventually, the analyzer could become a small command-line security tool capable of taking a log file and automatically producing a useful security summary.

---

# ⚠️ Disclaimer

This project is intended for:

* Educational purposes
* Defensive security analysis
* Python programming practice
* Authorized security testing
* Understanding security automation

Only analyze logs and systems that you have permission to analyze.

---

# 📚 Why I'm Building This

I'm learning Python as part of a broader Computer Science and cybersecurity journey.

Rather than learning Python only through isolated exercises, I'm using this project to continuously apply what I learn to problems related to:

* Cybersecurity
* Automation
* Log analysis
* Web security
* Reconnaissance
* Detection engineering
* Security tooling

The project will continue evolving as my Python and cybersecurity knowledge improves.

---

## 📈 Project Progress

This is a living project.

Features will continue to be added, redesigned, tested, and improved as I learn.

> **Learn it → build it → break it → fix it → improve it.**

---

## 👤 Author

**Cybernerddd**

GitHub:
https://linkedin.com/in/cybernerddd

---

## 📜 License

Licensed under the Apache License 2.0.
