# How to Run the ML-based Web Application Firewall (WAF)

This document provides instructions on how to set up and run the ML-based Web Application Firewall.

## Overview

This project is a machine learning-based WAF that can detect:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Path Traversal attacks
- Command Injection (CMDi)
- Parameter Tampering

## Prerequisites

- **Python 3.8+** (tested with Python 3.13.7)
- **Administrator privileges** (required for network sniffing)

## Installation

### 1. Install Dependencies

Navigate to the project directory and install the required packages:

```bash
cd DB-guardian/ML-based-WAF
pip install -r requirements.txt
```

Or install individually:

```bash
pip install flask dash pandas numpy scikit-learn plotly scapy requests
```

> **Note:** If you encounter import errors with newer versions of Dash, the imports in `dashboard.py` have been updated for Dash 2.x+ compatibility.

## Project Structure

```
ML-based-WAF/
├── Classifier/           # Pre-trained ML models
│   ├── predictor.joblib         # TF-IDF + SVM classifier for threat detection
│   └── pt_predictor.joblib      # Decision tree for parameter tampering
├── Dataset/              # Training datasets and preprocessing notebooks
├── WAF/                  # Main WAF application
│   ├── sniffing.py       # Main WAF - sniffs network traffic
│   ├── dashboard.py      # Web dashboard for viewing logs
│   ├── rest_app.py       # Simple test REST server
│   ├── classifier.py     # Threat classification module
│   ├── request.py        # Request handling and DB logging
│   ├── simple_testing.py # Sends test attack requests
│   └── log.db            # SQLite database for request logs
└── requirements.txt
```

## Running the Application

### Step 1: Start the Target REST Server (Terminal 1)

Open a terminal and run the test REST server:

```bash
cd DB-guardian/ML-based-WAF/WAF
python rest_app.py
```

The server will start on `http://127.0.0.1:5000`.

### Step 2: Start the WAF (Terminal 2) - Requires Admin Privileges

Open a new terminal **as Administrator** and run the WAF:

**Windows (PowerShell as Admin):**
```powershell
cd DB-guardian\ML-based-WAF\WAF
python sniffing.py --port 5000
```

**Linux/Mac:**
```bash
cd DB-guardian/ML-based-WAF/WAF
sudo python sniffing.py --port 5000
```

> **Note:** The `--port` flag specifies which port to sniff (default: 5000).

### Step 3: Start the Dashboard (Terminal 3)

Open another terminal to view the WAF dashboard:

```bash
cd DB-guardian/ML-based-WAF/WAF
python dashboard.py
```

The dashboard will be available at `http://127.0.0.1:8050`.

### Step 4: Generate Test Traffic (Optional)

To test the WAF with sample attack payloads:

```bash
cd DB-guardian/ML-based-WAF/WAF
python simple_testing.py
```

This sends requests defined in `testing_requests.json` to the REST server.

## Dashboard Features

The dashboard at `http://127.0.0.1:8050` provides:

- **Pie Charts** showing:
  - Valid vs. Attack requests
  - Types of attacks detected
  - Attack locations (Request, Body, Cookie, etc.)
- **Request Table** with filtering capabilities
- **Request Review** - Click on individual requests to see details

## Caution

⚠️ **This WAF is intended for educational purposes only and should NOT be used in production environments.** It was created as a demonstration project and has not been thoroughly tested for production use.

## Troubleshooting

### "ModuleNotFoundError: No module named 'dash_core_components'"
The code has been updated for Dash 2.x+. If you see this error, ensure you're running the latest version of the files.

### "Permission denied" when running sniffing.py
You need administrator privileges to sniff network traffic. Run the command with `sudo` (Linux/Mac) or in an Administrator terminal (Windows).

### scikit-learn version compatibility
The pre-trained models may require a specific version of scikit-learn. If you encounter errors loading the models, try installing the version from requirements.txt:
```bash
pip install scikit-learn==0.22.1
```
