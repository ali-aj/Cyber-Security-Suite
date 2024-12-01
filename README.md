# Comprehensive Cybersecurity Suite (CCS)

This project is an integrated cybersecurity platform that simulates and defends against modern threats. It incorporates real-time attack detection, cryptographic applications, and web vulnerability assessment tools.

## Features

1. Attack Simulation Framework
2. Web Security Analyzer
3. Cryptographic Toolkit
4. Real-Time Intrusion Detection System (IDS)
5. Ethical Hacking Lab
6. Secure Communication Module

## Installation

1. Clone this repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - On Windows: `venv\Scripts\activate`
   - On macOS and Linux: `source venv/bin/activate`
4. Install the required packages: `pip install -r requirements.txt`

## Usage

1. Initialize the database:
   - `flask db init `
   - `flask db migrate -m "Initial migration."`
   - `flask db upgrade`
2. Set the Flask application environment variable:
   - On CMD: `set FLASK_APP=app:create_app`
   - On Powershell: `$env:FLASK_APP = "app:create_app"`  
3. Run the application: `python main.py`
4. Open a web browser and navigate to `http://localhost:5000`

## Contributing

Please read CONTRIBUTING.md for details on our code of conduct, and the process for submitting pull requests.