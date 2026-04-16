# Ethical Network Port Scanner (Node.js + Python)

This project is a hybrid Network Port Scanner that uses a **Node.js CLI** as the backend interface and **Python** for the core scanning engine.

## 🛡️ Ethical Use & Legal Warning
**IMPORTANT: FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY.**

This tool is designed for ethical security professionals and students to audit their own networks or networks they have explicit, written permission to test. Unauthorized scanning of networks can be considered illegal or a violation of terms of service.

### Ethical Guidelines:
- **Permission First:** Never scan a network, host, or IP that you do not own or have formal authorization to audit.
- **Local Scope:** By default, this tool detects and stays within private IP ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`) to prevent accidental public scanning.
- **Do No Harm:** Do not use this tool to disrupt services or perform malicious activity.
- **Responsibility:** The developer assumes no liability for misuse of this tool or any damage caused by it.

## Features
- **Fast Scanning:** Uses Python's threading for parallel host discovery and port scanning.
- **Node.js CLI:** Modern command-line interface with colored output.
- **Auto-Detection:** Automatically detects your local network (supports private IPv4 ranges).
- **JSON Output:** Support for JSON output for integration with other tools.
- **GitHub Ready:** Pre-configured `.gitignore` to prevent leaking personal info or scan results.

## 🛠️ Prerequisites
- [Node.js](https://nodejs.org/) (v14+)
- [Python 3](https://www.python.org/)

## 📦 Installation
1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd network-port-scanner
   ```
2. Install dependencies:
   ```bash
   npm install
   ```

## 📖 Usage
Run the scanner using the following command:
```bash
node index.js scan --start 1 --end 1024
```

### Options:
- `-s, --start <port>`: Starting port number (default: 1)
- `-e, --end <port>`: Ending port number (default: 1024)
- `-j, --json`: Output results in JSON format

### Global Usage (Optional):
You can link the command to use it globally:
```bash
npm link
network-scanner scan --start 80 --end 443
```

## 🛡️ Safety & Privacy
- **Local Only:** The scanner is restricted to private network ranges (192.168.x.x, 10.x.x.x, etc.) to ensure ethical use.
- **Git Safety:** The `.gitignore` file is configured to exclude:
  - `node_modules/`
  - Python cache (`__pycache__`)
  - Personal scan results (`results.json`, `scan_report.txt`)
  - Environment files (`.env`)

## ⚖️ License
This project is for educational and ethical testing purposes only. Use it only on networks you own or have explicit permission to scan.
