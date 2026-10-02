# Network Security Scanner

A Python-based network security scanner designed for authorized
lab environments. The tool identifies open TCP ports, maps
common services, performs basic risk classification, attempts
basic banner detection, and generates JSON/CSV reports.

## Features

- TCP port scanning
- Concurrent scanning using ThreadPoolExecutor
- Custom port ranges
- IP address validation
- Common service identification
- Basic risk classification
- HTTP banner detection
- JSON reporting
- CSV reporting
- Command-line interface

## Technologies

- Python 3
- TCP/IP
- Python Socket Programming
- ThreadPoolExecutor
- JSON
- CSV
- Nmap for validation
- Kali Linux

## Usage

```bash
python3 scanner.py 127.0.0.1 --ports 1-1000
