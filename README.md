# PrettyRecon CLI

A command-line interface for PrettyRecon, a web-based reconnaissance and security scanning platform.

## Features

- Subdomain enumeration
- DNS information gathering
- Port scanning
- Wayback URL discovery
- Security misconfiguration scanning
- Exposed secrets detection
- Custom subdomain scanning

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/prettyrecon-cli.git
cd prettyrecon-cli
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
Create a `.env` file in the project root:
```
PRETTYRECON_EMAIL=your_email
PRETTYRECON_PASSWORD=your_password
```

## Usage

### Basic Scan
```bash
python main.py -t example.com -st basic -o
```

### Full Scan
```bash
python main.py -t example.com -st all -o
```

### Subdomain Only Scan
```bash
python main.py -t example.com -st sub -o
```

### Vulnerability Scan
```bash
python main.py -t example.com -st vuln -o
```

### Custom Subdomain Scan
```bash
python main.py -cscn subdomains.txt
```

## Command Line Arguments

- `-t, --target`: Target domain to scan (e.g., example.com)
- `-st, --scan_type`: Scan type (all/basic/vuln/sub)
- `-o, --output`: Save results to JSON files
- `-cscn, --customsubscan`: File containing custom subdomains to scan

## Output

When using the `-o` flag, results are saved in the `output/<target>` directory:

- `subdomains.json`: Discovered subdomains
- `dnsinfo.json`: DNS information
- `ports.json`: Open ports
- `waybackurls.txt`: Historical URLs
- `exposed_creds.json`: Exposed credentials
- `misc_vulns.json`: Miscellaneous vulnerabilities

## Error Handling

The tool includes comprehensive error handling for:
- Network issues
- Authentication failures
- Invalid input
- File operations
- API errors

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
