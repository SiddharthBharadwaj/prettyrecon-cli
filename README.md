# PrettyRecon CLI

A command-line interface for PrettyRecon, a web-based reconnaissance and security scanning platform.

## Features

### Core Scanning Capabilities
- **Subdomain Enumeration**: Comprehensive subdomain discovery
- **DNS Information**: Detailed DNS record analysis
- **Port Scanning**: Service and port identification
- **Wayback URLs**: Historical URL discovery
- **Vulnerability Assessment**: Security misconfiguration detection
- **Secrets Detection**: Exposed credentials and sensitive information scanning
- **Custom Subdomain Scanning**: Support for bulk scanning with custom target lists

### Advanced Features
- **Pagination Support**: Efficiently handle large datasets with automatic pagination
- **Interrupt Handling**: Use Ctrl+C to gracefully stop scans and save partial results
- **Job Management**: Monitor and control running scan tasks
- **Rescan Capability**: Ability to retrigger specific scan types
- **Batch Processing**: Handle up to 300 targets per batch in custom scans

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

### Basic Commands

1. Full Reconnaissance Scan:
```bash
python main.py -t example.com -st all -o
```
Performs complete scanning including subdomains, DNS, ports, URLs, and vulnerabilities.

2. Basic Scan:
```bash
python main.py -t example.com -st basic -o
```
Performs basic reconnaissance including subdomains, DNS records, ports, and wayback URLs.

3. Vulnerability-focused Scan:
```bash
python main.py -t example.com -st vuln -o
```
Focuses on security aspects including vulnerabilities, exposed secrets, and CVEs.

4. Subdomain-only Scan:
```bash
python main.py -t example.com -st sub -o
```
Performs only subdomain enumeration.

### Advanced Usage

1. Custom Subdomain Scan:
```bash
python main.py -cscn targets.txt
```
Process multiple targets from a file (up to 300 per batch).

2. Retrigger Specific Scan:
```bash
python main.py -t example.com -st vuln -r
```
Restart a specific type of scan.

### Command Line Arguments

- `-t, --target`: Target domain to scan (e.g., example.com)
- `-st, --scan_type`: Scan type (all/basic/vuln/sub)
- `-o, --output`: Save results to JSON files
- `-cscn, --customsubscan`: File containing targets for custom subdomain scan
- `-r, --rescan`: Retrigger scans for the specified type

## Output Files

When using the `-o` flag, results are saved in the `output/<target>` directory:

- `subdomains.json`: Discovered subdomains
- `dnsinfo.json`: DNS records and information
- `ports.json`: Open ports and services
- `waybackurls.json`: Historical URLs
- `common_vulns.json`: Common vulnerabilities
- `exposed_creds.json`: Exposed credentials/secrets
- `cves.json`: Identified CVEs

## Error Handling

The tool implements comprehensive error handling for:
- Network connectivity issues
- Authentication failures
- Invalid input validation
- File operation errors
- API response errors
- Session management
- CSRF token handling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request


## Support

For support, please open an issue in the GitHub repository.


## Disclaimer

Use this tool responsibly and only on systems you have permission to test. The authors are not responsible for any misuse or damage.
