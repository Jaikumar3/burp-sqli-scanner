# burp-sqli-scanner

This tool automates SQL injection testing from Burp Suite history logs using Ghauri and SQLMap.

## Features

- **Multi-format support**: Parses Burp Suite XML and text log formats
- **Multiple tools**: Supports both Ghauri and SQLMap
- **Concurrent testing**: Option to run tests concurrently or sequentially
- **Comprehensive reporting**: JSON and CSV output formats
- **Request filtering**: Supports GET, POST, PUT, DELETE, and other HTTP methods
- **Detailed results**: Captures vulnerability status, injection types, and exploitable parameters

## Installation

### Prerequisites

1. **Python 3.7+** is required
2. **Ghauri** - Fast SQL injection detection and exploitation tool
3. **SQLMap** - Automatic SQL injection and database takeover tool

### Install Tools

```bash
# Install Ghauri
pip3 install ghauri

# Install SQLMap (if not already installed)
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
# Add to PATH or use full path
```

> **Note:** No additional Python dependencies are required. The tool does not require a `requirements.txt` file.

### Setup

```bash
# Make the script executable
chmod +x burp_sqli_scanner.py

# Optional: Create a symlink for easy access
sudo ln -s $(pwd)/burp_sqli_scanner.py /usr/local/bin/burp-sqli-scanner
```

### Optional Configuration

You can customize tool behavior by editing the `config.ini` file. If not present, built-in defaults will be used.

### GitHub Actions CI

A pre-configured GitHub Actions workflow is included in `.github/workflows/python-app.yml` to automatically lint, format, and test your code on push or pull request.

## Usage

### Basic Usage

```bash
# Test with both Ghauri and SQLMap (default)
python3 burp_sqli_scanner.py burp_history.log

# Test with specific tool only
python3 burp_sqli_scanner.py burp_history.log -t ghauri
python3 burp_sqli_scanner.py burp_history.log -t sqlmap

# Test with both tools
python3 burp_sqli_scanner.py burp_history.log -t ghauri sqlmap
```

### Advanced Options

```bash
# Run tests concurrently (faster but more resource intensive)
python3 burp_sqli_scanner.py burp_history.log --concurrent --max-workers 10

# Specify custom output directory
python3 burp_sqli_scanner.py burp_history.log -o my_results

# Generate specific report formats
python3 burp_sqli_scanner.py burp_history.log --json-report results.json
python3 burp_sqli_scanner.py burp_history.log --csv-report results.csv
python3 burp_sqli_scanner.py burp_history.log --json-report results.json --csv-report results.csv
```

### Complete Example

```bash
# Full featured run with concurrent testing and both report formats
python3 burp_sqli_scanner.py burp_history.xml \
    --tools ghauri sqlmap \
    --concurrent \
    --max-workers 8 \
    --output sqli_test_results \
    --json-report vulnerability_report.json \
    --csv-report vulnerability_report.csv
```

## Input Formats

### Burp Suite XML Export
1. In Burp Suite, go to **Proxy** → **HTTP history**
2. Select the requests you want to test
3. Right-click → **Save items** → Choose **XML** format

### Burp Suite Text Log
1. In Burp Suite, go to **Proxy** → **HTTP history**
2. Select requests → Right-click → **Copy as requests**
3. Save to a text file

## Output

### Directory Structure
```
sqli_results/
├── request_0.txt    # Individual request files
├── request_1.txt
├── request_2.txt
└── ...
```

### JSON Report Format
```json
{
  "timestamp": "2025-08-01T12:34:56",
  "total_requests": 10,
  "vulnerable_requests": 3,
  "results": [
    {
      "tool": "ghauri",
      "request_file": "sqli_results/request_0.txt",
      "host": "example.com",
      "method": "POST",
      "path": "/login",
      "vulnerable": true,
      "injection_type": "boolean-based blind",
      "exploitable_params": ["username"],
      "output": "...",
      "error": null
    }
  ]
}
```

### CSV Report Format
| tool | request_file | host | method | path | vulnerable | injection_type | exploitable_params | error |
|------|-------------|------|---------|------|------------|----------------|-------------------|-------|
| ghauri | request_0.txt | example.com | POST | /login | true | boolean-based blind | username | null |

## Tool-Specific Notes

### Ghauri
- Fast and modern SQL injection tool
- Good for quick scans
- Better at detecting time-based injections
- Command: `ghauri -r request_file --batch --level 3 --risk 3`

### SQLMap
- Comprehensive and mature tool
- Extensive database support
- Better exploitation capabilities
- Command: `sqlmap -r request_file --batch --level 3 --risk 3 --technique BEUSTQ`

## Performance Considerations

### Sequential vs Concurrent
- **Sequential**: Safer, less resource intensive, easier to debug
- **Concurrent**: Faster, but uses more CPU/memory/network

### Recommended Settings
- **Small logs (< 50 requests)**: Sequential mode
- **Large logs (> 50 requests)**: Concurrent with 3-5 workers
- **Very large logs (> 200 requests)**: Concurrent with 8-10 workers

## Troubleshooting

### Common Issues

1. **Tool not found errors**
   ```bash
   # Ensure tools are in PATH
   which ghauri
   which sqlmap
   
   # Or specify full paths in the script
   ```
2. **Missing config.ini**
   - The tool will use default settings if `config.ini` is not present.

2. **Permission errors**
   ```bash
   # Make script executable
   chmod +x burp_sqli_scanner.py
   
   # Check output directory permissions
   mkdir -p sqli_results
   chmod 755 sqli_results
   ```

3. **Timeout errors**
   ```bash
   # Reduce concurrent workers
   python3 burp_sqli_scanner.py log.xml --concurrent --max-workers 2
   
   # Or use sequential mode
   python3 burp_sqli_scanner.py log.xml
   ```

4. **Memory issues with large logs**
   ```bash
   # Process in smaller batches or use sequential mode
   # Split large log files before processing
   ```

### Debugging

Enable verbose output by modifying the script or adding debug flags:

```python
# Add to main() function for debugging
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Security Considerations

- **Test only on authorized targets**
- **Use in isolated environments** when possible
- **Be aware of rate limiting** and WAF detection
- **Review and sanitize** logs before sharing reports
- **Consider using VPN/proxy** for testing external targets

## Extending the Tool

### Adding New Tools
1. Create a new method in `SQLiTester` class
2. Follow the pattern of existing tool methods
3. Add tool name to argument choices

### Custom Report Formats
1. Extend `ReportGenerator` class
2. Add new format methods
3. Update CLI arguments

### Enhanced Parsing
1. Modify `BurpLogParser` class
2. Add support for new log formats
3. Improve request extraction logic

## License

This tool is provided as-is for educational and authorized testing purposes only.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the tool documentation
3. Create an issue with detailed error information
