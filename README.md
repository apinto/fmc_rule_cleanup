# FMC Access Rule Hit Count Analysis and Auto-Disable Script

A Python script that analyzes Cisco Firewall Management Center (FMC) access control rules based on hit counts and automatically disables unused rules that meet specific criteria.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Command Line Arguments](#command-line-arguments)
- [Rule Disable Criteria](#rule-disable-criteria)
- [Safety Features](#safety-features)
- [Output](#output)
- [Best Practices](#best-practices)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Hit Count Analysis**: Retrieves and analyzes hit counts for all access rules on a specified device
- **Intelligent Rule Filtering**: Identifies rules with zero hit counts that meet disable criteria
- **Zone Exclusion**: Supports excluding rules that involve specific security zones
- **IP Prefix Exclusion**: Exclude rules based on source/destination IP address ranges (CIDR notation)
- **Enhanced Retry Logic**: Progressive backoff retry strategy with consecutive retry limits
- **Clean Console Interface**: Progress bar with real-time updates and retry information
- **Excel Report Generation**: Export operation summary, disabled rules, and ignored rules to Excel format
- **Dry Run Mode**: Simulate operations without making actual changes to FMC
- **Comprehensive Logging**: Detailed logging with configurable verbosity levels, directed to file only when specified
- **Safety Limits**: Configurable maximum number of rules to disable per execution
- **Command-Line Interface**: Flexible argument-based configuration
- **Production Ready**: Built with enterprise security operations in mind

## Requirements

- Python 3.7+
- Access to Cisco FMC with API permissions
- Required Python packages (see requirements.txt)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/apinto/fmc_rule_cleanup.git
   cd fmc_rule_cleanup
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. For development (optional):
   ```bash
   pip install -r requirements-dev.txt
   ```

## Configuration

### Using Environment Configuration

The `example.env` file provides a template for creating environment-specific configurations that set shell variables for easier script execution:

#### Method 1: Create Environment Configuration Script

1. **Copy and customize the template:**
   ```bash
   cp example.env my-production.env
   ```

2. **Edit the file with your actual values:**
   ```bash
   # my-production.env
   export FMC_HOST="192.168.1.100"
   export FMC_USERNAME="your_username"
   export FMC_PASSWORD="your_password"
   export DEVICE_NAME="firewall01.example.local"
   export MAX_RULES="1000"
   export LOG_FILE="production.log"
   export EXCLUDE_ZONES="TRUSTED CRITICAL MANAGEMENT"  # Space-separated list
   ```

3. **Source the environment file and run the script:**
   ```bash
   # Load environment variables
   source my-production.env
   
   # Run the script using the variables
   python3 fmc_rule_cleanup.py \
     --host "$FMC_HOST" \
     --username "$FMC_USERNAME" \
     --password "$FMC_PASSWORD" \
     --device "$DEVICE_NAME" \
     --max-rules "$MAX_RULES" \
     --log-file "$LOG_FILE" \
     --exclude-zones $EXCLUDE_ZONES \
     --dry-run
   ```

#### Method 2: Create a Wrapper Script

1. **Create an executable wrapper script:**
   ```bash
   # create-production-script.sh
   #!/bin/bash
   
   # Load environment configuration
   source my-production.env
   
   # Run FMC script with environment variables
   python3 fmc_rule_cleanup.py \
     --host "$FMC_HOST" \
     --username "$FMC_USERNAME" \
     --password "$FMC_PASSWORD" \
     --device "$DEVICE_NAME" \
     --max-rules "$MAX_RULES" \
     --log-file "$LOG_FILE" \
     --exclude-zones $EXCLUDE_ZONES \
     "$@"  # Pass any additional arguments
   ```

2. **Make it executable and use:**
   ```bash
   chmod +x create-production-script.sh
   ./create-production-script.sh --dry-run
   ./create-production-script.sh --max-rules 500
   ```

#### Method 3: Direct Environment Variables

```bash
# Set variables directly in your session
export FMC_HOST="192.168.1.100"
export FMC_USERNAME="your_username"
export FMC_PASSWORD="your_password"
export DEVICE_NAME="firewall01.example.local"

# Use them in the script
python3 fmc_rule_cleanup.py \
  --host "$FMC_HOST" \
  --username "$FMC_USERNAME" \
  --password "$FMC_PASSWORD" \
  --device "$DEVICE_NAME" \
  --dry-run
```

**Security Note:** Keep your `.env` files secure and exclude them from version control. They contain sensitive credentials.

## Quick Start

⚠️ **Always start with a dry run to understand what the script will do:**

```bash
python3 fmc_rule_cleanup.py \
  --host YOUR_FMC_IP \
  --username YOUR_USERNAME \
  --password YOUR_PASSWORD \
  --device YOUR_DEVICE_NAME \
  --dry-run
```

**Note:** By default, no security zones are excluded. To exclude specific zones (e.g., TRUSTED, DMZ), use the `--exclude-zones` flag:

```bash
python3 fmc_rule_cleanup.py \
  --host YOUR_FMC_IP \
  --username YOUR_USERNAME \
  --password YOUR_PASSWORD \
  --device YOUR_DEVICE_NAME \
  --exclude-zones TRUSTED DMZ \
  --dry-run
```

**Note:** To exclude rules based on IP address ranges (e.g., protecting internal networks), use the `--exclude-prefixes` flag with CIDR notation:

```bash
python3 fmc_rule_cleanup.py \
  --host YOUR_FMC_IP \
  --username YOUR_USERNAME \
  --password YOUR_PASSWORD \
  --device YOUR_DEVICE_NAME \
  --exclude-prefixes 10.0.0.0/8 192.168.0.0/16 \
  --dry-run
```

## Usage

### Basic Usage

```bash
python3 fmc_rule_cleanup.py --host 192.168.1.100 --username apiuser --password secret --device firewall01.example.local
```

### Dry Run (Recommended for first use)

```bash
python3 fmc_rule_cleanup.py --host 192.168.1.100 --username apiuser --password secret --device firewall01.example.local --dry-run
```

### Advanced Usage

```bash
python3 fmc_rule_cleanup.py \
  --host 192.168.1.100 \
  --username apiuser \
  --password secret \
  --device firewall01.example.local \
  --max-rules 500 \
  --exclude-zones TRUSTED DMZ \
  --log-file fmc_analysis.log \
  --debug \
  --dry-run
```

**Zone Exclusion Behavior:**
- By default, **no zones are excluded** - all rules are candidates for disabling if they meet other criteria
- Use `--exclude-zones` to specify one or more zones (space-separated) to protect from rule changes
- Rules involving excluded zones (as source or destination) will be skipped
- Example: `--exclude-zones TRUSTED CRITICAL MANAGEMENT` will skip any rule that involves any of these zones

**IP Prefix Exclusion:**
- Exclude rules based on IP address ranges using CIDR notation
- Use `--exclude-prefixes` to specify one or more IP prefixes (space-separated)
- Rules with source or destination networks matching excluded prefixes will be skipped
- Supports:
  - **CIDR notation**: `10.0.0.0/8`, `192.168.1.0/24`
  - **Single IPs**: `10.1.1.5`, `192.168.1.100`
  - **IP ranges**: `10.1.1.5-10.1.1.50` (FMC range notation)
  - **Network objects**: Automatically resolved via FMC API, including nested groups
- Example: `--exclude-prefixes 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12` protects RFC1918 private networks
- Works with both IPv4 and IPv6 addresses
- IP ranges containing > 256 addresses check only start and end IPs for performance

**Prefix Match Modes:**
- **overlap mode (default)**: Excludes rules with ANY network overlap
  - Rule with `10.0.0.0/8` → excluded when using `--exclude-prefixes 10.2.0.0/16` (superset)
  - Rule with `10.2.5.0/24` → excluded when using `--exclude-prefixes 10.2.0.0/16` (subset)
  - Rule with `"any"` → excluded (encompasses all IPs)
  - **Use case**: Conservative protection - prevents disabling any rule that might affect excluded networks
  
- **subnet mode**: Only excludes rules with networks that are subsets of excluded prefixes
  - Rule with `10.0.0.0/8` → NOT excluded when using `--exclude-prefixes 10.2.0.0/16` (superset)
  - Rule with `10.2.5.0/24` → excluded when using `--exclude-prefixes 10.2.0.0/16` (subset)
  - Rule with `"any"` → NOT excluded
  - **Use case**: Strict matching - only protects rules specifically targeting excluded networks
  - Enable with: `--prefix-match-mode subnet`

### Customizing Rule Selection Criteria

**Target older rules (created before 2020):**
```bash
python3 fmc_rule_cleanup.py \
  --host 192.168.1.100 \
  --username apiuser \
  --password secret \
  --device firewall01.example.local \
  --year-threshold 2020 \
  --dry-run
```

**Target BLOCK rules instead of ALLOW rules:**
```bash
python3 fmc_rule_cleanup.py \
  --host 192.168.1.100 \
  --username apiuser \
  --password secret \
  --device firewall01.example.local \
  --rule-actions BLOCK \
  --dry-run
```

**Target both ALLOW and BLOCK rules:**
```bash
python3 fmc_rule_cleanup.py \
  --host 192.168.1.100 \
  --username apiuser \
  --password secret \
  --device firewall01.example.local \
  --rule-actions ALLOW BLOCK \
  --dry-run
```

**Combined advanced criteria:**
```bash
python3 fmc_rule_cleanup.py \
  --host 192.168.1.100 \
  --username apiuser \
  --password secret \
  --device firewall01.example.local \
  --year-threshold 2022 \
  --rule-actions ALLOW BLOCK \
  --max-rules 200 \
  --exclude-zones TRUSTED CRITICAL \
  --exclude-prefixes 10.0.0.0/8 192.168.0.0/16 \
  --log-file cleanup.log \
  --dry-run
```

**Protect RFC1918 private networks:**
```bash
python3 fmc_rule_cleanup.py \
  --host 192.168.1.100 \
  --username apiuser \
  --password secret \
  --device firewall01.example.local \
  --exclude-prefixes 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 \
  --dry-run
```

**Use strict subnet matching (only exclude rules with exact subnets):**
```bash
python3 fmc_rule_cleanup.py \
  --host 192.168.1.100 \
  --username apiuser \
  --password secret \
  --device firewall01.example.local \
  --exclude-prefixes 10.2.0.0/16 \
  --prefix-match-mode subnet \
  --dry-run
```

**Generate Excel report with analysis results:**
```bash
python3 fmc_rule_cleanup.py \
  --host 192.168.1.100 \
  --username apiuser \
  --password secret \
  --device firewall01.example.local \
  --excel-report analysis_report.xlsx \
  --dry-run
```

## Command Line Arguments

### Required Arguments

- `--host`: FMC host IP address
- `--username`: FMC username with API access
- `--password`: FMC password
- `--device`: Target device name (cluster name)

### Optional Arguments

- `--autodeploy`: Enable automatic deployment (default: False)
- `--page-limit`: API page limit for queries (default: 500)
- `--debug`: Enable debug logging (default: False)
- `--timeout`: API timeout in seconds (default: 10). Increase this value (e.g., 30-60) if you experience frequent timeout errors with large rulesets
- `--log-file`: Log file name (default: console only). Logs are directed to the file only, keeping console output clean
- `--max-rules`: Maximum rules to disable per run (default: 1000)
- `--dry-run`: Simulate without making changes (default: False)
- `--exclude-zones`: Space-separated list of zones to exclude from processing (no default - must be explicitly specified if needed)
- `--exclude-prefixes`: Space-separated list of IP prefixes in CIDR notation to exclude from processing (e.g., 10.0.0.0/8 192.168.0.0/16)
- `--prefix-match-mode`: Mode for matching excluded prefixes - `overlap` (default, excludes any overlap) or `subnet` (only excludes subsets)
- `--excel-report`: Generate an Excel report file with three tabs: Operation Summary, Disabled Rules, and Ignored Rules (e.g., report.xlsx). Requires openpyxl package.
- `--year-threshold`: Consider rules created before this year for disabling (default: current year - 1)
- `--rule-actions`: Rule actions to consider for disabling - ALLOW, BLOCK, or both (default: ALLOW)

> **Note**: The year threshold automatically defaults to the previous year (e.g., in 2025 it defaults to 2024). This provides a sensible balance: protecting recent rules while targeting older unused rules for cleanup. The threshold adjusts automatically each year without requiring code changes.

## Rule Disable Criteria

A rule will be disabled if it meets ALL of the following criteria:

1. **Zero Hit Count**: The rule has never been triggered (hit count = 0)
2. **Enabled**: The rule is currently enabled
3. **Matching Action**: The rule has an action specified in `--rule-actions` (default: "ALLOW")
4. **Age or Previous Script Action**: Either:
   - Rule was created before the year specified by `--year-threshold` (default: current year - 1), OR
   - Rule was previously processed by this script
5. **Not in Excluded Zones**: Rule doesn't involve any zones specified in `--exclude-zones` (if provided)
6. **Not Using Excluded Prefixes**: Rule doesn't use any IP addresses/networks overlapping with `--exclude-prefixes` (if provided)
   - Checks both source and destination networks
   - Resolves network objects via FMC API to check actual IP ranges
   - Rules with "any" as source/destination are excluded if prefixes are specified (since "any" encompasses all IPs)

## Safety Features

- **Dry Run Mode**: Test the script without making changes
- **Maximum Rule Limit**: Prevents disabling too many rules in one execution
- **Consecutive Retry Limit**: Stops processing after 10 consecutive retry failures to prevent infinite loops
- **Progressive Backoff**: Increasing retry delays (60s, 90s, 120s, 240s) to handle temporary connectivity issues
- **Zone Exclusion**: Protects critical network zones from rule changes
- **IP Prefix Exclusion**: Protects rules involving specific IP address ranges (with automatic network object resolution)
- **Clean Console Interface**: Progress bar with real-time updates and retry information
- **Excel Report Generation**: Export detailed analysis to Excel with three sheets (Summary, Disabled Rules, Ignored Rules)
- **Comprehensive Logging**: Track all actions and decisions with separate log file
- **Error Handling**: Graceful handling of API errors, timeouts, and rate limits

## Output

The script provides detailed output including:

- Clean console interface with progress bar and percentage completion
- Retry countdown timers showing seconds remaining during retries
- Comprehensive summary of rules analyzed, disabled, and skipped
- Connection failure tracking with progressive backoff
- Detailed logging to file (when --log-file is specified)
- Final statistics report with detailed breakdown
- Optional Excel report with three tabs:
  - **Operation Summary**: Device name, analysis date, execution mode, and statistics
  - **Disabled Rules**: List of rules that were disabled (Rule Name, ID, First Comment, Disable Reason)
  - **Ignored Rules**: Zero-hit rules that were NOT disabled with detailed explanations:
    - **For excluded zones**: Shows specific zone names (source/destination)
    - **For excluded prefixes**: Shows network objects/literals and match mode used
    - **For criteria not met**: Shows rule creation year vs threshold
    - **For action/enabled issues**: Shows current state vs required state

Example console output:
```
Logging to file: firewall01.log
Successfully connected to FMC at 192.168.1.100
DRY RUN MODE - No changes will be made to FMC

Found 450 rules with zero hit counts
Processing 450 rules...
Progress: |█████████████████████████████████████████████████| 100.0% Complete (120 rules disabled)

============================================================
ANALYSIS COMPLETE - Summary:
  - Total rules analyzed:  1250
  - Rules with zero hits:  450
  - Rules disabled:        120
  - Rules skipped:         330
  - Connection failures:   0

DRY RUN COMPLETED - No changes were made to FMC.
============================================================
```

Example output during connection retry:
```
Progress: |████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░| 45.2% (25 rules) | Retry #2/4 - 43s remaining (consecutive: 3/10)
```

## Best Practices

1. **Always use --dry-run first** to understand what the script will do
2. **Start with smaller --max-rules values** for testing
3. **Increase timeout for large rulesets** - Use `--timeout 30` or `--timeout 60` when analyzing devices with thousands of rules
4. **Review logs carefully** before running in production
5. **Test in a non-production environment** first
6. **Coordinate with network teams** before mass rule changes
7. **Keep backups** of your FMC configuration

## Performance & Resilience

The script includes several features to handle large deployments and edge cases:

### Retry & Throttling
- **Advanced retry logic**: Connection timeouts are retried with progressive backoff delays (60s, 90s, 120s, 240s)
- **Consecutive retry limit**: Maximum of 10 consecutive retries across rules to prevent infinite retry loops
- **Rate limit handling**: HTTP 429 errors are handled internally by the fmcapi library with automatic retry
- **Visual countdown timer**: Shows remaining seconds during retry waits with progress updates
- **Configurable timeout**: Adjust with `--timeout` flag based on your environment (default: 10 seconds)
- **Enhanced progress tracking**: Clean console output with progress bar showing completion percentage and retry status

### IP Address Format Handling
The script handles various IP address formats used in FMC rules:

- **CIDR notation**: `10.0.0.0/8`, `192.168.1.0/24` - Standard network format
- **Single IPs**: `10.1.1.5` - Treated as /32 (IPv4) or /128 (IPv6)
- **IP ranges**: `10.1.1.5-10.1.1.50` - FMC's range notation
  - Small ranges (≤256 IPs): Every IP checked individually
  - Large ranges (>256 IPs): Only start and end IPs checked for performance
- **Network objects**: Automatically resolved and expanded via FMC API
- **Nested groups**: Recursively resolved with circular reference protection

**For large environments (1000+ rules with zero hits):**
```bash
python3 fmc_rule_cleanup.py \
  --host 192.168.1.100 \
  --username apiuser \
  --password secret \
  --device firewall01.example.local \
  --timeout 60 \
  --max-rules 100 \
  --log-file firewall01.log \
  --dry-run
```

The script will show a clean progress bar with retry information when needed:
```
Progress: |████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░| 45.2% (25 rules disabled)
```

If connection issues occur, the retry information is integrated into the progress display:
```
Progress: |████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░| 45.2% (25 rules) | Retry #2/4 - 43s remaining (consecutive: 3/10)
```

## Development

### Code Quality

The script follows Python best practices:

- PEP 8 code style compliance
- Type hints for better code documentation
- Comprehensive error handling
- Modular, object-oriented design
- Extensive logging and documentation

### Linting and Formatting

```bash
# Check code style
flake8 fmc_rule_cleanup.py

# Format code
black fmc_rule_cleanup.py

# Type checking
mypy fmc_rule_cleanup.py

# Comprehensive linting
pylint fmc_rule_cleanup.py
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**: Verify FMC credentials and API access permissions
2. **Device Not Found**: Ensure device name exactly matches FMC configuration
3. **API Timeouts**: Increase --timeout value for large environments
4. **Permission Denied**: Ensure user has access to modify access policies
5. **Connection Failures**: The script handles connection timeouts with progressive backoff and will automatically retry up to 4 times per rule with increasing delays (60s, 90s, 120s, 240s)
6. **Maximum Consecutive Retries**: If 10 consecutive connection failures occur across rules, the script will stop processing to prevent infinite retry loops

### Debug Mode

Use `--debug` flag for detailed troubleshooting information:

```bash
python3 fmc_rule_cleanup.py --host 192.168.1.100 --username apiuser --password secret --device firewall01.example.local --debug --dry-run
```

## Author

Artur Pinto (arturj.pinto@gmail.com)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided as-is for educational and operational purposes. Use at your own risk and ensure proper testing before production use. 