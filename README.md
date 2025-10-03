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
- **Dry Run Mode**: Simulate operations without making actual changes to FMC
- **Comprehensive Logging**: Detailed logging with configurable verbosity levels
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
   export EXCLUDE_ZONES="TRUSTED CRITICAL MANAGEMENT"
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
  --log-file cleanup.log \
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
- `--timeout`: API timeout in seconds (default: 10)
- `--log-file`: Log file name (default: console only)
- `--max-rules`: Maximum rules to disable per run (default: 1000)
- `--dry-run`: Simulate without making changes (default: False)
- `--exclude-zones`: Zones to exclude from processing (default: TRUSTED)
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
5. **Not in Excluded Zones**: Rule doesn't involve any zones specified in --exclude-zones

## Safety Features

- **Dry Run Mode**: Test the script without making changes
- **Maximum Rule Limit**: Prevents disabling too many rules in one execution
- **Zone Exclusion**: Protects critical network zones from rule changes
- **Comprehensive Logging**: Track all actions and decisions
- **Error Handling**: Graceful handling of API errors and edge cases

## Output

The script provides detailed output including:

- Progress information during execution
- Summary of rules analyzed, disabled, and skipped
- Detailed reasoning for each rule decision (in debug mode)
- Final statistics report

Example output:
```
==================================================
OPERATION SUMMARY
==================================================
Total rules analyzed: 1250
Rules with zero hits: 450
Rules disabled: 120
Rules skipped: 330

NOTE: This was a dry run - no changes were made to FMC
==================================================
```

## Best Practices

1. **Always use --dry-run first** to understand what the script will do
2. **Start with smaller --max-rules values** for testing
3. **Review logs carefully** before running in production
4. **Test in a non-production environment** first
5. **Coordinate with network teams** before mass rule changes
6. **Keep backups** of your FMC configuration

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