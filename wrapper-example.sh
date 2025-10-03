#!/bin/bash
#
# Example wrapper script for FMC Hit Count Analysis
# 
# Usage:
#   1. Copy this file: cp wrapper-example.sh my-wrapper.sh
#   2. Create your environment file: cp example.env my-production.env
#   3. Edit my-production.env with your actual values
#   4. Make executable: chmod +x my-wrapper.sh
#   5. Run: ./my-wrapper.sh --dry-run
#

# Name of your environment file
ENV_FILE="my-production.env"

# Check if environment file exists
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: Environment file '$ENV_FILE' not found!"
    echo "Please create it by copying and editing example.env:"
    echo "  cp example.env $ENV_FILE"
    echo "  # Edit $ENV_FILE with your actual values"
    exit 1
fi

# Load environment variables
echo "Loading configuration from $ENV_FILE..."
source "$ENV_FILE"

# Verify required variables are set
if [ -z "$FMC_HOST" ] || [ -z "$FMC_USERNAME" ] || [ -z "$FMC_PASSWORD" ] || [ -z "$DEVICE_NAME" ]; then
    echo "Error: Required environment variables not set!"
    echo "Please check your $ENV_FILE file contains:"
    echo "  FMC_HOST, FMC_USERNAME, FMC_PASSWORD, DEVICE_NAME"
    exit 1
fi

# Build the command
CMD="python3 fmc_rule_cleanup.py"
CMD="$CMD --host \"$FMC_HOST\""
CMD="$CMD --username \"$FMC_USERNAME\""
CMD="$CMD --password \"$FMC_PASSWORD\""
CMD="$CMD --device \"$DEVICE_NAME\""

# Add optional parameters if set
[ -n "$MAX_RULES" ] && CMD="$CMD --max-rules $MAX_RULES"
[ -n "$PAGE_LIMIT" ] && CMD="$CMD --page-limit $PAGE_LIMIT"
[ -n "$TIMEOUT" ] && CMD="$CMD --timeout $TIMEOUT"
[ -n "$LOG_FILE" ] && CMD="$CMD --log-file \"$LOG_FILE\""
[ -n "$EXCLUDE_ZONES" ] && CMD="$CMD --exclude-zones $EXCLUDE_ZONES"
[ -n "$YEAR_THRESHOLD" ] && CMD="$CMD --year-threshold $YEAR_THRESHOLD"
[ -n "$RULE_ACTIONS" ] && CMD="$CMD --rule-actions $RULE_ACTIONS"
[ "$DEBUG" = "true" ] && CMD="$CMD --debug"
[ "$AUTODEPLOY" = "true" ] && CMD="$CMD --autodeploy"

# Add any additional arguments passed to this script
CMD="$CMD $@"

# Show the command being executed
echo "Executing: $CMD"
echo ""

# Execute the command
eval $CMD