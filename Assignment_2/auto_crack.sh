#!/bin/bash

# Define paths and filenames
PIN_BIN="../../../pin"
PIN_TOOL="obj-intel64/rsa_attack.so"
PYTHON_EXTRACTOR="extract_key.py"
TRACE_FILE="trace.txt"
KEY_FILE="key.txt"

# Check if the user provided a target binary
if [ -z "$1" ]; then
    echo "Usage: ./auto_crack.sh <path_to_vulnerable_binary>"
    echo "Example: ./auto_crack.sh ./leaky_rsa"
    exit 1
fi

TARGET_BIN="$1"

echo "=================================================="
echo "          RSA Square & Multiply Auto-Cracker      "
echo "=================================================="

# Step 1: Clean up old artifacts
rm -f $TRACE_FILE $KEY_FILE

# Step 2: Run the PIN instrumentation
echo "[*] Step 1: Instrumenting target binary to generate execution trace..."
$PIN_BIN -t $PIN_TOOL -- $TARGET_BIN > /dev/null 2>&1

if [ ! -f "$TRACE_FILE" ]; then
    echo "[-] Error: Failed to generate trace file. Check your PIN paths and compilation."
    exit 1
fi
echo "[+] Trace generated successfully."

# Step 3: Run the Python parsing script
echo "[*] Step 2: Parsing trace to extract 64-bit secret key..."
python3 $PYTHON_EXTRACTOR > /dev/null

if [ ! -f "$KEY_FILE" ]; then
    echo "[-] Error: Python script failed to generate key.txt."
    exit 1
fi

# Step 4: Verify the key against the target binary
EXTRACTED_KEY=$(cat $KEY_FILE)
echo "[+] Key extracted: $EXTRACTED_KEY"
echo "[*] Step 3: Verifying key against the target binary..."
echo "--------------------------------------------------"

$TARGET_BIN -a $EXTRACTED_KEY

echo "--------------------------------------------------"
echo "[+] Exploit sequence complete."
