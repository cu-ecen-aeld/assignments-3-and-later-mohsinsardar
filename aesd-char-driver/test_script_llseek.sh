#!/bin/bash

# Define the character device file
CHAR_DEVICE="/dev/aesdchar"

# Create a test string to write to the device
TEST_STRING="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Write the test string to the device using echo
echo "$TEST_STRING" > "$CHAR_DEVICE"

# Define the positions to seek to and the expected data
POSITIONS=("10" "20" "30")
EXPECTED_DATA=("A" "K" "U")

# Loop through the positions and verify llseek functionality
for i in "${!POSITIONS[@]}"; do
    POSITION="${POSITIONS[$i]}"
    EXPECTED="${EXPECTED_DATA[$i]}"
    
    # Use dd to seek to the specified position and read 1 byte
    DATA=$(dd if="$CHAR_DEVICE" bs=1 count=1 skip="$POSITION" 2>/dev/null)

    if [ "$DATA" == "$EXPECTED" ]; then
        echo "Position $POSITION: Passed (Expected: $EXPECTED, Got: $DATA)"
    else
        echo "Position $POSITION: Failed (Expected: $EXPECTED, Got: $DATA)"
    fi
done

# Clean up by removing the output file
rm -f outputfile