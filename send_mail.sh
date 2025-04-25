#!/bin/bash

# Email variables
TO="andrew.saw@vanguardmm.com"
SUBJECT="csv-import"
BODY="This is the vpn usage per user."
ATTACHMENT="/tmp/radius_usage.csv"  # Path to the CSV file

# Send the email with attachment using mutt and msmtp
echo "$BODY" | mutt -s "$SUBJECT" -a "$ATTACHMENT" -- "$TO"

# Check if the mail command was successful
if [ $? -eq 0 ]; then
    echo "Email sent successfully."
else
    echo "Failed to send the email."
fi
