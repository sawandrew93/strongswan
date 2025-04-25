#!/bin/bash

# Combine logs into a single file
cat /var/log/freeradius/radacct/127.0.0.1/detail-* > /tmp/radius.log

# Process logs and output to CSV
awk '
/User-Name/ { user = $NF }
/Acct-Input-Octets/ { input[user] += $NF }
/Acct-Output-Octets/ { output[user] += $NF }
END {
    # Print CSV header
    print "User Name,Input (MB),Output (MB),Total (MB)"
    for (u in input) {
        # Print data in CSV format
        printf "%s,%.2f,%.2f,%.2f\n", u, input[u]/(1024*1024), output[u]/(1024*1024), (input[u] + output[u])/(1024*1024)
    }
}
' /tmp/radius.log > /tmp/radius_usage.csv

# Notify user of the output file location
echo "CSV file generated at /tmp/radius_usage.csv"
