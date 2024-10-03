#!/bin/bash

# Clear ip addressing on eth0
flush_eth0_ip() {
    ip addr flush dev eth0
    ip -6 addr flush dev eth0
}

# Function to run the startup script after a delay
# run_startup_script() {
#     # Flush eth0 IP address

# }

# # Start the function in the background
# run_startup_script

flush_eth0_ip

sleep 5

# Run IOUYAP
exec /usr/bin/iouyap 513 -q &

# Get the highest numbered eth interface
max_eth=$(ls /sys/class/net | grep eth | grep -o -E '[0-9]+' | sort -n | tail -1)
num_slots=$(( (max_eth + 4) / 4 ))

# Start IOL
# exec /iol/iol.bin 10 -e $num_slots -s 0 -c config.txt
exec /iol/iol.bin 1 -e $num_slots -s 0 -d 0 -c config.txt -- -n 1024 -q -m 1024


# Start bash interactively
exec "$@"