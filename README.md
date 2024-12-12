# A Linux Firewall Based on Netfilter


## Overview

A Linux firewall based on Netfilter and Character Device.

Features:



## Features
- Key features of your firewall:
   - Real-time packet filtering.
   - User-space and kernel-space communication via Character Device.
   - Filter packets based on source IP, destination IP, port number, and protocol.
   - Users can add, delete, and view all rules.
   - Log packet filtering activities and allow users to view log contents.
   - Connection state detection.


## Requirements
- List of dependencies:
  - Linux Kernel version: `6.8.0`.
  - Build tools: `gcc version 11.4.0`.


Here's the revised version of your usage section with the updated command format, which includes `sudo ./myfw` for each command:

## Usage

### Clone the repository

### Build the kernel module
```
make
```

### Load the kernel module
```
sudo insmod myfw.ko
```

### `-p, --print [Options]`
This option allows users to print all current data, including rules, connections, and logs. Use this command to view the state of your firewall rules and other relevant information.

Example usage:
```bash
sudo ./myfw -p
```

### `-a, --add <src_ip> <dst_ip> <src_mask> <dst_mask> <src_port> <dst_port> <protocol> <action> <log>`
This option is used to add a new firewall rule. The user can specify the source and destination IP addresses, source and destination subnet masks, source and destination port numbers, the protocol (TCP/UDP), the action to take (e.g., allow or block), and whether or not to log the traffic.

Example usage:
```bash
sudo ./myfw -a 192.168.0.1 192.168.1.1 255.255.255.0 255.255.255.0 8080 80 TCP allow true
```
This command adds a rule to allow TCP traffic from IP 192.168.0.1 to IP 192.168.1.1 on port 8080 to 80.

### `-d, --del <index1, index2...>`
This option allows users to delete firewall rules by specifying their index positions in the rule list. Multiple rule indices can be provided, separated by commas.

Example usage:
```bash
sudo ./myfw -d 1,3,5
```
This command deletes the rules at indices 1, 3, and 5 from the rule set.

### `-c, --commit`
This option commits the current firewall rules to the Linux kernel. It applies the active rules, making them effective in the system’s networking stack.

Example usage:
```bash
sudo ./myfw -c
```

### `--dl`
This option removes all rules from the database. It clears out the rule set, returning the firewall to a default state.

Example usage:
```bash
sudo ./myfw --dl
```

### Example Usage

```bash
# Add a new rule
sudo ./myfw -a 192.168.1.1 10.0.0.1 255.255.255.0 255.255.255.0 80 80 TCP allow true

# Print current rules
sudo ./myfw -p

# Commit the changes to the kernel
sudo ./myfw -c

# Delete rules by index
sudo ./myfw -d 2,4

# Clear all rules from the database
sudo ./myfw --dl
```

