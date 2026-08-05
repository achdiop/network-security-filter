PROJECT: NETWORK SECURITY FILTER AND DIGITAL DETOX
PART: NETWORK SECURITY FILTER

This system acts as a high-speed, probabilistic firewall. It drops malicious 
network packets before they can reach the target application (e.g., a game 
server) by matching incoming IP addresses against a Bloom Filter.

To overcome the strict network isolation of Docker containers, this project 
utilizes a "Split-System Architecture":
1. The Internal Hook: Runs directly on the Host VM to intercept 
   raw packets at the edge.
2. The Admin Panel: Runs safely inside an isolated container (Pterodactyl 
   Panel) to provide a 24/7 interactive management dashboard.

--- FILES---
1. network_filter.py
   - Role: The Control Panel (User Interface).
   - Location: Runs inside the Pterodactyl container.
   - Function: Provides the interactive console, manages the local Bloom Filter, 
     updates the shared blocklist, and uses multi-threading to display live 
     traffic logs from the host.

2. host_interceptor.py
   - Role: The Interceptor (Packet Dropper).
   - Location: Runs natively on the Oracle VM host as root.
   - Function: Hooks into the Linux kernel via NetfilterQueue (Queue 1). It reads 
     the shared blocklist to build its own high-speed Bloom Filter in RAM and 
     silently drops (packet.drop()) any TCP traffic matching a blocked IP.

3. blocked_ips.txt
   - Role: Shared Memory.
   - Function: Acts as the bridge between the Docker container and the Host VM. 
     The UI writes to it, and the Host uses an OS-level watchdog to hot-reload 
     its Bloom Filter whenever this file is modified.

4. traffic.log
   - Role: Asynchronous Feedback Loop.
   - Function: The Host Interceptor writes live network strike events here. The 
     UI container continuously tails this file in a background thread to display 
     live events to the administrator.

--- DEPLOYMENT & EVALUATION GUIDE ---
PART A: Dependencies
Host VM (Root):
$ sudo apt install build-essential python3-dev libnetfilter-queue-dev
$ pip3 install mmh3 bitarray netfilterqueue scapy --break-system-packages

Container (Control Panel):
$ pip install mmh3 bitarray

PART B: Execution
1. Start the Control Panel:
   Run `network_filter.py` inside the Pterodactyl panel. The system will 
   initialize and wait at the `> ` prompt.

2. Route the Traffic (Host VM):
   Route incoming traffic for the target port (e.g., 25565 for my Minecraft server as showed in project demo) into the Netfilter.
   queue. Because Docker modifies iptables, this must be placed in the FORWARD chain:
   $ sudo iptables -I FORWARD -p tcp --dport 25565 -j NFQUEUE --queue-num 1

3. Start the Interceptor (Host VM):
   $ sudo python3 host_interceptor.py

PART C: Interactive Testing
In the Pterodactyl Control Panel, type `help` to view commands.
- Attempt to connect to the server from that IP.
- Type `add <IP>` to dynamically block a target.
- Attempt to connect to the server from that IP (blocked).

--- CLEANUP ---
To restore normal network traffic after evaluation, remove the kernel hook:
$ sudo iptables -D FORWARD -p tcp --dport 25565 -j NFQUEUE --queue-num 1

--- SOURCES ---
- Pterodactyl Panel:
https://pterodactyl.io/

- Python Environment Configuration:
https://github.com/pelican-eggs/generic/tree/main/python