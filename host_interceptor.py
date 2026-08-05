import os
import time
import math
import mmh3
from bitarray import bitarray
from netfilterqueue import NetfilterQueue
from scapy.all import IP

# ---  DATA STRUCTURE ---
def create_bloom_filter(expected_items, fp_rate):
    # Calculate optimal size (m) of the bit array based on expected items and desired false positive rate
    m = int(-(expected_items * math.log(fp_rate)) / (math.log(2)**2))
    # Calculate optimal number of hash functions (k) to minimize false positives
    k = int((m / expected_items) * math.log(2))  

    # Initialize the bit array with all bites to 0.
    b_array = bitarray(m) 
    b_array.setall(0) 

    return {"size": m, "hash_count": k, "bit_array": b_array}

def add_item(filter_data, item):
    # Pass the item through 'k' number of hash functions
    for times in range(filter_data["hash_count"]):
        # mmh3 (MurmurHash3) is used for fast, non-cryptographic hashing.
        # Modulo (%) ensures the hash value fits within our bit array bounds.
        filter_data["bit_array"][mmh3.hash(item, times) % filter_data["size"]] = 1 

def check_item(filter_data, item):
    # To check membership, hash the item 'k' times again
    for i in range(filter_data["hash_count"]):
        # If ANY of the required bits are 0, the item is DEFINITELY NOT in the set
        if filter_data["bit_array"][mmh3.hash(item, i) % filter_data["size"]] == 0: 
            return False
    # If all checked bits are 1, the item is PROBABLY in the set
    return True 

# ---  CONFIGURATION & ---
# The physical path on the Oracle VM hard drive where Pterodactyl stores this server's files
SHARED_DIR = "/var/lib/pterodactyl/volumes/1387f578-a596-4267-99a2-97cfab06e4fb"
SHARED_BLOCKLIST = os.path.join(SHARED_DIR, "blocked_ips.txt")
SHARED_LOG = os.path.join(SHARED_DIR, "traffic.log")

# Global variables to hold our active filter and track file changes for the hot-reload feature
active_filter = None
last_modified_time = 0

def load_filter_from_shared_file():
    """Reads the text file and populates the high-speed Bloom Filter in RAM."""
    global active_filter, last_modified_time
    print("[*] Loading Host Bloom Filter from Pterodactyl shared file...")

    # Initialize a fresh filter designed to hold 1 million IPs with a 1% error rate
    active_filter = create_bloom_filter(expected_items=1000000, fp_rate=0.01)
    
    if os.path.exists(SHARED_BLOCKLIST):
        with open(SHARED_BLOCKLIST, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip: 
                    add_item(active_filter, ip)

        # Record the exact timestamp the file was last edited so we know if it changes later
        last_modified_time = os.path.getmtime(SHARED_BLOCKLIST)
        print("[*] Host Filter Sync Complete.")

# --- PACKET PROCESSING INTERCEPTOR ---
def process_packet(packet):
    global last_modified_time
    
    # HOT-RELOAD CHECK: Before processing the packet, see if the Pterodactyl UI added a new IP
    if os.path.exists(SHARED_BLOCKLIST):
        current_mtime = os.path.getmtime(SHARED_BLOCKLIST)
        if current_mtime > last_modified_time:
            print("\n[*] Panel update detected! Reloading blocklist...")
            load_filter_from_shared_file()

    # Convert the raw network payload into a readable Scapy IP object
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(IP):
        src_ip = scapy_packet[IP].src
        
        # O(k) Time Complexity Check: Is the source IP in our Bloom Filter?
        if check_item(active_filter, src_ip):
            # MALICIOUS: Silently destroy the packet. The sender gets no response.
            packet.drop()
            # Log it so the Pterodactyl UI can display the strike
            with open(SHARED_LOG, 'a') as log_file:
                log_file.write(f"📡 [LIVE STRIKE] Dropped malicious packet from {src_ip}\n")
            print(f"📡 [LIVE STRIKE] Dropped malicious packet from {src_ip}\n")
        else:
            # SAFE: Allow the packet to pass through to the Docker container
            packet.accept()
            with open(SHARED_LOG, 'a') as log_file:
                log_file.write(f"📡 [LIVE STRIKE] Accepted packet from {src_ip}\n")
            print(f"📡 [LIVE STRIKE] Accepted packet from {src_ip}\n")


# --- MAIN EXECUTION ---
if __name__ == "__main__":
    load_filter_from_shared_file()
    try:
        # Create a connection to the Linux Kernel's Netfilter system
        queue = NetfilterQueue()
        # Bind to Queue #1 (matching our iptables command) and assign our processing function
        queue.bind(1, process_packet)
        print("[*] Host Interceptor running on Queue 1. Protecting system...")
        # Start the infinite loop to catch packets (Context Switch begins here)
        queue.run()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\n[*] Shutting down Host Interceptor...")
    finally:
        # Release the queue back to the operating system to prevent network lockups
        queue.unbind()