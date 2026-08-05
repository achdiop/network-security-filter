import math 
import os 
import mmh3 
from bitarray import bitarray 
import time
import threading

# --- DATA STRUCTURE ---
def create_bloom_filter(expected_items, fp_rate): 
    m = int(-(expected_items * math.log(fp_rate)) / (math.log(2)**2))  
    k = int((m / expected_items) * math.log(2))  
    b_array = bitarray(m) 
    b_array.setall(0) 
    return {"size": m, "hash_count": k, "bit_array": b_array}

def add_item(filter_data, item): 
    for times in range(filter_data["hash_count"]): 
        filter_data["bit_array"][mmh3.hash(item, times) % filter_data["size"]] = 1 

def check_item(filter_data, item): 
    for i in range(filter_data["hash_count"]):
        if filter_data["bit_array"][mmh3.hash(item, i) % filter_data["size"]] == 0: 
            return False
    return True 


# --- LOGIC & LOGGING ---
def load_blocklist(filepath, filter_data): 
    """Ensures the text file exists and loads it into the UI's local filter."""
    if not os.path.exists(filepath): 
        # Create a default file if this is the very first time running
        with open(filepath, 'w') as f: f.write("203.0.113.42")
    
    count = 0
    with open(filepath, 'r') as f: 
        for line in f:
            target = line.strip()
            if target:
                add_item(filter_data, target) 
                count += 1
    print(f"[*] Successfully loaded {count} malicious IPs into the Bloom Filter.") 

def tail_logs():
    """
    A daemon function designed to run in the background. 
    It constantly watches traffic.log and prints new lines to the console
    so the user sees real-time network drops without typing commands.
    """
    log_file = "traffic.log"
    if not os.path.exists(log_file):
        open(log_file, 'w').close()

    with open(log_file, 'r') as f:
        # Move the file cursor to the absolute end (byte 0 from SEEK_END).
        # We only want to see NEW traffic, not the entire historical log.
        f.seek(0, os.SEEK_END) 
        
        while True:
            line = f.readline()
            if not line:
                # If no new line was written, sleep briefly to save CPU, then check again
                time.sleep(0.5) 
                continue
            
            # \r clears the current input prompt so the log doesn't mess up typed text
            # flush=True forces the terminal to print immediately
            print(f"\r{line.strip()}\n> ", end="", flush=True) 


# --- PTERODACTYL INTERACTIVE UI  ---
if __name__ == "__main__":
    # Workaround: Ensures Docker container has required libraries installed on startup
    os.system("pip install mmh3 bitarray --quiet")

    print("\n" + "="*50)
    print("🛡️  NETWORK SECURITY CONTROL PANEL  🛡️")
    print("="*50)
    
    # Initialize the UI's local Bloom Filter
    network_filter = create_bloom_filter(expected_items=1000000, fp_rate=0.01)
    load_blocklist("blocked_ips.txt", network_filter)
    
    print("\nCOMMAND DASHBOARD:\n")
    print("  help         : Displays a list of valid commands.")
    print("  <IP Address> : Checks if the IP is currently blocked.")
    print("  add <IP>     : Permanently adds an IP to the blocklist.")
    print("  reload       : Re-reads the entire text file.")
    print("  exit/stop    : Shuts down the panel.\n")

    # Spawn the background thread to watch the log file while we listen for input
    monitor_thread = threading.Thread(target=tail_logs, daemon=True)
    monitor_thread.start()

    # Infinite loop to keep the Pterodactyl server marked as "Running" 24/7
    while True:
        try:
            # Block and wait for the user to type something in the Pterodactyl web console
            user_input = input("> ").strip()
            if not user_input: continue
            
            # Parse the command
            parts = user_input.split()
            command = parts[0].lower()

            if command in ['exit', 'stop', 'quit']:
                print("[*] Shutting down Control Panel...")
                break

            elif command == 'add':
                if len(parts) > 1:
                    new_ip = parts[1]
                    # 1. Save to disk so the Host Interceptor sees it
                    with open("blocked_ips.txt", "a") as f: 
                        f.write(f"\n{new_ip}")
                    # 2. Update the local UI filter instantly
                    add_item(network_filter, new_ip)
                    print(f"🔒  [UPDATED] {new_ip} added to file. Host will sync automatically.")
                else:
                    print("⚠️  [ERROR] Specify an IP. Example: add 192.168.1.50")

            elif command == 'reload':
                # Rebuilds the UI filter from scratch
                network_filter = create_bloom_filter(expected_items=1000000, fp_rate=0.01)
                load_blocklist("blocked_ips.txt", network_filter)

            elif command == 'help':
                print("\nCOMMAND DASHBOARD:\n")
                print("  help         : Displays a list of valid commands.")
                print("  check <IP>   : Checks if the IP is currently blocked.")
                print("  add <IP>     : Permanently adds an IP to the blocklist.")
                print("  reload       : Re-reads the entire text file.")
                print("  exit/stop    : Shuts down the panel.\n")

            elif command == 'check':
                if len(parts) == 1:
                    print("⚠️  [ERROR] Specify an IP. Example: check 192.168.1.50")
                elif len(parts) > 1:
                    # Allows checking multiple IPs at once (e.g. check 192.168.1.1 10.0.0.1)
                    for i in range(1, len(parts)):
                        target_ip = parts[i]
                        if check_item(network_filter, target_ip):
                            print(f"🚨 [BLOCKED] {target_ip} is currently on the blocklist.")
                        else:
                            print(f"✅ [ALLOWED] {target_ip} is clear.")
            
            else:
                print("⚠️  [ERROR] Not a valid input. Try help")

        except EOFError: 
            # Prevents crashes if the web socket to the Pterodactyl console temporarily drops
            time.sleep(1)
        except KeyboardInterrupt: 
            # Handles forceful SIGINT stops
            break