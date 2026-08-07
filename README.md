# 🛜🔐 Network Security Filter — Bloom Filter Firewall 🫷🛑

A high-speed, probabilistic firewall that drops malicious traffic before it reaches a target application (e.g. a game server), using a **Bloom Filter** for O(k) IP membership checks instead of a linear list lookup.

This was built as a practical implementation of Bloom filters for a Data Structures & Algorithms course. A companion project applying the same data structure to a different problem — application-level access control for digital wellbeing — is linked at the bottom of this README.

---

## 🤔 How It Works

Standard firewalls check incoming IPs against a blocklist using a list or hash set. As the list grows, so does lookup cost (or memory). This project swaps that lookup for a **Bloom filter**: a probabilistic set membership structure that answers "definitely not blocked" or "probably blocked" in constant time, using a fraction of the memory a full IP set would need — at the cost of a small, tunable false-positive rate.

Because the target application runs inside a Docker container (Pterodactyl), and Docker's network isolation prevents raw packet interception from inside the container, the system is split across two cooperating processes:

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│   HOST VM (root)             │         │   DOCKER CONTAINER            │
│                               │         │   (Pterodactyl Panel)         │
│   host_interceptor.py         │         │   network_filter.py           │
│   • Hooks kernel via          │         │   • Interactive admin console │
│     NetfilterQueue            │         │   • Local Bloom filter for    │
│   • Builds Bloom filter        │◄──────►│     instant IP checks         │
│     from shared file           │  file   │   • Writes new IPs to the    │
│   • Drops/accepts packets      │  based  │     shared blocklist file    │
│   • Logs strikes               │  bridge │   • Tails the log file live  │
└─────────────────────────────┘         └──────────────────────────────┘
              │                                          ▲
              └──────── blocked_ips.txt / traffic.log ───┘
```

The two processes don't share memory directly — they communicate through two files on disk:

- **`blocked_ips.txt`** — the blocklist. The admin panel appends to it; the host watches its modified timestamp and hot-reloads its own in-RAM Bloom filter whenever it changes.
- **`traffic.log`** — the event feed. The host writes a line every time it drops or accepts a packet; the admin panel tails this file in a background thread to show live activity.

---

## 📂 Files

| File | Runs On | Role |
|---|---|---|
| `host_interceptor.py` | Host VM, as root | Intercepts raw packets via NetfilterQueue and drops traffic from blocked IPs |
| `network_filter.py` | Inside the Docker/Pterodactyl container | Interactive control panel: add/check IPs, reload the filter, watch live traffic |
| `blocked_ips.txt` | Shared file | The blocklist — the bridge between container and host |
| `traffic.log` | Shared file (generated at runtime) | Live log of dropped/accepted packets |

---

## 👨‍👩‍👧‍👦 Prerequisites

- An Oracle/Linux VM (or similar) where you have root access, running Docker with a Pterodactyl panel (or any container platform with a similar isolation model)
- A target application/game server running inside the container (this project was demoed against a Minecraft server on port `25565`)
- Python 3 on both the host and inside the container

---

## 🔢 Step-by-Step Setup

### 1. Install host dependencies (on the VM, as root)

```bash
sudo apt install build-essential python3-dev libnetfilter-queue-dev
pip3 install mmh3 bitarray netfilterqueue scapy --break-system-packages
```

### 2. Install container dependencies (inside the Pterodactyl panel)

```bash
pip install mmh3 bitarray
```

### 3. Configure the shared directory path

`host_interceptor.py` needs to know where the container's shared volume lives on the host filesystem so it can read `blocked_ips.txt` and write `traffic.log`. Update the `SHARED_DIR` constant near the top of the file to match your Pterodactyl volume path, e.g.:

```python
SHARED_DIR = "/var/lib/pterodactyl/volumes/<your-server-volume-uuid>"
```

> This path is server-specific — find it under your Pterodactyl data directory for the relevant server instance.

### 4. Start the Control Panel (inside the container)

```bash
python3 network_filter.py
```

This initializes the local Bloom filter, loads any existing entries from `blocked_ips.txt`, spawns the log-tailing thread, and drops you into an interactive `>` prompt.

### 5. Route traffic into the Netfilter queue (on the host)

Because Docker rewrites `iptables`, the rule has to go into the `FORWARD` chain rather than `INPUT`:

```bash
sudo iptables -I FORWARD -p tcp --dport 25565 -j NFQUEUE --queue-num 1
```

(Replace `25565` with your application's port.)

### 6. Start the Interceptor (on the host, as root)

```bash
sudo python3 host_interceptor.py
```

You should see:

```
[*] Loading Host Bloom Filter from Pterodactyl shared file...
[*] Host Filter Sync Complete.
[*] Host Interceptor running on Queue 1. Protecting system...
```

---

## 🧪 Interactive Testing

With both processes running:

1. In the control panel, type `help` to see available commands.
2. Connect to the target server from a test IP — it should pass through normally.
3. In the control panel, block that IP:
   ```
   > add <IP>
   ```
4. Attempt to connect again from the same IP — it should now be silently dropped, and you'll see a live strike event logged in both the panel and the host console.
5. Use `check <IP>` at any time to test membership without adding it.

---

## 🧹 Cleanup

Once you're done evaluating, remove the kernel hook to restore normal traffic:

```bash
sudo iptables -D FORWARD -p tcp --dport 25565 -j NFQUEUE --queue-num 1
```

---

## 📓 Design Notes & Limitations

- **Two independent Bloom filters.** The host and the container each maintain their own in-memory filter, kept in sync only by re-reading the shared text file — this is a simple, coursework-appropriate approach rather than true shared memory or IPC.
- **No deletions.** Bloom filters don't natively support removing an item without a more complex structure (e.g. a counting Bloom filter), so unblocking an IP currently requires rebuilding the filter from an edited blocklist file.
- **False positives are possible, false negatives are not.** With `fp_rate=0.01`, roughly 1% of legitimate IPs could — in rare cases — be mistakenly flagged, but a truly blocked IP will never slip through.
- **File-based hot reload.** The host checks `blocked_ips.txt`'s modified timestamp on every packet, which is simple and effective at this scale but wouldn't be the pattern of choice for a production system.

---

## 🖇️ Companion Project

This is one of two Bloom filter implementations built for the same DSA coursework. The second project, **Digital Detox Filter**, applies the same underlying data structure to application/website-level blocking for digital wellbeing:

🔗 [Digital Detox Filter](https://github.com/achdiop/digital-detox-filter)

---

## 🤝 Team
This project was a collaborative team effort.

| Name | Contribution |
| :--- | :--- |
| [**Abbas Dar**](https://github.com/achdiop) | Worked on the Network Security Filter including the VM setup |
| [**Muhammad Saad Masood**](https://github.com/) | Worked on the Digital Detox including the custom browser extension setup |
| [**Syed Aayan Rizvi**](https://github.com/AAyannn-del) | Coordinated with both the teammates and worked on documentations and presentations |

---

## Sources

- [Pterodactyl Panel](https://pterodactyl.io/)
- [Python Environment Configuration (Pelican Eggs)](https://github.com/pelican-eggs/generic/tree/main/python)
