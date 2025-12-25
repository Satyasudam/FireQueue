# FireQueue
A custom Linux firewall system written in c integrating iptables, libpcap and NFQUEUE (libnetfilter_queue)
Supports Dual Modes:

- **Simulation** (sniff-only via `libpcap`)
- **Enforcement** (active filtering via `NFQUEUE`)

Includes modular rule matching, NAT and redirection support, and a CLI interface for managing rules. Designed for learning, testing, and demonstrating packet-level filtering and traffic control in Linux using raw socket-level access and Netfilter hooks.

---

## Project Structure
``` bash
firewall-project/
├── include/                        # Header files
│   ├── cli.h
│   ├── fw_core.h
│   ├── logger.h
│   ├── nfqueue_handler.h
│   ├── packet_parser.h
│   ├── rules.h
│   ├── config.h
│   └── stats.h
│
├── src/                            # Source code
│   ├── cli.c
│   ├── fw_core.c
│   ├── logger.c
│   ├── main.c                      # Entry point
│   ├── nfqueue_handler.c
│   ├── packet_parser.c
│   ├── rule.c
│   └── stats.c
│
├── scripts/                          # Helper scripts
│   ├── flush_nfqueue.sh              # flushes the iptables rule chains
│   ├── clean.sh                      # cleans the logs and rules
│
├── data/                           # Persistent runtime data
│   └── rules.conf                  # Rule definitions (loaded at runtime)
|
├── Makefile                        # Project build script
├── README.md                       # Project overview
└── run_enforce.sh                  # Runs the enforcement mode
|__ run_sim.sh                      # Runs only the simulation mode
```


---

##  Features

-  **IPv4 & IPv6 support**  
-  **NFQUEUE integration** for enforcement mode  
-  **libpcap-based passive mode**  
-  **CLI-based rule management** (add/delete/enable/disable/order)
-  **Persistent rule config**  
-  **Basic traffic logging**

---

##  Dependencies

- `libpcap-dev`  
- `libnetfilter-queue-dev`  
- `iptables`, `ip6tables`

Install via:

```bash
sudo apt install libpcap-dev libnetfilter-queue-dev iptables iproute2
```

 Usage
Run in Enforcement Mode (NFQUEUE-based)
```bash
sudo ./run_enforce.sh
```

This will load iptables/ip6tables rules and launch the firewall in active mode.

Run in Simulation Mode (Sniffer)
```base
sudo ./run_simulate.sh
```

This passively monitors traffic and matches rules without enforcing any verdicts.

 Rule Management CLI
```bash
===== FIREWALL MENU ====:
1. Add rule
2. Show rules
3. Delete rule
4. Enable/Disable rule
5. Save rules
6. Load rules
7. Start simulation
8. Exit
```
```bash
Select mode:
1. Simulation (pcap)
2. Enforcement (NFQUEUE)
3. Main menu
0. Exit
```
