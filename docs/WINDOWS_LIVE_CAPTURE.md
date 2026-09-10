# Live capture on Windows

NetGuard uses Scapy for packet access. Live capture must only be used on a
network that you own or are explicitly authorized to monitor.

1. Install the current Npcap release with its WinPcap-compatible option.
2. Open PowerShell as Administrator in the repository directory.
3. Install the optional capture dependency:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[pcap]"
```

List the interface names visible to Scapy:

```powershell
.\.venv\Scripts\python.exe -c "from scapy.all import get_if_list; print('\n'.join(get_if_list()))"
```

Capture for 30 seconds using Scapy's default interface:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.cli --live --duration 30
```

Or select an interface explicitly:

```powershell
.\.venv\Scripts\python.exe -m netguard_ids.cli --live --interface "Ethernet" --duration 60
```

The JSON report and HTML dashboard are saved under `reports/`.
