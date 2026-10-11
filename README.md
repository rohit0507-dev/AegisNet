

<img width="1918" height="984" alt="03_Traffic_Records" src="https://github.com/user-attachments/assets/43c30b85-72c3-4ca8-b11c-f4d3de40d81f" />
# AegisNet — Computer Networks project

**Real-Time Network Traffic Monitoring and Intrusion Detection System**

| Team member | Registration number |
| --- | --- |
| Bhumireddi Rohit | 24BDS0387 |<img width="1918" height="984" alt="02_Dashboard" src="https://github.com/user-attachments/assets/2e81ab00-3a1f-4bac-bb1d-ec1a78086411" />
<img width="1918" height="984" alt="01_Homepage" src="https://github.com/user-attachments/assets/15268c7d-a5f4-4920-a795-f87ddd5960ec" />
<img width="1918" height="984" alt="06_Project_Details" src="https://github.com/user-attachments/assets/f11bf8bf-6be2-41f7-96e6-4613cd8820e8" />
<img width="1918" height="984" alt="05_Tools_Results" src="https://github.com/user-attachments/assets/7d1a7aac-c232-4de0-99dd-07eb50a80700" />
<img width="1918" height="984" alt="04_Network_Tools" src="https://github.com/user-attachments/assets/522f94aa-53e3-48ea-b86b-db5eac233738" />

| Parth Batra | 24BDS0416 |
| Somya Raj Singh Dalawat | 24BCE3001 |

A local network monitoring project built with Python, Scapy, Flask, and SQLite. It groups packets into directional flows, checks them for unusual behaviour, and displays the results in a browser. Isolation Forest provides an additional anomaly check alongside the network rules.

## Start on Windows — VS Code / PowerShell

Extract the ZIP first. Open the **inner AegisNet folder containing `requirements.txt`** in VS Code. Windows may create an outer folder such as `AegisNet (2)`; the actual project folder is inside it. Use **Python 3.12 (64-bit)** for the tested dependency versions.

Run these commands in that folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --train-model
.\.venv\Scripts\python.exe run_dashboard.py
```

Open **http://127.0.0.1:5000** in Chrome or Edge. The project introduction opens first; choose **Open network monitor** to enter the dashboard. Keep the terminal open.

If an older version is still running, stop that terminal with **Ctrl+C** before starting this copy. Use **Ctrl+F5** in the browser to reload the new styles. Run setup commands one at a time and let dependency installation finish; interrupting it can leave packages such as `joblib` missing.

There is no need to activate the environment or change PowerShell execution policy. The setup trains the same Isolation Forest architecture on the included 166-row feature dataset; it is a small academic baseline.

Alternatively, double-click **INSTALL_WINDOWS.bat** once, then **START_WINDOWS.bat** on subsequent runs. Installation needs internet access. Dashboard CSS, icons, charts, and JavaScript are local and work offline after setup.

### Live capture on Windows

1. Install [Npcap](https://npcap.com/#download), following the [Scapy Windows instructions](https://scapy.readthedocs.io/en/stable/installation.html#windows). It is the packet-capture driver; installing a Python package does not install it.
2. Launch the dashboard. If Npcap is restricted to administrators, open the terminal as **Administrator** before running the dashboard.
3. Click **Capture controls**, select the active Wi-Fi or Ethernet adapter, then **Start capture**.
4. Browse normally or use another authorised application on that machine. Flow windows are processed approximately every five seconds. A busy window may take longer to analyse.
5. Click **Stop capture** to save the last window. **Pause updates** freezes dashboard polling only; it does not stop capture.

The sensor sees traffic available on the selected interface. It does not automatically see every device on a switched LAN. Capture only traffic you are authorised to inspect.

### Existing data

Your original **103,315 flow records and 3,785 response events are retained**. The UI labels them **Saved data**, including their original dates. No generated traffic was added to your database.

Time selections such as **Latest 5 minutes** end at the newest saved record. This makes recorded sessions explorable even when capture is stopped. Starting a capture appends new records; a short range then follows the new capture. **All saved records** includes previous runs.

To keep the original history and start a separate empty database:

```powershell
$env:AEGISNET_DB = "$PWD\data\fresh_capture.db"
.\.venv\Scripts\python.exe run_dashboard.py
```

The capture process inherits the chosen database path. To return to the included database, stop the dashboard, then run `Remove-Item Env:AEGISNET_DB` in that terminal and restart. No history is deleted.

## Dashboard pages

| Section | Purpose |
| --- | --- |
| Project home | Project introduction, illustrative packet path, workflow, team, and FAQs. |
| Dashboard | Packet counts, captured bytes, protocol distribution, source addresses, and recent records. |
| Traffic records | Search, filter, sort, inspect a flow, and export the matching records as CSV. |
| Alerts | Review rule matches and statistical outliers. |
| Response history | Inspect saved window scores and simulated response decisions. |
| CN tools | Calculate subnets, CRC, Internet checksum, and Hamming code; review the OSI layers. |
| Project details | Read the project scope, team information, and limitations. |

The interface uses warm off-white, charcoal, rust, and muted sage. Space Grotesk provides the headings and Manrope the interface text; IBM Plex Mono is used for addresses and packet fields. The introduction uses an original network illustration and editorial sections. The monitor uses horizontal navigation, joined statistics, open chart sections, and structured tables. Font files and their licenses are included locally. No frontend build step, npm installation, or online font service is needed.

The frontend has readable formatting and a separate `network_tools.js` file for the three error-control algorithms. This visual revision adds a project introduction and keeps all six monitoring/project sections and their existing behaviour. The packet illustration is a frontend teaching example; it does not discover devices or send traffic. Start with **`docs/CODE_GUIDE.md`** to trace the source code and **`docs/PROJECT_GUIDE.md`** to plan the demonstration. The capture, detection, ML, and database logic remains the same as in the previous revision.

## Measurement definitions

| Dashboard term | Meaning |
| --- | --- |
| Flow record | One directional five-tuple aggregated within a capture window. ARP/ICMP use zero ports where transport ports do not apply. |
| Captured packets | Sum of `packet_count` in the selected records. |
| Captured traffic | Sum of recorded frame bytes, shown in binary units such as KiB and MiB. |
| Traffic rate | An estimate from captured bytes or packets grouped by stored record timestamps. Idle buckets within the selected span are included. This is not measured link capacity or application goodput. |
| Protocol distribution | Share of **packets**, not number of flows. |
| Observed endpoints | Distinct source and destination address strings. These are not a count of physical devices. |
| Flagged flows | Records with at least one rule alert or ML anomaly. A flow matching both counts once. |
| Rule-alert instances | Sum of rule matches; a flow may match several rules. This is not a count of independent attacks. |
| ML anomaly | A statistical outlier according to Isolation Forest. The decision value is not an attack probability. |
| Fused score | A window-level score from the existing fusion engine, separate from an individual flow score. |
| Response action | A **simulated** decision. No firewall rule is applied and no traffic is blocked. |
| Clock | Original capture-host local timestamps; old records do not contain timezone offsets. |

Latency, packet loss, actual NIC bandwidth utilization, routing-protocol operation, and TCP congestion-control implementation are **not measured or implemented** by these stored flow features. The UI does not fabricate those readings. CRC, checksum, and Hamming tools are separate educational exercises, not validation of live packets.

HTTP/HTTPS/service labels inferred from port numbers are marked **port hint**. DNS is marked **decoded** only when identified in a newly captured packet. Encrypted payloads are not inspected. A high packet rate, ML flag, or SYN imbalance alone does not establish a malicious attack.

## Troubleshooting

| Problem | Action |
| --- | --- |
| `requirements.txt` not found | You are probably in the outer extracted folder. Run `cd .\AegisNet`, check that `requirements.txt` is present, then run the setup commands there. |
| `No module named flask/scapy/joblib/...` | Use the `.venv\Scripts\python.exe` interpreter and let `pip install -r requirements.txt` finish successfully. Do not copy the old Windows `venv` folder. |
| No adapters / capture error | Check Npcap, adapter permissions, and `data/capture.log`. Try an Administrator terminal if required by Npcap. |
| Capture runs but dashboard is quiet | Select the adapter actually carrying traffic. Generate normal traffic and allow a processing window to finish. |
| ML not available | Stop capture, run `.\.venv\Scripts\python.exe main.py --train-model`, then start capture again. Rule-based processing continues if ML cannot load. |
| Port 5000 is occupied | Run `.\.venv\Scripts\python.exe run_dashboard.py --port 5001` and open `http://127.0.0.1:5001`. |
| Dashboard says saved traffic | Capture is stopped; this is expected while reviewing the included history. |
| Graph shows a spike | Capture records are aggregated and saved in windows; bucketed rates can be bursty. Inspect individual flows before drawing conclusions. |
| Old screenshot looks different | Use the new `run_dashboard.py` entry point. `docs/original_dashboard.py` is a reference copy of the uploaded UI. |

The interface is a **local academic application**. It intentionally binds to `127.0.0.1` and has no remote-user authentication. It is not a public network-monitoring service.

## Manual capture terminal (optional)

```powershell
.\.venv\Scripts\python.exe main.py --list-interfaces
.\.venv\Scripts\python.exe main.py --interface 16
```

Replace `16` with the index listed on **your** computer. Stop terminal-started captures with **Ctrl+C in that terminal**. Dashboard **Stop capture** controls only the process started by that dashboard.

Linux/macOS: create a Python 3.12 virtual environment, install `requirements.txt`, and run `python run_dashboard.py`. Live capture additionally needs the operating system's capture privileges; Linux can use native packet sockets. The supplied Windows launchers are not used on those systems.

## Project structure

- `run_dashboard.py` — local dashboard entry point.
- `main.py` — capture CLI and ML training.
- `app/capture/` — packet capture, process heartbeat, and final-window handling.
- `app/analysis/` — directional flows, window features, source context, and baseline.
- `app/detection/`, `app/scoring/`, `app/ml/`, `app/response/` — existing detection and response architecture.
- `app/dashboard/templates/` and `static/` — dashboard layout, styles, and browser controls.
- `app/dashboard/dashboard.py` — read APIs, filters, exports, subnetting, and local capture controls.
- `app/database/` — SQLite schema and additive migration.
- `data/` — original saved records, project dataset, models, and original evaluation artefacts.
- `docs/` — code guide, demonstration guide, change log, validation notes, and original dashboard reference.
- `tests/` — API and offline packet-analysis regression checks.

## Verification

Run the included tests from the project root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

These tests create temporary databases and construct packets offline. They never transmit traffic or alter the supplied database. See `docs/VALIDATION.md` for browser checks and test limitations.

The original evaluation scripts are retained. Their pre-existing result files describe earlier experiments, not a new validation of this revision. To use the plotting scripts, additionally install `requirements-evaluation.txt`.
