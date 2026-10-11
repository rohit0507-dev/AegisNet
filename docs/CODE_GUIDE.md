# Reading the source code

The application has two entry points: `run_dashboard.py` starts the Flask dashboard, and `main.py` starts packet capture or trains the ML model. The browser talks to Flask; Scapy runs in the local capture process.

## Follow one packet through the project

1. **Capture:** `app/capture/packet_capture.py` receives a Scapy packet in `PacketCapture.process_packet()`.
2. **Build a flow:** `app/analysis/flow_engine.py` uses `FlowEngine.get_flow_key()` to identify the source IP, destination IP, source port, destination port, and protocol. The reverse direction has a separate key.
3. **Update counters:** `Flow.add_packet()` records the packet time, frame size, and TCP flags. `Flow.get_features()` calculates the flow's numeric features.
4. **Analyse the window:** approximately every five seconds, `PacketCapture.process_window()` runs the rules, port-scan check, ML prediction, source context, and temporal checks. The window's evidence is combined into a threat score.
5. **Store results:** `app/database/database.py` writes flow records and simulated response events to SQLite.
6. **Read results:** `app/dashboard/dashboard.py` queries SQLite through routes such as `/api/dashboard` and `/api/flows`.
7. **Display results:** `app/dashboard/static/app.js` requests the JSON data and updates the tables, counts, and charts.

The large capture file connects the different analysis modules. Start with the smaller flow and rule files before reading `process_window()` in detail.

## Files used by the interface

| File | What to look for |
| --- | --- |
| `app/dashboard/templates/index.html` | Shared masthead, workspace navigation, six existing sections, forms, tables, and dialogs. |
| `app/dashboard/templates/home.html` | Project introduction, original SVG packet diagram, workspace links, team, and native FAQ disclosures. |
| `app/dashboard/static/app.css` | Local fonts, warm colour palette, monitor controls, tables, and responsive navigation. |
| `app/dashboard/static/presentation.css` | Introduction layout, typography, illustration styles, and responsive section layouts. |
| `app/dashboard/static/presentation.js` | Example-packet stages, finite playback, reduced motion, and navigation to introduction sections. |
| `app/dashboard/static/app.js` | `state`, `navigate()`, `loadDashboard()`, `loadFlows()`, and the rendering functions. |
| `app/dashboard/static/network_tools.js` | Standalone `crcRemainder()`, `internetChecksum()`, and `hamming()` calculations. |
| `app/dashboard/dashboard.py` | Parameterised database filters, summary totals, exports, and subnet calculations. |
| `app/dashboard/capture_control.py` | Starts and stops the capture process requested from the dashboard. |

The scripts are ordinary JavaScript. `network_tools.js` loads first so its calculation functions are available to `app.js`. `presentation.js` loads after `app.js`; it only handles the introduction and does not call a network-capture API. There is no frontend framework or build step. Local fonts live in `static/fonts/`, with their open-font licenses. The mobile menu code changes navigation layout only; it does not change the data APIs or capture logic.

The short `$()` helper selects one HTML element; `$$()` selects a list of elements. `esc()` escapes values inserted into HTML. The `state` object holds the current tab, time range, filters, and latest API response. The request counters prevent a slow, older response from replacing a newer search result.

## Network measurements

For a flow with `packet_count` packets and `total_bytes` captured bytes:

- Average packet size is `total_bytes / packet_count`.
- Duration is the last packet timestamp minus the first packet timestamp.
- Packet rate is `packet_count / duration` when duration is at least one millisecond.
- A TCP flag ratio is that flag's count divided by the packet count. A SYN+ACK packet increments both counters.

The dashboard graph uses a different calculation: it groups saved flow totals into time buckets, then divides bytes × 8 by the bucket duration. It is an estimate of captured traffic rate. It does not establish the physical link's utilization.

## Detection examples

`app/detection/rule_engine.py` contains the simple threshold checks. For example, its SYN rule flags a directional flow with at least 100 SYN packets and fewer ACKs than 20% of the SYN count. This is a heuristic: reverse-direction ACKs are stored separately, so the check does not prove handshake failure.

`app/detection/port_scan_detector.py` groups destination ports by source address within a window. Its defaults are 20 distinct destination ports and 10 flows. A scan flag is a reason to inspect the source's behaviour, not proof of an attack.

`app/ml/anomaly_detector.py` trains and runs Isolation Forest on 14 numeric features from the supplied 166-row dataset. Keep these three values distinct when explaining the output:

- A rule alert records a threshold match.
- An ML anomaly records a statistical outlier.
- The fused score combines several kinds of evidence at the window level.

The response modules save simulated decisions. They do not install firewall rules.

## CN calculation examples

Read each function in `network_tools.js`, then try its matching input in **CN tools**:

| Calculation | Input | Expected result |
| --- | --- | --- |
| CRC | Data `1101011011`, generator `10011` | Remainder `1110` |
| Internet checksum | Text `AB` | `0xBEBD` |
| Hamming (7,4) | Data `1011` | Codeword `0110011` |
| Hamming correction | Flip position 3 in that codeword | Syndrome 3; corrected data `1011` |
| IPv4 subnet | `192.168.1.10/26` | Network `192.168.1.0/26`, broadcast `192.168.1.63`, 62 usable addresses |

CRC uses XOR division. The checksum sums 16-bit words, folds carry bits, and complements the result. Hamming places parity bits at positions 1, 2, and 4 and can correct one changed bit in this exercise. The subnet route uses Python's `ipaddress` module.

## Small changes to understand before the demonstration

Try changing a chart from bit rate to packet rate, filtering one source IP, and inspecting a TCP flow. Find the corresponding HTML control, JavaScript handler, and Flask route. In the CN tools, change the generator or one Hamming bit and explain why the result changes.

Use the supplied tests after changing calculations or detection rules:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

These tests use temporary databases and offline packet fixtures. Running them does not send network traffic.
