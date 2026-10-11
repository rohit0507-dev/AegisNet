# AegisNet — project presentation guide

## Title

Real-Time Network Traffic Monitoring and Intrusion Detection System

## Team

Bhumireddi Rohit — 24BDS0387  
Parth Batra — 24BDS0416  
Somya Raj Singh Dalawat — 24BCE3001

## Updated abstract, aligned with the implemented project

AegisNet is a software-based network monitoring and intrusion detection project that captures traffic from a selected network interface, groups packets into directional flows, and presents network behaviour through an interactive local dashboard. The system identifies IPv4 and IPv6 traffic, analyses TCP and UDP conversations, records TCP control flags, and distinguishes ICMP, ICMPv6, ARP, and decoded DNS in newly captured traffic. It reports captured packet and byte counts, estimated traffic rates, protocol distribution, and observed endpoints.

The detection pipeline combines rule-based indicators, port-scan heuristics, an Isolation Forest model, source context, and temporal analysis to highlight unusual traffic patterns. Signals include high SYN activity, high packet rates, ICMP flooding indicators, TCP reset rates, and destination-port fan-out. Evidence is combined into a window-level threat score, and proposed response actions are recorded in simulation mode for inspection.

Developed using Python, Scapy, Flask, SQLite, Pandas, and Scikit-learn, the project connects Computer Networks principles with practical traffic analysis. The separate CN tools page provides subnet calculations, CRC, Internet checksum, Hamming-code exercises, and OSI-layer explanations. The system supports flow inspection and report export, serving as an academic platform for understanding packet structure, protocol behaviour, and network intrusion indicators.

## A five-minute demonstration

1. **Dashboard — 45 seconds.** Explain the difference between a packet and a flow. Show captured packets, captured bytes, protocol proportions, and observed endpoints. Point to the saved/live label so the audience knows the data source.
2. **Traffic records — 60 seconds.** Filter TCP or UDP, search an address, and inspect a flow. Explain the five-tuple, ports, IPv4/IPv6, and TCP flags. Export matching records as CSV.
3. **Alerts — 45 seconds.** Open a flagged flow and identify its evidence. Distinguish a rule alert from an ML outlier. Explain that a flag invites investigation.
4. **Response history — 30 seconds.** Explain flow-level versus fused window-level scores. Show the simulated decision and state transition. No blocking is claimed.
5. **CN tools — 60 seconds.** Calculate `192.168.1.10/26`; show network `192.168.1.0/26`, broadcast `192.168.1.63`, and 62 conventional usable addresses. Encode `1011` with Hamming (7,4), flip one bit, and show correction.
6. **Live capture — optional.** Start an authorised adapter, generate normal browsing traffic, and show new records. Stop capture before closing the app.

## Questions you can answer clearly

**Why use a five-tuple?** It identifies a directional transport conversation using source/destination IPs, source/destination ports, and transport protocol. AegisNet records one such flow per window. The reverse direction is a separate flow.

**Why can percentages of TCP flags add to more than 100%?** A single TCP packet can have multiple flags, such as SYN+ACK. Each flag count is independent.

**What does the Isolation Forest do?** It isolates uncommon combinations of 14 numeric flow features. Unusual samples tend to require fewer partitions. Its decision value is not an attack probability. The supplied 166-row dataset is an academic baseline.

**How are port scans detected?** The supplied detector checks destination-port fan-out per source within a window: at least 20 distinct destination ports and at least 10 flows. This heuristic can also flag legitimate activity; source context is needed.

**What is the rate on the graph?** Captured bytes multiplied by eight, divided by the display bucket duration. It is an estimate from stored flow timestamps, not physical link utilization.

**Why no latency or packet loss percentage?** Those measurements require appropriate sequence, timestamp, endpoint, or probe observations. Aggregated flow totals alone do not establish them reliably.

**Why might DNS appear under UDP?** The protocol-distribution chart separates transport/network protocols. A newly decoded DNS packet can have UDP as its transport and DNS as its application protocol.

**Does it prevent attacks?** It detects indicators and records simulated response choices. It does not implement firewall enforcement.

**How does this remain a Computer Networks project?** Packet capture, protocol layers, IP addressing, ports, TCP flags, frame size, traffic rates, subnetting, and error-control coding are central. ML supports analysis of those network features.

## Correct scope for submission

Do not claim production accuracy, guaranteed attack detection, measured latency/loss, routing-protocol execution, packet checksum verification, or actual traffic blocking. Wireshark can be used independently to compare packets during your demonstration; PyShark and Plotly are not required by this delivered runtime.
