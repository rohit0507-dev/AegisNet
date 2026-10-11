# Editorial redesign — October 2026

- Added a project introduction with a labelled packet-path illustration, direct workspace links, project workflow, supplied team details, and practical FAQs.
- Replaced the navy sidebar with a shared masthead, horizontal workspace navigation, and a mobile drawer with an explicit close control.
- Changed the palette to warm off-white, charcoal, rust, and sage; switched interface typography to Manrope and Space Grotesk.
- Opened up the monitor layout: joined statistics, fewer panel outlines, stronger section headings, and readable tables.
- Added finite diagram playback, direct stage selection, reduced-motion handling, section navigation, and restrained reveal motion.
- Preserved all Python code, saved records, ML files, requirements, launchers, and the existing CN calculations.
- Clarified installation completion, stopping the previous server, and refreshing cached styles.
- Current verification and its limits are in VALIDATION.md; earlier browser results below are historical, not a browser verification of this revision.

# Visual refinement of the existing monitor

- Kept the original six sections: Dashboard, Traffic records, Alerts, Response history, CN tools, and Project details.
- Added a compact navy sidebar with consistent line icons and an accessible mobile drawer.
- Used locally bundled IBM Plex Sans and IBM Plex Mono, with the font licenses included.
- Aligned the summary values in a single flat strip; used crisp `#E5E7EB` borders and restrained blue/teal accents.
- Refined table spacing, chart labels, breadcrumbs, and focus states.
- Kept all Python backend files, algorithms, ML assets, saved data, and dependencies unchanged.
- Added clearer instructions for opening the inner extracted project folder before running commands.

# Interface revision

- Replaced the sidebar with six horizontal tabs and changed to a light blue-and-white layout using Arial.
- Removed slogans, decorative icon cards, the theme switch, and the branded hero sections.
- Replaced the protocol donut with labelled bars showing packet counts and percentages.
- Used a plain line chart and a team table, with simpler page names and descriptions.
- Reformatted the frontend files and moved CRC, checksum, and Hamming algorithms into `network_tools.js`.
- Added `CODE_GUIDE.md` to explain the important files and the packet-to-dashboard path.
- Fixed chart sizing when returning to Dashboard, overlapping time labels on phones, and focus for the `/` search shortcut.
- Retained the capture, detection, ML, SQLite, reports, and CN exercises from the previous revision.

# Revision 2.0

- Replaced the single long embedded HTML dashboard with a Flask template, local CSS/JavaScript, six focused views, and light/dark themes.
- Added actual SQLite-backed filters, pagination, flow detail, report export, empty states, and recoverable error messages.
- Changed protocol distribution from flow counts to packet counts and kept evidence terminology precise.
- Added same-origin local capture controls and runtime heartbeat. Replaced the fixed adapter index with user selection and a CLI argument.
- Preserved the original database and detection architecture. Schema changes are additive: application protocol, IP family, and ML-availability fields. Legacy values remain unknown rather than fabricated.
- Distinguished ICMP, ICMPv6, ARP, and DNS for new captures; added an ICMP-flood heuristic.
- Used packet timestamps for per-flow duration; continued window IDs across runs; saved final pending flows on normal stop.
- Added subnetting, CRC, Internet checksum, Hamming coding, OSI explanations, project title, and the supplied team details.
- Rebuilt the Isolation Forest from the original 166-row dataset using the tested scikit-learn environment. This does not rewrite historical predictions.
- Removed the machine-specific `venv`, bytecode caches, and Git internal files from the distribution. Source modules, historical data, evaluation artefacts, and an original-dashboard reference remain included.
