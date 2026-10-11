# Interface notes

The visual revision keeps Flask, ordinary HTML/CSS/JavaScript, and the existing monitoring APIs. It introduces a project home page; the original Dashboard, Traffic records, Alerts, Response history, CN tools, and Project details remain available from the workspace navigation.

## Design choices

- Warm off-white `#F6F3EC` forms the background. Charcoal `#242922` anchors text, navigation, and the packet illustration.
- Rust `#A24528` marks emphasis and links. Muted sage supports protocol charts and the process diagram.
- Space Grotesk is used for headings; Manrope for interface text; IBM Plex Mono for addresses and technical fields. Open-font licenses are included in `static/fonts/`.
- The introduction uses broad typography, numbered sections, an original SVG diagram, open rows, and a simple team roster. The monitor uses smaller headings and denser data layouts.
- The reference informed the use of a strong type hierarchy, restrained outlines, and contrasting light/dark areas. Its source, artwork, branding, team content, and fonts were not copied into this project.

## Behaviour

The default view is `#home`. `#overview` still opens the monitor directly, and all original view hashes remain supported. Masthead links can return from the monitor to a particular introduction section.

The diagram is an educational illustration. Its four stages explain the client, switch, router, and destination server. Selecting a stage changes the highlighted device and explanation. Follow the packet plays the stages once and stops. Selecting a device or leaving the page cancels playback. Reduced-motion settings skip timed playback.

The diagram never calls capture APIs, discovers devices, or transmits traffic. Actual capture is still controlled through the original Capture controls dialog. No statistics, testimonials, team roles, awards, or contact details were invented.

## Where to edit

- `templates/home.html`: introduction copy and original network SVG.
- `static/presentation.css`: introduction composition and responsive styles.
- `static/presentation.js`: example-packet controls and section scrolling.
- `templates/index.html`: shared masthead and original monitoring controls.
- `static/app.css`: shared fonts, colours, forms, tables, charts, and navigation.
- `static/app.js`: original monitoring behaviour and view navigation.

No Python package or frontend framework was added for the redesign. See `VALIDATION.md` for the checks that were completed and the browser-preview limitation.
