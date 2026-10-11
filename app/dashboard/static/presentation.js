"use strict";

// The home-page diagram is an illustration; it never sends network traffic.
(() => {
  const stages = [
    [
      "The conversation starts here.",
      "An application creates data. TCP adds ports; IP adds the source and destination addresses.",
      96,
      96,
    ],
    [
      "A frame crosses the local network.",
      "The switch uses the destination MAC address to forward the Ethernet frame to the appropriate port.",
      194,
      216,
    ],
    [
      "A router chooses the next hop.",
      "The router checks the destination IP address and forwards the packet using its routing table.",
      286,
      216,
    ],
    [
      "The destination receives the data.",
      "The receiving host processes the frame, IP packet and transport segment, then delivers the data to the application.",
      468,
      112,
    ],
  ];
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const root = document.getElementById("page-home");
  const replay = document.getElementById("replay-packet");
  let timers = [];

  function stopPlayback() {
    timers.forEach(clearTimeout);
    timers = [];
    replay.disabled = false;
    replay.setAttribute("aria-label", "Follow the example packet");
  }

  function showStage(index) {
    const [title, copy, x, y] = stages[index];
    document.getElementById("hop-title").textContent = title;
    document.getElementById("hop-copy").textContent = copy;
    const packet = document.getElementById("example-packet");
    packet.setAttribute("cx", x);
    packet.setAttribute("cy", y);
    root.querySelectorAll("[data-hop]").forEach((button) => {
      button.setAttribute(
        "aria-pressed",
        String(Number(button.dataset.hop) === index),
      );
    });
    root.querySelectorAll("[data-device]").forEach((node) => {
      node.classList.toggle(
        "is-selected",
        Number(node.dataset.device) === index,
      );
    });
  }

  root.querySelectorAll("[data-hop]").forEach((button) => {
    button.addEventListener("click", () => {
      stopPlayback();
      showStage(Number(button.dataset.hop));
    });
  });
  replay.addEventListener("click", () => {
    stopPlayback();
    if (reducedMotion.matches) {
      showStage(3);
      return;
    }
    showStage(0);
    replay.disabled = true;
    replay.setAttribute("aria-label", "Following the example packet");
    stages.slice(1).forEach((_, i) => {
      timers.push(
        setTimeout(
          () => {
            showStage(i + 1);
            if (i === stages.length - 2) stopPlayback();
          },
          (i + 1) * 1150,
        ),
      );
    });
  });
  window.addEventListener("hashchange", stopPlayback);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopPlayback();
  });
  reducedMotion.addEventListener("change", stopPlayback);

  document.querySelectorAll("[data-scroll]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = document.getElementById(button.dataset.scroll);
      if (!target) return;
      const revealTarget = () => {
        target.scrollIntoView({
          behavior: reducedMotion.matches ? "instant" : "smooth",
          block: "start",
        });
        target.focus({ preventScroll: true });
      };
      if (root.hidden) {
        window.addEventListener("hashchange", revealTarget, { once: true });
        location.hash = "home";
      } else revealTarget();
    });
  });

  // Content stays visible if this enhancement or IntersectionObserver is unavailable.
  if ("IntersectionObserver" in window && !reducedMotion.matches) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("section-entered");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12 },
    );
    root
      .querySelectorAll(
        ".editorial-section, .workspace-section, .pipeline-section",
      )
      .forEach((section) => observer.observe(section));
  }
})();
