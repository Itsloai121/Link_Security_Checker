// Classic (non-module) script, runs before first paint so CSS can tell "JavaScript is available" from "it is not",
// and so a saved "pause animations" choice applies without a flash of motion.
document.documentElement.classList.add("js");
try {
  if (localStorage.getItem("unmask.motion") === "off") document.documentElement.classList.add("no-motion");
} catch { /* storage blocked: default motion */ }
