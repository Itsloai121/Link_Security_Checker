// WCAG 2.2.2 (Pause, Stop, Hide): moving content that lasts more than five seconds needs a way to pause it.
const root = document.documentElement;

export function initMotionToggle() {
  const button = document.getElementById("motion-toggle");
  if (!button) return;
  const paint = () => {
    const off = root.classList.contains("no-motion");
    button.setAttribute("aria-pressed", String(off));
    button.textContent = off ? "Resume animations" : "Pause animations";
  };
  button.addEventListener("click", () => {
    const off = root.classList.toggle("no-motion");
    try { off ? localStorage.setItem("unmask.motion", "off") : localStorage.removeItem("unmask.motion"); } catch { /* ignore */ }
    paint();
  });
  paint();
}
