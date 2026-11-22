// Fade in AND fade out while scrolling: --vis (0..1) follows how much of the element is on screen (see [data-reveal]).
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("no-motion");
let observer;

export function initReveal(root = document) {
  const els = [...root.querySelectorAll("[data-reveal]:not([data-reveal-ready])")];
  if (reduced || !("IntersectionObserver" in window)) return;
  observer ??= new IntersectionObserver((entries) => {
    for (const e of entries) {
      const basis = Math.max(1, Math.min(e.boundingClientRect.height, window.innerHeight * 0.55));
      const vis = Math.max(0, Math.min(1, e.intersectionRect.height / basis));
      e.target.style.setProperty("--vis", vis.toFixed(2));
    }
  }, { threshold: Array.from({ length: 21 }, (_, i) => i / 20) });
  for (const el of els) { el.dataset.revealReady = "1"; observer.observe(el); }
}
