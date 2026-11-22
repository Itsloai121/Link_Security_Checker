// Soft, slow, inertial scrolling for mouse wheels. Native behaviour is kept for keyboard, touch, scrollbar drags,
// nested scrollable areas and for people who prefer reduced motion.
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("no-motion");

export function initSmoothScroll({ ease = 0.07, wheel = 0.9 } = {}) {
  if (reduced) return;
  let target = window.scrollY, current = target, raf = 0;
  const max = () => document.documentElement.scrollHeight - window.innerHeight;
  const clamp = (v) => Math.max(0, Math.min(max(), v));
  const tick = () => {
    const diff = target - current;
    if (Math.abs(diff) < 0.4) { current = target; window.scrollTo(0, current); raf = 0; return; }
    current += diff * ease;
    window.scrollTo(0, current);
    raf = requestAnimationFrame(tick);
  };
  const kick = () => { if (!raf) raf = requestAnimationFrame(tick); };
  const innerCanScroll = (el, dy) => {
    for (; el && el !== document.body; el = el.parentElement) {
      if (!/(auto|scroll)/.test(getComputedStyle(el).overflowY) || el.scrollHeight <= el.clientHeight + 1) continue;
      if ((dy < 0 && el.scrollTop > 0) || (dy > 0 && el.scrollTop + el.clientHeight < el.scrollHeight - 1)) return true;
    }
    return false;
  };
  window.addEventListener("wheel", (e) => {
    if (e.ctrlKey || e.defaultPrevented || document.documentElement.classList.contains("no-motion") || innerCanScroll(e.target, e.deltaY)) return;
    e.preventDefault();
    const unit = e.deltaMode === 1 ? 32 : e.deltaMode === 2 ? window.innerHeight : 1;
    target = clamp(target + e.deltaY * unit * wheel);
    kick();
  }, { passive: false });
  window.addEventListener("scroll", () => { if (!raf && Math.abs(window.scrollY - current) > 1.5) target = current = window.scrollY; }, { passive: true });
  window.addEventListener("resize", () => { target = clamp(target); });
  document.addEventListener("click", (e) => {   // same-page #anchors glide too
    const a = e.target.closest?.("a[href]");
    if (!a || e.defaultPrevented || e.metaKey || e.ctrlKey || e.shiftKey || a.target) return;
    const url = new URL(a.href, location.href);
    if (url.origin !== location.origin || url.pathname !== location.pathname || !url.hash) return;
    const dest = document.getElementById(decodeURIComponent(url.hash.slice(1)));
    if (!dest) return;
    e.preventDefault();
    const offset = (parseInt(getComputedStyle(document.documentElement).getPropertyValue("--header-h"), 10) || 72) + 16;
    target = clamp(dest.getBoundingClientRect().top + window.scrollY - offset);
    kick();
    history.pushState(null, "", url.hash);
  });
}
