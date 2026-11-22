import { initMotionToggle } from "./motion-toggle.js";
import { initReveal } from "./reveal.js";
import { initSmoothScroll } from "./smooth-scroll.js";
import { initTyping } from "./typing.js";

export { initReveal, initTyping };
export function initPage() {
  initMotionToggle();
  initSmoothScroll();
  initTyping();
  initReveal();
}
