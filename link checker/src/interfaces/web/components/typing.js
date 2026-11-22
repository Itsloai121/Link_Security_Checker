// Soft, slow, blurred typing: every character sharpens out of a blur, one after another (see .type-ch in effects.css).
// Accessible: screen readers get one plain copy of the text; the animated copy is aria-hidden.
import { safeText } from "./safe-text.js";

const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("no-motion");
const SPEED = { chars: 34, words: 52 };

function wrap(node, mode, state) {
  for (const child of [...node.childNodes]) {
    if (child.nodeType === Node.TEXT_NODE) {
      const frag = document.createDocumentFragment();
      for (const part of child.textContent.split(/(\s+)/)) {
        if (!part) continue;
        if (/^\s+$/.test(part)) { frag.append(document.createTextNode(" ")); continue; }
        const word = document.createElement("span");
        word.className = "type-word";
        if (mode === "words") {
          word.classList.add("type-ch");
          word.textContent = part;
          word.style.setProperty("--i", state.i++);
        } else {
          for (const ch of part) {
            const span = document.createElement("span");
            span.className = "type-ch";
            span.textContent = ch;
            span.style.setProperty("--i", state.i++);
            word.append(span);
          }
        }
        frag.append(word);
      }
      child.replaceWith(frag);
    } else if (child.nodeType === Node.ELEMENT_NODE) {
      wrap(child, mode, state);
    }
  }
}

function prepare(el) {
  if (el.dataset.typePrepared) return 0;
  const mode = el.dataset.type === "words" ? "words" : "chars";
  const plain = el.textContent.replace(/\s+/g, " ").trim();
  const sr = Object.assign(document.createElement("span"), { className: "sr-only", textContent: plain });
  const line = document.createElement("span");
  line.className = "type-line";
  line.setAttribute("aria-hidden", "true");
  line.append(...el.childNodes);
  el.replaceChildren(sr, line);
  const state = { i: 0 };
  wrap(line, mode, state);
  el.dataset.typePrepared = "1";
  return state.i;
}

function start(el, count) {
  const mode = el.dataset.type === "words" ? "words" : "chars";
  const speed = Number(el.dataset.typeSpeed) || SPEED[mode];
  if (reduced || count === 0) { el.classList.add("is-typed"); return; }
  el.style.setProperty("--speed", `${speed}ms`);
  el.classList.add("is-typing");
  setTimeout(() => { el.classList.remove("is-typing"); el.classList.add("is-typed"); }, count * speed + 1200);
}

/** Prepare every [data-type] element now; start each one the first time it scrolls into view. */
export function initTyping(root = document) {
  const targets = [...root.querySelectorAll("[data-type]:not([data-type-prepared])")];
  const counts = new Map(targets.map((el) => [el, prepare(el)]));
  if (reduced || !("IntersectionObserver" in window)) { targets.forEach((el) => start(el, 0)); return; }
  const io = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      io.unobserve(entry.target);
      start(entry.target, counts.get(entry.target) ?? 0);
    }
  }, { threshold: 0.2 });
  targets.forEach((el) => io.observe(el));
}

/** Replace the text of an element and type it immediately (used when results arrive). */
export function typeNow(el, text, speed = 16) {
  el.classList.remove("is-typing", "is-typed");
  el.removeAttribute("data-type-prepared");
  el.dataset.type = "chars";
  el.dataset.typeSpeed = String(speed);
  el.textContent = safeText(text);
  const count = prepare(el);
  start(el, count);
}
