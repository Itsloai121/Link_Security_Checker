// Display spoofing defence: submitted links can hide bidirectional-override and zero-width characters that visually
// reorder or disguise text (e.g. U+202E). Anything shown to a person goes through safeText(), which makes them visible.
const HIDDEN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;

export function safeText(value) {
  return String(value ?? "").replace(HIDDEN, (c) => `⟦U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}⟧`);
}
