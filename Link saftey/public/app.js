const form = document.querySelector('#scan-form');
const input = document.querySelector('#url-input');
const error = document.querySelector('#form-error');
const analysis = document.querySelector('#analysis');
const loader = document.querySelector('#analysis-loader');
const sections = [...document.querySelectorAll('main > section')];
const observer = new IntersectionObserver(entries => entries.forEach(entry => {
  if (entry.isIntersecting) { entry.target.classList.add('visible'); observer.unobserve(entry.target); }
}), { threshold: .12 });
document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
let scrollTarget = window.scrollY;
let scrollFrame = 0;
let lastScrollFrame = 0;
function clampScrollTarget(value) { return Math.max(0, Math.min(value, document.documentElement.scrollHeight - window.innerHeight)); }
function smoothScrollTo(value) {
  scrollTarget = clampScrollTarget(value);
  if (reducedMotion.matches) { window.scrollTo(0, scrollTarget); return; }
  if (!scrollFrame) { lastScrollFrame = 0; scrollFrame = requestAnimationFrame(animatePageScroll); }
}
function animatePageScroll(now) {
  if (!lastScrollFrame) lastScrollFrame = now;
  const elapsed = Math.min(48, now - lastScrollFrame);
  lastScrollFrame = now;
  const blend = 1 - Math.exp(-elapsed / 155);
  const current = window.scrollY;
  const next = current + (scrollTarget - current) * blend;
  window.scrollTo(0, next);
  if (Math.abs(scrollTarget - next) < 0.8) {
    window.scrollTo(0, scrollTarget);
    scrollFrame = 0; lastScrollFrame = 0;
  } else scrollFrame = requestAnimationFrame(animatePageScroll);
}
function canScrollInside(target, deltaY) {
  for (let element = target instanceof Element ? target : null; element && element !== document.body && element !== document.documentElement; element = element.parentElement) {
    const overflow = getComputedStyle(element).overflowY;
    if (!/(auto|scroll)/.test(overflow) || element.scrollHeight <= element.clientHeight + 1) continue;
    if (deltaY < 0 && element.scrollTop > 0) return true;
    if (deltaY > 0 && element.scrollTop + element.clientHeight < element.scrollHeight - 1) return true;
  }
  return false;
}
window.addEventListener('wheel', event => {
  if (reducedMotion.matches || event.ctrlKey || event.shiftKey || event.defaultPrevented || !event.deltaY || canScrollInside(event.target, event.deltaY)) return;
  const unit = event.deltaMode === WheelEvent.DOM_DELTA_LINE ? 16 : event.deltaMode === WheelEvent.DOM_DELTA_PAGE ? window.innerHeight : 1;
  event.preventDefault();
  smoothScrollTo((scrollFrame ? scrollTarget : window.scrollY) + event.deltaY * unit);
}, { passive: false });
document.addEventListener('keydown', event => {
  if (reducedMotion.matches || event.altKey || event.ctrlKey || event.metaKey) return;
  if (event.target.closest('input, textarea, select, button, [contenteditable="true"]')) return;
  const max = document.documentElement.scrollHeight - window.innerHeight;
  let destination = null;
  if (event.key === 'ArrowDown') destination = window.scrollY + 56;
  else if (event.key === 'ArrowUp') destination = window.scrollY - 56;
  else if (event.key === 'PageDown' || (event.key === ' ' && !event.shiftKey)) destination = window.scrollY + window.innerHeight * 0.82;
  else if (event.key === 'PageUp' || (event.key === ' ' && event.shiftKey)) destination = window.scrollY - window.innerHeight * 0.82;
  else if (event.key === 'Home') destination = 0;
  else if (event.key === 'End') destination = max;
  if (destination !== null) { event.preventDefault(); smoothScrollTo(destination); }
});
document.addEventListener('click', event => {
  if (event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
  const link = event.target.closest('a[href^="#"]');
  if (!link) return;
  const id = decodeURIComponent(link.getAttribute('href').slice(1));
  const target = document.getElementById(id);
  if (!target) return;
  event.preventDefault();
  if (!analysis.classList.contains('hidden') && !analysis.contains(target)) navigateHome();
  if (location.hash !== `#${id}`) history.pushState(null, '', `#${id}`);
  smoothScrollTo(target.getBoundingClientRect().top + window.scrollY - 78);
});
function navigateToAnalysis() {
  sections.forEach(section => section.classList.toggle('hidden', section.id !== 'analysis'));
  history.replaceState(null, '', '#analysis');
  smoothScrollTo(0);
}
function navigateHome() {
  sections.forEach(section => section.classList.remove('hidden'));
  analysis.classList.add('hidden');
  document.querySelectorAll('.reveal').forEach(el => { el.classList.remove('visible'); observer.observe(el); });
}
function runLoadingSequence() {
  const steps = [
    { id: 'loader-step-1', status: 'Normalizing the destination', width: '28%' },
    { id: 'loader-step-2', status: 'Checking public DNS, registry, and TLS signals', width: '60%' },
    { id: 'loader-step-3', status: 'Safely inspecting the destination page', width: '88%' }
  ];
  const progress = document.querySelector('#loader-progress');
  const status = document.querySelector('#loader-status');
  steps.forEach((step, index) => setTimeout(() => {
    document.querySelectorAll('.loader-steps span').forEach((el, i) => el.classList.toggle('active', i === index));
    status.textContent = step.status;
    progress.style.width = step.width;
  }, index * 300));
  return new Promise(resolve => setTimeout(resolve, 1050));
}
function hideLoader() {
  loader.classList.add('leaving');
  setTimeout(() => { loader.classList.add('hidden'); loader.classList.remove('leaving'); }, 280);
}
window.addEventListener('hashchange', () => { if (location.hash !== '#analysis') navigateHome(); });

form.addEventListener('submit', async event => {
  event.preventDefault(); error.textContent = '';
  const raw = input.value.trim();
  if (!raw) return;
  analysis.classList.remove('has-results');
  const submitButton = form.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  navigateToAnalysis();
  loader.classList.remove('hidden', 'leaving');
  document.querySelector('#loader-progress').style.width = '0';
  document.querySelectorAll('.loader-steps span').forEach((step, i) => step.classList.toggle('active', i === 0));
  const animation = runLoadingSequence();
  try {
    const response = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: raw }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Unable to analyze this URL.');
    await animation;
    render(data);
    hideLoader();
    smoothScrollTo(0);
  } catch (err) {
    await animation;
    hideLoader();
    navigateHome();
    error.textContent = err.message || 'Could not reach the local analyzer.';
    const scanSection = document.querySelector('#scan');
    smoothScrollTo(scanSection.getBoundingClientRect().top + window.scrollY - window.innerHeight * 0.35);
  } finally { submitButton.disabled = false; }
});

function render(data) {
  analysis.classList.add('has-results');
  const score = Math.max(0, Math.min(100, Number(data.score) || 0));
  const color = '#c6a14a';
  const ring = document.querySelector('#score-ring');
  ring.style.setProperty('--score-color', color);
  const progressRing = document.querySelector('#score-progress');
  const circumference = 2 * Math.PI * 42;
  progressRing.style.strokeDasharray = String(circumference);
  progressRing.style.strokeDashoffset = String(circumference);
  requestAnimationFrame(() => requestAnimationFrame(() => {
    progressRing.style.strokeDashoffset = String(circumference * (1 - score / 100));
  }));
  animateNumber(document.querySelector('#score-number'), score);
  const badge = document.querySelector('#verdict-badge');
  badge.textContent = data.verdict === 'high' ? 'HIGH CONCERN' : data.verdict === 'caution' ? 'REVIEW' : data.verdict === 'clear' ? 'NO SIGNALS FOUND' : 'INCOMPLETE';
  badge.className = 'badge ' + (data.verdict === 'high' ? 'high' : data.verdict === 'incomplete' ? 'incomplete' : '');
  document.querySelector('#verdict-title').textContent = data.verdict === 'high' ? 'Several risk signals' : data.verdict === 'caution' ? 'Review these signals' : data.verdict === 'clear' ? 'No obvious risk signals found' : 'No obvious URL pattern found';
  document.querySelector('#verdict-copy').textContent = data.summary;
  document.querySelector('#result-host').textContent = data.host;
  document.querySelector('#result-url').textContent = data.normalized;
  document.querySelector('#check-count').textContent = `(${data.checks.length})`;
  const labels = { clear: 'NO OBVIOUS ISSUE', warning: 'REVIEW', pending: 'NOT CHECKED', error: 'UNAVAILABLE', blocked: 'BLOCKED BY POLICY' };
  document.querySelector('#check-list').innerHTML = data.checks.map((check, index) => `<article class="check-item status-${check.status}" style="--item-index:${index}"><div class="check-item-head"><i class="status-dot"></i><h4>${escapeHtml(check.title)}</h4><span class="status-label">${labels[check.status]}</span></div><p>${escapeHtml(check.description)}</p><p class="check-detail">${escapeHtml(check.detail)}</p></article>`).join('');
  const counts = { clear: data.checks.filter(check => check.status === 'clear').length, warning: data.checks.filter(check => check.status === 'warning').length, pending: data.checks.filter(check => check.status === 'pending').length, error: data.checks.filter(check => check.status === 'error').length, blocked: data.checks.filter(check => check.status === 'blocked').length };
  const total = data.checks.length || 1;
  document.querySelector('#chart-total').textContent = `${data.checks.length} checks`;
  for (const key of ['clear', 'warning', 'pending', 'error', 'blocked']) {
    const percent = Math.round(counts[key] / total * 100);
    document.querySelector(`#chart-${key}-count`).textContent = counts[key];
    document.querySelector(`#chart-${key}-pct`).textContent = `${percent}%`;
    const segment = document.querySelector(`#chart-${key}`);
    segment.style.width = '0%';
    requestAnimationFrame(() => requestAnimationFrame(() => { segment.style.width = `${counts[key] / total * 100}%`; }));
  }
  document.querySelectorAll('.check-item').forEach((card, index) => setTimeout(() => card.classList.add('shown'), 35 * index));
}
function animateNumber(element, target) {
  const start = performance.now();
  const duration = 820;
  function tick(now) {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    element.textContent = Math.round(target * eased);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}
function escapeHtml(text) { return String(text).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]); }
function buildMarkdownReport() {
  const host = document.querySelector('#result-host').textContent;
  const checks = [...document.querySelectorAll('.check-item')];
  const counts = {
    clear: checks.filter(el => el.classList.contains('status-clear')).length,
    review: checks.filter(el => el.classList.contains('status-warning')).length,
    unchecked: checks.filter(el => el.classList.contains('status-pending')).length,
    unavailable: checks.filter(el => el.classList.contains('status-error')).length,
    blocked: checks.filter(el => el.classList.contains('status-blocked')).length
  };
  const clean = value => String(value).replace(/\r?\n/g, ' ').replace(/`/g, "'");
  const rows = checks.map(el => {
    const status = el.classList.contains('status-clear') ? 'Clear' : el.classList.contains('status-warning') ? 'Review' : el.classList.contains('status-blocked') ? 'Blocked by policy' : el.classList.contains('status-error') ? 'Unavailable' : 'Not checked';
    return `### ${clean(el.querySelector('h4').textContent)}\n\n- **Status:** ${status}\n- **What this checks:** ${clean(el.querySelector('.check-item-head').nextElementSibling.textContent)}\n- **Finding:** ${clean(el.querySelector('.check-detail').textContent)}`;
  });
  return [
    '# Link Safety Analysis Report', '',
    `- **Generated:** ${new Date().toISOString()}`,
    `- **Destination:** ${clean(document.querySelector('#result-url').textContent)}`,
    `- **Host:** ${clean(host)}`,
    `- **Verdict:** ${clean(document.querySelector('#verdict-title').textContent)}`,
    `- **URL signal score:** ${document.querySelector('#score-number').textContent}%`, '',
    `> ${clean(document.querySelector('#verdict-copy').textContent)} This is a screening result, not a safety guarantee.`, '',
    '## Check status overview', '',
    `- Clear: ${counts.clear}`,
    `- Review: ${counts.review}`,
    `- Not checked: ${counts.unchecked}`,
    `- Unavailable: ${counts.unavailable}`,
    `- Blocked by policy: ${counts.blocked}`,
    `- Total checks: ${checks.length}`, '',
    '## Detailed checks', '', rows.join('\n\n'), ''
  ].join('\n');
}
document.querySelector('#copy-report').addEventListener('click', async () => {
  const button = document.querySelector('#copy-report');
  try { await navigator.clipboard.writeText(buildMarkdownReport()); button.textContent = 'Copied ✓'; setTimeout(() => button.textContent = 'Copy Markdown', 1600); }
  catch { button.textContent = 'Clipboard unavailable'; setTimeout(() => button.textContent = 'Copy Markdown', 1800); }
});
document.querySelector('#copy-donate-local').addEventListener('click', async () => {
  const button = document.querySelector('#copy-donate-local');
  try {
    await navigator.clipboard.writeText(document.querySelector('#donate-local-number').textContent.trim());
    button.textContent = 'Copied ✓';
  } catch { button.textContent = 'Select to copy'; }
  setTimeout(() => { button.textContent = 'Copy local'; }, 1800);
});
document.querySelector('#copy-vodafone-code').addEventListener('click', async () => {
  const button = document.querySelector('#copy-vodafone-code');
  const status = document.querySelector('#donate-code-status');
  try {
    await navigator.clipboard.writeText('*9*7#');
    button.textContent = 'Copied ✓';
    status.textContent = 'Dial *9*7# on your Vodafone line.';
  } catch {
    button.textContent = 'Copy unavailable';
    status.textContent = 'You can select and copy the code above.';
  }
  setTimeout(() => { button.textContent = 'Copy code'; status.textContent = ''; }, 2000);
});
document.querySelector('#copy-donate-number').addEventListener('click', async () => {
  const button = document.querySelector('#copy-donate-number');
  const status = document.querySelector('#donate-copy-status');
  try {
    await navigator.clipboard.writeText(document.querySelector('#donate-number').textContent.trim());
    button.textContent = 'Number copied ✓';
    status.textContent = 'The number is ready to paste.';
  } catch {
    button.textContent = 'Copy unavailable';
    status.textContent = 'You can select and copy the number above.';
  }
  setTimeout(() => { button.innerHTML = 'Copy number <span>↗</span>'; status.textContent = ''; }, 2000);
});
document.querySelector('#download-report').addEventListener('click', () => {
  const content = buildMarkdownReport();
  const host = document.querySelector('#result-host').textContent.toLowerCase().replace(/[^a-z0-9.-]+/g, '-').replace(/^-|-$/g, '') || 'link';
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = `link-safety-report-${host}.md`;
  document.body.appendChild(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
});
if (location.hash === '#analysis') navigateHome();



