// The only thing remembered in the browser is the ID of your latest report, for this tab only (sessionStorage).
const KEY = "unmask.lastScan";
export const rememberScan = (id) => { try { sessionStorage.setItem(KEY, id); } catch { /* storage blocked: harmless */ } };
export const lastScan = () => { try { return sessionStorage.getItem(KEY); } catch { return null; } };
export const forgetScan = () => { try { sessionStorage.removeItem(KEY); } catch { /* ignore */ } };
