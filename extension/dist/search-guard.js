const a=new Map;let c=null;function m(r){try{let t=r;if(t.includes("/url?")){const n=new URL(t),o=n.searchParams.get("q")||n.searchParams.get("url");o&&(t=o)}const e=new URL(t);return e.protocol!=="http:"&&e.protocol!=="https:"||e.hostname.endsWith("google.com")||e.hostname.endsWith("google.co.in")||e.hostname.includes("google.")?"":`${e.protocol}//${e.hostname.toLowerCase()}${e.pathname.replace(/\/+$/,"")||"/"}${e.search}`}catch{return""}}function g(r,t){const e=document.createElement("span");e.className="aegis-search-badge",e.setAttribute("role","status"),e.setAttribute("aria-label",`AEGIS Security: ${r}`);const n=`
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 7px;
    border-radius: 9999px;
    font-size: 11px;
    font-weight: 700;
    line-height: 1;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    vertical-align: middle;
    margin-left: 8px;
    letter-spacing: 0.02em;
    user-select: none;
    box-sizing: border-box;
  `;return r==="CHECKING"?(e.style.cssText=`${n} background: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE;`,e.innerHTML=`
      <span style="display:inline-block; width:10px; height:10px; border:2px solid #2563EB; border-top-color:transparent; border-radius:50%; animation: aegisSpin 0.8s linear infinite;"></span>
      <span>Checking</span>
    `):r==="SAFE"?(e.style.cssText=`${n} background: #ECFDF5; color: #047857; border: 1px solid #A7F3D0;`,e.innerHTML=`
      <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM14.707 7.707a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l5-5z" clip-rule="evenodd"/></svg>
      <span>Safe</span>
    `,t&&(e.title=`AEGIS: ${t}`)):r==="SUSPICIOUS"?(e.style.cssText=`${n} background: #FFFBEB; color: #B45309; border: 1px solid #FDE68A;`,e.innerHTML=`
      <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
      <span>Suspicious</span>
    `,t&&(e.title=`AEGIS Warning: ${t}`)):r==="CRITICAL"?(e.style.cssText=`${n} background: #FEF2F2; color: #B91C1C; border: 1px solid #FECACA;`,e.innerHTML=`
      <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" clip-rule="evenodd"/></svg>
      <span>Critical Threat</span>
    `,t&&(e.title=`AEGIS Critical: ${t}`)):(e.style.cssText=`${n} background: #F1F5F9; color: #475569; border: 1px solid #CBD5E1;`,e.innerHTML="<span>Unable to Verify</span>"),e}function y(){if(a.size===0)return;const r=new Map(a);a.clear();const t=Array.from(r.keys());chrome.runtime.sendMessage({type:"BATCH_ANALYZE",payload:t},e=>{const n=e==null?void 0:e.data,o=n==null?void 0:n.results,l={};Array.isArray(o)?o.forEach(s=>{s!=null&&s.url&&(l[s.url]=s)}):o&&typeof o=="object"&&Object.assign(l,o);for(const[s,h]of r.entries()){const i=l[s],f=i?i.verdict:"INSUFFICIENT_EVIDENCE",b=i==null?void 0:i.reason;h.forEach(u=>{const p=u.querySelector(".aegis-search-badge");p&&p.remove();const C=g(f,b);u.appendChild(C)})}})}function d(){document.querySelectorAll("#search a[href], #rso a[href], div.g a[href]").forEach(t=>{const e=t.querySelector("h3");if(!e||t.dataset.aegisScanned==="true")return;t.dataset.aegisScanned="true";const n=m(t.href);if(!n)return;const o=g("CHECKING");e.appendChild(o),a.has(n)||a.set(n,[]),a.get(n).push(e)}),c!==null&&window.clearTimeout(c),c=window.setTimeout(y,150)}document.readyState==="loading"?document.addEventListener("DOMContentLoaded",d):d();const E=new MutationObserver(()=>{d()});E.observe(document.body,{childList:!0,subtree:!0});console.log("[AEGIS SearchGuard] Monitoring organic Google search results.");
