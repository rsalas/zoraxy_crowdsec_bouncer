package web

// editorPage is a minimal zero-dependency config editor: it renders every
// config field from GET api/config, lets the admin edit values and POSTs the
// changes back as JSON.
const editorPage = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Bouncer config</title>
<style>
body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;background:#f4f4f4}
h1{font-size:1.3rem}.row{display:flex;align-items:center;margin:.5rem 0;background:#fff;padding:.6rem .8rem;border-radius:6px}
label{flex:0 0 260px;font-family:monospace;font-size:.85rem}
input[type=text],input[type=password]{flex:1;padding:.4rem;border:1px solid #ccc;border-radius:4px;font-family:monospace;font-size:.85rem}
input[type=checkbox]{transform:scale(1.3)}
button{margin-top:1rem;padding:.6rem 1.6rem;border:0;border-radius:4px;background:#333;color:#fff;cursor:pointer}
#msg{margin-top:1rem;font-size:.85rem;white-space:pre-wrap}
small{color:#888;display:block}
</style></head><body>
<a href="../" style="font-family:sans-serif;font-size:.9rem;text-decoration:none">← Volver</a>
<h1>CrowdSec Bouncer configuration</h1>
<small>Masked secrets (••••xxxx) are kept as-is unless a new value is typed.</small>
<div id="form"></div>
<button onclick="save()">Save</button>
<div id="msg"></div>
<script>
const BOOLS = ["is_proxied_behind_cloudflare","appsec_enabled","appsec_fail_open","appsec_inspect_body","static_bypass","captcha_enabled"];
async function load(){
  const r = await fetch("config");
  const d = await r.json();
  const f = document.getElementById("form");
  f.innerHTML = "";
  for (const [k,v] of Object.entries(d.config).sort()){
    const row = document.createElement("div"); row.className="row";
    const lab = document.createElement("label"); lab.textContent=k; row.appendChild(lab);
    let inp;
    if (BOOLS.includes(k)) { inp=document.createElement("input"); inp.type="checkbox"; inp.checked=!!v; }
    else { inp=document.createElement("input"); inp.type=k.includes("key")||k.includes("secret")?"password":"text"; inp.value=(v===null?"":v); }
    inp.id="f_"+k; row.appendChild(inp); f.appendChild(row);
  }
}
async function save(){
  const body={};
  document.querySelectorAll("#form input").forEach(i=>{
    const k=i.id.slice(2);
    body[k]= i.type==="checkbox" ? i.checked : (i.id==="f_appsec_max_body" ? parseInt(i.value||"0") : i.value);
  });
  const r = await fetch("config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const d = await r.json();
  document.getElementById("msg").textContent = d.saved
    ? "Saved. Applied live: "+(d.applied_live||[]).join(", ")+
      (d.restart_required&&d.restart_required.length?"\nRequires plugin restart: "+d.restart_required.join(", "):"")
    : "Error: "+JSON.stringify(d);
}
load();
</script></body></html>`
