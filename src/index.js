const PASSCODE_KEY = 'imgbed:passcode';
const SESSION_PREFIX = 'imgbed:session:';
const SESSION_MAX_AGE = 86400 * 7;
const DEFAULT_PASSCODE = 'imgbed123';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Public image serving
    if (path.startsWith('/i/')) return serveImage(path.slice(3), env);

    // Auth routes
    if (path === '/login' && request.method === 'POST') return handleLogin(request, env);
    if (path === '/logout') return handleLogout(request, env);
    if (path === '/change-passcode' && request.method === 'POST') return handleChangePasscode(request, env);

    // Protected routes
    const session = await checkSession(request, env);
    if (path === '/upload' && request.method === 'POST') {
      if (!session) return json({ error: 'Unauthorized' }, 401);
      return handleUpload(request, env, url);
    }
    if (path === '/api/list') {
      if (!session) return json({ error: 'Unauthorized' }, 401);
      return handleList(request, env, url);
    }
    if (path === '/api/delete' && request.method === 'POST') {
      if (!session) return json({ error: 'Unauthorized' }, 401);
      return handleDelete(request, env);
    }

    // Pages
    if (!session) return html(loginPage());
    return html(uploadPage());
  },
};

// --- Auth ---

async function checkSession(request, env) {
  const cookie = parseCookie(request.headers.get('Cookie') || '');
  const token = cookie['imgbed_session'];
  if (!token) return null;
  const data = await env.KV.get(SESSION_PREFIX + token);
  return data ? JSON.parse(data) : null;
}

async function handleLogin(request, env) {
  const form = await request.formData();
  const input = form.get('passcode') || '';
  const stored = (await env.KV.get(PASSCODE_KEY)) || DEFAULT_PASSCODE;

  if (input !== stored) {
    return html(loginPage('Wrong passcode'), 401);
  }

  const token = randomHex(32);
  await env.KV.put(SESSION_PREFIX + token, JSON.stringify({ t: Date.now() }), { expirationTtl: SESSION_MAX_AGE });

  return new Response(null, {
    status: 302,
    headers: {
      Location: '/',
      'Set-Cookie': `imgbed_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MAX_AGE}`,
    },
  });
}

async function handleLogout(request, env) {
  const cookie = parseCookie(request.headers.get('Cookie') || '');
  const token = cookie['imgbed_session'];
  if (token) await env.KV.delete(SESSION_PREFIX + token);

  return new Response(null, {
    status: 302,
    headers: {
      Location: '/',
      'Set-Cookie': 'imgbed_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
    },
  });
}

async function handleChangePasscode(request, env) {
  const session = await checkSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);

  const form = await request.formData();
  const current = form.get('current') || '';
  const next = form.get('next') || '';

  const stored = (await env.KV.get(PASSCODE_KEY)) || DEFAULT_PASSCODE;
  if (current !== stored) return json({ error: 'Current passcode is wrong' }, 403);
  if (next.length < 4) return json({ error: 'Passcode must be at least 4 characters' }, 400);

  await env.KV.put(PASSCODE_KEY, next);
  return json({ ok: true });
}

// --- Images ---

async function handleUpload(request, env, url) {
  const form = await request.formData();
  const file = form.get('file');
  if (!file || !file.name) return json({ error: 'No file' }, 400);

  const ext = file.name.split('.').pop().toLowerCase();
  const allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico', 'bmp', 'avif'];
  if (!allowed.includes(ext)) return json({ error: 'File type not allowed' }, 400);

  const key = randomHex(8) + '.' + ext;
  await env.BUCKET.put(key, file.stream(), {
    httpMetadata: { contentType: file.type },
    customMetadata: { name: file.name, uploaded: new Date().toISOString() },
  });

  const base = url.origin;
  const imgUrl = `${base}/i/${key}`;
  return json({ url: imgUrl, key, html: `<img src="${imgUrl}" alt="${file.name}" width=100%>`, md: `![${file.name}](${imgUrl})`, bbcode: `[img]${imgUrl}[/img]` });
}

async function serveImage(key, env) {
  const obj = await env.BUCKET.get(key);
  if (!obj) return new Response('Not found', { status: 404 });

  return new Response(obj.body, {
    headers: {
      'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
      'Cache-Control': 'public, max-age=31536000, immutable',
      ETag: obj.etag,
    },
  });
}

async function handleList(request, env, url) {
  const cursor = url.searchParams.get('cursor') || undefined;
  const listed = await env.BUCKET.list({ limit: 50, cursor });

  const items = listed.objects.map((o) => ({
    key: o.key,
    url: `${url.origin}/i/${o.key}`,
    size: o.size,
    uploaded: o.uploaded.toISOString(),
    name: o.customMetadata?.name || o.key,
  }));
  return json({ items, cursor: listed.truncated ? listed.cursor : null });
}

async function handleDelete(request, env) {
  const { key } = await request.json();
  if (!key) return json({ error: 'No key' }, 400);
  await env.BUCKET.delete(key);
  return json({ ok: true });
}

// --- Helpers ---

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

function parseCookie(str) {
  const obj = {};
  for (const pair of str.split(';')) {
    const [k, ...v] = pair.trim().split('=');
    if (k) obj[k] = v.join('=');
  }
  return obj;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

function html(body, status = 200) {
  return new Response(body, { status, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

// --- Pages ---

function loginPage(error = '') {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>imgbed</title><style>${css()}</style></head><body>
<div class="card login-card">
  <h1>imgbed</h1>
  <p class="sub">Image hosting for embedding</p>
  ${error ? `<p class="error">${error}</p>` : ''}
  <form method="POST" action="/login">
    <input type="password" name="passcode" placeholder="Passcode" autofocus required>
    <button type="submit">Log in</button>
  </form>
</div></body></html>`;
}

function uploadPage() {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>imgbed</title><style>${css()}</style></head><body>
<nav>
  <span class="logo">imgbed</span>
  <div class="nav-right">
    <button onclick="showSettings()" class="btn-sm">Settings</button>
    <a href="/logout" class="btn-sm">Logout</a>
  </div>
</nav>

<div class="card">
  <div id="drop" class="dropzone" onclick="fileInput.click()">
    <p>Drop image here, paste, or click to select</p>
    <input type="file" id="fileInput" accept="image/*" multiple hidden>
  </div>
  <div id="results"></div>
</div>

<div id="gallery" class="card">
  <h3>Uploaded images</h3>
  <div id="gallery-grid"></div>
  <button id="load-more" onclick="loadMore()" class="btn-sm" style="display:none">Load more</button>
</div>

<dialog id="settings-dialog">
  <div class="dialog-content">
    <h3>Change passcode</h3>
    <form id="passcode-form">
      <input type="password" id="pc-current" placeholder="Current passcode" required>
      <input type="password" id="pc-new" placeholder="New passcode (min 4 chars)" required minlength="4">
      <div class="dialog-actions">
        <button type="button" onclick="document.getElementById('settings-dialog').close()">Cancel</button>
        <button type="submit">Save</button>
      </div>
      <p id="pc-msg"></p>
    </form>
  </div>
</dialog>

<script>
const drop = document.getElementById('drop');
const fileInput = document.getElementById('fileInput');
const results = document.getElementById('results');

drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); upload(e.dataTransfer.files); });
fileInput.addEventListener('change', () => upload(fileInput.files));
document.addEventListener('paste', e => {
  const files = e.clipboardData?.files;
  if (files?.length) upload(files);
});

async function upload(files) {
  for (const file of files) {
    const row = document.createElement('div');
    row.className = 'result-row';
    row.innerHTML = '<span class="fname">' + esc(file.name) + '</span> <span class="status">uploading...</span>';
    results.prepend(row);

    const fd = new FormData();
    fd.append('file', file);
    try {
      const r = await fetch('/upload', { method: 'POST', body: fd });
      const d = await r.json();
      if (d.error) { row.querySelector('.status').textContent = d.error; continue; }
      row.className = 'result-card';
      row.innerHTML = '<img src="' + d.url + '" class="thumb">'
        + '<div class="embed-rows">'
        + embedRow('URL', d.url)
        + embedRow('MarkDown', d.md)
        + embedRow('HTML', d.html)
        + embedRow('BBCode', d.bbcode)
        + '</div>';
      galleryCursor = null;
      loadGallery();
    } catch(e) { row.querySelector('.status').textContent = 'Failed'; }
  }
}

function copyText(t, btn) {
  navigator.clipboard.writeText(t);
  if (btn) { const orig = btn.textContent; btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = orig, 1200); }
}
function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;'); }
function embedRow(label, value) {
  const escaped = value.replace(/&/g,'&amp;').replace(/"/g,'&quot;');
  return '<div class="embed-row"><span class="embed-label">' + label + '</span>'
    + '<input readonly value="' + escaped + '" onclick="this.select()">'
    + '<button class="copy-btn" onclick="copyText(this.previousElementSibling.value, this)">Copy</button></div>';
}

let galleryCursor = null;
async function loadGallery() {
  const r = await fetch('/api/list' + (galleryCursor ? '?cursor='+galleryCursor : ''));
  const d = await r.json();
  const grid = document.getElementById('gallery-grid');
  if (!galleryCursor) grid.innerHTML = '';
  for (const item of d.items) {
    const el = document.createElement('div');
    el.className = 'gallery-item';
    const md = '![' + item.name + '](' + item.url + ')';
    const ht = '<img src="' + item.url + '" alt="' + item.name + '" width=100%>';
    const bb = '[img]' + item.url + '[/img]';
    el.innerHTML = '<img src="' + item.url + '" loading="lazy">'
      + '<div class="gallery-overlay">'
      + '<button onclick="copyText(\\''+item.url+'\\',this)">URL</button>'
      + '<button onclick="copyText(\\''+md.replace(/'/g,"\\\\'")+'\\'  ,this)">MarkDown</button>'
      + '<button onclick="copyText(\\''+ht.replace(/'/g,"\\\\'")+'\\'  ,this)">HTML</button>'
      + '<button onclick="copyText(\\''+bb+'\\'  ,this)">BBCode</button>'
      + '<button class="del-btn" onclick="delImg(\\''+item.key+'\\',this)">Delete</button>'
      + '</div>';
    grid.appendChild(el);
  }
  galleryCursor = d.cursor;
  document.getElementById('load-more').style.display = d.cursor ? '' : 'none';
}
function loadMore() { loadGallery(); }

async function delImg(key, btn) {
  if (!confirm('Delete this image?')) return;
  await fetch('/api/delete', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({key}) });
  btn.closest('.gallery-item').remove();
}

function showSettings() { document.getElementById('settings-dialog').showModal(); }
document.getElementById('passcode-form').onsubmit = async e => {
  e.preventDefault();
  const msg = document.getElementById('pc-msg');
  const r = await fetch('/change-passcode', { method:'POST', body: new FormData(e.target) });
  const d = await r.json();
  msg.textContent = d.error || 'Passcode changed!';
  msg.style.color = d.error ? '#e74c3c' : '#27ae60';
  if (d.ok) setTimeout(() => document.getElementById('settings-dialog').close(), 1000);
};
document.getElementById('pc-current').name = 'current';
document.getElementById('pc-new').name = 'next';

loadGallery();
</script></body></html>`;
}

function css() {
  return `*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#f0f2f5;min-height:100vh;color:#333}
nav{display:flex;justify-content:space-between;align-items:center;padding:12px 24px;background:#fff;border-bottom:1px solid #e0e0e0}
.logo{font-size:20px;font-weight:700;color:#2563eb}
.nav-right{display:flex;gap:8px;align-items:center}
.btn-sm{padding:6px 14px;border:1px solid #d0d0d0;border-radius:6px;background:#fff;cursor:pointer;font-size:13px;color:#555;text-decoration:none}
.btn-sm:hover{background:#f5f5f5}
.card{max-width:720px;margin:24px auto;background:#fff;border-radius:12px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.login-card{margin-top:20vh;max-width:360px;text-align:center}
h1{font-size:28px;color:#2563eb;margin-bottom:4px}
.sub{color:#888;margin-bottom:20px}
.error{color:#e74c3c;margin-bottom:12px;font-size:14px}
input[type=password],input[readonly]{width:100%;padding:10px 14px;border:1px solid #d0d0d0;border-radius:8px;font-size:14px;margin-bottom:10px}
button[type=submit]{width:100%;padding:10px;border:none;border-radius:8px;background:#2563eb;color:#fff;font-size:15px;cursor:pointer}
button[type=submit]:hover{background:#1d4ed8}
.dropzone{border:2px dashed #c0c0c0;border-radius:10px;padding:48px 24px;text-align:center;cursor:pointer;transition:border-color .2s;color:#888}
.dropzone.over,.dropzone:hover{border-color:#2563eb;color:#2563eb}
.result-card{padding:14px 0;border-bottom:1px solid #f0f0f0;display:flex;gap:14px;align-items:flex-start}
.thumb{width:64px;height:64px;object-fit:cover;border-radius:8px;flex-shrink:0}
.embed-rows{flex:1;display:flex;flex-direction:column;gap:6px}
.embed-row{display:flex;align-items:center;gap:8px}
.embed-label{width:70px;flex-shrink:0;font-size:12px;font-weight:600;color:#888;text-align:right}
.embed-row input[readonly]{flex:1;font-size:12px;padding:6px 10px;margin:0;border:1px solid #e0e0e0;border-radius:6px;background:#f8f9fa;color:#555}
.copy-btn{padding:5px 12px;border:1px solid #d0d0d0;border-radius:6px;background:#fff;cursor:pointer;font-size:12px;color:#555;white-space:nowrap}
.copy-btn:hover{background:#f0f4ff;border-color:#2563eb;color:#2563eb}
.result-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #f0f0f0}
.fname{font-size:13px;color:#555}
.status{font-size:13px;color:#888}
#gallery h3{margin-bottom:12px;font-size:16px;color:#555}
.gallery-grid-wrapper{overflow:hidden}
#gallery-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px}
.gallery-item{position:relative;aspect-ratio:1;border-radius:8px;overflow:hidden;background:#f5f5f5}
.gallery-item img{width:100%;height:100%;object-fit:cover}
.gallery-overlay{position:absolute;inset:0;background:rgba(0,0,0,.6);display:flex;flex-direction:column;justify-content:center;align-items:center;gap:5px;opacity:0;transition:opacity .2s;padding:8px}
.gallery-item:hover .gallery-overlay{opacity:1}
.gallery-overlay button{padding:4px 12px;border:none;border-radius:4px;background:#fff;cursor:pointer;font-size:11px;width:80%;color:#333}
.gallery-overlay button:hover{background:#f0f4ff;color:#2563eb}
.gallery-overlay .del-btn{background:transparent;color:#fff;border:1px solid rgba(255,255,255,.5);margin-top:2px}
.gallery-overlay .del-btn:hover{background:rgba(231,76,60,.8);border-color:transparent;color:#fff}
dialog{border:none;border-radius:12px;padding:24px;max-width:380px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.15)}
dialog::backdrop{background:rgba(0,0,0,.3)}
.dialog-actions{display:flex;gap:8px;justify-content:flex-end}
.dialog-actions button{width:auto;padding:8px 16px;font-size:13px}
.dialog-actions button:first-child{background:#fff;color:#555;border:1px solid #d0d0d0}
#pc-msg{margin-top:8px;font-size:13px}`;
}
