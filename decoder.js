/* CredentialDecoder – SD-JWT VC & mDOC (ISO 18013-5 CBOR) */

function b64urlDecode(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return atob(s); }
function parseUtf8Base64Url(s) {
  try {
    const raw = b64urlDecode(s);
    try {
      return decodeURIComponent(escape(raw));
    } catch (e) {
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      return new TextDecoder('utf-8').decode(bytes);
    }
  } catch (e) { return null; }
}
function b64urlDecodeJson(s) { try { return JSON.parse(parseUtf8Base64Url(s)); } catch (e) { return null; } }
function b64ToUint8(b64) { const s = b64.replace(/-/g, '+').replace(/_/g, '/'), b = atob(s), a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++)a[i] = b.charCodeAt(i); return a; }
function uint8ToB64(a) { const u = a instanceof ArrayBuffer ? new Uint8Array(a) : (ArrayBuffer.isView(a) ? new Uint8Array(a.buffer, a.byteOffset, a.byteLength) : a); let s = ''; for (let i = 0; i < u.length; i++)s += String.fromCharCode(u[i]); return btoa(s); }
function escHtml(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
function isEmpty(v) { return v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length); }
function fmtDT(v) { if (!v) return null; try { const d = new Date(v); return isNaN(d) ? v : d.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'long', timeStyle: 'short' }); } catch (e) { return v; } }

function detectFormat(txt) {
  const t = txt.trim();
  if (/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]/.test(t)) return 'sdjwt';
  if (/^[A-Za-z0-9+/=\r\n\s]+$/.test(t) && t.replace(/\s/g, '').length > 150) return 'mdoc';
  return 'unknown';
}

function decodeSDJWT(raw) {
  const parts = raw.trim().split('~');
  const jp = parts[0].split('.');
  if (jp.length < 3) throw new Error('Invalid SD-JWT: expected 3 parts');
  const h = b64urlDecodeJson(jp[0]), p = b64urlDecodeJson(jp[1]);
  if (!p) throw new Error('Cannot decode JWT payload');
  const c = {};
  parts.slice(1).forEach(d => {
    try {
      const jsonStr = parseUtf8Base64Url(d) || b64urlDecode(d);
      const obj = JSON.parse(jsonStr);
      if (Array.isArray(obj) && obj.length >= 3) {
        let k = obj[1], v = obj[2];
        if (typeof v === 'string' && k.toLowerCase().includes('image') && !v.startsWith('data:')) {
          v = 'data:image/jpeg;base64,' + v;
        }
        c[k] = v;
      }
    } catch (e) { }
  });
  return { format: 'SD-JWT VC', formatDetail: 'alg: ' + (h && h.alg || '?') + ' | kid: ' + (h && h.kid || '?'), meta: { iss: p.iss, iat: fmtDT(p.iat ? p.iat * 1000 : null), exp: fmtDT(p.exp ? p.exp * 1000 : null), id: p.id }, claims: c, rawPayload: p };
}

function decodeMDOC(raw) {
  const bytes = b64ToUint8(raw.trim().replace(/\s/g, '')).buffer;
  const outer = CBOR.decode(bytes);
  const docs = outer && outer.documents ? outer.documents : (outer && outer.issuerSigned ? [outer] : (Array.isArray(outer) ? outer : [outer]));
  const c = {}; let docType = '', meta = {};
  docs.forEach(doc => {
    docType = doc.docType || docType;
    const ns = (doc.issuerSigned || doc).nameSpaces || {};
    Object.keys(ns).forEach(nsK => {
      ns[nsK].forEach(ib => {
        try {
          let item = ib; if (ib && ib.tag === 24 && ib.value) item = CBOR.decode(ib.value.buffer || ib.value);
          else if (ib instanceof Uint8Array || ArrayBuffer.isView(ib)) item = CBOR.decode(ib.buffer || ib);
          if (!item || item.elementIdentifier === undefined) return;
          let k = item.elementIdentifier, v = item.elementValue;
          if (k.toLowerCase().includes('image') && ArrayBuffer.isView(v)) {
            v = 'data:image/jpeg;base64,' + uint8ToB64(v.buffer || v);
          } else if (v instanceof Uint8Array || ArrayBuffer.isView(v)) {
            try { v = new TextDecoder('utf-8').decode(v); } catch (e) { }
          } else if (typeof v === 'string') {
            try { v = decodeURIComponent(escape(v)); } catch (e) { }
          }
          c[k] = v;
        } catch (e) { }
      });
    });
    try {
      const ia = (doc.issuerSigned || doc).issuerAuth || [];
      if (ia[2]) meta = CBOR.decode(ia[2].buffer || ia[2]);
    } catch (e) { }
  });
  return { format: 'mDOC (ISO 18013-5)', formatDetail: 'docType: ' + docType, meta: { docType, alg: meta.digestAlgorithm }, claims: c, rawPayload: { docType, meta, claimCount: Object.keys(c).length } };
}

const CM = {
  resident_name: { l: 'Name', t: 'identity' }, ResidentName: { l: 'Name', t: 'identity' },
  local_resident_name: { l: 'Name (Local)', t: 'identity' }, LocalResidentName: { l: 'Name (Local)', t: 'identity' },
  dob: { l: 'Date of Birth', t: 'identity' }, Dob: { l: 'Date of Birth', t: 'identity' },
  gender: { l: 'Gender', t: 'identity' }, Gender: { l: 'Gender', t: 'identity' },
  masked_uid: { l: 'Masked UID', t: 'identity', m: 1 }, MaskedUID: { l: 'Masked UID', t: 'identity', m: 1 },
  aadhaar_type: { l: 'Aadhaar Type', t: 'identity' }, AadhaarType: { l: 'Aadhaar Type', t: 'identity' },
  address: { l: 'Full Address', t: 'address' }, Address: { l: 'Full Address', t: 'address' },
  building: { l: 'Building', t: 'address' }, Building: { l: 'Building', t: 'address' },
  street: { l: 'Street', t: 'address' }, Street: { l: 'Street', t: 'address' },
  vtc: { l: 'VTC', t: 'address' }, Vtc: { l: 'VTC', t: 'address' },
  district: { l: 'District', t: 'address' }, District: { l: 'District', t: 'address' },
  state: { l: 'State', t: 'address' }, State: { l: 'State', t: 'address' },
  pincode: { l: 'Pincode', t: 'address', m: 1 }, Pincode: { l: 'Pincode', t: 'address', m: 1 },
  mobile: { l: 'Mobile', t: 'contact', m: 1 }, Mobile: { l: 'Mobile', t: 'contact', m: 1 },
  email: { l: 'Email', t: 'contact', m: 1 }, Email: { l: 'Email', t: 'contact', m: 1 },
  resident_image: { l: 'Photo', t: 'photo' }, ResidentImage: { l: 'Photo', t: 'photo' }
};

function boolBadge(v) {
  const s = String(v).toUpperCase();
  if (s === 'YES' || s === 'TRUE') return '<span class="badge badge-green">' + escHtml(s) + '</span>';
  if (s === 'NO' || s === 'FALSE') return '<span class="badge badge-red">' + escHtml(s) + '</span>';
  return escHtml(v);
}

function renderTable(rows) {
  if (!rows.length) return '<p style="padding:16px;color:var(--text-muted);font-size:13px;">No data available.</p>';
  return '<table class="data-table"><tbody>' +
    rows.map(([lbl, val, opts = {}]) => {
      let cell = '';
      if (opts.photo) cell = val && val.startsWith('data:') ? '<img class="photo-img" src="' + val + '" />' : '<span class="cell-muted">N/A</span>';
      else if (opts.b) cell = boolBadge(val);
      else if (opts.dt) cell = '<span>' + (fmtDT(val) || '<span class="cell-muted">—</span>') + '</span>';
      else if (isEmpty(val)) cell = '<span class="cell-muted">—</span>';
      else cell = '<span class="' + (opts.m ? 'cell-mono' : '') + '">' + escHtml(val) + '</span>';
      return '<tr><th>' + escHtml(lbl) + '</th><td>' + cell + '</td></tr>';
    }).join('') + '</tbody></table>';
}

function renderResult(decoded) {
  document.getElementById('format-badge-container').innerHTML =
    '<span class="badge ' + (decoded.format.startsWith('SD') ? 'badge-blue' : 'badge-purple') + ' badge-lg">' + escHtml(decoded.format) + '</span>' +
    '<span style="font-size:12px;color:var(--text-muted);margin-left:10px;">' + escHtml(decoded.formatDetail) + '</span>';

  const tc = { identity: [], address: [], contact: [], issuance: [], photo: [] }, ex = [];
  Object.keys(decoded.claims).forEach(k => {
    const m = CM[k];
    if (m) tc[m.t].push([m.l, decoded.claims[k], { m: m.m, b: m.b, dt: m.dt, photo: m.t === 'photo' }]);
    else ex.push([k, decoded.claims[k], { m: 1 }]);
  });

  const mRows = [];
  Object.keys(decoded.meta).forEach(k => { if (decoded.meta[k]) mRows.push([k, decoded.meta[k], { m: 1 }]); });

  document.getElementById('tab-identity').innerHTML = '<div class="panel-section-title">Identity Claims</div>' + renderTable(tc.identity) + '<div class="panel-section-title">Metadata</div>' + renderTable(mRows);
  document.getElementById('tab-address').innerHTML = '<div class="panel-section-title">Address Claims</div>' + renderTable(tc.address);
  document.getElementById('tab-contact').innerHTML = '<div class="panel-section-title">Contact Claims</div>' + renderTable(tc.contact);
  document.getElementById('tab-issuance').innerHTML = '<div class="panel-section-title">Issuance Claims</div>' + renderTable(tc.issuance);

  document.getElementById('tab-photo').innerHTML = '<div class="panel-section-title">Resident Photo</div>' +
    '<div class="photo-panel">' + (tc.photo[0] && tc.photo[0][1] ? '<img class="photo-img" src="' + tc.photo[0][1] + '" />' : '<div class="photo-placeholder">No Photo</div>') + '</div>';

  if (ex.length) {
    document.getElementById('tab-identity').innerHTML += '<div class="panel-section-title">Other Claims</div>' + renderTable(ex);
  }

  document.getElementById('tab-raw').innerHTML = '<div class="panel-section-title">Parsed Structure</div><pre class="raw-json">' + escHtml(JSON.stringify(decoded.rawPayload, null, 2)) + '</pre>';
}

document.addEventListener('DOMContentLoaded', () => {
  const tabs = document.querySelectorAll('.tab'), panels = document.querySelectorAll('.tab-panel');
  tabs.forEach(t => {
    t.addEventListener('click', () => {
      tabs.forEach(x => x.classList.remove('active'));
      panels.forEach(x => x.classList.add('hidden'));
      t.classList.add('active');
      document.getElementById('tab-' + t.dataset.tab).classList.remove('hidden');
    });
  });

  const input = document.getElementById('credential-input');
  const btnDec = document.getElementById('btn-decode'), btnClr = document.getElementById('btn-clear');
  const outSec = document.getElementById('output-section'), errSec = document.getElementById('error-section'), errMsg = document.getElementById('error-message'), hint = document.getElementById('format-hint');

  // Try to use a sample if buttons exist
  document.getElementById('btn-sample-sdjwt')?.addEventListener('click', () => {
    input.value = "eyJhbGciOiJSUzI1NiIsImtpZCI6InVpZGFpLTRiNGQ3MjJkLTUxODctNDBhNi1iM2IyLWU0Mjg3ZDA1MDUzMSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL3VpZGFpLmdvdi5pbiIsImV4cCI6MTgwMDQ1NzE5OCwiaWF0IjoxNzY4OTIxMTk4LCJpZCI6IjU0ZGFkODAxLThlM2QtNGZjYy04NjRhLTQ4YzBhMDIwNmExZSIsImNuZiI6eyJqd2siOnsiYWxnIjoiUlMyNTYiLCJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJ0WFRIUWZ6cTEtNFB1c2ZJXzZIUkhxaVFNQUwtTXFRRmNEUktvM2VoV0hQN19ud1BuTGlnbkJ6TXpQYVBiMmZWQ2xnU0VZX1h2TXY2cGxNYmh0dFY0Nmw5eEJUSVNMR0hIVWY3T0pqVWFfdVNEM0h6SWkxTU90OUF5WTVkWVNYLWVQRENUbGQzMUxTZDdQZHJPMzgtV3VkRV9TRmZRLXUwemJXZXhPRVdJV2Z1bEtmenZYaHFEbTNjdmppbjRCMEk4WDJRWG1zWkF5aGtBYXFBamVXekJoSG9IWVAtdExtc0J2X2dKMG4yYmNGckVoSHppc2RDMkJQVUNoc0pBS19DVHFnVmlmVHl5aFZzODVNYmhGektLQWtsVDJ3RXNJNjQ2QmpwNW5hU1ViZnotdHRackF4OGtJbWs0SExHOE8xUWFBTk1TSnRKNXdmSzRELTJXbUZKalEifX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIjBoNl9hMHJRVThWOTZ5bldxQmZJMlFkeXpOMWd1YWhMeS1JV1BEX3NwdDAiLCIyN3E3M1JvaURlUXQ0NGlwT3libWpOUGptdGE1cDlUWm04WlYzd0JGeV9zIiwiTVgyVjFndjhneGFCVVFBQzBad2tvYWNhaDdwN1QxaXA5ejNJU0FINWwyOCIsIlFydkpnT2I3TjZUV19MRER3LTNPY2tCU0dNWGs3Q2RmcG8zYjVHeXNQT1UiLCJQWjhaWGZYS3czc1BxbExZbXpLNVY1c2tIQ0tfcHBxQkxoVzczbGtFU28wIiwiVTVCZlRyZXU4aVJJbUJmRk5XbVRFcG8tamlKZkFVb0pGOHJFdC1qMXB6SSIsIkhWLU0wcUJVNDFnOXZVZmJwZjE3b1BZbXhRTmJxSjdJcFJOa1Vyb0JUY28iLCJLUUFoMXVXSWUtYjRqbmdCZS1JLXNncWM2X2VfRXAwVlpjaGdEME1OQmQwIiwiSnBDUktlQTJNYVdJUFhnanJYUldPU0M5STZvYVBCSUVCX0h4eTcxdHZjNCIsInlSSWVYMGYzNWt2N2Z2VjVVVzlRYlFMa3UwcS1XQTFWaVlBck1UZEMzcE0iLCI3MTVublRUOUFjWllpQXNhMUstY2V2QjBMY2RGd0ZTVzE2bFdOek5ObmlRIiwiQ2JVMkpyaVpoLUc4X3E4aGg3bUJGTTVCZzZ2MmFXeFlsUGRVczQ3LTJaMCIsIl80akRGR0ZXNzhlcVE5dkdoTkU2OVZESWVrR1ZyYmRFZ01FV1NKOXktV00iLCJzaXRUSktsRU9XUHhNcXB3R3FzUE9BZGRBRzhoQ2gwMlFGa3owamtQbDVRIiwibmpqeHk4M0pGaGd2Wk1KTmpuRy1yWWFMVzZCOXNjNDd6Wko5Q2F5NTRSSSIsImdtekt3SXcxZ0hhLTFTZGFadkNNNHJ0bGUyWFpSazNaTFVRWW9JXzJuSU0iLCJEQXVQVy1lOUkxd2JyUUJrQTBlNTBoZEphT09sZ2MxQTA4c19JY2lzVDQ4Iiwib09CTmszSXB0TXhNMDVDUzNaNm9tUmFUWFNjUW9XQ0NzNkVBakl0aVV5WSIsIi0wX3cxQVRmYXpIdGQ4N09GNlBVdzRCN2FqYjVIdC1VT2hGbW1KR3lZOEkiLCJyMEtoOVE3cGdZdHhUNVFJX25hc01HOWE5MUk2OFBNOUpYNWVHR2ZuMlNvIiwiTTM4S0QtcjVCQ0xhNmJ4MHpyaFlqZWxSNmVzZ2tiY0xWVTllRkg1X1BjNCIsIjdmUW1uYTdQdlJEVG9MN0tUT3RQOU9iTXBqd1JuUHlxd3Y3QjJfRTBNN0EiLCItOExlR3FZUzYyQ0pxbFQxdTNsN3VVcUZKN3FWOUlaZGFHQk41aDRic3Y4IiwiWG1hTlhuaTV3bmtGRU5qQzFnLVBWTDFDN29vQTFqaFZJLVM0c0lGYUUtUSIsIkJxZUdHc3ZldF9tOEw5a05uUEc3enRyQ0VHbVVtQnRYdGNta2dvUmNHZE0iLCJ4Q1g5NFJkb0RiUnZqQUlCcXI3Uk9UT0xJQ3lDYXJybFA3WHNtOFpSb3lZIiwic2hvUVduSHI2M3NGZm92OE1vZ21HUXhoRENLYkRIaTJEaHYtRUExN2g4OCIsImJmQ0ZqekF6ZGY4UnhNc1VWZm1zUHZ2Q1hvckpxcmFIS1Rlb0JYaHkzTEUiLCJYR3dPYXBiamdpYVd1UWp2UW9jV0VJQ1MwdDB1SmM4SUZiT2lpUE00Wk5FIiwid3NqWVdxNFVzZzJrRmw3Znp0S1hJeHdrSzhDVG1FYk1ZNWlMTnBGWGRaayIsIjNxekRORV9GZ3doWk92emo0WXBDd2ZrNUE2UTJ1ejVHNmxPVWhRU0taZjAiLCJvVmtmYUk0bkFyVzZMUzJ4a0xmeFdsWHpzTzdTc1Y3alhhU0hBRWgySVB3IiwiLV9pM1Q5QWNncW1aMF9fYWJIUEtnejZIbGFyTlhfZXpVWGlKWGxSdHBUcyIsIk1IaHAzYnBPMHVuM0k0ZkNUUm5taHRBVDl0aXlTUVNtNjY0Tk5VVFRwLUkiLCJqeU1nUUhwZjVmaGVDU1hxR1pXdUJNcVlUaGlsWmxXRzJIQ1FyVy03WTZnIiwid1ZjNUhGaEpiVnF4TzlUcEhxaFMtREdUdEV1dXFvS1FBdko3TERKekRaVSIsIkF6R2p1a09BT2t4VUlLWGJNakVmWmtiZjVya09kRFo1a1ZjNXBPYm45UkUiLCJ2VHhZTkdpTm9nOVhMUGRNUnVxNlZfMDFLSTNSaU1XM1ptRGUxODBYTHFNIiwiY21FZl9fTFU0TEhaMHF5dHFkamxXOUxJaXpzaS1CQTVQVV9NNzRuelZnSSIsImtGM2Z0UWhmZndUUzdDZGIzWmJVU0VqbllwY1J1ckptS1dlZjlMSWl6dnciLCJ2Nnlsai1sSVVnMkpUSjJvV0JOUUtzWEVxSktLQUZ5ZkZ0YzZQandsRDN3IiwiZDVCN2cyQTgzSUVWT2NVRTZhSnJqUHBHWlhYVHBSdGpwYlByclkycHF4USIsInVFeEczUXFURFZBU3U2MnEzbnpxZ05lanJLbEJEckhZTDFSNTgySjZMcTAiLCI3WWZmbks5X1Myb21vNzkyVE40NWtwN29MeGVsVXIxOWlwVHk3cFV2N3BnIl19.AQc3SIsV4_r-wQvI1P5IJILxaG83S07dXPs-nIaNn1v1tM4XMWGMapWC_dkkTaZv2o4tQHysbeWyFBmjg8ssXvK_IxoahVqZVR46_BYXm_Hs2axR9j9ob4eZt0sdLc8zoMLLYxBqyDzk1wRBN8Wluwf2t2OAdDse5TeEWbQnvxQhhsM91m1Afp2D-my_fLoUHG06oaqFVABkYW-mqGM__IEPMXpmSfCR0dq5xAfL6bj3YiIccqN4_YhSQIEPmmYXJZVQPgsTHN0r9dHg1d2D7XeH_vrzPay4VJXKQqpO1PvK9rofdVsOfa3GUNDXyp7I5CUc34a468ygOxIMVcC3YA~WyJhMjk5MzNjNy04NmU1LTRjZTAtYjc0OS0xNDI1Yzk0ZWVhOTUiLCJDcmVkZW50aWFsSXNzdWluZ0RhdGUiLCIyMDI2LTAxLTIwVDIwOjI5OjU4Il0~WyJiZjdmMjQ3ZC0xYWNhLTRkZTMtOTk0NS1kYmM0Nzc1MjA2NzYiLCJFbnJvbG1lbnREYXRlIiwiMjAyNS0xMi0yM1QxMjoyODo1NSJd~WyI0NzVhZjkwNS1jMmU4LTRjMTctOWE2NS0yMDNlM2RkN2Q1OWEiLCJFbnJvbG1lbnROdW1iZXIiLCJTMTQ1OTAzMzIyOTQ4MCJd~WyI1MGNjNWNiMS0wNTY3LTRmZGYtYTY0ZC01Mzk1MGYwNWI5MzgiLCJJc05SSSIsIk5vIl0~WyI2MDZmYWIwYy05MDkxLTQzMmMtODk0OC1mMDU3ZDQxYTZhYzEiLCJJc1Jlc2lkZW50Rm9yZWlnbmVyIiwiTm8iXQ~WyJkODZkMzY1NC1iNjhjLTQ5ZmItOWFmMy1hOTQ4YTg0YjFkZjEiLCJBYWRoYWFyRXhwaXJlc09uIiwiIl0~WyJlNDQzNmViYy0xYjNjLTRkN2QtYTZjNC1kMGM5OTVhZjU4ZjQiLCJBYWRoYWFyVHlwZSIsIklOIl0~WyI3YTFhNmUyMy1mNGU1LTRmNGEtOGI5MS00NDc2ZDIzZDIyNzQiLCJSZXNpZGVudE5hbWUiLCJTYXVyYXYgTnJpIl0~WyJkMDRkYzhhYi00NWI5LTRjMGEtOTcxNy1jNjJiNWNhODY5MTYiLCJBZ2VBYm92ZTE4IiwiWWVzIl0~WyI5MjVhNDJmNS1iNzU1LTQxODYtOTk2ZC1lMzYyMThjYzFjMDQiLCJBZ2VBYm92ZTUwIiwiTm8iXQ~WyI0MzFmOWExMC1kZjc0LTQ3ZjAtODE3OC01OTE4MzM4OWM0MWIiLCJBZ2VBYm92ZTYwIiwiTm8iXQ~WyIxNTA5NzQ5ZS1iOTNlLTQ2YjUtOGVjZC0yMGVkOGE1Njg0NTAiLCJBZ2VBYm92ZTc1IiwiTm8iXQ~WyJhZmIwMTQzOS0yNTRhLTRlYTgtYjYwNS1mNGVkY2I1ZTI4ZTYiLCJEb2IiLCIxOTkxLTAyLTEwIl0~WyI0Y2UwNzg2ZC02MzNkLTRjMmItYWQyMi02NjMwZTk3MTE0NGUiLCJHZW5kZXIiLCJNQUxFIl0~WyJkZWNkZGU2OC02ZmVmLTQxZmQtYmMyYy1jODc5OWJlNTU0ZDkiLCJDYXJlT2YiLCJDL086IEVjbXAgTG91IFRlc3RpbmciXQ~WyIxNTJjZTcyNi01MjIxLTRhYjQtYTdjNS1kN2FiN2Y3MmE0ZTYiLCJCdWlsZGluZyIsIlN0YWdlIFRlYW0iXQ~WyIyNjRjNTU1Mi1hMTRjLTRiMzktYmRhNy03OWJlN2YyZTgwOWMiLCJMb2NhbGl0eSIsIiJd~WyJlNGUzMzMwOS05ODRkLTQ2MDItYWNiZS1lMGMzZTJkNTljMDkiLCJTdHJlZXQiLCJ1aWRhaSJd~WyI0ZWVkYWQ2Yi1lMTM0LTQzNTYtYTU5NS0xMDVjNWRlYThmYWEiLCJMYW5kbWFyayIsIiJd~WyJiOTc5ZDA3NC0zYTBhLTRjNWMtOTZkYi0zYzZiYmY5ZDUzMTAiLCJWdGMiLCJCYW5nYWxvcmUgTm9ydGgiXQ~WyJkOTA2Zjg3NS03NjBmLTQyMjQtYTE5ZC03OTNjYTljZThkMjQiLCJTdWJEaXN0cmljdCIsIkJhbmdhbG9yZSBOb3J0aCJd~WyIyN2VmZDcwMi0yNTU5LTQ1M2ItOTNkNy1lNGNjOGQzMjI3ZmUiLCJEaXN0cmljdCIsIkJlbmdhbHVydSJd~WyJlZDBmZjEzMy00ZWM3LTQ3N2EtOTY0NC01YzQ2YzM1YWJmNzUiLCJTdGF0ZSIsIkthcm5hdGFrYSJd~WyIxYWMwMTMwNy1lZTQ3LTQ0YmItOTc4ZS0wY2U1N2ZkOWQ2ODEiLCJQb05hbWUiLCJNYXJhdGhhaGFsbGkgQ29sb255Il0~WyI2MGNkYTQ0Mi01NDVhLTQxMzctYTRiMC00YWUyNzBlYmQyNjAiLCJQaW5jb2RlIiwiNTYwMDM3Il0~WyJkMDQzNTkyOC1lYmI2LTRlY2ItYjZiNS1lODZmODE0MDBkZDYiLCJBZGRyZXNzIiwiQy9POiBFY21wIExvdSBUZXN0aW5nIFN0YWdlIFRlYW0gdWlkYWkgQmFuZ2Fsb3JlIE5vcnRoIE1hcmF0aGFoYWxsaSBDb2xvbnkgQmVuZ2FsdXJ1IEthcm5hdGFrYSA1NjAwMzciXQ~WyJmNDQxYmJiZC0yMGYwLTRiOTItYmQ2ZS05NmVkYmUwNDI2OTQiLCJNb2JpbGUiLCIrOTEgOTg0NDYxOTA5MSJd~WyI2ZmM1ODI0ZS1mOWZiLTQ1ZWYtYWQ2Zi0wYzAzNDcxMWMwNzYiLCJNYXNrZWRNb2JpbGUiLCIrOTFYWFhYWC1YOTA5MSJd~WyI1MWYyNTJhNi1mMzk1LTRmY2ItYjBjMi00YTdkM2NkY2ZkMTYiLCJFbWFpbCIsImFudW1vbnIudGNzQHVpZGFpLm5ldC5pbiJd~WyJkZTY5YmM1Zi1mOTEwLTQ2ZDYtOTU1MC1iYWZmZTI3YjE2ZjAiLCJNYXNrZWRFbWFpbCIsImFudW1YWFhYWHQuaW4iXQ~WyI2ZWQwMGM3NC0zMWNlLTQxODctOGU1Yi1lNjkyN2U0OGZmNDUiLCJNYXNrZWRVSUQiLCJYWFhYLVhYWFgtOTk5OSJd~";
    input.dispatchEvent(new Event('input'));
  });

  btnClr.addEventListener('click', () => {
    input.value = ''; outSec.classList.add('hidden'); errSec.classList.add('hidden'); hint.textContent = '';
  });

  input.addEventListener('input', () => {
    const fmt = detectFormat(input.value);
    if (fmt === 'sdjwt') hint.innerHTML = '<span style="color:var(--green)">✓ SD-JWT VC Detected</span>';
    else if (fmt === 'mdoc') hint.innerHTML = '<span style="color:var(--accent2)">✓ mDOC (CBOR) Detected</span>';
    else hint.textContent = '';
  });

  btnDec.addEventListener('click', () => {
    errSec.classList.add('hidden'); outSec.classList.add('hidden');
    const val = input.value.trim(); if (!val) return;
    const fmt = detectFormat(val);
    try {
      let dec;
      if (fmt === 'sdjwt') dec = decodeSDJWT(val);
      else if (fmt === 'mdoc') dec = decodeMDOC(val);
      else throw new Error('Unrecognized format. Please provide a valid SD-JWT or base64 CBOR mDOC.');
      renderResult(dec);
      outSec.classList.remove('hidden');
    } catch (e) {
      errMsg.textContent = e.message; errSec.classList.remove('hidden');
    }
  });

  document.getElementById('btn-copy-json').addEventListener('click', function () {
    const text = document.querySelector('.raw-json').textContent;
    navigator.clipboard.writeText(text);
    const og = this.innerHTML;
    this.innerHTML = 'Copied!';
    setTimeout(() => this.innerHTML = og, 2000);
  });
});
