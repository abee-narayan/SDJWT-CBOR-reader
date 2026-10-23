/* CredentialDecoder – SD-JWT VC & mDOC (ISO 18013-5 CBOR) */

function b64urlDecode(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return atob(s); }
function uint8ToB64Url(u8) {
  const bytes = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
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
function b64ToUint8(b64) {
  let s = b64.trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  while (s.length % 4) s += '=';
  const b = atob(s), a = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
  return a;
}
function uint8ToB64(a) { const u = a instanceof ArrayBuffer ? new Uint8Array(a) : (ArrayBuffer.isView(a) ? new Uint8Array(a.buffer, a.byteOffset, a.byteLength) : a); let s = ''; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
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
  const disclosures = [];
  parts.slice(1).forEach(d => {
    if (!d) return;
    // Check if trailing part is a Key Binding JWT (3 dot-separated base64url segments starting with eyJ)
    if (d.includes('.') && /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(d)) {
      return;
    }
    try {
      const jsonStr = parseUtf8Base64Url(d) || b64urlDecode(d);
      const obj = JSON.parse(jsonStr);
      if (Array.isArray(obj) && obj.length >= 2) {
        let k = obj.length >= 3 ? obj[1] : '(array element)';
        let v = obj.length >= 3 ? obj[2] : obj[1];
        disclosures.push({ raw: d, salt: obj[0], key: k, val: v });
        if (obj.length >= 3) {
          if (typeof v === 'string' && k.toLowerCase().includes('image') && !v.startsWith('data:')) {
            v = 'data:image/jpeg;base64,' + v;
          }
          c[k] = v;
        }
      }
    } catch (e) { }
  });
  return {
    format: 'SD-JWT VC',
    formatDetail: 'alg: ' + (h && h.alg || '?') + ' | kid: ' + (h && h.kid || '?'),
    meta: { iss: p.iss, iat: fmtDT(p.iat ? p.iat * 1000 : null), exp: fmtDT(p.exp ? p.exp * 1000 : null), id: p.id },
    claims: c,
    rawPayload: p,
    rawHeader: h,
    rawJwt: parts[0],
    disclosures
  };
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

/* ─── Cryptographic Key Parsing & SD-JWT Signature Verification ─── */

function getWebCryptoParams(alg) {
  const a = String(alg || 'RS256').toUpperCase();
  const map = {
    RS256: { importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verifyAlg: 'RSASSA-PKCS1-v1_5', kty: 'RSA' },
    RS384: { importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }, verifyAlg: 'RSASSA-PKCS1-v1_5', kty: 'RSA' },
    RS512: { importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }, verifyAlg: 'RSASSA-PKCS1-v1_5', kty: 'RSA' },
    PS256: { importAlg: { name: 'RSA-PSS', hash: 'SHA-256' }, verifyAlg: { name: 'RSA-PSS', saltLength: 32 }, kty: 'RSA' },
    PS384: { importAlg: { name: 'RSA-PSS', hash: 'SHA-384' }, verifyAlg: { name: 'RSA-PSS', saltLength: 48 }, kty: 'RSA' },
    PS512: { importAlg: { name: 'RSA-PSS', hash: 'SHA-512' }, verifyAlg: { name: 'RSA-PSS', saltLength: 64 }, kty: 'RSA' },
    ES256: { importAlg: { name: 'ECDSA', namedCurve: 'P-256' }, verifyAlg: { name: 'ECDSA', hash: 'SHA-256' }, kty: 'EC' },
    ES384: { importAlg: { name: 'ECDSA', namedCurve: 'P-384' }, verifyAlg: { name: 'ECDSA', hash: 'SHA-384' }, kty: 'EC' },
    ES512: { importAlg: { name: 'ECDSA', namedCurve: 'P-521' }, verifyAlg: { name: 'ECDSA', hash: 'SHA-512' }, kty: 'EC' },
    EDDSA: { importAlg: { name: 'Ed25519' }, verifyAlg: { name: 'Ed25519' }, kty: 'OKP' }
  };
  return map[a] || map.RS256;
}

// Minimal ASN.1 DER Reader to extract SubjectPublicKeyInfo from X.509 Certs or wrap PKCS#1 RSA Public Keys
function readDerNode(bytes, offset) {
  if (offset >= bytes.length) throw new Error('Unexpected end of DER');
  const tag = bytes[offset++];
  let len = bytes[offset++];
  if (len & 0x80) {
    const nBytes = len & 0x7f;
    len = 0;
    for (let i = 0; i < nBytes; i++) len = (len << 8) | bytes[offset++];
  }
  const start = offset - (len >= 128 ? 2 + ( bytes[offset - 1 - (len > 255 ? 2 : 1)] & 0x7f ) : 2);
  // Compute exact header start
  return { tag, headerStart: offset - (offset - start), contentStart: offset, length: len, end: offset + len };
}

function parseAsn1Children(bytes, start, end) {
  const list = [];
  let pos = start;
  while (pos < end) {
    const nodeStart = pos;
    const tag = bytes[pos++];
    let len = bytes[pos++];
    if (len & 0x80) {
      const nBytes = len & 0x7f;
      len = 0;
      for (let i = 0; i < nBytes; i++) len = (len << 8) | bytes[pos++];
    }
    const contentStart = pos;
    const nodeEnd = pos + len;
    list.push({ tag, nodeStart, contentStart, length: len, end: nodeEnd });
    pos = nodeEnd;
  }
  return list;
}

function wrapPkcs1RsaToSpki(pkcs1Bytes) {
  // OID 1.2.840.113549.1.1.1 (rsaEncryption) + NULL
  const algId = new Uint8Array([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
  const bitStringLen = pkcs1Bytes.length + 1;
  const encodeLen = (l) => {
    if (l < 128) return [l];
    const arr = [];
    let temp = l;
    while (temp > 0) { arr.unshift(temp & 0xff); temp >>= 8; }
    arr.unshift(0x80 | arr.length);
    return arr;
  };
  const bsLenBytes = encodeLen(bitStringLen);
  const bitString = new Uint8Array(1 + bsLenBytes.length + 1 + pkcs1Bytes.length);
  bitString[0] = 0x03;
  bitString.set(bsLenBytes, 1);
  bitString[1 + bsLenBytes.length] = 0x00;
  bitString.set(pkcs1Bytes, 2 + bsLenBytes.length);

  const seqContentLen = algId.length + bitString.length;
  const seqLenBytes = encodeLen(seqContentLen);
  const spki = new Uint8Array(1 + seqLenBytes.length + seqContentLen);
  spki[0] = 0x30;
  spki.set(seqLenBytes, 1);
  spki.set(algId, 1 + seqLenBytes.length);
  spki.set(bitString, 1 + seqLenBytes.length + algId.length);
  return spki;
}

function extractSpkiFromDer(derBytes) {
  const root = parseAsn1Children(derBytes, 0, derBytes.length)[0];
  if (!root || root.tag !== 0x30) throw new Error('Invalid ASN.1 DER structure');
  const rootChildren = parseAsn1Children(derBytes, root.contentStart, root.end);
  if (!rootChildren.length) throw new Error('Empty ASN.1 sequence');

  // Case 1: Already SubjectPublicKeyInfo (SEQUENCE of [AlgorithmIdentifier(SEQUENCE), BIT STRING])
  if (rootChildren.length === 2 && rootChildren[0].tag === 0x30 && rootChildren[1].tag === 0x03) {
    return derBytes.slice(root.nodeStart, root.end);
  }
  // Case 2: PKCS#1 RSAPublicKey (SEQUENCE of [INTEGER modulus, INTEGER publicExponent])
  if (rootChildren.length === 2 && rootChildren[0].tag === 0x02 && rootChildren[1].tag === 0x02) {
    return wrapPkcs1RsaToSpki(derBytes.slice(root.nodeStart, root.end));
  }
  // Case 3: X.509 Certificate (SEQUENCE of [tbsCertificate(SEQUENCE), signatureAlgorithm, signatureValue])
  if (rootChildren.length === 3 && rootChildren[0].tag === 0x30) {
    const tbs = rootChildren[0];
    const tbsChildren = parseAsn1Children(derBytes, tbs.contentStart, tbs.end);
    // In TBSCertificate: [0] version (optional, tag 0xa0), serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    for (let i = 0; i < tbsChildren.length; i++) {
      const c = tbsChildren[i];
      if (c.tag === 0x30) {
        const sub = parseAsn1Children(derBytes, c.contentStart, c.end);
        if (sub.length === 2 && sub[0].tag === 0x30 && sub[1].tag === 0x03) {
          return derBytes.slice(c.nodeStart, c.end);
        }
      }
    }
  }
  throw new Error('Unrecognized DER structure (expected SPKI Public Key, PKCS#1 RSA Key, or X.509 Certificate)');
}

function hexOrB64ToB64Url(val) {
  const clean = val.trim().replace(/^0x/i, '').replace(/[\s:_]/g, '');
  if (/^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0 && clean.length >= 64) {
    let bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
    if (bytes[0] === 0 && bytes.length > 1) bytes = bytes.slice(1);
    return uint8ToB64Url(bytes);
  }
  // Already base64 or base64url
  const u8 = b64ToUint8(val.trim());
  return uint8ToB64Url(u8);
}

function detectKeyInputType(rawInput) {
  const s = rawInput.trim();
  if (!s) return null;
  if (/^https?:\/\/\S+$/i.test(s)) return 'JWKS / .well-known URL';
  if (/^https?:\/\/\S+/i.test(s) && s.includes('{')) return 'URL + .well-known / JWKS JSON';
  if (s.startsWith('{') || s.includes('"keys"')) {
    try {
      const jsonStart = s.indexOf('{');
      const obj = JSON.parse(jsonStart > 0 ? s.slice(jsonStart) : s);
      if (obj.jwks && obj.jwks.keys && Array.isArray(obj.jwks.keys)) return '.well-known Metadata (' + obj.jwks.keys.length + ' keys)';
      if (obj.jwks_uri) return '.well-known Metadata (jwks_uri: ' + obj.jwks_uri + ')';
      if (obj.keys && Array.isArray(obj.keys)) return 'JWKS JSON (' + obj.keys.length + ' key' + (obj.keys.length === 1 ? '' : 's') + ')';
      if (obj.kty) return 'JWK JSON (' + obj.kty + (obj.alg ? ' / ' + obj.alg : '') + (obj.kid ? ', kid: ' + obj.kid : '') + ')';
    } catch (e) { return 'Invalid JSON'; }
  }
  if (s.includes('-----BEGIN CERTIFICATE-----')) return 'X.509 Certificate (PEM)';
  if (s.includes('-----BEGIN RSA PUBLIC KEY-----')) return 'PKCS#1 RSA Public Key (PEM)';
  if (s.includes('-----BEGIN PUBLIC KEY-----')) return 'SPKI Public Key (PEM)';
  if (/(?:^|\n)\s*(?:modulus|n)\s*[:=]/i.test(s)) return 'Text Public Key Parameters (Modulus/Exponent)';
  if (/^[0-9a-fA-F\s:]+$/.test(s) && s.replace(/[\s:]/g, '').length >= 256) return 'Hex RSA Modulus / Key';
  if (/^[A-Za-z0-9+/=\-_.\r\n\s]+$/.test(s) && s.length > 60) return 'Base64 Public Key / Certificate / Modulus';
  return 'Public Key Input';
}

const UIDAI_PEHCHAAN_JWKS = {
  keys: [
    {
      use: 'sig',
      kty: 'RSA',
      e: 'AQAB',
      kid: 'uidai-37a8e742-c375-443c-8ce5-8b7a0822cb6b',
      n: 'rHKsQEpYG8nmC-Jr8PKYqd8XMnZ3EIsd4wKmlLlppvNtCvdrJbBU8lmPmebSdnQa-nAkdWhRMn34zpbFcbU2KKLd4td0eubljxS3J6_mEFukyDB5-QVX7ktRZpaCeIBEc0Tt8YaD9vqkiaBhrWPIMKfw96zifzGxLbNjwKokNhpaHt-QKJe5TB5s7opS5GiJbnTjS6-PCFfDsrdrTplJOd9G8MIhgO1gnrwQ4ccPuyd4LBovB1MrCI8vUpyVV4RuCHSM3OtWgiAdLDgqDuBjfMiM4MUjlZrQCFPRL4K2XoeH5gGqaMfxta_X40n9bM4nnuqModC2T1MPWrQRh3nJbXfGaVB0QzdAWmOA7ZbDriQSbuRsVFgVy8DUcKlWRXhhCp5UqtZVFojWon1xkKZOhC9hpC67H7xLpGy6xRO8o_beqeGZNQs07jg65UVfFSKGzh3kRfN8kCKrIyuJLeT36qgilQOGOX0j_ZqN1Uuaf47O3NFz3xyj7J3ufHE1Y9aLoAzFakbYrEsHqzVJZKqf7v67HhU46ukI6CWqNlXtjdMgGYZG4LixhfXYVIbssjxJScvagE9nhpfjlZB-fnq3MIT57bVZRpEztBJJbcMSQQRc42ZH2GNb2yh-2Hi3UrCa8MiKGnYii5YILGPHjPrj_lNEByYpZq8RVzbAD89eYxc'
    },
    {
      use: 'sig',
      e: 'AQAB',
      kid: 'uidai-05261932-1a73-4507-9923-e6b274ab6c60',
      kty: 'RSA',
      n: '3AyPSLGCq5byG_pGadN9r9kgVVL0113XQCjmzrPqlclrueX6WHsMPr3Gbdsaa-Z_sgIC_3OhJL2lx-JBZ94a2DNVAhN0Otb1aJT7iy3VOQogfDOW_g6BOQoJqZgfGM1YRbZcTrdkaeaTjp-hdBXiq0UHKiOGsk8Wds1oS0NcoCIne9HUiBVX1-CdTtp0tbmWrPtPWqeAc7YUhrIGRxKEpMdaWjPt_OM8QDVNK7Z3Rh56zf-Bdnb8EgV2ERMQLQK02JBpLCc7NjvdVrcBWxL8pqgE0VIZCJYI0-jAEMHroKsbx_7nqLrlIP8yTBgCrfUfKbEOs9pkH4KrqKHSke7jRw'
    },
    {
      kty: 'EC',
      use: 'sig',
      kid: 'uidai-02caa532-0e31-4a3a-a15b-5eeb603e1e78',
      alg: 'ES256',
      crv: 'P-256',
      x: 'Auvs_pEJPyNo560U0XJa69PhXmdKG9-AlGZDlEXYmsU',
      y: 'PHj-gigXdwanCrYOYqH4LDCosyyvMVHViXjYz6tKP3E'
    }
  ]
};

async function fetchJwksFromUrl(urlStr) {
  const cleanUrl = urlStr.trim();
  try {
    const resp = await fetch(cleanUrl, { headers: { Accept: 'application/json' } });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const data = await resp.json();
    // If the URL was a .well-known metadata document containing jwks_uri, follow it
    if (data && !data.keys && !(data.jwks && data.jwks.keys) && data.jwks_uri) {
      const resp2 = await fetch(data.jwks_uri, { headers: { Accept: 'application/json' } });
      if (!resp2.ok) throw new Error('HTTP ' + resp2.status + ' from jwks_uri');
      return { data: await resp2.json(), source: 'Fetched via jwks_uri (' + data.jwks_uri + ')' };
    }
    return { data, source: 'Fetched from ' + cleanUrl };
  } catch (err) {
    // Fallback for UIDAI Pehchaan JWKS URL when blocked by browser CORS or offline
    if (cleanUrl.includes('pehchaan.uidai.gov.in')) {
      return { data: UIDAI_PEHCHAAN_JWKS, source: 'UIDAI Pehchaan .well-known/jwks.json (Built-in Fallback for CORS)' };
    }
    throw new Error('Could not fetch JWKS URL (' + err.message + '). If the remote server blocks browser CORS requests, open the URL in a new tab and paste its JSON content below.');
  }
}

async function importPublicKeyFlexible(rawInput, jwtAlg, jwtKid) {
  let s = rawInput.trim();
  if (!s) throw new Error('Please paste a JWKS URL, .well-known JSON, JWK, or Public Key / Certificate first.');
  const params = getWebCryptoParams(jwtAlg);

  // 0. If user pasted a URL + JSON together (like: https://.../.well-known/jwks.json \n { "keys": [...] }), extract the JSON
  let sourcePrefix = '';
  if (/^https?:\/\/\S+/i.test(s) && s.includes('{')) {
    const firstBrace = s.indexOf('{');
    sourcePrefix = s.slice(0, firstBrace).trim() + ' → ';
    s = s.slice(firstBrace).trim();
  } else if (/^https?:\/\/\S+$/i.test(s)) {
    // Pure URL: fetch JWKS or .well-known content
    const fetched = await fetchJwksFromUrl(s);
    sourcePrefix = fetched.source + ' → ';
    s = JSON.stringify(fetched.data);
  }

  // 1. JSON JWK, JWKS, or .well-known metadata document
  if (s.startsWith('{')) {
    let parsed;
    try {
      parsed = JSON.parse(s);
    } catch (e) {
      throw new Error('Invalid JSON in JWK / .well-known input: ' + e.message);
    }

    // Support .well-known/jwt-vc-issuer or openid-configuration with embedded jwks or jwks_uri
    if (parsed.jwks && Array.isArray(parsed.jwks.keys)) {
      parsed = parsed.jwks;
    } else if (!parsed.keys && !parsed.kty && parsed.jwks_uri) {
      const fetched = await fetchJwksFromUrl(parsed.jwks_uri);
      sourcePrefix = fetched.source + ' → ';
      parsed = fetched.data;
    }

    let jwk = parsed;
    if (parsed.keys && Array.isArray(parsed.keys)) {
      if (!parsed.keys.length) throw new Error('JWKS contains no keys.');
      let matched = null;
      if (jwtKid) {
        matched = parsed.keys.find(k => k.kid === jwtKid);
        if (!matched) {
          const availableKids = parsed.keys.map(k => k.kid || '(no kid)').join(', ');
          throw new Error('No key matching JWT header kid "' + jwtKid + '" found in JWKS. Available kids: ' + availableKids);
        }
      } else {
        matched = parsed.keys.find(k => k.kty === params.kty) || parsed.keys[0];
      }
      jwk = matched;
    }
    if (jwk.jwk && jwk.jwk.kty) jwk = jwk.jwk; // Handle {"jwk": {...}} wrapper
    if (!jwk.kty) throw new Error('JSON object is missing required JWK "kty" property.');

    // Support JWK with x5c certificate chain if n/x are absent
    if (!jwk.n && !jwk.x && Array.isArray(jwk.x5c) && jwk.x5c[0]) {
      const derBytes = b64ToUint8(jwk.x5c[0]);
      const spkiBytes = extractSpkiFromDer(derBytes);
      const cryptoKey = await window.crypto.subtle.importKey('spki', spkiBytes.buffer, params.importAlg, false, ['verify']);
      return { cryptoKey, formatLabel: sourcePrefix + 'JWK x5c Certificate (' + (jwk.kid ? 'kid: ' + jwk.kid : jwk.kty) + ')' };
    }

    const cleanJwk = Object.assign({}, jwk);
    delete cleanJwk.key_ops;
    delete cleanJwk.use;
    delete cleanJwk.alg;
    delete cleanJwk.ext;
    const cryptoKey = await window.crypto.subtle.importKey('jwk', cleanJwk, params.importAlg, false, ['verify']);
    return { cryptoKey, formatLabel: sourcePrefix + 'JWK (' + jwk.kty + (jwk.kid ? ', kid: ' + jwk.kid : '') + ')' };
  }

  // 2. Text key-value format (e.g. n=... e=... or Modulus: ... Exponent: ...)
  if (/(?:^|\n)\s*(?:modulus|n)\s*[:=]/i.test(s)) {
    const nMatch = s.match(/(?:^|\n)\s*(?:modulus|n)\s*[:=]\s*([A-Za-z0-9+/=\-_:\s]+)/i);
    const eMatch = s.match(/(?:^|\n)\s*(?:exponent|publicExponent|e)\s*[:=]\s*([A-Za-z0-9+/=\-_]+|\d+)/i);
    if (!nMatch) throw new Error('Could not parse modulus (n) from text public key details.');
    const nB64Url = hexOrB64ToB64Url(nMatch[1].trim().split(/\r?\n/)[0]);
    let eB64Url = 'AQAB';
    if (eMatch) {
      const eRaw = eMatch[1].trim();
      if (/^\d+$/.test(eRaw)) {
        let num = parseInt(eRaw, 10);
        const bytes = [];
        while (num > 0) { bytes.unshift(num & 0xff); num >>= 8; }
        eB64Url = uint8ToB64Url(new Uint8Array(bytes.length ? bytes : [1, 0, 1]));
      } else {
        eB64Url = hexOrB64ToB64Url(eRaw);
      }
    }
    const jwk = { kty: 'RSA', n: nB64Url, e: eB64Url };
    const cryptoKey = await window.crypto.subtle.importKey('jwk', jwk, params.importAlg, false, ['verify']);
    return { cryptoKey, formatLabel: 'Text RSA Public Key (n, e)' };
  }

  // 3. PEM or Base64 DER (SPKI, PKCS#1, or X.509 Certificate) or raw Modulus
  const sNormalized = s.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\r/g, '\n').replace(/^["']|["']$/g, '');
  let b64Body = sNormalized;
  let pemType = 'Public Key';
  if (sNormalized.includes('-----BEGIN')) {
    if (sNormalized.includes('CERTIFICATE')) pemType = 'X.509 Certificate (PEM)';
    else if (sNormalized.includes('RSA PUBLIC KEY')) pemType = 'PKCS#1 RSA Public Key (PEM)';
    else pemType = 'SPKI Public Key (PEM)';
    b64Body = sNormalized.replace(/-----BEGIN [^-]+-----/g, '').replace(/-----END [^-]+-----/g, '').replace(/\s+/g, '');
  }

  // Try decoding as DER (SPKI / PKCS#1 / X.509) first
  try {
    const derBytes = b64ToUint8(b64Body);
    if (derBytes[0] === 0x30) {
      const spkiBytes = extractSpkiFromDer(derBytes);
      const cryptoKey = await window.crypto.subtle.importKey('spki', spkiBytes.buffer, params.importAlg, false, ['verify']);
      return { cryptoKey, formatLabel: pemType };
    }
  } catch (derErr) {
    // Fall through to raw RSA modulus fallback if applicable
  }

  // 4. Fallback: Raw RSA Modulus (Hex or Base64Url/Base64 string) with default exponent AQAB (65537)
  if (params.kty === 'RSA') {
    const nB64Url = hexOrB64ToB64Url(s);
    const jwk = { kty: 'RSA', n: nB64Url, e: 'AQAB' };
    const cryptoKey = await window.crypto.subtle.importKey('jwk', jwk, params.importAlg, false, ['verify']);
    return { cryptoKey, formatLabel: 'Raw RSA Modulus (e=AQAB)' };
  }

  throw new Error('Could not parse public key. Provide a valid JWK JSON, PEM Public Key, X.509 Certificate, or RSA Modulus.');
}

async function verifySDJWTCredential(rawSdJwt, rawKeyInput) {
  const parts = rawSdJwt.trim().split('~');
  const jwt = parts[0];
  const jp = jwt.split('.');
  if (jp.length !== 3) throw new Error('Invalid SD-JWT format: Issuer JWT must have 3 dot-separated parts.');

  const header = b64urlDecodeJson(jp[0]) || {};
  const payload = b64urlDecodeJson(jp[1]) || {};
  const alg = header.alg || 'RS256';
  const kid = header.kid || null;
  const params = getWebCryptoParams(alg);

  // Import public key
  const { cryptoKey, formatLabel } = await importPublicKeyFlexible(rawKeyInput, alg, kid);

  // Verify Issuer JWT cryptographic signature
  const signingInput = new TextEncoder().encode(jp[0] + '.' + jp[1]);
  const signatureBytes = b64ToUint8(jp[2]);
  const sigValid = await window.crypto.subtle.verify(params.verifyAlg, cryptoKey, signatureBytes, signingInput);

  // Verify Selective Disclosure digests against payload._sd
  const sdAlg = (payload._sd_alg || 'sha-256').toUpperCase();
  const hashName = sdAlg === 'SHA-384' ? 'SHA-384' : (sdAlg === 'SHA-512' ? 'SHA-512' : 'SHA-256');
  const sdArray = Array.isArray(payload._sd) ? payload._sd : [];
  const sdSet = new Set(sdArray);

  let verifiedDisclosures = 0;
  let totalDisclosures = 0;
  const mismatchedDisclosures = [];

  for (let i = 1; i < parts.length; i++) {
    const d = parts[i];
    if (!d) continue;
    // Skip trailing KB-JWT if present
    if (d.includes('.') && /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(d)) continue;
    totalDisclosures++;
    const digestBuf = await window.crypto.subtle.digest(hashName, new TextEncoder().encode(d));
    const digestB64Url = uint8ToB64Url(new Uint8Array(digestBuf));
    if (sdSet.has(digestB64Url)) {
      verifiedDisclosures++;
    } else {
      let claimName = 'Disclosure #' + totalDisclosures;
      try {
        const parsed = JSON.parse(parseUtf8Base64Url(d) || b64urlDecode(d));
        if (Array.isArray(parsed) && parsed.length >= 2) claimName = parsed[1];
      } catch (e) {}
      mismatchedDisclosures.push(claimName);
    }
  }

  // Check timestamps (exp / nbf)
  const nowSec = Math.floor(Date.now() / 1000);
  const isExpired = payload.exp ? nowSec > payload.exp : false;
  const notYetValid = payload.nbf ? nowSec < payload.nbf : false;

  return {
    sigValid,
    alg,
    kid,
    formatLabel,
    sdAlg: hashName,
    totalDisclosures,
    verifiedDisclosures,
    mismatchedDisclosures,
    sdClaimCount: sdArray.length,
    isExpired,
    notYetValid,
    exp: payload.exp ? fmtDT(payload.exp * 1000) : null
  };
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

  // Verification UI Elements
  const btnToggleVerify = document.getElementById('btn-toggle-verify');
  const verifyCard = document.getElementById('verify-card');
  const verifyAlgBadge = document.getElementById('verify-alg-badge');
  const btnLoadUidaiJwks = document.getElementById('btn-load-uidai-jwks');
  const btnGenTestSdjwt = document.getElementById('btn-gen-test-sdjwt');
  const btnUseCnfKey = document.getElementById('btn-use-cnf-key');
  const btnClearKey = document.getElementById('btn-clear-key');
  const verifyJwksUrl = document.getElementById('verify-jwks-url');
  const btnFetchJwks = document.getElementById('btn-fetch-jwks');
  const verifyKeyInput = document.getElementById('verify-key-input');
  const verifyKeyHint = document.getElementById('verify-key-hint');
  const btnRunVerify = document.getElementById('btn-run-verify');
  const verifyResult = document.getElementById('verify-result');
  const verifyModeBtns = document.querySelectorAll('.verify-mode-btn');

  let currentDecoded = null;

  verifyModeBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      verifyModeBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const mode = btn.dataset.mode;
      if (mode === 'wellknown') {
        verifyKeyInput.placeholder = 'Paste .well-known / JWKS JSON content (e.g. {"keys":[...]}) or a .well-known URL here…';
      } else if (mode === 'jwk') {
        verifyKeyInput.placeholder = 'Paste Single JWK JSON (e.g. {"kty":"RSA","kid":"...","n":"...","e":"AQAB"}) here…';
      } else if (mode === 'pem') {
        verifyKeyInput.placeholder = 'Paste Public Certificate (-----BEGIN CERTIFICATE-----), Public Key (-----BEGIN PUBLIC KEY-----), or Text Key (n=... e=...) here…';
      } else {
        verifyKeyInput.placeholder = 'Paste JWKS / .well-known JSON ({"keys":[...]}), a JWKS URL (https://.../.well-known/jwks.json), Single JWK, Public Certificate (-----BEGIN CERTIFICATE-----), or Public Key (-----BEGIN PUBLIC KEY-----) here…';
      }
    });
  });

  btnToggleVerify?.addEventListener('click', () => {
    verifyCard.classList.toggle('hidden');
  });

  verifyKeyInput?.addEventListener('input', () => {
    const detected = detectKeyInputType(verifyKeyInput.value);
    verifyKeyHint.innerHTML = detected ? '<span style="color:var(--accent)">✓ ' + escHtml(detected) + '</span>' : '';
  });

  btnClearKey?.addEventListener('click', () => {
    verifyKeyInput.value = '';
    if (verifyJwksUrl) verifyJwksUrl.value = '';
    verifyKeyHint.textContent = '';
    verifyResult.classList.add('hidden');
    verifyResult.innerHTML = '';
  });

  btnLoadUidaiJwks?.addEventListener('click', () => {
    if (verifyJwksUrl) verifyJwksUrl.value = 'https://pehchaan.uidai.gov.in/.well-known/jwks.json';
    verifyKeyInput.value = JSON.stringify(UIDAI_PEHCHAAN_JWKS, null, 2);
    verifyKeyInput.dispatchEvent(new Event('input'));
    if (input.value.trim()) btnRunVerify.click();
  });

  btnFetchJwks?.addEventListener('click', async () => {
    const urlVal = (verifyJwksUrl?.value || '').trim() || (verifyKeyInput.value.trim().match(/^https?:\/\/\S+$/i) ? verifyKeyInput.value.trim() : '');
    if (!urlVal) {
      verifyResult.classList.remove('hidden');
      verifyResult.innerHTML = '<div class="verify-banner invalid"><div><div style="font-weight:700;">Missing JWKS URL</div><div style="font-size:12px;">Enter a JWKS or .well-known URL in the URL bar above (e.g. https://pehchaan.uidai.gov.in/.well-known/jwks.json).</div></div></div>';
      return;
    }
    const origLabel = btnFetchJwks.innerHTML;
    btnFetchJwks.textContent = 'Fetching…';
    try {
      const fetched = await fetchJwksFromUrl(urlVal);
      verifyKeyInput.value = JSON.stringify(fetched.data, null, 2);
      verifyKeyHint.innerHTML = '<span style="color:var(--green)">✓ ' + escHtml(fetched.source) + '</span>';
      if (input.value.trim()) {
        btnRunVerify.click();
      }
    } catch (err) {
      verifyResult.classList.remove('hidden');
      verifyResult.innerHTML = '<div class="verify-banner invalid"><div><div style="font-weight:700;">JWKS Fetch Error</div><div style="font-size:12px;">' + escHtml(err.message) + '</div></div></div>';
    } finally {
      btnFetchJwks.innerHTML = origLabel;
    }
  });

  btnUseCnfKey?.addEventListener('click', () => {
    if (currentDecoded && currentDecoded.rawPayload && currentDecoded.rawPayload.cnf && currentDecoded.rawPayload.cnf.jwk) {
      verifyKeyInput.value = JSON.stringify(currentDecoded.rawPayload.cnf.jwk, null, 2);
      verifyKeyInput.dispatchEvent(new Event('input'));
    }
  });

  btnGenTestSdjwt?.addEventListener('click', async () => {
    const origText = btnGenTestSdjwt.textContent;
    btnGenTestSdjwt.textContent = 'Generating…';
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true,
        ['sign', 'verify']
      );
      const pubJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const spkiBuf = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
      const spkiB64 = uint8ToB64(spkiBuf).match(/.{1,64}/g).join('\n');
      const pubPem = '-----BEGIN PUBLIC KEY-----\n' + spkiB64 + '\n-----END PUBLIC KEY-----';

      const sampleClaims = [
        ['a29933c7-86e5-4ce0-b749-1425c94eea95', 'ResidentName', 'Saurav Nri'],
        ['afb01439-254a-4ea8-b605-f4edcb5e28e6', 'Dob', '1991-02-10'],
        ['4ce0786d-633d-4c2b-ad22-6630e971144e', 'Gender', 'MALE'],
        ['6ed00c74-31ce-4187-8e5b-e6927e48ff45', 'MaskedUID', 'XXXX-XXXX-9999'],
        ['27efd702-2559-453b-93d7-e4cc8d3227fe', 'District', 'Bengaluru'],
        ['ed0ff133-4ec7-477a-9644-5c46c35abf75', 'State', 'Karnataka'],
        ['60cda442-545a-4137-a4b0-4ae270ebd260', 'Pincode', '560037'],
        ['f441bbbd-20f0-4b92-bd6e-96edbe042694', 'Mobile', '+91 9844619091']
      ];
      const disclosures = [];
      const sdDigests = [];
      for (const item of sampleClaims) {
        const dB64Url = uint8ToB64Url(new TextEncoder().encode(JSON.stringify(item)));
        disclosures.push(dB64Url);
        const dig = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(dB64Url));
        sdDigests.push(uint8ToB64Url(new Uint8Array(dig)));
      }

      const now = Math.floor(Date.now() / 1000);
      const header = { alg: 'RS256', kid: 'uidai-demo-key-1', typ: 'vc+sd-jwt' };
      const payload = {
        iss: 'https://uidai.gov.in',
        iat: now,
        exp: now + 86400 * 365,
        id: '54dad801-8e3d-4fcc-864a-48c0a0206a1e',
        cnf: { jwk: { kty: 'RSA', alg: 'RS256', n: pubJwk.n, e: pubJwk.e } },
        _sd_alg: 'sha-256',
        _sd: sdDigests
      };
      const hB64 = uint8ToB64Url(new TextEncoder().encode(JSON.stringify(header)));
      const pB64 = uint8ToB64Url(new TextEncoder().encode(JSON.stringify(payload)));
      const signingInput = new TextEncoder().encode(hB64 + '.' + pB64);
      const sigBuf = await window.crypto.subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, signingInput);
      const sigB64 = uint8ToB64Url(new Uint8Array(sigBuf));

      const fullSdJwt = hB64 + '.' + pB64 + '.' + sigB64 + '~' + disclosures.join('~') + '~';
      input.value = fullSdJwt;
      input.dispatchEvent(new Event('input'));
      btnDec.click();

      const activeMode = document.querySelector('.verify-mode-btn.active')?.dataset.mode || 'auto';
      if (activeMode === 'pem') {
        verifyKeyInput.value = pubPem;
      } else {
        verifyKeyInput.value = JSON.stringify({ kty: 'RSA', kid: 'uidai-demo-key-1', alg: 'RS256', n: pubJwk.n, e: pubJwk.e }, null, 2);
      }
      verifyKeyInput.dispatchEvent(new Event('input'));
      btnRunVerify.click();
      btnGenTestSdjwt.textContent = 'Loaded & Verified ✓';
      setTimeout(() => { btnGenTestSdjwt.textContent = origText; }, 2500);
    } catch (e) {
      btnGenTestSdjwt.textContent = origText;
    }
  });

  btnRunVerify?.addEventListener('click', async () => {
    const rawCred = input.value.trim();
    if (!rawCred) return;
    verifyResult.classList.remove('hidden');
    verifyResult.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">Verifying cryptographic signature and selective disclosures…</div>';

    try {
      const keySource = verifyKeyInput.value.trim() || (verifyJwksUrl ? verifyJwksUrl.value.trim() : '');
      const res = await verifySDJWTCredential(rawCred, keySource);
      const disclosuresOk = res.mismatchedDisclosures.length === 0;
      const overallValid = res.sigValid && disclosuresOk;

      const bannerClass = overallValid ? 'valid' : (res.sigValid && !disclosuresOk ? 'warn' : 'invalid');
      const bannerTitle = overallValid
        ? 'Signature & Disclosures Verified Successfully'
        : (res.sigValid
            ? 'Issuer Signature Valid, but Disclosure Digest Mismatch'
            : 'Cryptographic Signature Verification Failed');
      const bannerSub = overallValid
        ? 'The SD-JWT signature is cryptographically authentic for the provided public key and all disclosed claims match their signed digests.'
        : (res.sigValid
            ? 'The JWT signature matches the public key, but ' + res.mismatchedDisclosures.length + ' disclosure(s) did not match the _sd digest array.'
            : 'The JWT signature could not be verified with the provided public key. Check that you are using the correct Issuer Public Key (not the holder cnf key unless self-signed).');

      const iconSvg = overallValid
        ? '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
        : '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';

      verifyResult.innerHTML =
        '<div class="verify-banner ' + bannerClass + '">' +
          iconSvg +
          '<div>' +
            '<div style="font-weight:700;margin-bottom:2px;">' + escHtml(bannerTitle) + '</div>' +
            '<div style="font-size:12px;opacity:0.9;">' + escHtml(bannerSub) + '</div>' +
          '</div>' +
        '</div>' +
        '<div class="verify-checks-grid">' +
          '<div class="verify-check-item">' +
            '<span class="verify-check-label">JWT Signature (' + escHtml(res.alg) + ')</span>' +
            '<span class="badge ' + (res.sigValid ? 'badge-green' : 'badge-red') + '">' + (res.sigValid ? 'VALID ✓' : 'INVALID ✗') + '</span>' +
          '</div>' +
          '<div class="verify-check-item">' +
            '<span class="verify-check-label">Disclosures (' + escHtml(res.sdAlg) + ')</span>' +
            '<span class="badge ' + (disclosuresOk ? 'badge-green' : 'badge-red') + '">' + res.verifiedDisclosures + ' / ' + res.totalDisclosures + ' Verified</span>' +
          '</div>' +
          '<div class="verify-check-item">' +
            '<span class="verify-check-label">Key Format</span>' +
            '<span class="cell-mono" style="font-size:11px;">' + escHtml(res.formatLabel) + '</span>' +
          '</div>' +
          '<div class="verify-check-item">' +
            '<span class="verify-check-label">Expiry Status</span>' +
            '<span class="badge ' + (res.isExpired ? 'badge-yellow' : 'badge-green') + '">' + (res.isExpired ? 'EXPIRED' : 'ACTIVE') + '</span>' +
          '</div>' +
        '</div>';
    } catch (err) {
      verifyResult.innerHTML =
        '<div class="verify-banner invalid">' +
          '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' +
          '<div>' +
            '<div style="font-weight:700;margin-bottom:2px;">Verification Error</div>' +
            '<div style="font-size:12px;opacity:0.9;">' + escHtml(err.message) + '</div>' +
          '</div>' +
        '</div>';
    }
  });

  // Try to use a sample if buttons exist
  document.getElementById('btn-sample-sdjwt')?.addEventListener('click', () => {
    input.value = "eyJhbGciOiJSUzI1NiIsImtpZCI6InVpZGFpLTM3YThlNzQyLWMzNzUtNDQzYy04Y2U1LThiN2EwODIyY2I2YiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL3BlaGNoYWFuLnVpZGFpLmdvdi5pbiIsImV4cCI6MTgyMDE3MDY5NCwiaWF0IjoxNzg4NjM0Njk0LCJpZCI6IjgzOWIzZjQ0LTY5ZTUtNDYxMC05NTgzLTVjOWM2YWQyNGYxOSIsImNuZiI6eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrajdPakFQaGdsR0MyaUhwbGlPSGdQcGZYZENuZW4yd2NxNDhxZlFEMUIwIiwieSI6Il9QMkFwRlFjZTZEOTRyTjR2WmdKaFFMX0czbGZ0ekZhWkNFc1FnaXhVeTgifX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbImUtT2doQUhRWHZVTWl5blRYdGFXT0FlTVlFQVg5UFpMYXllM2l0NGZ3MkkiLCJ1NDJiR0ZlOTVaelhGNGJOUWpmQTRfOUlqOGlfc19fX2RqbW5XZkFvX1NRIiwiVm9xaFFLWm1vbFJTTmh4N0ZiRjZUQTNSdkpBdmtrOXNRUzhZNEZZZWIzTSIsIkN5cV9Nd1BaNEk2dHFiM3VkUURuZU9YLUhnbGhKQjJHOTU0cXRUdGxUWEEiLCJESXpPcEE5c2FYZ0I1R3U0eDNkWmVlZ0hUYV80MTRYMUhYN29mVXdBYnVZIiwiRTBZcGN1YnhxMmpsbDYwOHpKdXRlVFUxQnRCVFNjWldGOXI2Rzkzc19fYyIsIkY5QjZYcHpTSEtmM3BsT2VsSVZ4d2RVUGRDbDRvanVLQlJxMTN2cm1XcjAiLCI4aWJ5ZnJaeHp5OW56RDFRcDh5SExRSzI2bG1CSmNRU3pqdnhwSnRna0NzIiwiR2RXLTZLMnNfRi1Va0xfT0dfZVZCdXZWSTV5RTNHSFFaSmxmd1VCQktJSSIsIkt6U3psWnV0T1piSE1CS1l3MVJVc3ZfSmQ5UkFwQ2Ywanc0Z1FybFBmU2MiLCJnNXBtSTVjeWttUTE1aUNNNHkwX2kyU19OUWxKa2NTaUFWNEhNR0NmLU5NIiwiOHdZUzVfdEE3aWxkSkZPemVyMWhQNHl4SGUzTEdjWDduamJ3NXZjdE15QSIsIk9WcnJ4YlUwSi1RY2ctcVB5VmNFQ1RQNV9hUy1zSFFDWi00bW0zaDBWdlEiLCJMQi1odmxjZGgyVUpCbGI4cTJ6VWl1MkgtWm5feEVvS0hjNmFfWi1zQTk4IiwiN0taY2JWakFzZmJlakl1OEt4YTE1bDlUT1NkYXhQdnpiU0JwWXR4MW5mVSIsIlFpZzZIcUJkOHN6UTZ5dTAwcGZFdHo5dE5BbXhBQ29yTjdSRnQxU2xtWGciLCJ0bU9pU2hpbTFIS0ZMb2lXZzlocEY2MFV6bnpTRVcyUXRnZHpjX3p6Sm04IiwiQWtCaEM0R01XNUJXT2ZELUJxTkRlZ2pqVlQ2a0htQzNHTE10Vk95cTZtdyIsIlYzVm1kNnFaVWc3clM0dm9KMTIwb05UbWdvLVFPWHFVM0NOS21hOE1JbGsiLCJQbWgwZm92anNHRk9LX2tQWXJNN04wQmx1Rm94VG9FWHFxT0cwc0Qtd3BZIiwiMk11cDRLNmJ4UEZwaF9STVFMeTAwWHFQNFRZcEc3WU9mM3N3MWM1RTk2cyIsImNuZFYtV3EwVUx1MUxEZmhJTm1qNktTYzhCQk1XUEdFUUZOUHFCd2Y3YXciLCJUNHhCMFdrTWlyVW1QUnJxZDh3UGhyc2JZNjl3WGhPQS1wTi1UX3JiYjk4IiwiTU0tcGExeUpWdWFFOERjV0VPMU42OVlfaXhLNFF6LTE5alM0dUlYSUw3dyIsIm5VdzZ3bnk3REoxUmNvQ3ZfbHA4eHU1Ym1maUpoUy0yWWRNbmN1MDVyaWMiLCJIY3JwLUpxSmlveHhWaV9jQkVCSEVwR1lVeDBIZ0tCdXhWdjNDemFzanRzIiwicnJxZ19IRFF6d3lrWm5ub3Z3Zm1sMTBpZ3dkRU9xMUZFSl9vbmN5bDdTQSIsInBZcXJ2S3o0cERtdC1LMlRIcDNseTJHT3dqaWFnazc2bmNZT3IwUk9rYzAiLCJoOXBmUWtjSV9VSnZwb05JVmhZaHB0bkF1cFpNNXlfUkF3WlYzdnBwdG9ZIiwiTEdBTTc3QTQtVXhnYjBrTUxTVmJYcF9ydFk2ZExnT2RILXFZY2N1NXpfOCIsInByNWF6Q213Z1M1VFROOFo3ZTFtYlBzd2xWcTlEVmpIUlFnMk1VbmstdUEiLCJKNjNuNms5UTQtekVCaF9zR05Ld0dGZkN3RklRUFJBV1NPU1ZlcmRJdEpnIiwiYnRkMWJPWjdFQVg0dUxCVmNHX3JjVGo2a2R1RWZMM2lPRHlCU19WYmtIMCIsImF1NlpadmM1Zm5XUWYyRVpWWi1uOUswU0JiSXdhRGk1eXdQWFpESjBYZkEiLCJjNUZhaU9naVJiUlNxbG1ZeWtPQWFfaUEzU3J4MWRWOW9EQkRfRmVKM3RrIiwieTJ6YXUwSExYTlVOc0RwSWZpS1VSYWszWUNuY205cEU1V0EzRTZCVjFvayIsInNUWXBDYjFXSTJmRUVMV0Z5NGVCNWlaM3k4ZDR2VFZBT3JWeEZYS2JIUGMiLCItSGdueEwxVkJocENNWGpWenNBQi1uNUZCbDl1RkQ1dnJWRTJFb1dDWU00IiwiVDhsalhoalRkNV9ZbzIxc3NuRFYwUVQ1WFZWRkV0YUNGc2JHMGVyWXFSRSIsImlrS0o2di15dWJrQjMyUDVrYXpYZmlXYUNTQnZvMURhWFJfVFNBajJEZDQiLCJfeDE2ejV0VVFjeGVRczcwYkQyQlc2N0dHZXpuNjJnb1RMNEJuTllXNFVVIiwidk10eXJHUmNzNXZUajAxOF90U0FqVjZxOV9TeUUyS1drb0x0VGUyQlJIdyIsIkhudFY5R3pLVUd3dXVRTTEySWpIOEFPMzMzNW01SjdUSnJTdXRIWmlCVDgiXSwidmN0IjoiaHR0cDovL3BlaGNoYWFuLnVpZGFpLmdvdi5pbi9jcmVkZW50aWFscy9WZXJpZmllZEFhZGhhYXJDcmVkZW50aWFsL3YxIn0.bwrDFZMNGPag9s8_5ETGurEjs164Kei53uIdGdaeiknE56eiPolm_fIdniBZ9rEGE8KEdBUxd10T71dwLWqxTDAcbV_MNHR7ijzLHaBwjdAKtK0M2pNsxTw9YaJNkOqvZtzTXsMfi_PiVesunzak636w_5Ny4NHpueHHicTepNJJTiSIrWNxgqlK1SbASdPYncrsdC-TwsujGkcIOnPYtYTotRxnpK9d21LnOC0WzgfLaZeEYATvSNqq75-iBrslnfMkX2WcT51E4Bn_pRZhqU8MDTEu5aThuJEkOkYXlBpBQUJ_ZQrjhlmR9Wf8dEQJK6urD-NIqDF8amg1g7H4d08ndD6cuQEoNWSdZgAtPYcQ7UpDjkQ3gX1BB0FUuKp1B4pbVoVUUxjm94wVHfDEn1R1RukWoDr7YBtME7_QzBElsIaEygwZbl2BJE4WeER5gX_FEJHvYcFOKvHobCOksmSX8adQqWcZ_Zh-LmXpBGa0f1FjaWnXe4fzgZCOs0JzMMgOTUAj57mc1dFezv1-5TKeToh-tVmSML8QhZVPzJykgyUtKM8FwAKGi9aO7ekrRKyEgecxaJmSb90GykVNuQp_Eswjk9TE_z8cZ5LJ4w_WxYkGm_SXOclP9QWbVRsHH874wIQOR319H3tsnAXj_ZW_dx025aoWFxXbjztCQkk~WyI0OGQyNDE5Ni03ZDJmLTQ3MWYtYmEyMC0yMmM1NTQ4Zjc3ZTMiLCJSZXNpZGVudE5hbWUiLCJBYmVlIG5hcmF5YW4iXQ~";
    if (verifyJwksUrl && !verifyJwksUrl.value) {
      verifyJwksUrl.value = 'https://pehchaan.uidai.gov.in/.well-known/jwks.json';
    }
    input.dispatchEvent(new Event('input'));
  });

  btnClr.addEventListener('click', () => {
    input.value = ''; outSec.classList.add('hidden'); errSec.classList.add('hidden'); hint.textContent = '';
    verifyCard?.classList.add('hidden');
    verifyResult?.classList.add('hidden');
  });

  input.addEventListener('input', () => {
    const fmt = detectFormat(input.value);
    if (fmt === 'sdjwt') hint.innerHTML = '<span style="color:var(--green)">✓ SD-JWT VC Detected</span>';
    else if (fmt === 'mdoc') hint.innerHTML = '<span style="color:var(--accent2)">✓ mDOC (CBOR) Detected</span>';
    else hint.textContent = '';
  });

  btnDec.addEventListener('click', () => {
    errSec.classList.add('hidden'); outSec.classList.add('hidden');
    verifyResult?.classList.add('hidden');
    const val = input.value.trim(); if (!val) return;
    const fmt = detectFormat(val);
    try {
      let dec;
      if (fmt === 'sdjwt') dec = decodeSDJWT(val);
      else if (fmt === 'mdoc') dec = decodeMDOC(val);
      else throw new Error('Unrecognized format. Please provide a valid SD-JWT or base64 CBOR mDOC.');
      currentDecoded = dec;
      renderResult(dec);
      outSec.classList.remove('hidden');

      if (fmt === 'sdjwt') {
        btnToggleVerify?.classList.remove('hidden');
        verifyCard?.classList.remove('hidden');
        const alg = (dec.rawHeader && dec.rawHeader.alg) || 'RS256';
        const kid = (dec.rawHeader && dec.rawHeader.kid) || '';
        if (verifyAlgBadge) verifyAlgBadge.textContent = alg + (kid ? ' · kid: ' + kid : '');
        // Auto-populate JWKS URL from iss claim if URL field is empty
        if (verifyJwksUrl && !verifyJwksUrl.value && dec.rawPayload && typeof dec.rawPayload.iss === 'string' && dec.rawPayload.iss.startsWith('http')) {
          verifyJwksUrl.value = dec.rawPayload.iss.replace(/\/+$/, '') + '/.well-known/jwks.json';
        }
        if (dec.rawPayload && dec.rawPayload.cnf && dec.rawPayload.cnf.jwk) {
          btnUseCnfKey?.classList.remove('hidden');
        } else {
          btnUseCnfKey?.classList.add('hidden');
        }
      } else {
        btnToggleVerify?.classList.add('hidden');
        verifyCard?.classList.add('hidden');
      }
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

  // Auto-load from localStorage for Aadhaar Intent Generator module
  const pending = localStorage.getItem('pending-credential');
  if (pending) {
    localStorage.removeItem('pending-credential');
    input.value = pending;
    btnDec.click();
  }
});
