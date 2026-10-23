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

function toArrayBufferSlice(bufOrView) {
  if (!bufOrView) return null;
  if (bufOrView instanceof ArrayBuffer) return bufOrView;
  if (ArrayBuffer.isView(bufOrView) || (bufOrView.buffer instanceof ArrayBuffer)) {
    return bufOrView.buffer.slice(bufOrView.byteOffset, bufOrView.byteOffset + bufOrView.byteLength);
  }
  return null;
}

function decodeMDOC(raw) {
  const bytes = toArrayBufferSlice(b64ToUint8(raw.trim().replace(/\s/g, '')));
  const outer = CBOR.decode(bytes);
  const docs = outer && outer.documents ? outer.documents : (outer && outer.issuerSigned ? [outer] : (Array.isArray(outer) ? outer : [outer]));
  const c = {}; let docType = '', meta = {};
  docs.forEach(doc => {
    docType = doc.docType || docType;
    const ns = (doc.issuerSigned || doc).nameSpaces || {};
    Object.keys(ns).forEach(nsK => {
      if (!docType) docType = nsK;
      ns[nsK].forEach(ib => {
        try {
          let item = ib;
          if (ib && ib.tag === 24 && ib.value) item = CBOR.decode(toArrayBufferSlice(ib.value) || ib.value);
          else if (ib instanceof Uint8Array || ArrayBuffer.isView(ib) || ib instanceof ArrayBuffer) item = CBOR.decode(toArrayBufferSlice(ib));
          if (!item || item.elementIdentifier === undefined) return;
          let k = item.elementIdentifier, v = item.elementValue;
          if (k.toLowerCase().includes('image')) {
            if (ArrayBuffer.isView(v) || v instanceof ArrayBuffer) {
              v = 'data:image/jpeg;base64,' + uint8ToB64(v);
            } else if (typeof v === 'string' && !v.startsWith('data:')) {
              v = 'data:image/jpeg;base64,' + v;
            }
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
      if (ia[2]) {
        let m = CBOR.decode(toArrayBufferSlice(ia[2]) || ia[2]);
        if (m instanceof Uint8Array || ArrayBuffer.isView(m) || m instanceof ArrayBuffer) {
          m = CBOR.decode(toArrayBufferSlice(m));
        }
        if (m && typeof m === 'object') {
          meta = m;
          if (m.docType) docType = m.docType;
        }
      }
    } catch (e) { }
  });
  const valInfo = meta.validityInfo || {};
  return {
    format: 'mDOC (ISO 18013-5)',
    formatDetail: 'docType: ' + docType,
    meta: {
      docType,
      alg: meta.digestAlgorithm,
      signed: fmtDT(valInfo.signed),
      validFrom: fmtDT(valInfo.validFrom),
      validUntil: fmtDT(valInfo.validUntil)
    },
    claims: c,
    rawPayload: { docType, digestAlgorithm: meta.digestAlgorithm, validityInfo: valInfo, claims: c }
  };
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
  age_above18: { l: 'Age Above 18', t: 'identity', b: 1 }, AgeAbove18: { l: 'Age Above 18', t: 'identity', b: 1 },
  age_above50: { l: 'Age Above 50', t: 'identity', b: 1 }, AgeAbove50: { l: 'Age Above 50', t: 'identity', b: 1 },
  age_above60: { l: 'Age Above 60', t: 'identity', b: 1 }, AgeAbove60: { l: 'Age Above 60', t: 'identity', b: 1 },
  age_above75: { l: 'Age Above 75', t: 'identity', b: 1 }, AgeAbove75: { l: 'Age Above 75', t: 'identity', b: 1 },
  is_nri: { l: 'Is NRI', t: 'identity', b: 1 }, IsNRI: { l: 'Is NRI', t: 'identity', b: 1 },
  is_resident_foreigner: { l: 'Is Resident Foreigner', t: 'identity', b: 1 }, IsResidentForeigner: { l: 'Is Resident Foreigner', t: 'identity', b: 1 },
  care_of: { l: 'Care Of', t: 'address' }, CareOf: { l: 'Care Of', t: 'address' },
  local_care_of: { l: 'Care Of (Local)', t: 'address' }, LocalCareOf: { l: 'Care Of (Local)', t: 'address' },
  address: { l: 'Full Address', t: 'address' }, Address: { l: 'Full Address', t: 'address' },
  regional_address: { l: 'Address (Local)', t: 'address' }, RegionalAddress: { l: 'Address (Local)', t: 'address' },
  building: { l: 'Building', t: 'address' }, Building: { l: 'Building', t: 'address' },
  local_building: { l: 'Building (Local)', t: 'address' }, LocalBuilding: { l: 'Building (Local)', t: 'address' },
  street: { l: 'Street', t: 'address' }, Street: { l: 'Street', t: 'address' },
  local_street: { l: 'Street (Local)', t: 'address' }, LocalStreet: { l: 'Street (Local)', t: 'address' },
  locality: { l: 'Locality', t: 'address' }, Locality: { l: 'Locality', t: 'address' },
  local_locality: { l: 'Locality (Local)', t: 'address' }, LocalLocality: { l: 'Locality (Local)', t: 'address' },
  landmark: { l: 'Landmark', t: 'address' }, Landmark: { l: 'Landmark', t: 'address' },
  local_landmark: { l: 'Landmark (Local)', t: 'address' }, LocalLandmark: { l: 'Landmark (Local)', t: 'address' },
  vtc: { l: 'VTC', t: 'address' }, Vtc: { l: 'VTC', t: 'address' },
  local_vtc: { l: 'VTC (Local)', t: 'address' }, LocalVtc: { l: 'VTC (Local)', t: 'address' },
  po_name: { l: 'Post Office', t: 'address' }, PoName: { l: 'Post Office', t: 'address' },
  local_po_name: { l: 'Post Office (Local)', t: 'address' }, LocalPoName: { l: 'Post Office (Local)', t: 'address' },
  sub_district: { l: 'Sub-District', t: 'address' }, SubDistrict: { l: 'Sub-District', t: 'address' },
  local_sub_district: { l: 'Sub-District (Local)', t: 'address' }, LocalSubDistrict: { l: 'Sub-District (Local)', t: 'address' },
  district: { l: 'District', t: 'address' }, District: { l: 'District', t: 'address' },
  local_district: { l: 'District (Local)', t: 'address' }, LocalDistrict: { l: 'District (Local)', t: 'address' },
  state: { l: 'State', t: 'address' }, State: { l: 'State', t: 'address' },
  local_state: { l: 'State (Local)', t: 'address' }, LocalState: { l: 'State (Local)', t: 'address' },
  pincode: { l: 'Pincode', t: 'address', m: 1 }, Pincode: { l: 'Pincode', t: 'address', m: 1 },
  mobile: { l: 'Mobile', t: 'contact', m: 1 }, Mobile: { l: 'Mobile', t: 'contact', m: 1 },
  masked_mobile: { l: 'Masked Mobile', t: 'contact', m: 1 }, MaskedMobile: { l: 'Masked Mobile', t: 'contact', m: 1 },
  email: { l: 'Email', t: 'contact', m: 1 }, Email: { l: 'Email', t: 'contact', m: 1 },
  masked_email: { l: 'Masked Email', t: 'contact', m: 1 }, MaskedEmail: { l: 'Masked Email', t: 'contact', m: 1 },
  credential_issuing_date: { l: 'Credential Issuing Date', t: 'issuance', dt: 1 }, CredentialIssuingDate: { l: 'Credential Issuing Date', t: 'issuance', dt: 1 },
  enrolment_date: { l: 'Enrolment Date', t: 'issuance', dt: 1 }, EnrolmentDate: { l: 'Enrolment Date', t: 'issuance', dt: 1 },
  enrolment_number: { l: 'Enrolment Number', t: 'issuance', m: 1 }, EnrolmentNumber: { l: 'Enrolment Number', t: 'issuance', m: 1 },
  aadhaar_expires_on: { l: 'Aadhaar Expires On', t: 'issuance', dt: 1 }, AadhaarExpiresOn: { l: 'Aadhaar Expires On', t: 'issuance', dt: 1 },
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

  const DUMMY_UIDAI_SDJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6InVpZGFpLTM3YThlNzQyLWMzNzUtNDQzYy04Y2U1LThiN2EwODIyY2I2YiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJpc3MiOiJodHRwczovL3BlaGNoYWFuLnVpZGFpLmdvdi5pbiIsImV4cCI6MTgyMDE3MDY5NCwiaWF0IjoxNzg4NjM0Njk0LCJpZCI6IjgzOWIzZjQ0LTY5ZTUtNDYxMC05NTgzLTVjOWM2YWQyNGYxOSIsImNuZiI6eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJrajdPakFQaGdsR0MyaUhwbGlPSGdQcGZYZENuZW4yd2NxNDhxZlFEMUIwIiwieSI6Il9QMkFwRlFjZTZEOTRyTjR2WmdKaFFMX0czbGZ0ekZhWkNFc1FnaXhVeTgifX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbImUtT2doQUhRWHZVTWl5blRYdGFXT0FlTVlFQVg5UFpMYXllM2l0NGZ3MkkiLCJ1NDJiR0ZlOTVaelhGNGJOUWpmQTRfOUlqOGlfc19fX2RqbW5XZkFvX1NRIiwiVm9xaFFLWm1vbFJTTmh4N0ZiRjZUQTNSdkpBdmtrOXNRUzhZNEZZZWIzTSIsIkN5cV9Nd1BaNEk2dHFiM3VkUURuZU9YLUhnbGhKQjJHOTU0cXRUdGxUWEEiLCJESXpPcEE5c2FYZ0I1R3U0eDNkWmVlZ0hUYV80MTRYMUhYN29mVXdBYnVZIiwiRTBZcGN1YnhxMmpsbDYwOHpKdXRlVFUxQnRCVFNjWldGOXI2Rzkzc19fYyIsIkY5QjZYcHpTSEtmM3BsT2VsSVZ4d2RVUGRDbDRvanVLQlJxMTN2cm1XcjAiLCI4aWJ5ZnJaeHp5OW56RDFRcDh5SExRSzI2bG1CSmNRU3pqdnhwSnRna0NzIiwiR2RXLTZLMnNfRi1Va0xfT0dfZVZCdXZWSTV5RTNHSFFaSmxmd1VCQktJSSIsIkt6U3psWnV0T1piSE1CS1l3MVJVc3ZfSmQ5UkFwQ2Ywanc0Z1FybFBmU2MiLCJnNXBtSTVjeWttUTE1aUNNNHkwX2kyU19OUWxKa2NTaUFWNEhNR0NmLU5NIiwiOHdZUzVfdEE3aWxkSkZPemVyMWhQNHl4SGUzTEdjWDduamJ3NXZjdE15QSIsIk9WcnJ4YlUwSi1RY2ctcVB5VmNFQ1RQNV9hUy1zSFFDWi00bW0zaDBWdlEiLCJMQi1odmxjZGgyVUpCbGI4cTJ6VWl1MkgtWm5feEVvS0hjNmFfWi1zQTk4IiwiN0taY2JWakFzZmJlakl1OEt4YTE1bDlUT1NkYXhQdnpiU0JwWXR4MW5mVSIsIlFpZzZIcUJkOHN6UTZ5dTAwcGZFdHo5dE5BbXhBQ29yTjdSRnQxU2xtWGciLCJ0bU9pU2hpbTFIS0ZMb2lXZzlocEY2MFV6bnpTRVcyUXRnZHpjX3p6Sm04IiwiQWtCaEM0R01XNUJXT2ZELUJxTkRlZ2pqVlQ2a0htQzNHTE10Vk95cTZtdyIsIlYzVm1kNnFaVWc3clM0dm9KMTIwb05UbWdvLVFPWHFVM0NOS21hOE1JbGsiLCJQbWgwZm92anNHRk9LX2tQWXJNN04wQmx1Rm94VG9FWHFxT0cwc0Qtd3BZIiwiMk11cDRLNmJ4UEZwaF9STVFMeTAwWHFQNFRZcEc3WU9mM3N3MWM1RTk2cyIsImNuZFYtV3EwVUx1MUxEZmhJTm1qNktTYzhCQk1XUEdFUUZOUHFCd2Y3YXciLCJUNHhCMFdrTWlyVW1QUnJxZDh3UGhyc2JZNjl3WGhPQS1wTi1UX3JiYjk4IiwiTU0tcGExeUpWdWFFOERjV0VPMU42OVlfaXhLNFF6LTE5alM0dUlYSUw3dyIsIm5VdzZ3bnk3REoxUmNvQ3ZfbHA4eHU1Ym1maUpoUy0yWWRNbmN1MDVyaWMiLCJIY3JwLUpxSmlveHhWaV9jQkVCSEVwR1lVeDBIZ0tCdXhWdjNDemFzanRzIiwicnJxZ19IRFF6d3lrWm5ub3Z3Zm1sMTBpZ3dkRU9xMUZFSl9vbmN5bDdTQSIsInBZcXJ2S3o0cERtdC1LMlRIcDNseTJHT3dqaWFnazc2bmNZT3IwUk9rYzAiLCJoOXBmUWtjSV9VSnZwb05JVmhZaHB0bkF1cFpNNXlfUkF3WlYzdnBwdG9ZIiwiTEdBTTc3QTQtVXhnYjBrTUxTVmJYcF9ydFk2ZExnT2RILXFZY2N1NXpfOCIsInByNWF6Q213Z1M1VFROOFo3ZTFtYlBzd2xWcTlEVmpIUlFnMk1VbmstdUEiLCJKNjNuNms5UTQtekVCaF9zR05Ld0dGZkN3RklRUFJBV1NPU1ZlcmRJdEpnIiwiYnRkMWJPWjdFQVg0dUxCVmNHX3JjVGo2a2R1RWZMM2lPRHlCU19WYmtIMCIsImF1NlpadmM1Zm5XUWYyRVpWWi1uOUswU0JiSXdhRGk1eXdQWFpESjBYZkEiLCJjNUZhaU9naVJiUlNxbG1ZeWtPQWFfaUEzU3J4MWRWOW9EQkRfRmVKM3RrIiwieTJ6YXUwSExYTlVOc0RwSWZpS1VSYWszWUNuY205cEU1V0EzRTZCVjFvayIsInNUWXBDYjFXSTJmRUVMV0Z5NGVCNWlaM3k4ZDR2VFZBT3JWeEZYS2JIUGMiLCItSGdueEwxVkJocENNWGpWenNBQi1uNUZCbDl1RkQ1dnJWRTJFb1dDWU00IiwiVDhsalhoalRkNV9ZbzIxc3NuRFYwUVQ1WFZWRkV0YUNGc2JHMGVyWXFSRSIsImlrS0o2di15dWJrQjMyUDVrYXpYZmlXYUNTQnZvMURhWFJfVFNBajJEZDQiLCJfeDE2ejV0VVFjeGVRczcwYkQyQlc2N0dHZXpuNjJnb1RMNEJuTllXNFVVIiwidk10eXJHUmNzNXZUajAxOF90U0FqVjZxOV9TeUUyS1drb0x0VGUyQlJIdyIsIkhudFY5R3pLVUd3dXVRTTEySWpIOEFPMzMzNW01SjdUSnJTdXRIWmlCVDgiXSwidmN0IjoiaHR0cDovL3BlaGNoYWFuLnVpZGFpLmdvdi5pbi9jcmVkZW50aWFscy9WZXJpZmllZEFhZGhhYXJDcmVkZW50aWFsL3YxIn0.bwrDFZMNGPag9s8_5ETGurEjs164Kei53uIdGdaeiknE56eiPolm_fIdniBZ9rEGE8KEdBUxd10T71dwLWqxTDAcbV_MNHR7ijzLHaBwjdAKtK0M2pNsxTw9YaJNkOqvZtzTXsMfi_PiVesunzak636w_5Ny4NHpueHHicTepNJJTiSIrWNxgqlK1SbASdPYncrsdC-TwsujGkcIOnPYtYTotRxnpK9d21LnOC0WzgfLaZeEYATvSNqq75-iBrslnfMkX2WcT51E4Bn_pRZhqU8MDTEu5aThuJEkOkYXlBpBQUJ_ZQrjhlmR9Wf8dEQJK6urD-NIqDF8amg1g7H4d08ndD6cuQEoNWSdZgAtPYcQ7UpDjkQ3gX1BB0FUuKp1B4pbVoVUUxjm94wVHfDEn1R1RukWoDr7YBtME7_QzBElsIaEygwZbl2BJE4WeER5gX_FEJHvYcFOKvHobCOksmSX8adQqWcZ_Zh-LmXpBGa0f1FjaWnXe4fzgZCOs0JzMMgOTUAj57mc1dFezv1-5TKeToh-tVmSML8QhZVPzJykgyUtKM8FwAKGi9aO7ekrRKyEgecxaJmSb90GykVNuQp_Eswjk9TE_z8cZ5LJ4w_WxYkGm_SXOclP9QWbVRsHH874wIQOR319H3tsnAXj_ZW_dx025aoWFxXbjztCQkk~WyI0OGQyNDE5Ni03ZDJmLTQ3MWYtYmEyMC0yMmM1NTQ4Zjc3ZTMiLCJSZXNpZGVudE5hbWUiLCJBYmVlIG5hcmF5YW4iXQ~";
  const DUMMY_UIDAI_JWKS_URL = "https://pehchaan.uidai.gov.in/.well-known/jwks.json";

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

  // Populate & decode sample credentials when Sample buttons are clicked
  document.getElementById('btn-sample-sdjwt')?.addEventListener('click', () => {
    input.value = DUMMY_UIDAI_SDJWT;
    input.dispatchEvent(new Event('input'));
    btnDec.click();
    if (verifyJwksUrl) verifyJwksUrl.value = DUMMY_UIDAI_JWKS_URL;
    if (verifyKeyInput) {
      verifyKeyInput.value = JSON.stringify(UIDAI_PEHCHAAN_JWKS, null, 2);
      verifyKeyInput.dispatchEvent(new Event('input'));
    }
    btnRunVerify?.click();
  });

  const DUMMY_UIDAI_MDOC = "oWxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhdmluLmdvdi51aWRhaS5hYWRoYWFyLjGYKdgYWGKkaGRpZ2VzdElEAGZyYW5kb21YIDsWhoWNsJd8Ww9LB7zXDrqEh2aD+k4tJARrwBxT5pqJcWVsZW1lbnRJZGVudGlmaWVyY2RvYmxlbGVtZW50VmFsdWVqMTk5Mi0wMS0wMdgYWGakaGRpZ2VzdElEAWZyYW5kb21YIHQplEgvw/q3HMRkrR7lUeV7yHoJBK6rOM8HDiVWMJnJcWVsZW1lbnRJZGVudGlmaWVyaGxvY2FsaXR5bGVsZW1lbnRWYWx1ZWlUYXRhbmFnYXLYGFirpGhkaWdlc3RJRAJmcmFuZG9tWCDPFZX8AyilsVZBnT2CpdKA+0S7MIL8sXDzyupth+254HFlbGVtZW50SWRlbnRpZmllcm5sb2NhbF9sYW5kbWFya2xlbGVtZW50VmFsdWV4R+CkteCljeCkr+CkvuCkuOCkviDgpIfgpILgpJ/gpLDgpKjgpYXgpLbgpKjgpLIg4KS14KS/4KSm4KWN4KSv4KS+4KSy4KSv2BhYc6RoZGlnZXN0SUQDZnJhbmRvbVggK3rpBdSN0dL/DR0qA1Joibk/eOTqw2LZRA41VDYqhyFxZWxlbWVudElkZW50aWZpZXJpbG9jYWxfdnRjbGVsZW1lbnRWYWx1ZXXgpLngpYvgpLDgpL7gpK7gpL7gpIrYGFhjpGhkaWdlc3RJRARmcmFuZG9tWCB2Z9tzcIMSbbG2RYaSmwyMd4nW4in5wou/gVaVJZTemXFlbGVtZW50SWRlbnRpZmllcmVzdGF0ZWxlbGVtZW50VmFsdWVpS2FybmF0YWth2BhYY6RoZGlnZXN0SUQFZnJhbmRvbVggcIHsMw3st6EyO40ZG0PxJd9Eo6PFtHD+nLdO8CvxhdtxZWxlbWVudElkZW50aWZpZXJrYWdlX2Fib3ZlMThsZWxlbWVudFZhbHVlY1llc9gYWHWkaGRpZ2VzdElEBmZyYW5kb21YIEXYtaKj1Nz+Rwq3FuqmEv3dVll5Mz11uhloX/8E8d0ocWVsZW1lbnRJZGVudGlmaWVya2xvY2FsX3N0YXRlbGVsZW1lbnRWYWx1ZXXgpJXgpLDgpY3gpKjgpL7gpJ/gpJXYGFhipGhkaWdlc3RJRAdmcmFuZG9tWCC3tztmj2AO1f7pcy75ZB7DxT2uNNEp/Mm28IbUO47w6nFlbGVtZW50SWRlbnRpZmllcmdwaW5jb2RlbGVsZW1lbnRWYWx1ZWY1NjAwNDPYGFhtpGhkaWdlc3RJRAhmcmFuZG9tWCC4lZKrlWk13mjkGtNMNT3e2S4tqfGaTYEpZIRJG5FcfXFlbGVtZW50SWRlbnRpZmllcmptYXNrZWRfdWlkbGVsZW1lbnRWYWx1ZW5YWFhYLVhYWFgtNDUxN9gYWGykaGRpZ2VzdElECWZyYW5kb21YINpgjnfWWUXPZuVrTKHH+ejpu/3PvDWvitbIadpcdFeFcWVsZW1lbnRJZGVudGlmaWVydWlzX3Jlc2lkZW50X2ZvcmVpZ25lcmxlbGVtZW50VmFsdWViTm/YGFhfpGhkaWdlc3RJRApmcmFuZG9tWCB5N9wETwgt1LkwlivjCnO16jx0VoXRiFS6GISBJk13kXFlbGVtZW50SWRlbnRpZmllcmZnZW5kZXJsZWxlbWVudFZhbHVlZE1BTEXYGFi2pGhkaWdlc3RJRAtmcmFuZG9tWCBR1aGobr/YsRu2nPZG1wpswwHuLPPe0UTGoR81M0MAFnFlbGVtZW50SWRlbnRpZmllcm5sb2NhbF9idWlsZGluZ2xlbGVtZW50VmFsdWV4UuCkjyA0MTIg4KSv4KWC4KSo4KWA4KSVIOCkleClieCkqOCljeCkleClieCksOCljeCkoSDgpIXgpKrgpL7gpLDgpY3gpJ/gpK7gpYfgpILgpJ/YGFiLpGhkaWdlc3RJRAxmcmFuZG9tWCC8FWfOAEbvykGrlGT3su3wjK+0nR9zZWVyEfW7Kgg0eHFlbGVtZW50SWRlbnRpZmllcmxsb2NhbF9zdHJlZXRsZWxlbWVudFZhbHVleCngpKbgpYfgpLXgpL/gpKjgpJfgpLAsIOCkpOCkn+CkvuCkqOCkl+CksNgYWHekaGRpZ2VzdElEDWZyYW5kb21YIMpdGo3mImOI1rdDR2n5419frjtTn0LRUIl7Qxt4rsl6cWVsZW1lbnRJZGVudGlmaWVybWxvY2FsX3BvX25hbWVsZWxlbWVudFZhbHVldeCkueCli+CksOCkvuCkruCkvuCkitgYWOKkaGRpZ2VzdElEDmZyYW5kb21YICrGNi4ZXN0bo+GLvQydpXP47uk49PmLKT9b6+BigYmkcWVsZW1lbnRJZGVudGlmaWVyZ2FkZHJlc3NsZWxlbWVudFZhbHVleIVBIDQxMiBVbmlxdWUgQ29uY29yZCBBcGFydG1lbnQgRGV2aW5hZ2FyLCBUYXRhbmFnYXIgVnlhc2EgSW50ZXJuYXRpb25hbCBTY2hvb2wgVGF0YW5hZ2FyIEhvcmFtYXZ1IEhvcmFtYXZ1IEJlbmdhbHVydSBLYXJuYXRha2EgNTYwMDQz2BhYcKRoZGlnZXN0SUQPZnJhbmRvbVggPTHkCrgNyVt5pabfla5tFN1MR9B8Fp3XK7wllwAm7s9xZWxlbWVudElkZW50aWZpZXJsc3ViX2Rpc3RyaWN0bGVsZW1lbnRWYWx1ZW9CYW5nYWxvcmUgU291dGjYGFh/pGhkaWdlc3RJRBBmcmFuZG9tWCD8tRIqPZA82DzR+wjjGv+KAEnjCYsy/rZM/stVHBBA1nFlbGVtZW50SWRlbnRpZmllcndjcmVkZW50aWFsX2lzc3VpbmdfZGF0ZWxlbGVtZW50VmFsdWVzMjAyNi0wMS0yMFQyMDowNjozONgYWG+kaGRpZ2VzdElEEWZyYW5kb21YIBqL2DmdFTPET84McSpUuCf+QH5dQEGy5eojKqzXJHlhcWVsZW1lbnRJZGVudGlmaWVybXJlc2lkZW50X25hbWVsZWxlbWVudFZhbHVlbU5vZWwgQXVndXN0aW7YGFhipGhkaWdlc3RJRBJmcmFuZG9tWCBdptU2hikrGoYeJ02XfTDdxrLfsT7SpPMtPRE5U7Y54HFlbGVtZW50SWRlbnRpZmllcmthZ2VfYWJvdmU1MGxlbGVtZW50VmFsdWViTm/YGFhipGhkaWdlc3RJRBNmcmFuZG9tWCBzWSi0xLpzEy8RL1zzWCc0Mp414Sp8RFKd6+dLlNqptXFlbGVtZW50SWRlbnRpZmllcmthZ2VfYWJvdmU2MGxlbGVtZW50VmFsdWViTm/YGFhipGhkaWdlc3RJRBRmcmFuZG9tWCC/zKtcpMt6rU4PSKNlMVzKB8l6Umv7c7SWeBGyw46oWnFlbGVtZW50SWRlbnRpZmllcmthZ2VfYWJvdmU3NWxlbGVtZW50VmFsdWViTm/YGFh1pGhkaWdlc3RJRBVmcmFuZG9tWCDtN29rXOq9ykuCCA7MQlzFicHzM2DWxATgIn2rE1NmXXFlbGVtZW50SWRlbnRpZmllcm5sb2NhbF9sb2NhbGl0eWxlbGVtZW50VmFsdWVy4KSk4KSf4KS+4KSo4KSX4KSw2BhYh6RoZGlnZXN0SUQWZnJhbmRvbVggJ45NLFDK1ZfOwGuB2WCTND3wtHS2DIBNPphpC7gPizpxZWxlbWVudElkZW50aWZpZXJybG9jYWxfc3ViX2Rpc3RyaWN0bGVsZW1lbnRWYWx1ZXgf4KSs4KSC4KSX4KSy4KWL4KSwIOCkuOCkvuCkieCkpdgYWF2kaGRpZ2VzdElEF2ZyYW5kb21YINwSSjnv5FtUM4m4hYyoIBLDBah6ws4sDaBVOy7QI0IXcWVsZW1lbnRJZGVudGlmaWVyZmlzX25yaWxlbGVtZW50VmFsdWViTm/YGFkfQqRoZGlnZXN0SUQYGGZyYW5kb21YIBpmS79aOKmWZZXAn223MG1ACUvpyFCmR2JP7lLFWvP7cWVsZW1lbnRJZGVudGlmaWVybnJlc2lkZW50X2ltYWdlbGVsZW1lbnRWYWx1ZXke3C85ai80QUFRU2taSlJnQUJBZ0FBQVFBQkFBRC8yd0JEQUFnR0JnY0dCUWdIQndjSkNRZ0tEQlFOREFzTERCa1NFdzhVSFJvZkhoMGFIQndnSkM0bklDSXNJeHdjS0RjcExEQXhORFEwSHljNVBUZ3lQQzR6TkRMLzJ3QkRBUWtKQ1F3TERCZ05EUmd5SVJ3aE1qSXlNakl5TWpJeU1qSXlNakl5TWpJeU1qSXlNakl5TWpJeU1qSXlNakl5TWpJeU1qSXlNakl5TWpJeU1qSXlNakwvd0FBUkNBRElBS0FEQVNJQUFoRUJBeEVCLzhRQUh3QUFBUVVCQVFFQkFRRUFBQUFBQUFBQUFBRUNBd1FGQmdjSUNRb0wvOFFBdFJBQUFnRURBd0lFQXdVRkJBUUFBQUY5QVFJREFBUVJCUkloTVVFR0UxRmhCeUp4RkRLQmthRUlJMEt4d1JWUzBmQWtNMkp5Z2drS0ZoY1lHUm9sSmljb0tTbzBOVFkzT0RrNlEwUkZSa2RJU1VwVFZGVldWMWhaV21Oa1pXWm5hR2xxYzNSMWRuZDRlWHFEaElXR2g0aUppcEtUbEpXV2w1aVptcUtqcEtXbXA2aXBxckt6dExXMnQ3aTV1c0xEeE1YR3g4akp5dExUMU5YVzE5aloydUhpNCtUbDV1Zm82ZXJ4OHZQMDlmYjMrUG42LzhRQUh3RUFBd0VCQVFFQkFRRUJBUUFBQUFBQUFBRUNBd1FGQmdjSUNRb0wvOFFBdFJFQUFnRUNCQVFEQkFjRkJBUUFBUUozQUFFQ0F4RUVCU0V4QmhKQlVRZGhjUk1pTW9FSUZFS1JvYkhCQ1NNelV2QVZZbkxSQ2hZa05PRWw4UmNZR1JvbUp5Z3BLalUyTnpnNU9rTkVSVVpIU0VsS1UxUlZWbGRZV1ZwalpHVm1aMmhwYW5OMGRYWjNlSGw2Z29PRWhZYUhpSW1La3BPVWxaYVhtSm1hb3FPa3BhYW5xS21xc3JPMHRiYTN1TG02d3NQRXhjYkh5TW5LMHRQVTFkYlgyTm5hNHVQazVlYm42T25xOHZQMDlmYjMrUG42LzlvQURBTUJBQUlSQXhFQVB3RDNQRkxTZ1VvRmFpRzROTGluWW94UmNZbUtNVTdGTGlsY0JsTGluWW95QlN1QTJtbW1YRjNiMnNMU3p6Unh4cU1zenNBQlhLMzN4SzhMV2p2R2RSRXBYcVlWTGo4eFR1UzNZNlZ6azAzRmNOTjhWL0N3VStYZFR1Mk03ZnN6akg0a0FWUXQvakJvanpsSllMcEU3T0VCSDVaeVAxcStaR1R1ZWpVWXJCc3ZHZmgvVUZWb05UdHpuK0ZtMmtmZ2NHdHhaRWRBNk1HVThnZzVCcWt4RGdLY0JRS1VDZ0FGTFJTZ1VBR0tLWEZHS1Z3SjZVQ2lsck5uUUxpaWlpa0FVaElVRW5nRHZUWlpZNEkya2xjSWlqTE14d0FLOE44ZC9FcTcxYWVTdzBlWjdmVDErVnBGR0htUGZuc3Y4NlFIVWVML0FJc3hhTmR5V09rMnkzRnhIeEpOTWNScWZRQUhKL1N2UDd6NHNlTGJzdHN2NHJkVDBFRUNqOVd5YTRxVnMvTXhKYk9jNXF0bGljRGlnUm8zK3ZhbnFUWnZ0VHVyajJsbFpoK1JPS3pqTXdQQkJIdUtqbHdvRzVnVDdWQ1pHQitYR1ByVEVXekllcEJ4UUNPbk9LcGVmTTNBeG1ucE5LR3c2RDZpbllEU3RwM3QzVjRuSVpUa2VsZWc2RDRsdURiRCt6WnBJYjZNYjJoTW1ZcGdCeXUwOEE4RWdqQjRPYzhWNW1zdVJubmpxS3RXMTE1VWl2RTVWd2NnamdnMEoySmtybjB0NGI4U1cydldYbXd1b2xVRHpZaWZtUSt2MDk2MzFjRUN2QWZEUGlhQ0JKWXIwZ2JRR1NUSkRLM1AzY2RLN3JRL2laWjNZV0s3SmprVTdES3d5ckVlL0ZhSjNNMm1qMGNVb3JuYlB4bm9WM01ZVjFTMTgzc0RLQm10Nk9aWkJsWFJoNnEyYUF1UzBVRDYwdElaTG1uWnFEZlI1bFptNVBta1p3cWttb3Q5Y1I4UnZGNTBMU3hhV2pBWHR5Q0ZQOXhlNXBNRGp2aWQ0NW51Ym1YU0xPNFVXYVlFaGo2dWZRbjA5cThwTnlXeUdKeG50VDVwVEl4SjUrdFJTQUdQUEFBOUtCREozQUc3ZGpQU3FmbmJNbm5KOTZmaHkzWDVmZWlSVWpYNS9tWTlzVUxRQmlTUE53QVI3MU1ka1M3aUJ1OU1VUlJ5RlNmNFQyRklSRkdTQ1d6M3pSY0JGY2taQUErdEswcTlHT1ByVGZNRGNiZmxGU1BIRVl3U28rdWFkd0dLZWNqbGM5UlN2d2Nwam52bW9RL2x2Z2NqUFQxcVVLcjhxUmp1RDFGQVdGanVuVmdoT1QyTlNRYWd3Y0svVUhqazFXS0V1R0hPMm1GU3NoSUlJUFlpbUt4Mk9sNnhZbVB5YnpUYmVkV1BKRWFxNDQ3UDF6bjNIMXJ2dkQzaVU2VHR1WW11cHRJWnRzMGNpbHZzdmZJYm5qcVNEMkdSNlY0MWJsaXcyOWZwVzM0ZTE2YlJkU1dWVkRxU1JOQ3h3a3lrRUZTUHg2MVNaRGlmVWxyTkZQRXJ4U3E2c01nZzVxeFdENFZGdkpvVmxMYlNNOFJoWEJicjA3KzliK0taS0lCUURSaWdDc0RjVXR0VW4wcjV6OGFheExyWGlHK3VIZk1hT1lvVkhSVVhqK2VUK05mUXQ5TWx0cDl4TzV3a2NiTzMwQUpyNVplVXlpUTdNN3VSNmlnRE9FeFdYSFdwOTRZWS9TcVVwdzNYRlR4T3ZsOWVleHBzQnI1VmdFd1dKNHBoaFZpV25sSU9lQUJuTlNyODU2N2Y2ME5Ia2pia2dkVG5GTzRFQlppZGluYUIzSnFKb2p0eThxbjZHcFpJUUNRZ3llL2Vxc2l1cDVVcjY5YVFFMGV3bkdNRDg2VjRnZjRUanIxcElZL01JR0NLdHRFWXdBb0xVWHNCU1pReENxUG9haThtV003MEk5eFdpSTlpOWhucUtIZ1VxRzc5NkV3c1VrWnBEZzVGU2VTUTJjZ25OSzBlM0dNKzlXSlVFUkpJengxRlZjUWtLckd4TEgycHNqZnZBd1BlcTV1REtvd3VCbnZTaGkyMEFZSFRtbUkraC9nOXFIMnJ3c2JZdVMxdkt5bFQyNk1NZm5qOERYbzllVGZCaTFLYWJjWEFiTzV0akwwS25nZy9TdldPdFdaZFNQRkdLZUJSaXNUY282ckFzK2szY1RnRldoZkk5ZURYeTR3QVhzZHcrbGZXRElyS1ZZQWc4RUh2WHkvNG1zRHBYaUhVTExhRUVNN3FvSDkzT1YvUWlrQnpjOE9DYzhVeEFBT3Y1VmVsaU1xQWhXNDZta3NkTW52SEt4UnMyT3VCUTJ1bzBtOWlLTldQYmp2VHhGanZnbXI4bW5YZHBqZmF5ZmlPRFRVdHJtZVFJdHN4WThjRG4vNjFUeklya1pVQkdTT3BIcFVYMmN5dDh3T00vclc5YmVITDJiSDdvS09NcXpjL3BXL1krSElvQ0htWVNPRGtFY0FmaFVUclJpaldGQ1VtY3BaYVBKS3U0cGdmeXA5eHAwMFFKVTRYMnJ1MnNVVk5xbkFBeGlxcDBrU01SdXJCVjIyZER3MFVqZ3ZJVlhHK1FuOE1WZGl0N2ZJSlVrZW1jVjA3ZUhZV2JrQSszV3BQN0hnaUFQa2hqbnZXeXFxeHpPbTBjcEpZSzBYUTcyUFFlbForcHdHMWpqM1pHNWVwcnZKTE5OdTJPSlkvWGFvNit0YzE0dGd3WWlGd2c0SHA5S3FNN3V4RW8yUnl5S1pHY0Q3bzRxMmtJY3Bqb09meHFDS0lvR09NazloV3JZV2IzdDFhMnFFQnBwRmhESHN6TUZIODYzTVdlK2ZETFNuMC93QUxXajR3TG1KTG5nbitNQnlDUFVic2Y4QkZkeFVGaGFKWVdNTnJIOXlOUWk4ZGh4VTVyUkdRWW9wMktNVmtkQTNIRmZQZnhMMDJhMjhaM3M4Z3d0M2laQ2U0QUMvK3kxOUQ0cnpyNHI2WERlYVZCTnZSTG1Fa3B1L2pIR1IrdWZ3cVdGanliUmhCYTZKUGRYRVRTRnBOaUtPOVF4YWxlUVNtVzNRUlJyL0NxOVB4TmRyNFowdUp0Q3RtbVJTVzN1TTg0eVRqOUtkcVZ6WjJTbEJBc3BIWm1Db3YxSnJqbFZ0SnExenJqUjVvM3ZZNVFlSzdsQnRsaVdRZjdRNXEvWStJNEx5YnlwWWRpbm9RU2Vmb0t5ZFJsdHBIYVJiYXlUY054WUdWaGpPTTVHQmpPS3AybDBiZVVTckJCUEdEejViRUVmclZ1S2tyMkZGdU1yWE8yT3BSK2Q1ZjNTT3c2Q3JTc1gya0RDbnBqdlZTd210TlRSR0NnYmprWjY4ZTlkQUxhS09LUEtBZ0RHSzQzTmJXTzZNSHVZbDlONUVSS0RjUU9RR0dmeXJKaTFKMElmWmxRZno1cnI3clRZcDRRWFhBSFlqdFhMYWhQcGRxclJQY0F0MDQ5YTBoSmRpS2wrNVRmeGdMZWRsa3QvM1lIVlR6bWlieGhhdW9LMjc1OXlQU3NhNGpzNUh5VEtzWlBYYXY5VFZxeDBqUjVXM085NGVNOGJEZ2ZSY211cE9OdGpoY1ozM0xWdDRwZ2xtQ1RRTWlOMGNIT1ByUjRuaVMrMEdTV0VoeEdRM0gxeFduYTZGb2wybjdoZ3hIM2h6dUgxQndSK05Xb2ZEdHZiVzF4YlJNN1JUTGpEanBSZUxlZ25HUzBaNWZBdVlGYzl5Ri9HdXkrSHVsM041NGgwMlJZeXdobEZ3eFBvcEIvbWE1R0pDc1lqWWhXM0FqZDB6WHZId2kwaDdUUWJtOXVrWmJpYVlvRlpjYlZYaitmOHE2NG5MTFE5RUI0RkxTR2tOYUdaTlJpbG9yRTNDdVE4YUtrcnd4eUFGUEtZOCt2TmRoaXVDK0l0MjFzaWVYOTlZR0krcHlLd3hGK1RRNk1OYjJtcHp1bktZdEd0TnZRd0lmekdmNjF6OTFGdDFTSzZ1WXpORXJCdktPTnZYOVQ5YTY1YmJaYlJ3cDBqUUlQb0JpcVZ4cHhsVGJqSjcxeExTVFoxcDZXTVR4YjRkdGRlbGoxQzB2STBaWVJFMFVzbmxZT2NnOHFmVWpIR2VEbjF6NDdPejB6UXBvYmhvcjIra1ZWQnQ0OExFRjZZYkF5ZVNTZXRiY21tZVZIeEVPbUJrbXM5dFBrbE8zQUE5QldrYXp0WVRwSy9NWTJpSmNHWU13TVkzOHFQNHZmMi8rdFhwRm9xVFc1MzhZQU9UV0ZaYVhzMm9GeDcxMGR0RUZ0MlhQUVZqTzBwM05ZdHFKbmF2S2ZKOHRUaGR1TWl2TGRXc1VTNWxlU1VGK0NpOG4vSnIxUFVyYnpFd295YTRyVmRGYVdRVElQbUdRUjYxMDBXa2N0VXdKZExiVWJHR09BbHBFRFpVWTNNVDA2a2Q4RDZHdWw4T2VEL0owMlM0MXExaHRZWTRtVkdaeUpaR0pCM241dmx4dHdNWVBKNHJFU3ptamtHSGNZOURYUjJGa0pZRjNibWRSM0hldG5LMmhrbzNkelBzMG5pdjFJbDg2SldLcTV6NW0zUEFic2E3T0JpVlZ1dFpLMlhsRXNGeDdWcTJpc0l3R0ZaTjNkeXVodytoNklsMzRndnhMOTIwbFlBWTlXT1AwRmV4ZkQ2Nlc0MGVaRlFJRWsrNEd6anFQNlY1N29yZVQ0MTFlSG9zcUszVGpJeC9pYTY3NGRzME9xYW5aa1k4c3R4L3dJZjQxdEdUOW9pT1JPaTMxUFFqVFRTbW0xMkk0UzFSaWdVdUt4T2dTdUI4YVd5WFd1MjhVK2ZLZUxCd2NldVA1VjZBQnpYTCtMYlBlMXRjREhCMjVQNS80MWpYVjRHMkhhVXpEalFNbFMrU21LanQyR1NLdUJlSzgxdHBub1JTYU1tNXRUS2NBOFZISFlMR01rQTFwT051VFZTV1pza0l1VzdDaTZSU2dWMitWc0FETldZVnpBN25JQTcxV2lzNWhMdWxKSmJyV2dZMFczQ1k1elZ3U0ZJcVNxQVFldFVaNEViSUFITmFNOFRLbWNjVm5Na3k1WWRQUTFyWXdlck0yNTBZT2ZNUVlQVTRGWGRPc2pIR1ErTW1ybGxKOW95R0dDdFhsdDhOa1VtNzZBb3BGWWFlcCtZa0gycEhpQ0Q1UlYyWDVCVk9RamsxcEV5bWNkTEJQRjRzZHhsUlBJcXJqdUFGeWZ6UDZHdTE4SVNBZU05UlZlanhaUDErWC9BVmtRV3NZMU43MlNYYzIzYXFGYzdlTzM4NjMvQW1ueUM1dmRTbVVCcEdLNDlNa2Nma1AxcldHczBUSnFOSm5iMGhwYWFhN3p6UzhLS0tDUUt3T2tXc0h4SkJKTXNEYytVaE9mWW5HTTFzUGNLdmZtcTdYRE43VVNwdWNiQkdxb1N1Y1F5Q0dYamtFZGF1UnRsYTB2RVVSa3RZcCtTWW13Zm9mL3JnZm5XQ3R4dGpPYTh2RVUzVGRqMGFGUlRWeVc1ZGVRRHpXUlBxRU5pNGQyQk9jWUpya05hOFd5dHFNME51eEVNWjI3djd4Ny9yV0hmYTVMZHJ0aTh4d0R1NTc0OXVhY0tEYXV5cFloTFk3ZFBIVnMxNDBVa2FoQjMyc3JEOHhnL2dhNnkxbXQ3dTJXZUtSU0c1QlU1RmVBdkZmWE0yK09KeHp6Z0hOWDdIeFhxK2lTRzJYZU8rSHpWeXczOGpKV0tUK0pIdFdvMzBWckFCSXlnY2tBbkZjMG5pK3p1b0hVUXVzb3l1enIrbzRyeXUrdk5ZMVNVM2wyWnBXZnVjNHg3ZTFQdEw2OWoyZ2tnQThIWi9uTmF4bzZhc3hkZXowUjZsYjNCQ3BMR2NrZFFPOWRKYVhDeko3MTVQWjY2d1VBdnRZY2xsL2xnL2xYVTZIcmtkeklZMFk3MTV3ZTQ5YW1WTnJVRldXeDE5MXd1YXlwcGZsSXF6TGM3azlhajAyM04vcXR0QmpLdElDNC8yUnlmMEZWVFY5RE9wS3hVdFExeEFzMFhKM0g4UlhkZUdzalRIQkdNU244ZUJVMy9DUDZjSldramhNSmM1WVJuQ2svVG9Qd3EvRERIYnhMRkVvVkIwRmROS2s0eXV6Q3JWaktGa09OTkpweDZWR2V0ZFNPVm1nVGdWU3VMazdpcTArNm4yREErOGFvYnNtczR4Nm1zNWRFUDNFbm1uZzFGbW5Cc1ZvWkRwWTFuZ2VGL3V1cFhQWEh2WEUzRWNrVFN4TVAzaTVCR2U0cnRnMWM5NGp0MVJsdTB3TjJGa0g4ai9UOHE0OFpTNTQ4eTNSMTRXcHl5cytwNDVCb1V6WDhodlk1RUc0c1F3Skxjbjg2MmJlMDBxMVhkTEpIR01mY0xBSDhxNldWOXpEaW9tanRIQk1rS0U5OGl2TmxWazl6MHFkT0tNeE5UMDZOY1FlVWc5UTROVkxpRFRMMlFYRHdRenVPaFBiOWEwMzB5eVZ5OEtCTTg3UXVCVmFTMFRQM01mVGlyaEtQUm12S210U3NicUpGQ1loQ2pqQngrVk5iN0JKbnpZSTBKL2pWdVAxcWI3Sjg0SXlBT2h6Vm1LMXRJbURzb2VUMUk2ZlQwclhtU1c1bk9LT2F2TkhzM2tQa0Q1ZittZmMraHhUL0RlazNGcHJQbk9qaUlJd0pJT0RucHpqNlYwenRIL0NvSDBGU1F5a0p0UFNtcWt0amxsQ082TFlPY2s0QXJxdkIxdEdZN2k4em1RdDVRSG9PQ2Z6NC9LdUtlYjVkb09jMTF2aE9VeGFWY3VyWkc5U1BybmFmNVYwWWRhbkxYYlNPd3BEU0JnNjdoM29KcnNPWVJqVVpQTk9KcGhOVWtTVjNrTHNXUFUwM05NelM1cERIQnFkdXFGMktjREc0aklCL3dBS3g3bWU5bGJ5MG1pREU0Q2lNOG50L0ZUQTJrdTRwSmpGR1dMRHI4aEEvTWpGY240ODFCN1BUWnJnS3pSMmlwSXdIY2xnUDBHZnpycExHSXhRa25yMHo2K3AvUEkrZ0ZZZmlTeE9wK0hOUVVJR00wVWpMNzRVN2Y1Q3M1N0Z3ZG1ZRWM2VDJ5U29jbzY1VTFFVitianJYTCtGTldQOW54eHlaWkI4cEhwL2tZcnFRQVU4eU1oa1BwWGl6anlTc2V2QjgwYm9ac09DRFZXV3hSai9BQmcrb2FycVRSRnRyL0szdjNxUmdoT1QwRk9NMFZab3hYMDJaRDhseklSN2swOUlwRUdDMjQrdGFwQ2tkUUJWU2FSVk9GK1krZ3JXTXJtVTdrS2s1RzRpcFBPM0hDanBVYXd2SWN0VXJlWGJ4Rm5ZS0JSS2FRb1VwTmFrTnhMNUVCYzhzU0ZVZjNtUFFWNkJvTm1iYlJZb1crOFZpWnZydlpqK2hyempTMU9zNjlCSXhJdDRuS3hKajd4eDh6SDZBZ2Y4Q3IxcTJBRUxrZnhTOEQwd0F2OEFNR3UzQ3grMHppeGJzK1ZDWFdxLzJiQTBubE5NQms3RUlEWUF5VHp4MEJOUjZiNGxzOVNPMExMQy9URXVNSDhRVFVOd3dGOURrQWdCaVFlZTJQNjE1N2MzVW1oK0twdFBoaTNXOHFpU0VCOEVaendNK2hCNytsZGU1eHBucnhOTUpybDlCOFErZE1sbmNoNDNiaEJJTVpQb0QwUDRHdWxQTlVobFlISXpnNCtsS3JqUEE2ZTlWNHVROHV4UUFUODVHU2Z4cGtzM2wyaGtZNEpHOCt3ck5zcTQyM244elZUSVQ4aS91LzZuOVNQeXFXU3hoanZwcjFNbVRpT01mM1Q2ajhUK2dxbFpSdjVjZWVaR080NDdrMXJHQ1h6a1RZK0VCZGpqdWY4QUpxT28vc2paY1FXVEJPTUx0WDZuZ2Z6cFo0Z0lBZzdEYitsUjNCTDNVRVE3RXV3K25BL1UvcFVydDkxVDFKcTdFcmU1NGZxTm11amVOYit5UWJZSmlKb3gvdkRKL3dESHQzNUN0VzN1NUxYbGVWN3FhdWZFZXdka2kxZVA1V3RyZ3hzQi9kWUtCK1RML3dDUEdzZTB1RnViVlpQVWMxNStJZ3JubzBKdTJoME1EUlg4VytQaGg5NWU0cHlXZ0RFTmdWZ1FYRWxsY2lXTS9VZW9ycWJhNGh2cmNQRzNQY0hxSzgrcEZ4MjJQUXB6VWxabFdXMVJjWTUrbFJDM0M4a1lGWG4rVDNxbkt6TmtaNHFGVWFSZnM3a01rcXhJY0RKOUt3NzU1cnlWSVkrV2R0cWp0V2xjamFEM3BOS3RsbHVUTElNaGVNRGpqLzYvU3RLS2M1Q3F0VTRYT2w4TmFiREJORnNVaFlZOXU0OWVlU2Z4d0RYWW9QTHRJd2Vwd1Q5VHlmNTFrNlZibExUTDREeUhCL0d0SzdsQUtnSGpjZjA0cjNhVWVXTmo1NnJQbWsyWmwxUC9BS2VWOUlzL21mOEE2MWVjK01oS2RZZ3VZaGw0d3VlUU9Nbit1SzdTOG14Zk93UC9BQ3pBL1UxeXV0a1NTWERiU3hXMkxZejEya21xYnNqT0MxTit4TVYxYnd4VEtVZG9sY3h5cmduak9SNi9oVmk4MXcyRUQydm1TVE9xNVFsejA1NFAweFdGSnFEend4NWNiWTdXSitCOXh5TThIOFAxck11SmpKS0xndHVWMTVJN2Q4L1NsRjJSVTk5RDFlU01pQ0szWGdNUXY0ZDZwNm9TVThySkJrWUp4NmQvMEZGRkpzYjJaUGJFcmtxQnVZYkZ6Mko2R3NDN2xlM25rUUZ6ZVB5em43eSs1NmNlbi82NktLemx1YlFlaEpwOS9xRnRlT0d2MHUzMlo4cTRYTEVBY2hXSFBIMS9DdG8zc054cU1VYkJvWkFqYlVKeUQweitsRkZLTW56V0hLS2NibVByTmltcGFCYzJrbVAzL3dBb1lqT0NXR0QrQndhOG4wbVNTMXVaTFNjYlhSaXJBOW1Cd1JSUlNycjNTc095OWRUaFRtb1lOUm10cFJKQzJDUDFvb3JrNVUwZGFiVHVqVmc4VHV6QlpvVk9lNDRyZllCN1paRkhERE5GRmNtSXB4amF4MlVKdVc1bk5GTmRUaUdGY3V4d00vNStwL0ExME9sYUpMSGNwRTJDSWszeUVBNUxuZ0Q4Qm4vdnFpaXUvQlU0OG5OMVBQekdyTG5VZWgxY2NYbHZHbm9DeC96K05VNytUNTB4eDhwL3BSUlhlZVdjMVBLSHU1aDNDci9Xc2xVTXVxVEtlUUkxVWoySk5GRlN4eExIOWlUTkM4VE1DSklsa0RZeHdVQS9UR0t3cnFLV0dRaEFQbFlBaHVuVVVVVkY3bXNsWm4vLzJRPT3YGFiPpGhkaWdlc3RJRBgZZnJhbmRvbVggw07oOJbplpggT3SQ9L9DW9vTTdvkkKuW3icyq88cv5hxZWxlbWVudElkZW50aWZpZXJzbG9jYWxfcmVzaWRlbnRfbmFtZWxlbGVtZW50VmFsdWV4JeCkqOCli+Ckj+CksiDgpJTgpJfgpYHgpLjgpY3gpJ/gpYDgpKjYGFkBpKRoZGlnZXN0SUQYGmZyYW5kb21YID8vijMR5YRA9T35M/rPOR3Ibgxw1oKR+wCK6nY0i5DrcWVsZW1lbnRJZGVudGlmaWVycHJlZ2lvbmFsX2FkZHJlc3NsZWxlbWVudFZhbHVleQE84KSPIDQxMiDgpK/gpYLgpKjgpYDgpJUg4KSV4KWJ4KSo4KWN4KSV4KWJ4KSw4KWN4KShIOCkheCkquCkvuCksOCljeCkn+CkruClh+CkguCknyDgpKbgpYfgpLXgpL/gpKjgpJfgpLAsIOCkpOCkn+CkvuCkqOCkl+CksCDgpLXgpY3gpK/gpL7gpLjgpL4g4KSH4KSC4KSf4KSw4KSo4KWF4KS24KSo4KSyIOCkteCkv+CkpuCljeCkr+CkvuCksuCkryDgpKTgpJ/gpL7gpKjgpJfgpLAg4KS54KWL4KSw4KS+4KSu4KS+4KSKIOCkueCli+CksOCkvuCkruCkvuCkiiDgpKzgpYfgpILgpJfgpL7gpLLgpYHgpLDgpYIg4KSV4KSw4KWN4KSo4KS+4KSf4KSVIDU2MDA0M9gYWH2kaGRpZ2VzdElEGBtmcmFuZG9tWCC0a2+XLTdIkPo2q8xVGoOqm/FWU/wruXRFzOMOaWnUj3FlbGVtZW50SWRlbnRpZmllcmhidWlsZGluZ2xlbGVtZW50VmFsdWV4HkEgNDEyIFVuaXF1ZSBDb25jb3JkIEFwYXJ0bWVudNgYWICkaGRpZ2VzdElEGBxmcmFuZG9tWCDCsT7E/Syfi30A8pKl3D+fidbeMCoIdXhNRlvF0IBw03FlbGVtZW50SWRlbnRpZmllcm5sb2NhbF9kaXN0cmljdGxlbGVtZW50VmFsdWV4G+CkrOClh+CkguCkl+CkvuCksuClgeCksOClgtgYWGWkaGRpZ2VzdElEGB1mcmFuZG9tWCDuPYU6mupk+OpnkAlkQCRYuJ0A98vuCNUCma6+DrceWnFlbGVtZW50SWRlbnRpZmllcmdwb19uYW1lbGVsZW1lbnRWYWx1ZWhIb3JhbWF2ddgYWHGkaGRpZ2VzdElEGB5mcmFuZG9tWCB+zgUBaVufS7Y5hTaTOc+iXc/NWjEmlVEhAPFaS/HEcHFlbGVtZW50SWRlbnRpZmllcm1tYXNrZWRfbW9iaWxlbGVsZW1lbnRWYWx1ZW4rOTFYWFhYWC1YODc5NNgYWHekaGRpZ2VzdElEGB9mcmFuZG9tWCAAbxupBBruOLwys83m16tIuzQ0FcLiqiDCp1zpG6q6ZXFlbGVtZW50SWRlbnRpZmllcm5lbnJvbG1lbnRfZGF0ZWxlbGVtZW50VmFsdWVzMjAyMC0wNS0yMVQxMzoxMTo0ONgYWHCkaGRpZ2VzdElEGCBmcmFuZG9tWCCC4L5a2CcQqRIqpknuZBOKQgtJ7eeg0WGAScS+bnetB3FlbGVtZW50SWRlbnRpZmllcmZzdHJlZXRsZWxlbWVudFZhbHVldERldmluYWdhciwgVGF0YW5hZ2Fy2BhYeaRoZGlnZXN0SUQYIWZyYW5kb21YIP3UvaIvu0nHAAXcEkxDM3a5amzb0DrA082Y2mZCbKBxcWVsZW1lbnRJZGVudGlmaWVyaGxhbmRtYXJrbGVsZW1lbnRWYWx1ZXgaVnlhc2EgSW50ZXJuYXRpb25hbCBTY2hvb2zYGFhhpGhkaWdlc3RJRBgiZnJhbmRvbVggQs9aviDPPtjzxd3hlONOc+6He1iKMS0+P/sk1O6I4jZxZWxlbWVudElkZW50aWZpZXJjdnRjbGVsZW1lbnRWYWx1ZWhIb3JhbWF2ddgYWGqkaGRpZ2VzdElEGCNmcmFuZG9tWCDrZeFP2VO01QTl8kD8JnYHiREY5VMRWaSq+offKedN2XFlbGVtZW50SWRlbnRpZmllcmZtb2JpbGVsZWxlbWVudFZhbHVlbis5MSA3MDEwMzE4Nzk02BhYd6RoZGlnZXN0SUQYJGZyYW5kb21YIAFnwf8IUODfR7Ubst4xcMEu2+r5jwUrDZDPSDsULxRJcWVsZW1lbnRJZGVudGlmaWVyZWVtYWlsbGVsZW1lbnRWYWx1ZXgbbm9lbC5ub2VsYXVndXN0aW5AZ21haWwuY29t2BhYb6RoZGlnZXN0SUQYJWZyYW5kb21YILyFz3y/1uBp17MQr2fBpS+jtIrXW4I76qiQ4P8niralcWVsZW1lbnRJZGVudGlmaWVybG1hc2tlZF9lbWFpbGxlbGVtZW50VmFsdWVtbm9lbFhYWFhYLmNvbdgYWGekaGRpZ2VzdElEGCZmcmFuZG9tWCB+Mp6AWAX1Q70reFCFZdQyO1FiiiRW+DeOSJapIpo763FlbGVtZW50SWRlbnRpZmllcmhkaXN0cmljdGxlbGVtZW50VmFsdWVpQmVuZ2FsdXJ12BhYdKRoZGlnZXN0SUQYJ2ZyYW5kb21YILWkqNVA3TRTF+tt+AXvueWQ5RbO3lKxKODZMESVkHJJcWVsZW1lbnRJZGVudGlmaWVycGVucm9sbWVudF9udW1iZXJsZWxlbWVudFZhbHVlbjAwMDA0NTY3ODAwMDAy2BhYZKRoZGlnZXN0SUQYKGZyYW5kb21YIIL1e2ICrkENyMh/T3uz24sOP7RWSgYZ7uKcWvYw3ILLcWVsZW1lbnRJZGVudGlmaWVybGFhZGhhYXJfdHlwZWxlbGVtZW50VmFsdWViSU5qaXNzdWVyQXV0aFkIv9KEQ6EBJqEYIYFZAXAwggFsMIIBEqADAgECAgEBMAoGCCqGSM49BAMCMCYxDjAMBgNVBAoTBVVJREFJMRQwEgYDVQQDEwttZG9jLWlzc3VlcjAeFw0yNjAxMjAxNDMxMzhaFw0yNzAxMjAxNDM2MzhaMCYxDjAMBgNVBAoTBVVJREFJMRQwEgYDVQQDEwttZG9jLWlzc3VlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDYWaK1xMuxAFSuvWnzksVIy0k0AooWQl4E/P/xlYJEq6sVGzRlvzSEYprO0/e0sEO1VFspcN8zy/O5+TZrBvVijMTAvMA4GA1UdDwEB/wQEAwIFoDAPBgNVHSUECDAGBgRVHSUAMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAwRQIhAJ1YA3Y6rkXb2Sgh9/kfJK49iGOIM4wwEVYpvc9Ux71sAiBfynGhjQm8+hP+QGJRJcwkeSILQ1c8Vi0aniKyevVidFkG/dgYWQb4pW9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOham5hbWVTcGFjZXOhdmluLmdvdi51aWRhaS5hYWRoYWFyLjG4KRdYIEQX6//A4uLVgiu/xUPrAaRAGaoES6f2ewhuz20thJjtGBlYIKSqRmvkLgRMtXouoF8t1Oyl4zE4LHYlvHe851cYQhTIGCFYIPBPvE8Oq9iUXKzf/zG9Ymo9ScRJs3oK7VrudCAJOET2GCVYINwjGpYajn9kODYo9it8gZjFkRcHlhYmUOQ4trvLCDNsAFggeJWFvkIifZGPayqUuYG3uLdX276bzrh5lB+0lx1mQ0wKWCBEr5M/TrBuBpLEyPnlTLgwoY3qCgKqfqFDX1zsfuQOEBgeWCBZZSq4J0BG8DT9bFTmrcxvhnBIjdw5dLRyf9Iu8OrPIhgnWCB27TdwLMfIRo+g8zM9AXqQ5w+U+JM9xfjtTGi2XQYfdwVYIDJtM3jyGQb983V4ilszIjIlyJaoHQqQBlMgSXyofHDSGB1YIOom7uMjvc//zaeZnbxuL6oRTPNkRIgleIpMpvsB2dM8DFggBDy3t/dq81yJhIXP7b3XTO9sPlDc3CbucI0xyXZ67o0RWCB9ANamnUgSVtENShybfyccJIC6VL082IBYFC7OadSpZxgcWCDwc/1EmaVpaQpAEO9K/SfQMr5+QPZxKJADmYdp2/tHmhgiWCBDdohvbiqT+8knLsC/AdnLBo9OQlVxFEbwG4Gh8H2yAQJYID4iZsy8lNsSCSXd4q6+Xrh0LzUSrOZPKMKmuqOERabCBFggSojohqli1hhWZkkqfHpn3LJA9U4LxCVZaiE0WwJ8aXwLWCBM5vSMaf6etfG4Gom5X8P2I4UyjYlu5gulCMpJxBQshxggWCAmekqaxVy7wszuXs3dimOonktd1xgcUxpV/Hg1AhC62AdYILcfmZloVabxL34rDLBZCQ+7zF13dePImIMs6ws1uFxECVggTZ8cm2CSUNjQQiT2ji3nxCq3DVsgvDBkpFSZjOnZDm8PWCAIAL0P4J2ZCN3eAM0ifZQUYKn4oQWvR8lmN0BNGKl94BBYIDufvE+ZN29NqqFBbPn2ZN85Rpk/iL32eG0zfMuyyI4SE1ggRSnOt8Pp1KAhsfSvtxIvcfGtd7qU5L41qfQjuPVG6mAWWCBWmYdjc1N1x/safUVOkryS31DXiZ95bgMDKKsiKQO4CRgjWCDM98pBjHrecPBVHAsqU0quzj+XokheTejW7LYeZm9VCRgmWCBQuznciT9kEnuEYRKAmWPZdZyT4RkuPIT/wuEgF6WGVwNYILLZu4AX7EOZphCDSH1gRxOkLQfMYzDYs6iTjaTF7gzSDlggCgGyKXhdjHKNjSj+wCXRJJKcu17OjrMbkdd8HTnSGpAYG1gg8xFwJD2aDmOVb1yfItZROaEVHA6inxdlbFyxgNKOYrkYH1ggAoOlWD21b8f1rhPhwOLt5h54Wh6qKCDKqhaLeEjpK7gYKFggleKBx0Qk8awxBxaZYBRcmNV2fEucpq+zKQj10Umd7RYYGlggDImdjQTej/BRK/5XAbbz8NH5zWkjvNXD/z4qeA7qPlkBWCD7TbKlyja491YhiydHjXBoYjXN5kTRKy3vBooaJyLxbQhYICFVAzqKwWW/Q72kITBXxctb37ZePfFje84KE0ugBbDoDVggNJX5QW00QD6L1e0saPES1ksicXTZRSKCAXH2QBPlU+kUWCCrfTVb2/h4LUbXtJ5zGqR8Z7Rp0CA/sBDqAfRoTpGrtRVYIKl2XTV81K12/Ey+wBLcDSDxztoGdKCjRj7NwEqqHKuRGBhYIGv5GLFTLpOk+10Nv0a5pJBByLvWjzLz9ap0YgDPq0uGGCRYIDkv0ZTgrJADzyl/TivLwRlPJlzAJQSv//jVQUUa6nviBlggMPD9rTixeDPvtosZlGX3YiPJKgFHvBlZrx4BHaGy9MMSWCBw4q1xJ+5H+dePC5UggXMTLtdWVfsNn4Uos3aOgSQr221kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmlAQIDJiABIVggJIhtfAZCNYn+tOqaYLX2SVZT+whH8K3TrNcznWOBZFgiWCBOQ0GUhEicG+GY5LV1NUzBNmRzzEbO6ePUA3Y3JajgcWdkb2NUeXBldmluLmdvdi51aWRhaS5hYWRoYWFyLjFsdmFsaWRpdHlJbmZvo2ZzaWduZWR4GTIwMjYtMDEtMjBUMjA6MDY6MzgrMDU6MzBpdmFsaWRGcm9teBkyMDI2LTAxLTIwVDIwOjA2OjM4KzA1OjMwanZhbGlkVW50aWx4GTIwMjctMDEtMjBUMjA6MDY6MzgrMDU6MzBYQOJ8YcZrdT8R9mdusrmN/civys6Lr4QwBX2s6NDYyFTb3BZrzdEUOnA0owwmQ9XR29roAbBCu52ecbAgk+Qfbto=";

  document.getElementById('btn-sample-mdoc')?.addEventListener('click', () => {
    input.value = DUMMY_UIDAI_MDOC;
    input.dispatchEvent(new Event('input'));
    btnDec.click();
  });

  btnClr.addEventListener('click', () => {
    input.value = ''; outSec.classList.add('hidden'); errSec.classList.add('hidden'); hint.textContent = '';
    if (verifyJwksUrl) verifyJwksUrl.value = '';
    if (verifyKeyInput) verifyKeyInput.value = '';
    if (verifyKeyHint) verifyKeyHint.textContent = '';
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
