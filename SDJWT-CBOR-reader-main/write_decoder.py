
code = r"""
/* CredentialDecoder – SD-JWT VC & mDOC (ISO 18013-5 CBOR) */

function b64urlDecode(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return atob(s);}
function b64urlDecodeJson(s){try{return JSON.parse(b64urlDecode(s));}catch{return null;}}
function b64ToUint8(b64){const s=b64.replace(/-/g,'+').replace(/_/g,'/'),b=atob(s),a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a;}
function uint8ToB64(a){return btoa(String.fromCharCode(...new Uint8Array(a)));}
function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function isEmpty(v){return v===null||v===undefined||v===''||(Array.isArray(v)&&!v.length);}
function fmtDT(v){if(!v)return null;try{const d=new Date(v);return isNaN(d)?v:d.toLocaleString('en-IN',{timeZone:'Asia/Kolkata'});}catch{return v;}}

/* ── Auto-detect format ──────────────────────────────── */
function detectFormat(txt){
  const t=txt.trim();
  if(/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]/.test(t))return'sdjwt';
  if(/^[A-Za-z0-9+/=\r\n]+$/.test(t)&&t.length>100)return'mdoc';
  return'unknown';
}

/* ── SD-JWT Decoder ──────────────────────────────────── */
function decodeSDJWT(raw){
  const parts=raw.trim().split('~');
  const jp=parts[0].split('.');
  if(jp.length<3)throw new Error('Invalid SD-JWT: not enough JWT parts.');
  const header=b64urlDecodeJson(jp[0]);
  const payload=b64urlDecodeJson(jp[1]);
  if(!payload)throw new Error('Cannot decode JWT payload as JSON.');
  const claims={};
  for(const disc of parts.slice(1).filter(Boolean)){
    try{const d=JSON.parse(b64urlDecode(disc));if(Array.isArray(d)&&d.length>=3)claims[d[1]]=d[2];}catch{}
  }
  return{
    format:'SD-JWT VC',
    formatDetail:`alg: ${header?.alg||'?'}  |  kid: ${header?.kid||'?'}`,
    meta:{iss:payload.iss,iat:payload.iat?new Date(payload.iat*1000).toISOString():null,exp:payload.exp?new Date(payload.exp*1000).toISOString():null,id:payload.id,holderAlg:payload.cnf?.jwk?.alg,holderKty:payload.cnf?.jwk?.kty},
    claims,rawPayload:payload
  };
}

/* ── mDOC / CBOR Decoder ─────────────────────────────── */
function decodeMDOC(raw){
  const cleaned=raw.trim().replace(/\s/g,'');
  let bytes;
  try{bytes=b64ToUint8(cleaned).buffer;}catch(e){throw new Error('Base64 decode failed: '+e.message);}
  let outer;
  try{outer=CBOR.decode(bytes);}catch(e){throw new Error('CBOR decode failed: '+e.message);}
  const documents=outer?.documents||(outer?.issuerSigned?[outer]:(Array.isArray(outer)?outer:[outer]));
  const claims={};
  let docType='',issuerMeta={},devKey={};
  for(const doc of documents){
    docType=doc.docType||'';
    const ns=(doc.issuerSigned||doc).nameSpaces||{};
    for(const items of Object.values(ns)){
      for(const ib of items){
        try{
          let item=ib;
          if(ib&&ib.tag===24&&ib.value){item=CBOR.decode(ib.value.buffer||ib.value);}
          else if(ib instanceof Uint8Array||ArrayBuffer.isView(ib)){item=CBOR.decode(ib.buffer||ib);}
          if(!item||item.elementIdentifier===undefined)continue;
          let val=item.elementValue;
          const k=item.elementIdentifier;
          if((k==='resident_image'||k==='ResidentImage')){
            if(val instanceof Uint8Array||ArrayBuffer.isView(val))val='data:image/jpeg;base64,'+uint8ToB64(val.buffer||val);
            else if(typeof val==='string'&&(val.startsWith('/9j')||val.startsWith('/9J')))val='data:image/jpeg;base64,'+val;
          }
          claims[k]=val;
        }catch{}
      }
    }
    try{
      const ia=(doc.issuerSigned||doc).issuerAuth||[];
      if(Array.isArray(ia)&&ia[2]){
        const mb=ia[2];
        const mso=CBOR.decode(mb.buffer||mb);
        if(mso){issuerMeta={digestAlgorithm:mso.digestAlgorithm,signed:mso.validityInfo?.signed,validFrom:mso.validityInfo?.validFrom,validUntil:mso.validityInfo?.validUntil};}
      }
    }catch{}
  }
  return{format:'mDOC (ISO 18013-5)',formatDetail:`docType: ${docType}`,meta:{docType,...issuerMeta},claims,rawPayload:{docType,issuerMeta,claimCount:Object.keys(claims).length}};
}

/* ── Claim mapping ───────────────────────────────────── */
const CM={
  resident_name:{l:'Name',t:'identity'},ResidentName:{l:'Name',t:'identity'},
  local_resident_name:{l:'Name (Local)',t:'identity'},LocalResidentName:{l:'Name (Local)',t:'identity'},
  dob:{l:'Date of Birth',t:'identity'},Dob:{l:'Date of Birth',t:'identity'},
  gender:{l:'Gender',t:'identity'},Gender:{l:'Gender',t:'identity'},
  masked_uid:{l:'Masked UID',t:'identity',m:1},MaskedUID:{l:'Masked UID',t:'identity',m:1},
  aadhaar_type:{l:'Aadhaar Type',t:'identity'},AadhaarType:{l:'Aadhaar Type',t:'identity'},
  AadhaarExpiresOn:{l:'Aadhaar Expires',t:'identity'},
  age_above_18:{l:'Age ≥ 18',t:'identity',b:1},AgeAbove18:{l:'Age ≥ 18',t:'identity',b:1},
  age_above_50:{l:'Age ≥ 50',t:'identity',b:1},AgeAbove50:{l:'Age ≥ 50',t:'identity',b:1},
  age_above_60:{l:'Age ≥ 60',t:'identity',b:1},AgeAbove60:{l:'Age ≥ 60',t:'identity',b:1},
  age_above_75:{l:'Age ≥ 75',t:'identity',b:1},AgeAbove75:{l:'Age ≥ 75',t:'identity',b:1},
  is_nri:{l:'Is NRI',t:'identity',b:1},IsNRI:{l:'Is NRI',t:'identity',b:1},
  is_resident_foreigner:{l:'Resident Foreigner',t:'identity',b:1},IsResidentForeigner:{l:'
