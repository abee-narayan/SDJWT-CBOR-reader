import os
p = os.path.join(os.path.dirname(__file__), 'decoder.js')
js = r"""
/* CredentialDecoder – SD-JWT VC & mDOC (ISO 18013-5 CBOR) */

// == Utilities ==
function b64urlDecode(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return atob(s);}
function b64urlDecodeJson(s){try{return JSON.parse(b64urlDecode(s));}catch(e){return null;}}
function b64ToUint8(b64){var s=b64.replace(/-/g,'+').replace(/_/g,'/'),b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a;}
function uint8ToB64(a){var u=a instanceof ArrayBuffer?new Uint8Array(a):(ArrayBuffer.isView(a)?new Uint8Array(a.buffer,a.byteOffset,a.byteLength):a);return btoa(String.fromCharCode.apply(null,u));}
function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function isEmpty(v){return v===null||v===undefined||v===''||(Array.isArray(v)&&!v.length);}
function fmtDT(v){if(!v)return null;try{var d=new Date(v);return isNaN(d)?v:d.toLocaleString('en-IN',{timeZone:'Asia/Kolkata',dateStyle:'long',timeStyle:'short'});}catch(e){return v;}}
function boolBadge(v){var s=String(v).toUpperCase();if(s==='YES'||s==='TRUE')return '<span class="badge badge-green">'+s+'</span>';if(s==='NO'||s==='FALSE')return '<span class="badge badge-red">'+s+'</span>';return escHtml(v);}

// == Auto-detect ==
function detectFormat(txt){
  var t=txt.trim();
  if(/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]/.test(t))return 'sdjwt';
  if(/^[A-Za-z0-9+\/=\r\n\s]+$/.test(t)&&t.replace(/\s/g,'').length>200)return 'mdoc';
  return 'unknown';
}

// == SD-JWT Decoder ==
function decodeSDJWT(raw){
  var parts=raw.trim().split('~');
  var jp=parts[0].split('.');
  if(jp.length<3)throw new Error('Invalid SD-JWT: expected 3 parts.');
  var header=b64urlDecodeJson(jp[0]);
  var payload=b64urlDecodeJson(jp[1]);
  if(!payload)throw new Error('Cannot decode JWT payload.');
  var claims
