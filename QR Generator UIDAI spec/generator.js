import QRCode from 'https://cdn.jsdelivr.net/npm/qrcode@1.5.4/+esm';

const claimsMap = [
    "credentialIssuingDate", "enrolmentDate", "enrolmentNumber", "isNRI", "residentImage",
    "residentName", "localResidentName", "ageAbove18", "ageAbove50", "ageAbove60",
    "ageAbove75", "dob", "gender", "careOf", "localCareOf", "building", "localBuilding",
    "locality", "localLocality", "street", "localStreet", "landmark", "localLandmark",
    "vtc", "localVtc", "subDistrict", "localSubDistrict", "district", "localDistrict",
    "state", "localState", "poName", "localPoName", "pincode", "address",
    "regionalAddress", "mobile", "maskedMobile", "email", "maskedEmail"
];

document.addEventListener('DOMContentLoaded', () => {
    const claimsGrid = document.getElementById('claims-grid');
    claimsMap.forEach((claim, idx) => {
        const label = document.createElement('label');
        label.className = 'claim-cb';
        label.innerHTML = `<input type="checkbox" id="chk-${idx}" checked> ${claim}`;
        claimsGrid.appendChild(label);
    });

    const btnWeb = document.getElementById('btn-generate-web');
    const btnQr = document.getElementById('btn-generate-qr');
    const errorMsg = document.getElementById('error-message');
    const resultsSection = document.getElementById('results-section');
    const resultText = document.getElementById('result-text');
    const qrContainer = document.getElementById('qr-container');
    const resultType = document.getElementById('result-type');
    
    // Polling UI
    const pollingSection = document.getElementById('polling-section');
    const callbackResult = document.getElementById('callback-result');
    const btnViewCred = document.getElementById('btn-view-credential');
    let pollingInterval = null;
    let receivedCredential = null;

    function showError(msg) {
        errorMsg.textContent = msg;
        errorMsg.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        pollingSection.classList.add('hidden');
    }

    function hideError() {
        errorMsg.classList.add('hidden');
    }

    function b64url(str) {
        return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }

    function ab2b64url(ab) {
        const bytes = new Uint8Array(ab);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return b64url(binary);
    }

    function pemToArrayBuffer(pem) {
        const lines = pem.split(/\r?\n/);
        let b64 = '';
        for (let line of lines) {
            line = line.trim();
            if (line && !line.startsWith('-')) {
                b64 += line;
            }
        }
        b64 = b64.replace(/[^A-Za-z0-9+/=]/g, '');
        while (b64.length % 4 !== 0) b64 += '=';
        
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    function generateUUID() {
        if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
        return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
            (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
        );
    }

    async function signJWT(header, payload, pemKey) {
        if (pemKey.includes('ENCRYPTED')) {
            throw new Error("Encrypted Private Keys are not supported by the browser. Please decrypt it first or use an unencrypted PKCS#8 Private Key.");
        }
        const headerStr = b64url(JSON.stringify(header));
        const payloadStr = b64url(JSON.stringify(payload));
        const dataToSign = `${headerStr}.${payloadStr}`;
        
        const keyBuffer = pemToArrayBuffer(pemKey);
        try {
            const cryptoKey = await window.crypto.subtle.importKey(
                'pkcs8',
                keyBuffer,
                { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
                false,
                ['sign']
            );

            const signatureBuffer = await window.crypto.subtle.sign(
                'RSASSA-PKCS1-v1_5',
                cryptoKey,
                new TextEncoder().encode(dataToSign)
            );

            return `${dataToSign}.${ab2b64url(signatureBuffer)}`;
        } catch (err) {
            throw new Error("Failed to parse Private Key. Ensure it is a valid, unencrypted PKCS#8 format.");
        }
    }

    function getScString() {
        let bin = '';
        for(let i=0; i<64; i++) {
            if(i < 40) {
                const el = document.getElementById(`chk-${i}`);
                bin += el.checked ? '1' : '0';
            } else {
                bin += '0';
            }
        }
        return bin;
    }

    async function generatePayload(mode) {
        const ac = document.getElementById('ac-input').value;
        const sa = document.getElementById('sa-input').value;
        const cb = document.getElementById('cb-input').value;
        const pem = document.getElementById('private-key-input').value.trim();

        if(!pem) throw new Error("Private Key is required.");
        if(!cb) throw new Error("Callback URL is required.");

        const aud = new URL(cb).origin;
        const iat = Math.floor(Date.now() / 1000);

        return {
            txn: generateUUID(),
            i: "credential",
            lang: "23",
            sc: getScString(),
            pop: 1,
            ch: mode === 'web' ? 'web' : 'qr',
            m: "1",
            ac, sa, cb, aud,
            iss: "https://uidai.gov.in",
            exp: iat + 300,
            iat,
            ht: "TEST USER",
            jti: generateUUID()
        };
    }

    async function compressToQR(jwt) {
        const data = new Uint8Array(jwt.length + 1);
        for(let i=0; i<jwt.length; i++) data[i] = jwt.charCodeAt(i);
        data[jwt.length] = 255; // Delimiter

        const cs = new CompressionStream('gzip');
        const writer = cs.writable.getWriter();
        writer.write(data);
        writer.close();

        const res = new Response(cs.readable);
        const compressed = new Uint8Array(await res.arrayBuffer());

        let hex = '0x';
        for (let i = 0; i < compressed.length; i++) hex += compressed[i].toString(16).padStart(2, '0');
        return 'https://maadhaar.com/getIntent?value=' + BigInt(hex).toString(10);
    }

    function renderQR(text) {
        const canvas = document.getElementById('qr-canvas');
        QRCode.toCanvas(canvas, text, { margin: 2, scale: 3 }, function (error) {
            if (error) {
                console.error(error);
                showError(`Failed to render QR Code: ${error.message || 'Payload might be too large.'}`);
            }
        });
    }

    function startPolling() {
        if(pollingInterval) clearInterval(pollingInterval);
        pollingSection.classList.remove('hidden');
        callbackResult.classList.add('hidden');
        
        // Clear previous on server
        fetch('/api/callback/clear', {method: 'POST'}).catch(()=>{});

        pollingInterval = setInterval(async () => {
            try {
                const res = await fetch('/api/callback/latest');
                if (res.status === 200) {
                    const json = await res.json();
                    if(json && json.data) {
                        clearInterval(pollingInterval);
                        pollingInterval = null;
                        
                        // Parse XML for <Credential> tag
                        const match = json.data.match(/<Credential>(.*?)<\/Credential>/s);
                        if(match && match[1]) {
                            receivedCredential = match[1].trim();
                            callbackResult.classList.remove('hidden');
                            document.querySelector('.polling-header').classList.add('hidden');
                        }
                    }
                }
            } catch(e) {}
        }, 3000);
    }

    btnViewCred.addEventListener('click', () => {
        if(receivedCredential) {
            localStorage.setItem('pending-credential', receivedCredential);
            window.location.href = '/';
        }
    });

    async function handleGenerate(mode) {
        hideError();
        try {
            const payload = await generatePayload(mode);
            const header = { alg: "RS256", typ: "JWT" };
            const pem = document.getElementById('private-key-input').value.trim();
            const jwt = await signJWT(header, payload, pem);

            resultsSection.classList.remove('hidden');
            resultType.textContent = mode === 'web' ? 'Web-to-App URL' : 'Cross-Device QR URL';

            if (mode === 'web') {
                const intentStr = `intent:#Intent;action=in.gov.uidai.pehchaan.WEB_INTENT_REQUEST;S.request=${jwt};end`;
                resultText.value = intentStr;
                qrContainer.classList.add('hidden');
            } else {
                const qrUrl = await compressToQR(jwt);
                resultText.value = qrUrl;
                qrContainer.classList.remove('hidden');
                renderQR(qrUrl);
            }

            if (document.getElementById('cb-input').value.includes('/api/callback')) {
                startPolling();
            }

        } catch (e) {
            showError(e.message);
        }
    }

    btnWeb.addEventListener('click', () => handleGenerate('web'));
    btnQr.addEventListener('click', () => handleGenerate('qr'));
    
    // Auto-fill Test Key Convenience Function
    document.getElementById('btn-fill-test-key')?.addEventListener('click', async () => {
        try {
            const btn = document.getElementById('btn-fill-test-key');
            btn.textContent = 'Generating...';
            const keyPair = await window.crypto.subtle.generateKey(
                { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
                true, ['sign', 'verify']
            );
            const privBuffer = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
            
            // Encode to Base64
            let binary = '';
            const bytes = new Uint8Array(privBuffer);
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            const b64 = window.btoa(binary);
            
            // Format to PEM
            const lines = b64.match(/.{1,64}/g).join('\n');
            const pem = `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----`;
            
            document.getElementById('private-key-input').value = pem;
            btn.textContent = 'Test Key Generated ✓';
            setTimeout(() => btn.textContent = 'Autofill Test Key', 3000);
        } catch(e) {
            console.error('Failed to generate test key:', e);
            document.getElementById('btn-fill-test-key').textContent = 'Failed!';
        }
    });

});
