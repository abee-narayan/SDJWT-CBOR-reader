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
    // ------------------------------------
    // Tab Switching
    // ------------------------------------
    const tabDirectJwt = document.getElementById('tabDirectJwt');
    const tabBuilder = document.getElementById('tabBuilder');
    const sectionDirectJwt = document.getElementById('section-direct-jwt');
    const sectionBuilder = document.getElementById('section-builder');

    function switchMode(mode) {
        if (mode === 'direct-jwt') {
            tabDirectJwt.classList.add('active');
            tabBuilder.classList.remove('active');
            sectionDirectJwt.classList.remove('hidden');
            sectionBuilder.classList.add('hidden');
        } else {
            tabBuilder.classList.add('active');
            tabDirectJwt.classList.remove('active');
            sectionBuilder.classList.remove('hidden');
            sectionDirectJwt.classList.add('hidden');
        }
    }

    tabDirectJwt.addEventListener('click', () => switchMode('direct-jwt'));
    tabBuilder.addEventListener('click', () => switchMode('builder'));

    // ------------------------------------
    // Builder: Populate Claims Checkboxes
    // ------------------------------------
    const claimsGrid = document.getElementById('claims-grid');
    claimsMap.forEach((claim, idx) => {
        const label = document.createElement('label');
        label.className = 'claim-cb';
        label.innerHTML = `<input type="checkbox" id="chk-${idx}" checked> ${claim}`;
        claimsGrid.appendChild(label);
    });

    // ------------------------------------
    // Common Elements
    // ------------------------------------
    const errorMsg = document.getElementById('error-message');
    const resultsSection = document.getElementById('results-section');
    const resultType = document.getElementById('result-type');
    const qrContainer = document.getElementById('qr-container');
    const qrCanvas = document.getElementById('qr-canvas');
    const resultText = document.getElementById('result-text');
    const urlLabel = document.getElementById('url-label');
    const btnCopyResult = document.getElementById('btn-copy-result');
    const btnDownloadQr = document.getElementById('btn-download-qr');

    // Direct JWT elements
    const jwtDirectInput = document.getElementById('jwt-direct-input');
    const btnGenerateFromJwt = document.getElementById('btn-generate-from-jwt');
    const btnGenerateWebDirect = document.getElementById('btn-generate-web-direct');
    const btnSampleJwt = document.getElementById('btn-sample-jwt');
    const btnClearJwt = document.getElementById('btn-clear-jwt');
    const jwtInspectCard = document.getElementById('jwt-inspect-card');
    const inspectHeader = document.getElementById('inspect-header');
    const inspectTxn = document.getElementById('inspect-txn');
    const inspectClient = document.getElementById('inspect-client');
    const inspectCb = document.getElementById('inspect-cb');
    const inspectValidity = document.getElementById('inspect-validity');
    const inspectClaimsList = document.getElementById('inspect-claims-list');

    // Builder elements
    const btnGenerateQrBuilder = document.getElementById('btn-generate-qr-builder');
    const btnGenerateWebBuilder = document.getElementById('btn-generate-web-builder');
    const btnFillTestKey = document.getElementById('btn-fill-test-key');

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

    // ------------------------------------
    // Encoding & Compression Helpers
    // ------------------------------------
    function b64url(str) {
        return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }

    function ab2b64url(ab) {
        const bytes = new Uint8Array(ab);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return b64url(binary);
    }

    function base64UrlDecode(str) {
        let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4 !== 0) b64 += '=';
        return decodeURIComponent(escape(atob(b64)));
    }

    function pemToArrayBuffer(pem) {
        const lines = pem.split(/\r?\n/);
        let b64 = '';
        for (let line of lines) {
            line = line.trim();
            if (line && !line.startsWith('-')) b64 += line;
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

    // Official UIDAI compression: ISO-8859-1 + byte 255 + GZIP + BigInt Base-10
    async function compressToQR(jwt) {
        const data = new Uint8Array(jwt.length + 1);
        for (let i = 0; i < jwt.length; i++) data[i] = jwt.charCodeAt(i);
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
        QRCode.toCanvas(qrCanvas, text, { margin: 2, scale: 3.5, width: 260 }, function (error) {
            if (error) {
                console.error(error);
                showError(`Failed to render QR Code: ${error.message || 'Payload might be too large.'}`);
            }
        });
    }

    // ------------------------------------
    // JWT Inspection
    // ------------------------------------
    function inspectJwt(jwtStr) {
        jwtInspectCard.classList.add('hidden');
        if (!jwtStr || !jwtStr.includes('.')) return null;

        const parts = jwtStr.split('.');
        if (parts.length < 2) return null;

        try {
            const header = JSON.parse(base64UrlDecode(parts[0]));
            const payload = JSON.parse(base64UrlDecode(parts[1]));

            inspectHeader.textContent = `${header.alg || 'N/A'} (typ: ${header.typ || 'JWT'})`;
            inspectTxn.textContent = payload.txn || payload.jti || 'N/A';
            inspectClient.textContent = `ac: ${payload.ac || '-'} | sa: ${payload.sa || '-'}`;
            inspectCb.textContent = payload.cb || 'N/A';

            if (payload.exp) {
                const expDate = new Date(payload.exp * 1000);
                const isExp = Date.now() > payload.exp * 1000;
                inspectValidity.innerHTML = `<span style="color: ${isExp ? 'var(--error)' : 'var(--success)'}; font-weight: 600;">${isExp ? 'Expired' : 'Active'}</span> (${expDate.toLocaleTimeString()})`;
            } else {
                inspectValidity.textContent = 'No expiry defined';
            }

            // Decode 'sc' claims
            inspectClaimsList.innerHTML = '';
            if (payload.sc && typeof payload.sc === 'string') {
                const sc = payload.sc;
                let foundAny = false;
                for (let i = 0; i < Math.min(sc.length, claimsMap.length); i++) {
                    if (sc[i] === '1') {
                        foundAny = true;
                        const tag = document.createElement('span');
                        tag.className = 'claim-tag';
                        tag.textContent = claimsMap[i];
                        inspectClaimsList.appendChild(tag);
                    }
                }
                if (!foundAny) {
                    inspectClaimsList.innerHTML = '<span style="color: var(--text-secondary); font-size: 0.75rem;">None requested (sc all zeros)</span>';
                }
            } else {
                inspectClaimsList.innerHTML = '<span style="color: var(--text-secondary); font-size: 0.75rem;">No `sc` claim present</span>';
            }

            jwtInspectCard.classList.remove('hidden');
            return { header, payload };
        } catch (e) {
            console.warn('Could not parse JWT:', e);
            return null;
        }
    }

    // Auto-inspect on typing/pasting
    jwtDirectInput.addEventListener('input', () => {
        const val = jwtDirectInput.value.trim();
        inspectJwt(val);
    });

    // ------------------------------------
    // Direct JWT: Actions
    // ------------------------------------
    btnGenerateFromJwt.addEventListener('click', async () => {
        hideError();
        const jwt = jwtDirectInput.value.trim();
        if (!jwt) {
            showError('Please paste your signed JWT first.');
            return;
        }

        try {
            const inspected = inspectJwt(jwt);
            resultsSection.classList.remove('hidden');
            resultType.textContent = 'Cross-Device QR URL';
            urlLabel.textContent = 'mAadhaar Redirect URL (Embedded in QR)';

            const qrUrl = await compressToQR(jwt);
            resultText.value = qrUrl;
            qrContainer.classList.remove('hidden');
            renderQR(qrUrl);

            if (inspected && inspected.payload && inspected.payload.cb && inspected.payload.cb.includes('/api/callback')) {
                startPolling();
            }
        } catch (e) {
            showError(`Compression failed: ${e.message}`);
        }
    });

    btnGenerateWebDirect.addEventListener('click', () => {
        hideError();
        const jwt = jwtDirectInput.value.trim();
        if (!jwt) {
            showError('Please paste your signed JWT first.');
            return;
        }

        try {
            inspectJwt(jwt);
            resultsSection.classList.remove('hidden');
            resultType.textContent = 'Web-to-App Intent URI';
            urlLabel.textContent = 'Android Web-to-App Intent URI';

            const intentStr = `intent:#Intent;action=in.gov.uidai.pehchaan.WEB_INTENT_REQUEST;S.request=${jwt};end`;
            resultText.value = intentStr;
            qrContainer.classList.add('hidden');
        } catch (e) {
            showError(`Error: ${e.message}`);
        }
    });

    btnClearJwt.addEventListener('click', () => {
        jwtDirectInput.value = '';
        jwtInspectCard.classList.add('hidden');
        resultsSection.classList.add('hidden');
        hideError();
    });

    // Load realistic test signed JWT
    btnSampleJwt.addEventListener('click', async () => {
        hideError();
        btnSampleJwt.textContent = 'Generating sample...';
        try {
            // Generate test key and sign sample payload on the fly
            const keyPair = await window.crypto.subtle.generateKey(
                { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
                true, ['sign', 'verify']
            );

            const iat = Math.floor(Date.now() / 1000);
            const sampleHeader = { alg: "RS256", typ: "JWT" };
            const samplePayload = {
                txn: generateUUID(),
                i: "credential",
                lang: "23",
                sc: "0000110000010000000000000000000000101010000000000000000000000000",
                pop: 1,
                ch: "qr",
                m: "1",
                ac: "1a2f",
                sa: "00b1",
                cb: "https://vcreader.com/api/callback",
                aud: "https://myaadhaarstage.uidai.gov.in",
                iss: "https://myaadhaarstage.uidai.gov.in/v1/esignet",
                exp: iat + 300,
                iat: iat,
                ht: "Abee Narayan",
                jti: generateUUID()
            };

            const headerStr = b64url(JSON.stringify(sampleHeader));
            const payloadStr = b64url(JSON.stringify(samplePayload));
            const dataToSign = `${headerStr}.${payloadStr}`;

            const sig = await window.crypto.subtle.sign(
                'RSASSA-PKCS1-v1_5',
                keyPair.privateKey,
                new TextEncoder().encode(dataToSign)
            );

            const jwt = `${dataToSign}.${ab2b64url(sig)}`;
            jwtDirectInput.value = jwt;
            inspectJwt(jwt);
            btnSampleJwt.textContent = 'Sample Loaded ✓';
            setTimeout(() => btnSampleJwt.textContent = 'Load Sample JWT', 2500);
        } catch (e) {
            console.error(e);
            btnSampleJwt.textContent = 'Load Sample JWT';
            showError('Could not create sample JWT: ' + e.message);
        }
    });

    // ------------------------------------
    // Builder: Sign and Generate
    // ------------------------------------
    function getScString() {
        let bin = '';
        for (let i = 0; i < 64; i++) {
            if (i < claimsMap.length) {
                const el = document.getElementById(`chk-${i}`);
                bin += (el && el.checked) ? '1' : '0';
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

        if (!pem) throw new Error("Private Key is required to sign the JWT.");
        if (!cb) throw new Error("Callback URL is required.");

        let aud = "https://myaadhaarstage.uidai.gov.in";
        try { aud = new URL(cb).origin; } catch(e) {}
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

    async function handleBuilderGenerate(mode) {
        hideError();
        try {
            const payload = await generatePayload(mode);
            const header = { alg: "RS256", typ: "JWT" };
            const pem = document.getElementById('private-key-input').value.trim();
            const jwt = await signJWT(header, payload, pem);

            // Also populate direct input
            jwtDirectInput.value = jwt;
            inspectJwt(jwt);

            resultsSection.classList.remove('hidden');
            resultType.textContent = mode === 'web' ? 'Web-to-App Intent URI' : 'Cross-Device QR URL';
            urlLabel.textContent = mode === 'web' ? 'Android Web-to-App Intent URI' : 'mAadhaar Redirect URL (Embedded in QR)';

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

    btnGenerateQrBuilder.addEventListener('click', () => handleBuilderGenerate('qr'));
    btnGenerateWebBuilder.addEventListener('click', () => handleBuilderGenerate('web'));

    btnFillTestKey.addEventListener('click', async () => {
        try {
            btnFillTestKey.textContent = 'Generating...';
            const keyPair = await window.crypto.subtle.generateKey(
                { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
                true, ['sign', 'verify']
            );
            const privBuffer = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
            
            let binary = '';
            const bytes = new Uint8Array(privBuffer);
            for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
            const b64 = window.btoa(binary);
            const lines = b64.match(/.{1,64}/g).join('\n');
            const pem = `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----`;
            
            document.getElementById('private-key-input').value = pem;
            btnFillTestKey.textContent = 'Test Key Generated ✓';
            setTimeout(() => btnFillTestKey.textContent = 'Autofill Test Key', 3000);
        } catch (e) {
            console.error('Failed to generate test key:', e);
            btnFillTestKey.textContent = 'Failed!';
        }
    });

    // ------------------------------------
    // Copy & Download Actions
    // ------------------------------------
    btnCopyResult.addEventListener('click', () => {
        if (!resultText.value) return;
        navigator.clipboard.writeText(resultText.value).then(() => {
            btnCopyResult.textContent = 'Copied! ✓';
            setTimeout(() => btnCopyResult.textContent = 'Copy', 2000);
        });
    });

    btnDownloadQr.addEventListener('click', () => {
        const link = document.createElement('a');
        link.download = 'uidai-maadhaar-qr.png';
        link.href = qrCanvas.toDataURL('image/png');
        link.click();
    });

    // ------------------------------------
    // Polling Mechanism
    // ------------------------------------
    function startPolling() {
        if (pollingInterval) clearInterval(pollingInterval);
        pollingSection.classList.remove('hidden');
        callbackResult.classList.add('hidden');
        
        fetch('/api/callback/clear', { method: 'POST' }).catch(() => {});

        pollingInterval = setInterval(async () => {
            try {
                const res = await fetch('/api/callback/latest');
                if (res.status === 200) {
                    const json = await res.json();
                    if (json && json.data) {
                        clearInterval(pollingInterval);
                        pollingInterval = null;
                        
                        const match = json.data.match(/<Credential>(.*?)<\/Credential>/s);
                        if (match && match[1]) {
                            receivedCredential = match[1].trim();
                            callbackResult.classList.remove('hidden');
                            document.querySelector('.polling-header').classList.add('hidden');
                        }
                    }
                }
            } catch (e) {}
        }, 3000);
    }

    btnViewCred.addEventListener('click', () => {
        if (receivedCredential) {
            localStorage.setItem('pending-credential', receivedCredential);
            window.location.href = '/';
        }
    });
});
