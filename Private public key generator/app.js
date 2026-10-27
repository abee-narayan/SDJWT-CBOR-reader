document.addEventListener('DOMContentLoaded', () => {
    const generateBtn = document.getElementById('generate-btn');
    const algSelect = document.getElementById('algorithm-select');
    const resultsSection = document.getElementById('results-section');
    const keysGrid = document.getElementById('keys-grid');
    const privateKeyCard = document.getElementById('private-key-card');
    const pubCard = document.getElementById('public-key-card');
    const csrSectionCard = document.getElementById('csr-section-card');
    const privateKeyDisplay = document.getElementById('private-key-display');
    const publicKeyDisplay = document.getElementById('public-key-display');
    const downloadPrivateBtn = document.getElementById('download-private-btn');
    const downloadPublicBtn = document.getElementById('download-public-btn');
    const copyPrivateBtn = document.getElementById('copy-private-btn');
    const copyPublicBtn = document.getElementById('copy-public-btn');
    const errorMsg = document.getElementById('error-message');

    // CSR Elements
    const generateCsrBtn = document.getElementById('generate-csr-btn');
    const csrOutputContainer = document.getElementById('csr-output-container');
    const csrDisplay = document.getElementById('csr-display');
    const csrSubjectPreview = document.getElementById('csr-subject-preview');
    const downloadCsrBtn = document.getElementById('download-csr-btn');
    const copyCsrBtn = document.getElementById('copy-csr-btn');

    const csrCn = document.getElementById('csr-cn');
    const csrO = document.getElementById('csr-o');
    const csrOu = document.getElementById('csr-ou');
    const csrC = document.getElementById('csr-c');
    const csrSt = document.getElementById('csr-st');
    const csrL = document.getElementById('csr-l');
    const csrEmail = document.getElementById('csr-email');
    const csrSan = document.getElementById('csr-san');

    // State
    let currentKeys = {
        private: null,
        public: null,
        csr: null,
        isSymmetric: false,
        alg: '',
        keyPair: null,
        spkiBuffer: null,
        pkcs8Buffer: null
    };

    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    function formatPEM(base64, type) {
        const lines = base64.match(/.{1,64}/g).join('\n');
        return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
    }

    function showError(msg) {
        errorMsg.textContent = msg;
        errorMsg.classList.remove('hidden');
        console.error(msg);
    }

    function hideError() {
        errorMsg.classList.add('hidden');
        errorMsg.textContent = '';
    }

    function downloadFile(content, filename) {
        const blob = new Blob([content], { type: 'application/x-pem-file;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function copyWithFeedback(btn, text) {
        if (!text) return;
        navigator.clipboard.writeText(text);
        const origHtml = btn.innerHTML;
        btn.textContent = '✓ Copied';
        setTimeout(() => {
            btn.innerHTML = origHtml;
        }, 1600);
    }

    // ─── ASN.1 DER Helpers for PKCS#10 CSR Generation ────────────────────────

    function encodeLength(len) {
        if (len < 0x80) return new Uint8Array([len]);
        const bytes = [];
        let temp = len;
        while (temp > 0) {
            bytes.unshift(temp & 0xff);
            temp >>= 8;
        }
        return new Uint8Array([0x80 | bytes.length, ...bytes]);
    }

    function concatBytes(...arrays) {
        const total = arrays.reduce((acc, a) => acc + a.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const a of arrays) {
            out.set(a, offset);
            offset += a.length;
        }
        return out;
    }

    function asn1Tag(tagByte, contentBytes) {
        return concatBytes(new Uint8Array([tagByte]), encodeLength(contentBytes.length), contentBytes);
    }

    function asn1Sequence(...items) {
        return asn1Tag(0x30, concatBytes(...items));
    }

    function asn1Set(...items) {
        return asn1Tag(0x31, concatBytes(...items));
    }

    function asn1Oid(oidBytes) {
        return asn1Tag(0x06, new Uint8Array(oidBytes));
    }

    function asn1Null() {
        return new Uint8Array([0x05, 0x00]);
    }

    function asn1Utf8String(str) {
        const encoded = new TextEncoder().encode(str);
        return asn1Tag(0x0c, encoded);
    }

    function asn1PrintableString(str) {
        const encoded = new TextEncoder().encode(str);
        return asn1Tag(0x13, encoded);
    }

    function asn1Ia5String(str) {
        const encoded = new TextEncoder().encode(str);
        return asn1Tag(0x16, encoded);
    }

    function asn1BitString(rawBytes) {
        // Prepend 0x00 for 0 unused bits in final byte
        const payload = concatBytes(new Uint8Array([0x00]), rawBytes);
        return asn1Tag(0x03, payload);
    }

    function asn1OctetString(rawBytes) {
        return asn1Tag(0x04, rawBytes);
    }

    function asn1PositiveInteger(rawBytes) {
        let start = 0;
        while (start < rawBytes.length - 1 && rawBytes[start] === 0) {
            start++;
        }
        const trimmed = rawBytes.subarray(start);
        if (trimmed[0] & 0x80) {
            return asn1Tag(0x02, concatBytes(new Uint8Array([0x00]), trimmed));
        }
        return asn1Tag(0x02, trimmed);
    }

    // Convert WebCrypto ECDSA raw (r || s) signature into ASN.1 DER SEQUENCE { r INTEGER, s INTEGER }
    function ecdsaRawToDer(rawSigBuffer) {
        const bytes = new Uint8Array(rawSigBuffer);
        const half = bytes.length / 2;
        const r = bytes.subarray(0, half);
        const s = bytes.subarray(half);
        return asn1Sequence(asn1PositiveInteger(r), asn1PositiveInteger(s));
    }

    function buildRdn(oidBytes, valueStr, stringType = 'utf8') {
        let valDer;
        if (stringType === 'printable') valDer = asn1PrintableString(valueStr);
        else if (stringType === 'ia5') valDer = asn1Ia5String(valueStr);
        else valDer = asn1Utf8String(valueStr);

        return asn1Set(asn1Sequence(asn1Oid(oidBytes), valDer));
    }

    function buildSubjectName(fields) {
        const rdns = [];
        // OIDs:
        // C:  2.5.4.6  -> [0x55, 0x04, 0x06]
        // ST: 2.5.4.8  -> [0x55, 0x04, 0x08]
        // L:  2.5.4.7  -> [0x55, 0x04, 0x07]
        // O:  2.5.4.10 -> [0x55, 0x04, 0x0a]
        // OU: 2.5.4.11 -> [0x55, 0x04, 0x0b]
        // CN: 2.5.4.3  -> [0x55, 0x04, 0x03]
        // emailAddress: 1.2.840.113549.1.9.1 -> [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01]

        if (fields.c) {
            const cleanC = fields.c.trim().toUpperCase().slice(0, 2);
            if (/^[A-Z]{2}$/.test(cleanC)) {
                rdns.push(buildRdn([0x55, 0x04, 0x06], cleanC, 'printable'));
            }
        }
        if (fields.st) rdns.push(buildRdn([0x55, 0x04, 0x08], fields.st));
        if (fields.l) rdns.push(buildRdn([0x55, 0x04, 0x07], fields.l));
        if (fields.o) rdns.push(buildRdn([0x55, 0x04, 0x0a], fields.o));
        if (fields.ou) rdns.push(buildRdn([0x55, 0x04, 0x0b], fields.ou));
        if (fields.cn) rdns.push(buildRdn([0x55, 0x04, 0x03], fields.cn));
        if (fields.email) rdns.push(buildRdn([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01], fields.email, 'ia5'));

        return asn1Sequence(...rdns);
    }

    function buildAttributes(sans) {
        const cleanSans = (sans || [])
            .map(s => s.trim())
            .filter(Boolean);

        if (cleanSans.length === 0) {
            // [0] IMPLICIT empty set of attributes
            return new Uint8Array([0xa0, 0x00]);
        }

        // GeneralNames ::= SEQUENCE OF GeneralName
        // dNSName [2] IMPLICIT IA5String (tag 0x82)
        const generalNames = cleanSans.map(domain => {
            const bytes = new TextEncoder().encode(domain);
            return asn1Tag(0x82, bytes);
        });
        const sanValueDer = asn1Sequence(...generalNames);

        // Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER (2.5.29.17), extnValue OCTET STRING }
        const subjectAltNameExt = asn1Sequence(
            asn1Oid([0x55, 0x1d, 0x11]), // 2.5.29.17 (subjectAltName)
            asn1OctetString(sanValueDer)
        );

        const extensionsSeq = asn1Sequence(subjectAltNameExt);

        // extensionRequest Attribute (1.2.840.113549.1.9.14)
        const extReqAttr = asn1Sequence(
            asn1Oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e]),
            asn1Set(extensionsSeq)
        );

        return asn1Tag(0xa0, extReqAttr);
    }

    function getSignatureAlgorithmIdentifierDer(alg) {
        // RSA PKCS#1 v1.5 and RSA-PSS (signed using PKCS#1 v1.5 for maximum X.509 CA compatibility)
        const rsaOids = {
            'RS256': [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b], // sha256WithRSAEncryption
            'RS384': [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c], // sha384WithRSAEncryption
            'RS512': [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d], // sha512WithRSAEncryption
            'PS256': [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
            'PS384': [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c],
            'PS512': [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d]
        };
        if (rsaOids[alg]) {
            return asn1Sequence(asn1Oid(rsaOids[alg]), asn1Null());
        }

        // ECDSA with SHA-256 / 384 / 512 (RFC 5758: parameters MUST be omitted)
        const ecdsaOids = {
            'ES256': [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02], // ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
            'ES384': [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03], // ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
            'ES512': [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]  // ecdsa-with-SHA512 (1.2.840.10045.4.3.4)
        };
        if (ecdsaOids[alg]) {
            return asn1Sequence(asn1Oid(ecdsaOids[alg]));
        }

        // Ed25519 (1.3.101.112)
        if (alg === 'EdDSA') {
            return asn1Sequence(asn1Oid([0x2b, 0x65, 0x70]));
        }

        throw new Error(`Unsupported CSR signature algorithm: ${alg}`);
    }

    async function generateCSR() {
        hideError();
        if (currentKeys.isSymmetric || !currentKeys.keyPair || !currentKeys.spkiBuffer) {
            showError('Please generate an asymmetric key pair (RSA, ECDSA, or EdDSA) first to create a CSR.');
            return;
        }

        const fields = {
            cn: (csrCn.value || '').trim() || 'vcreader.com',
            o: (csrO.value || '').trim(),
            ou: (csrOu.value || '').trim(),
            c: (csrC.value || '').trim().toUpperCase(),
            st: (csrSt.value || '').trim(),
            l: (csrL.value || '').trim(),
            email: (csrEmail.value || '').trim()
        };
        const sans = (csrSan.value || '').split(',').map(s => s.trim()).filter(Boolean);

        try {
            // 1. Build CertificationRequestInfo ::= SEQUENCE { version INTEGER(0), subject Name, subjectPKInfo, attributes [0] }
            const versionDer = new Uint8Array([0x02, 0x01, 0x00]); // INTEGER 0 (v1)
            const subjectDer = buildSubjectName(fields);
            const spkiDer = new Uint8Array(currentKeys.spkiBuffer);
            const attributesDer = buildAttributes(sans);

            const certReqInfoDer = asn1Sequence(versionDer, subjectDer, spkiDer, attributesDer);

            // 2. Sign CertificationRequestInfo with the private key
            const alg = currentKeys.alg;
            let rawSignature;
            let sigBytesDer;

            if (alg.startsWith('RS') || alg.startsWith('PS')) {
                const hashMap = {
                    'RS256': 'SHA-256', 'RS384': 'SHA-384', 'RS512': 'SHA-512',
                    'PS256': 'SHA-256', 'PS384': 'SHA-384', 'PS512': 'SHA-512'
                };
                let signingKey = currentKeys.keyPair.privateKey;
                // If generated as RSA-PSS, import PKCS#8 for RSASSA-PKCS1-v1_5 so standard CAs & OpenSSL verify out of the box
                if (alg.startsWith('PS') && currentKeys.pkcs8Buffer) {
                    signingKey = await window.crypto.subtle.importKey(
                        'pkcs8',
                        currentKeys.pkcs8Buffer,
                        { name: 'RSASSA-PKCS1-v1_5', hash: hashMap[alg] },
                        false,
                        ['sign']
                    );
                }
                rawSignature = await window.crypto.subtle.sign(
                    { name: 'RSASSA-PKCS1-v1_5' },
                    signingKey,
                    certReqInfoDer
                );
                sigBytesDer = new Uint8Array(rawSignature);
            } else if (alg.startsWith('ES')) {
                const hashMap = { 'ES256': 'SHA-256', 'ES384': 'SHA-384', 'ES512': 'SHA-512' };
                rawSignature = await window.crypto.subtle.sign(
                    { name: 'ECDSA', hash: { name: hashMap[alg] } },
                    currentKeys.keyPair.privateKey,
                    certReqInfoDer
                );
                sigBytesDer = ecdsaRawToDer(rawSignature);
            } else if (alg === 'EdDSA') {
                rawSignature = await window.crypto.subtle.sign(
                    { name: 'Ed25519' },
                    currentKeys.keyPair.privateKey,
                    certReqInfoDer
                );
                sigBytesDer = new Uint8Array(rawSignature);
            }

            // 3. Assemble CertificationRequest ::= SEQUENCE { certificationRequestInfo, signatureAlgorithm, signature BIT STRING }
            const sigAlgDer = getSignatureAlgorithmIdentifierDer(alg);
            const sigBitStringDer = asn1BitString(sigBytesDer);
            const csrDer = asn1Sequence(certReqInfoDer, sigAlgDer, sigBitStringDer);

            const csrPem = formatPEM(arrayBufferToBase64(csrDer.buffer), 'CERTIFICATE REQUEST');
            currentKeys.csr = csrPem;

            // Build human-readable Subject summary
            const dnParts = [];
            if (fields.c) dnParts.push(`C=${fields.c}`);
            if (fields.st) dnParts.push(`ST=${fields.st}`);
            if (fields.l) dnParts.push(`L=${fields.l}`);
            if (fields.o) dnParts.push(`O=${fields.o}`);
            if (fields.ou) dnParts.push(`OU=${fields.ou}`);
            if (fields.cn) dnParts.push(`CN=${fields.cn}`);
            if (fields.email) dnParts.push(`emailAddress=${fields.email}`);

            csrSubjectPreview.textContent = `Subject: /${dnParts.join('/')} · Signed with ${alg}`;
            csrDisplay.value = csrPem;
            csrOutputContainer.classList.remove('hidden');
        } catch (err) {
            showError(`Failed to generate CSR: ${err.message}`);
        }
    }

    async function generateKeys() {
        hideError();
        generateBtn.classList.add('loading');

        try {
            const alg = algSelect.value;
            let keyPair = null, secretKey = null;
            let pubPem = null, privPem = null;
            let spkiBuffer = null, pkcs8Buffer = null;
            let isSymmetric = false;

            if (alg.startsWith('HS')) {
                isSymmetric = true;
                const hashMap = { 'HS256': 'SHA-256', 'HS384': 'SHA-384', 'HS512': 'SHA-512' };
                secretKey = await window.crypto.subtle.generateKey(
                    { name: 'HMAC', hash: { name: hashMap[alg] } },
                    true,
                    ['sign', 'verify']
                );
                const rawBuffer = await window.crypto.subtle.exportKey('raw', secretKey);
                privPem = arrayBufferToBase64(rawBuffer);
            } else if (alg.startsWith('RS') || alg.startsWith('PS')) {
                const isPSS = alg.startsWith('PS');
                const hashMap = {
                    'RS256': 'SHA-256', 'RS384': 'SHA-384', 'RS512': 'SHA-512',
                    'PS256': 'SHA-256', 'PS384': 'SHA-384', 'PS512': 'SHA-512'
                };
                keyPair = await window.crypto.subtle.generateKey(
                    {
                        name: isPSS ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5',
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: hashMap[alg]
                    },
                    true,
                    ['sign', 'verify']
                );
            } else if (alg.startsWith('ES')) {
                const curveMap = { 'ES256': 'P-256', 'ES384': 'P-384', 'ES512': 'P-521' };
                keyPair = await window.crypto.subtle.generateKey(
                    { name: 'ECDSA', namedCurve: curveMap[alg] },
                    true,
                    ['sign', 'verify']
                );
            } else if (alg === 'EdDSA') {
                try {
                    keyPair = await window.crypto.subtle.generateKey(
                        { name: 'Ed25519' },
                        true,
                        ['sign', 'verify']
                    );
                } catch (err) {
                    throw new Error('Your browser does not support Ed25519 keys via WebCrypto API yet. Try Chrome 113+ or Safari 17+.');
                }
            }

            if (!isSymmetric && keyPair) {
                pkcs8Buffer = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
                spkiBuffer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);

                privPem = formatPEM(arrayBufferToBase64(pkcs8Buffer), 'PRIVATE KEY');
                pubPem = formatPEM(arrayBufferToBase64(spkiBuffer), 'PUBLIC KEY');
            }

            currentKeys = {
                private: privPem,
                public: pubPem,
                csr: null,
                isSymmetric,
                alg,
                keyPair,
                spkiBuffer,
                pkcs8Buffer
            };

            resultsSection.classList.remove('hidden');

            if (isSymmetric) {
                keysGrid.classList.add('single-col');
                pubCard.classList.add('hidden');
                csrSectionCard.classList.add('hidden');
                privateKeyCard.querySelector('h2').innerHTML = `Secret Key <span class="tag">Base64</span>`;
                privateKeyDisplay.value = privPem;
            } else {
                keysGrid.classList.remove('single-col');
                pubCard.classList.remove('hidden');
                csrSectionCard.classList.remove('hidden');
                privateKeyCard.querySelector('h2').innerHTML = `Private Key <span class="tag">PEM</span>`;
                privateKeyDisplay.value = privPem;
                publicKeyDisplay.value = pubPem;

                // Automatically generate the CSR for the newly generated key pair
                await generateCSR();
            }
        } catch (error) {
            showError(`Failed to generate keys: ${error.message}`);
        } finally {
            generateBtn.classList.remove('loading');
        }
    }

    generateBtn.addEventListener('click', generateKeys);
    generateCsrBtn.addEventListener('click', generateCSR);

    downloadPrivateBtn.addEventListener('click', () => {
        if (!currentKeys.private) return;
        const ext = currentKeys.isSymmetric ? 'txt' : 'pem';
        const prefix = currentKeys.isSymmetric ? 'secret' : 'private';
        downloadFile(currentKeys.private, `${currentKeys.alg}_${prefix}_key.${ext}`);
    });

    downloadPublicBtn.addEventListener('click', () => {
        if (!currentKeys.public) return;
        downloadFile(currentKeys.public, `${currentKeys.alg}_public_key.pem`);
    });

    downloadCsrBtn.addEventListener('click', () => {
        if (!currentKeys.csr) return;
        const safeCn = ((csrCn.value || 'certificate').trim().replace(/[^a-zA-Z0-9._-]/g, '_')) || 'request';
        downloadFile(currentKeys.csr, `${safeCn}_${currentKeys.alg}.csr`);
    });

    copyPrivateBtn?.addEventListener('click', () => copyWithFeedback(copyPrivateBtn, currentKeys.private));
    copyPublicBtn?.addEventListener('click', () => copyWithFeedback(copyPublicBtn, currentKeys.public));
    copyCsrBtn?.addEventListener('click', () => copyWithFeedback(copyCsrBtn, currentKeys.csr));
});
