document.addEventListener('DOMContentLoaded', () => {
    const generateBtn = document.getElementById('generate-btn');
    const algSelect = document.getElementById('algorithm-select');
    const resultsSection = document.getElementById('results-section');
    const privateKeyCard = document.getElementById('private-key-card');
    const publicKeyCard = document.getElementById('publicKeyCard'); // Fix casing below
    const pubCard = document.getElementById('public-key-card');
    const privateKeyDisplay = document.getElementById('private-key-display');
    const publicKeyDisplay = document.getElementById('public-key-display');
    const downloadPrivateBtn = document.getElementById('download-private-btn');
    const downloadPublicBtn = document.getElementById('download-public-btn');
    const errorMsg = document.getElementById('error-message');
    const privateTag = document.getElementById('private-tag');

    // State
    let currentKeys = { private: null, public: null, isSymmetric: false, alg: '' };

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
        resultsSection.classList.add('hidden');
        console.error(msg);
    }

    function hideError() {
        errorMsg.classList.add('hidden');
        errorMsg.textContent = '';
    }

    function downloadFile(content, filename) {
        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
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

    async function generateKeys() {
        hideError();
        generateBtn.classList.add('loading');
        
        try {
            const alg = algSelect.value;
            let keyPair, secretKey;
            let pubPem = null, privPem = null;
            let isSymmetric = false;

            // Algorithm config mapping
            if (alg.startsWith('HS')) {
                // HMAC
                isSymmetric = true;
                const hashMap = { 'HS256': 'SHA-256', 'HS384': 'SHA-384', 'HS512': 'SHA-512' };
                secretKey = await window.crypto.subtle.generateKey(
                    { name: 'HMAC', hash: { name: hashMap[alg] } },
                    true,
                    ['sign', 'verify']
                );
                
                const rawBuffer = await window.crypto.subtle.exportKey('raw', secretKey);
                privPem = arrayBufferToBase64(rawBuffer); // For symmetric, just output base64
                
            } else if (alg.startsWith('RS') || alg.startsWith('PS')) {
                // RSA variants
                const isPSS = alg.startsWith('PS');
                const hashMap = {
                    'RS256': 'SHA-256', 'RS384': 'SHA-384', 'RS512': 'SHA-512',
                    'PS256': 'SHA-256', 'PS384': 'SHA-384', 'PS512': 'SHA-512'
                };
                
                keyPair = await window.crypto.subtle.generateKey(
                    {
                        name: isPSS ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5',
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]), // 65537
                        hash: hashMap[alg]
                    },
                    true,
                    ['sign', 'verify']
                );
            } else if (alg.startsWith('ES')) {
                // ECDSA
                const curveMap = { 'ES256': 'P-256', 'ES384': 'P-384', 'ES512': 'P-521' };
                keyPair = await window.crypto.subtle.generateKey(
                    { name: 'ECDSA', namedCurve: curveMap[alg] },
                    true,
                    ['sign', 'verify']
                );
            } else if (alg === 'EdDSA') {
                // Ed25519
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

            // Export Async Pairs
            if (!isSymmetric && keyPair) {
                const privBuffer = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
                const pubBuffer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
                
                privPem = formatPEM(arrayBufferToBase64(privBuffer), 'PRIVATE KEY');
                pubPem = formatPEM(arrayBufferToBase64(pubBuffer), 'PUBLIC KEY');
            }

            // Update UI
            currentKeys = { private: privPem, public: pubPem, isSymmetric, alg };
            
            resultsSection.classList.remove('hidden');
            
            if (isSymmetric) {
                pubCard.classList.add('hidden');
                privateKeyCard.querySelector('h2').innerHTML = `Secret Key <span class="tag">Base64</span>`;
                privateKeyDisplay.value = privPem;
            } else {
                pubCard.classList.remove('hidden');
                privateKeyCard.querySelector('h2').innerHTML = `Private Key <span class="tag">PEM</span>`;
                privateKeyDisplay.value = privPem;
                publicKeyDisplay.value = pubPem;
            }

        } catch (error) {
            showError(`Failed to generate keys: ${error.message}`);
        } finally {
            generateBtn.classList.remove('loading');
        }
    }

    generateBtn.addEventListener('click', generateKeys);

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
});
