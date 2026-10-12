// cer to pem converter app.js

document.addEventListener('DOMContentLoaded', () => {
    // Tab switching
    const tabCerToPem = document.getElementById('tabCerToPem');
    const tabPemToCer = document.getElementById('tabPemToCer');
    const sectionCerToPem = document.getElementById('sectionCerToPem');
    const sectionPemToCer = document.getElementById('sectionPemToCer');

    function switchTab(target) {
        if (target === 'cer2pem') {
            tabCerToPem.classList.add('active');
            tabPemToCer.classList.remove('active');
            sectionCerToPem.classList.remove('hidden');
            sectionPemToCer.classList.add('hidden');
        } else {
            tabPemToCer.classList.add('active');
            tabCerToPem.classList.remove('active');
            sectionPemToCer.classList.remove('hidden');
            sectionCerToPem.classList.add('hidden');
        }
    }

    tabCerToPem.addEventListener('click', () => switchTab('cer2pem'));
    tabPemToCer.addEventListener('click', () => switchTab('pem2cer'));

    // ==========================================
    // Helper: Format Certificate Metadata HTML
    // ==========================================
    function renderCertInfo(cert) {
        try {
            const subject = cert.subject.attributes.map(a => `${a.shortName || a.name}=${a.value}`).join(', ');
            const issuer = cert.issuer.attributes.map(a => `${a.shortName || a.name}=${a.value}`).join(', ');
            const notBefore = cert.validity.notBefore ? new Date(cert.validity.notBefore).toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'N/A';
            const notAfter = cert.validity.notAfter ? new Date(cert.validity.notAfter).toLocaleDateString(undefined, { dateStyle: 'medium' }) : 'N/A';
            const now = new Date();
            const isExpired = cert.validity.notAfter && now > cert.validity.notAfter;
            const notYetValid = cert.validity.notBefore && now < cert.validity.notBefore;
            
            let statusBadge = '<span class="cert-badge valid">Valid</span>';
            if (isExpired) statusBadge = '<span class="cert-badge expired">Expired</span>';
            else if (notYetValid) statusBadge = '<span class="cert-badge expired">Not Yet Active</span>';

            // SHA-256 fingerprint of DER
            const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
            const md = forge.md.sha256.create();
            md.update(derBytes);
            const sha256Hex = md.digest().toHex().match(/.{2}/g).join(':').toUpperCase();

            return `
                <div class="cert-card-header">
                    <span class="cert-card-title">Certificate Inspection</span>
                    ${statusBadge}
                </div>
                <div class="cert-grid">
                    <div class="cert-label">Subject:</div>
                    <div class="cert-val">${escapeHtml(subject || 'Unknown')}</div>
                    <div class="cert-label">Issuer:</div>
                    <div class="cert-val">${escapeHtml(issuer || 'Unknown')}</div>
                    <div class="cert-label">Validity:</div>
                    <div class="cert-val">${notBefore} — ${notAfter}</div>
                    <div class="cert-label">Serial Number:</div>
                    <div class="cert-val">${cert.serialNumber || 'N/A'}</div>
                    <div class="cert-label">SHA-256 Fingerprint:</div>
                    <div class="cert-val" style="font-size: 10.5px;">${sha256Hex}</div>
                </div>
            `;
        } catch (e) {
            console.warn('Could not parse cert details:', e);
            return '';
        }
    }

    function escapeHtml(str) {
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ==========================================
    // 1. CER / CRT to PEM Handling
    // ==========================================
    const uploadAreaCer = document.getElementById('uploadAreaCer');
    const fileInputCer = document.getElementById('fileInputCer');
    const errorCer = document.getElementById('errorCer');
    const resultCerArea = document.getElementById('resultCerArea');
    const pemOutput = document.getElementById('pemOutput');
    const downloadPemBtn = document.getElementById('downloadPemBtn');
    const copyPemBtn = document.getElementById('copyPemBtn');
    const cerFileNameTag = document.getElementById('cerFileNameTag');
    const certInfoCer = document.getElementById('certInfoCer');

    let currentCerFileName = 'certificate.pem';
    let currentPemResult = '';

    setupDropZone(uploadAreaCer, (file) => {
        if (file.name.toLowerCase().endsWith('.pem')) {
            switchTab('pem2cer');
            handlePemFile(file);
        } else {
            handleCerFile(file);
        }
    });

    fileInputCer.addEventListener('change', (e) => {
        if (e.target.files.length) handleCerFile(e.target.files[0]);
    });

    function handleCerFile(file) {
        errorCer.classList.add('hidden');
        resultCerArea.classList.add('hidden');
        certInfoCer.classList.add('hidden');

        const lowerName = file.name.toLowerCase();
        currentCerFileName = file.name.replace(/\.(cer|crt|der)$/i, '') + '.pem';
        cerFileNameTag.textContent = file.name;

        const reader = new FileReader();
        reader.onload = function(e) {
            const contents = e.target.result;
            try {
                // Try reading as DER binary
                convertCerToPem(contents, true);
            } catch (err) {
                // Try as plain text
                const textReader = new FileReader();
                textReader.onload = function(e2) {
                    try {
                        convertCerToPem(e2.target.result, false);
                    } catch (err2) {
                        errorCer.textContent = "Error parsing certificate. Please verify that this is a valid X.509 .cer or .crt file.";
                        errorCer.classList.remove('hidden');
                    }
                };
                textReader.readAsText(file);
            }
        };
        reader.readAsBinaryString(file);
    }

    function convertCerToPem(data, isBinary) {
        let certObj = null;
        let pem = '';

        if (isBinary) {
            try {
                const asn1 = forge.asn1.fromDer(data);
                certObj = forge.pki.certificateFromAsn1(asn1);
                pem = forge.pki.certificateToPem(certObj);
            } catch (e) {
                throw new Error("Invalid DER");
            }
        } else {
            if (data.includes('-----BEGIN CERTIFICATE-----')) {
                pem = data.trim();
                certObj = forge.pki.certificateFromPem(pem);
            } else {
                const base64Clean = data.replace(/\s+/g, '');
                const certBytes = forge.util.decode64(base64Clean);
                const asn1 = forge.asn1.fromDer(certBytes);
                certObj = forge.pki.certificateFromAsn1(asn1);
                pem = forge.pki.certificateToPem(certObj);
            }
        }

        currentPemResult = pem;
        pemOutput.value = pem;
        resultCerArea.classList.remove('hidden');

        if (certObj) {
            const infoHtml = renderCertInfo(certObj);
            if (infoHtml) {
                certInfoCer.innerHTML = infoHtml;
                certInfoCer.classList.remove('hidden');
            }
        }
    }

    downloadPemBtn.addEventListener('click', () => {
        if (!currentPemResult) return;
        downloadBlob(new Blob([currentPemResult], { type: 'application/x-pem-file' }), currentCerFileName);
    });

    copyPemBtn.addEventListener('click', () => {
        if (!currentPemResult) return;
        navigator.clipboard.writeText(currentPemResult).then(() => {
            copyPemBtn.textContent = 'Copied! ✓';
            setTimeout(() => {
                copyPemBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy PEM`;
            }, 2000);
        });
    });

    // ==========================================
    // 2. PEM to CER (Binary DER) Handling
    // ==========================================
    const uploadAreaPem = document.getElementById('uploadAreaPem');
    const fileInputPem = document.getElementById('fileInputPem');
    const pemInput = document.getElementById('pemInput');
    const btnConvertPemToCer = document.getElementById('btnConvertPemToCer');
    const btnClearPem = document.getElementById('btnClearPem');
    const errorPem = document.getElementById('errorPem');
    const warnPem = document.getElementById('warnPem');
    const resultPemArea = document.getElementById('resultPemArea');
    const downloadCerBtn = document.getElementById('downloadCerBtn');
    const downloadCerBase64Btn = document.getElementById('downloadCerBase64Btn');
    const certInfoPem = document.getElementById('certInfoPem');

    let currentDerBytes = null;
    let currentBase64Cer = '';
    let currentExportName = 'certificate.cer';

    setupDropZone(uploadAreaPem, (file) => {
        if (file.name.toLowerCase().endsWith('.cer') || file.name.toLowerCase().endsWith('.crt')) {
            switchTab('cer2pem');
            handleCerFile(file);
        } else {
            handlePemFile(file);
        }
    });

    fileInputPem.addEventListener('change', (e) => {
        if (e.target.files.length) handlePemFile(e.target.files[0]);
    });

    function handlePemFile(file) {
        currentExportName = file.name.replace(/\.(pem|crt|txt)$/i, '') + '.cer';
        const reader = new FileReader();
        reader.onload = (e) => {
            pemInput.value = e.target.result;
            processPemToCer();
        };
        reader.readAsText(file);
    }

    btnClearPem.addEventListener('click', () => {
        pemInput.value = '';
        errorPem.classList.add('hidden');
        warnPem.classList.add('hidden');
        resultPemArea.classList.add('hidden');
        currentDerBytes = null;
    });

    btnConvertPemToCer.addEventListener('click', processPemToCer);

    function processPemToCer() {
        errorPem.classList.add('hidden');
        warnPem.classList.add('hidden');
        resultPemArea.classList.add('hidden');
        certInfoPem.classList.add('hidden');
        currentDerBytes = null;

        const rawText = pemInput.value.trim();
        if (!rawText) {
            errorPem.textContent = 'Please paste or upload a PEM certificate.';
            errorPem.classList.remove('hidden');
            return;
        }

        // Check if user accidentally pasted a private key
        if (rawText.includes('PRIVATE KEY')) {
            warnPem.innerHTML = `<strong>Private Key Detected:</strong> This file appears to contain a Private Key, not a public certificate. .cer files are meant for public X.509 certificates.`;
            warnPem.classList.remove('hidden');
            return;
        }

        try {
            // Find certificate block
            let certObj = null;
            let derBinaryStr = '';

            if (rawText.includes('-----BEGIN CERTIFICATE-----')) {
                certObj = forge.pki.certificateFromPem(rawText);
                const asn1 = forge.pki.certificateToAsn1(certObj);
                derBinaryStr = forge.asn1.toDer(asn1).getBytes();
            } else if (rawText.includes('-----BEGIN PUBLIC KEY-----')) {
                // Public key PEM support
                const pubKey = forge.pki.publicKeyFromPem(rawText);
                const asn1 = forge.pki.publicKeyToAsn1(pubKey);
                derBinaryStr = forge.asn1.toDer(asn1).getBytes();
                warnPem.innerHTML = `<strong>Note:</strong> Converted as a raw SubjectPublicKeyInfo DER file rather than a signed X.509 certificate.`;
                warnPem.classList.remove('hidden');
            } else {
                // Try if raw base64 without headers
                const cleanB64 = rawText.replace(/\s+/g, '');
                const rawDer = forge.util.decode64(cleanB64);
                const asn1 = forge.asn1.fromDer(rawDer);
                certObj = forge.pki.certificateFromAsn1(asn1);
                derBinaryStr = rawDer;
            }

            // Convert to Uint8Array for binary download
            const u8 = new Uint8Array(derBinaryStr.length);
            for (let i = 0; i < derBinaryStr.length; i++) {
                u8[i] = derBinaryStr.charCodeAt(i);
            }
            currentDerBytes = u8;
            currentBase64Cer = forge.util.encode64(derBinaryStr);

            resultPemArea.classList.remove('hidden');

            if (certObj) {
                const infoHtml = renderCertInfo(certObj);
                if (infoHtml) {
                    certInfoPem.innerHTML = infoHtml;
                    certInfoPem.classList.remove('hidden');
                }
            }
        } catch (err) {
            console.error(err);
            errorPem.textContent = 'Could not parse PEM certificate. Ensure it has valid -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- markers.';
            errorPem.classList.remove('hidden');
        }
    }

    downloadCerBtn.addEventListener('click', () => {
        if (!currentDerBytes) return;
        const blob = new Blob([currentDerBytes], { type: 'application/x-x509-ca-cert' });
        downloadBlob(blob, currentExportName);
    });

    downloadCerBase64Btn.addEventListener('click', () => {
        if (!currentBase64Cer) return;
        const b64Name = currentExportName.replace(/\.cer$/i, '_base64.cer');
        const blob = new Blob([currentBase64Cer], { type: 'text/plain' });
        downloadBlob(blob, b64Name);
    });

    // ==========================================
    // Generic Helper Functions
    // ==========================================
    function setupDropZone(dropZone, onFile) {
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                onFile(e.dataTransfer.files[0]);
            }
        });
    }

    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
});
