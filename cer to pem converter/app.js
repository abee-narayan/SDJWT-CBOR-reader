const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const errorMessage = document.getElementById('errorMessage');
const resultArea = document.getElementById('resultArea');
const pemOutput = document.getElementById('pemOutput');
const downloadBtn = document.getElementById('downloadBtn');

let currentFileName = '';
let currentPemData = '';

// Handle drag and drop
uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.classList.add('dragover');
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.classList.remove('dragover');
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
        handleFile(e.dataTransfer.files[0]);
    }
});

// Handle file input change
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) {
        handleFile(e.target.files[0]);
    }
});

function handleFile(file) {
    errorMessage.style.display = 'none';
    resultArea.classList.remove('active');

    const lowerName = file.name.toLowerCase();
    if (!lowerName.endsWith('.cer') && !lowerName.endsWith('.crt')) {
        errorMessage.style.display = 'block';
        return;
    }

    currentFileName = file.name.replace(/\.(cer|crt)$/i, '.pem');

    const reader = new FileReader();

    reader.onload = function(e) {
        const contents = e.target.result;
        try {
            convertCerToPem(contents, true);
        } catch (err) {
            // Try as text if binary fails
            const textReader = new FileReader();
            textReader.onload = function(e2) {
                try {
                    convertCerToPem(e2.target.result, false);
                } catch (err2) {
                    errorMessage.textContent = "Error parsing certificate. It might be invalid or unsupported.";
                    errorMessage.style.display = 'block';
                }
            };
            textReader.readAsText(file);
        }
    };

    // First try reading as binary string (for DER format)
    reader.readAsBinaryString(file);
}

function convertCerToPem(data, isBinary) {
    let pem = '';
    
    if (isBinary) {
        try {
            // Try decoding as DER
            const asn1 = forge.asn1.fromDer(data);
            const cert = forge.pki.certificateFromAsn1(asn1);
            pem = forge.pki.certificateToPem(cert);
        } catch (e) {
            throw new Error("Not a valid DER format");
        }
    } else {
        // Assume it's already base64 or PEM, but might be missing headers/footers
        if (data.includes('-----BEGIN CERTIFICATE-----')) {
            pem = data; // Already PEM
        } else {
            // Convert raw base64 to PEM format
            const base64Clean = data.replace(/\\s+/g, '');
            const certBytes = forge.util.decode64(base64Clean);
            const asn1 = forge.asn1.fromDer(certBytes);
            const cert = forge.pki.certificateFromAsn1(asn1);
            pem = forge.pki.certificateToPem(cert);
        }
    }

    currentPemData = pem;
    pemOutput.value = pem;
    resultArea.classList.add('active');
}

downloadBtn.addEventListener('click', () => {
    if (!currentPemData) return;

    const blob = new Blob([currentPemData], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = currentFileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
});
