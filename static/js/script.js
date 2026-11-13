// ============================================================
// AI-Based Spam & Threat Detection System - Client JavaScript
// ============================================================

document.addEventListener('DOMContentLoaded', () => {

    // ------------------------------------------------------------
    // 1. MESSAGE SPAM DETECTION ENGINE
    // ------------------------------------------------------------
    const detectForm = document.getElementById('detectForm');
    const messageInput = document.getElementById('messageInput');
    const charCounter = document.getElementById('charCounter');
    const btnDetect = document.getElementById('btnDetect');
    const btnSpinner = document.getElementById('btnSpinner');
    const btnIcon = document.getElementById('btnIcon');
    const btnClear = document.getElementById('btnClear');
    
    const errorAlert = document.getElementById('errorAlert');
    const errorMessage = document.getElementById('errorMessage');

    const resultContainer = document.getElementById('resultContainer');
    const resultCard = document.getElementById('resultCard');
    const resultIcon = document.getElementById('resultIcon');
    const resultTitle = document.getElementById('resultTitle');
    const resultSubtitle = document.getElementById('resultSubtitle');
    const confidenceText = document.getElementById('confidenceText');
    const confidenceBar = document.getElementById('confidenceBar');
    const scanTimestamp = document.getElementById('scanTimestamp');

    const msgSamples = {
        spam: "Congratulations! You won a free prize. Call now to claim.",
        ham: "Hey, are we meeting at 5 pm today?"
    };

    document.querySelectorAll('.sample-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.getAttribute('data-type');
            if (msgSamples[type] && messageInput) {
                messageInput.value = msgSamples[type];
                updateCharCount();
                if (errorAlert) errorAlert.classList.add('d-none');
                if (resultContainer) resultContainer.classList.add('d-none');
                messageInput.focus();
            }
        });
    });

    function updateCharCount() {
        if (!messageInput || !charCounter) return;
        const len = messageInput.value.length;
        charCounter.textContent = `${len} / 1000`;
        if (len > 1000) {
            charCounter.classList.add('text-danger', 'fw-bold');
            charCounter.classList.remove('text-muted-cyber');
        } else {
            charCounter.classList.remove('text-danger', 'fw-bold');
            charCounter.classList.add('text-muted-cyber');
        }
    }

    if (messageInput) {
        messageInput.addEventListener('input', updateCharCount);
    }

    if (btnClear) {
        btnClear.addEventListener('click', () => {
            if (messageInput) {
                messageInput.value = '';
                updateCharCount();
            }
            if (errorAlert) errorAlert.classList.add('d-none');
            if (resultContainer) resultContainer.classList.add('d-none');
            if (messageInput) messageInput.focus();
        });
    }

    if (detectForm) {
        detectForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (errorAlert) errorAlert.classList.add('d-none');
            if (resultContainer) resultContainer.classList.add('d-none');

            const text = messageInput ? messageInput.value.trim() : '';

            if (!text) {
                if (errorAlert && errorMessage) {
                    errorMessage.textContent = "Message cannot be empty or whitespace only.";
                    errorAlert.classList.remove('d-none');
                }
                if (messageInput) messageInput.focus();
                return;
            }

            if (text.length > 1000) {
                if (errorAlert && errorMessage) {
                    errorMessage.textContent = "Message exceeds the maximum allowed limit of 1000 characters.";
                    errorAlert.classList.remove('d-none');
                }
                return;
            }

            btnDetect.disabled = true;
            btnSpinner.classList.remove('d-none');
            btnIcon.classList.add('d-none');

            try {
                const response = await fetch('/predict', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: text })
                });

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || `Server error (${response.status})`);
                }

                // Render result
                resultCard.classList.remove('result-spam', 'result-ham');
                resultIcon.classList.remove('fa-triangle-exclamation', 'fa-circle-check', 'result-icon-spam', 'result-icon-ham');
                confidenceBar.classList.remove('bg-danger', 'bg-success');

                if (data.is_spam) {
                    resultCard.classList.add('result-spam');
                    resultIcon.classList.add('fa-triangle-exclamation', 'result-icon-spam');
                    resultTitle.textContent = "SPAM DETECTED";
                    resultTitle.style.color = "var(--spam-danger)";
                    resultSubtitle.textContent = "Warning: This message exhibits high-confidence characteristics of fraudulent or unsolicited spam.";
                    confidenceBar.classList.add('bg-danger');
                } else {
                    resultCard.classList.add('result-ham');
                    resultIcon.classList.add('fa-circle-check', 'result-icon-ham');
                    resultTitle.textContent = "GENUINE MESSAGE (NOT SPAM)";
                    resultTitle.style.color = "var(--ham-safe)";
                    resultSubtitle.textContent = "Verified: This message appears to be safe and legitimate personal or conversational text.";
                    confidenceBar.classList.add('bg-success');
                }

                confidenceText.textContent = `${data.confidence}%`;
                confidenceBar.style.width = `${data.confidence}%`;
                scanTimestamp.textContent = data.scanned_at;
                resultContainer.classList.remove('d-none');
                resultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

            } catch (err) {
                if (errorAlert && errorMessage) {
                    errorMessage.textContent = err.message || "Failed to communicate with prediction backend.";
                    errorAlert.classList.remove('d-none');
                }
            } finally {
                btnDetect.disabled = false;
                btnSpinner.classList.add('d-none');
                btnIcon.classList.remove('d-none');
            }
        });
    }

    // ------------------------------------------------------------
    // 2. LINK / PHISHING URL DETECTION ENGINE
    // ------------------------------------------------------------
    const linkDetectForm = document.getElementById('linkDetectForm');
    const urlInput = document.getElementById('urlInput');
    const btnLinkDetect = document.getElementById('btnLinkDetect');
    const btnLinkSpinner = document.getElementById('btnLinkSpinner');
    const btnLinkIcon = document.getElementById('btnLinkIcon');
    const btnLinkClear = document.getElementById('btnLinkClear');

    const linkErrorAlert = document.getElementById('linkErrorAlert');
    const linkErrorMessage = document.getElementById('linkErrorMessage');

    const linkResultContainer = document.getElementById('linkResultContainer');
    const linkResultCard = document.getElementById('linkResultCard');
    const linkResultIcon = document.getElementById('linkResultIcon');
    const linkResultTitle = document.getElementById('linkResultTitle');
    const linkResultSubtitle = document.getElementById('linkResultSubtitle');
    const analyzedHost = document.getElementById('analyzedHost');
    const riskScoreText = document.getElementById('riskScoreText');
    const riskBar = document.getElementById('riskBar');
    const indicatorList = document.getElementById('indicatorList');
    const linkTimestamp = document.getElementById('linkTimestamp');

    document.querySelectorAll('.link-sample-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const url = btn.getAttribute('data-url');
            if (url && urlInput) {
                urlInput.value = url;
                if (linkErrorAlert) linkErrorAlert.classList.add('d-none');
                if (linkResultContainer) linkResultContainer.classList.add('d-none');
                urlInput.focus();
            }
        });
    });

    if (btnLinkClear) {
        btnLinkClear.addEventListener('click', () => {
            if (urlInput) urlInput.value = '';
            if (linkErrorAlert) linkErrorAlert.classList.add('d-none');
            if (linkResultContainer) linkResultContainer.classList.add('d-none');
            if (urlInput) urlInput.focus();
        });
    }

    if (linkDetectForm) {
        linkDetectForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (linkErrorAlert) linkErrorAlert.classList.add('d-none');
            if (linkResultContainer) linkResultContainer.classList.add('d-none');

            const url = urlInput ? urlInput.value.trim() : '';
            if (!url) {
                if (linkErrorAlert && linkErrorMessage) {
                    linkErrorMessage.textContent = "Please enter a valid website link or URL.";
                    linkErrorAlert.classList.remove('d-none');
                }
                return;
            }

            btnLinkDetect.disabled = true;
            btnLinkSpinner.classList.remove('d-none');
            btnLinkIcon.classList.add('d-none');

            try {
                const response = await fetch('/predict-link', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || `Server error (${response.status})`);
                }

                // Render result
                linkResultCard.classList.remove('result-spam', 'result-ham');
                linkResultIcon.classList.remove('fa-triangle-exclamation', 'fa-circle-check', 'fa-shield-halved', 'result-icon-spam', 'result-icon-ham');
                riskBar.classList.remove('bg-danger', 'bg-warning', 'bg-success');

                if (data.risk_level === 'High Risk') {
                    linkResultCard.classList.add('result-spam');
                    linkResultIcon.classList.add('fa-triangle-exclamation', 'result-icon-spam');
                    linkResultTitle.textContent = "MALICIOUS PHISHING LINK DETECTED";
                    linkResultTitle.style.color = "var(--spam-danger)";
                    linkResultSubtitle.textContent = "High probability of credential harvesting, fraudulent impersonation, or deceptive scam infrastructure.";
                    riskBar.classList.add('bg-danger');
                    riskScoreText.textContent = `${data.risk_score}% Threat Risk`;
                    riskScoreText.className = "fw-bold my-1 text-danger";
                } else if (data.risk_level === 'Suspicious') {
                    linkResultCard.classList.add('result-spam');
                    linkResultIcon.classList.add('fa-triangle-exclamation', 'text-warning');
                    linkResultTitle.textContent = "SUSPICIOUS URL WARNING";
                    linkResultTitle.style.color = "var(--warning-accent)";
                    linkResultSubtitle.textContent = "This link exhibits multiple suspicious patterns (URL masking, non-standard domain, or keyword lures).";
                    riskBar.classList.add('bg-warning');
                    riskScoreText.textContent = `${data.risk_score}% Threat Risk`;
                    riskScoreText.className = "fw-bold my-1 text-warning";
                } else {
                    linkResultCard.classList.add('result-ham');
                    linkResultIcon.classList.add('fa-circle-check', 'result-icon-ham');
                    linkResultTitle.textContent = "SAFE & LEGITIMATE LINK";
                    linkResultTitle.style.color = "var(--ham-safe)";
                    linkResultSubtitle.textContent = "No deceptive social engineering indicators, masked redirects, or anomalous domain patterns detected.";
                    riskBar.classList.add('bg-success');
                    riskScoreText.textContent = `${data.risk_score}% Low Risk`;
                    riskScoreText.className = "fw-bold my-1 text-success";
                }

                analyzedHost.textContent = data.hostname || data.url;
                riskBar.style.width = `${data.risk_score}%`;

                // Render security indicators
                indicatorList.innerHTML = '';
                (data.indicators || []).forEach(ind => {
                    const li = document.createElement('li');
                    li.className = "mb-1";
                    li.textContent = ind;
                    indicatorList.appendChild(li);
                });

                linkTimestamp.textContent = data.scanned_at;
                linkResultContainer.classList.remove('d-none');
                linkResultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

            } catch (err) {
                if (linkErrorAlert && linkErrorMessage) {
                    linkErrorMessage.textContent = err.message || "Failed to inspect URL.";
                    linkErrorAlert.classList.remove('d-none');
                }
            } finally {
                btnLinkDetect.disabled = false;
                btnLinkSpinner.classList.add('d-none');
                btnLinkIcon.classList.remove('d-none');
            }
        });
    }

    // ------------------------------------------------------------
    // 3. FILE & BATCH DOCUMENT DETECTION ENGINE
    // ------------------------------------------------------------
    const fileDetectForm = document.getElementById('fileDetectForm');
    const fileInput = document.getElementById('fileInput');
    const dropZone = document.getElementById('dropZone');
    const selectedFileInfo = document.getElementById('selectedFileInfo');
    const selectedFileName = document.getElementById('selectedFileName');
    const btnFileDetect = document.getElementById('btnFileDetect');
    const btnFileSpinner = document.getElementById('btnFileSpinner');
    const btnFileIcon = document.getElementById('btnFileIcon');
    const btnFileClear = document.getElementById('btnFileClear');

    const fileErrorAlert = document.getElementById('fileErrorAlert');
    const fileErrorMessage = document.getElementById('fileErrorMessage');

    const fileResultContainer = document.getElementById('fileResultContainer');
    const resTotalScanned = document.getElementById('resTotalScanned');
    const resSpamCount = document.getElementById('resSpamCount');
    const resSpamRatio = document.getElementById('resSpamRatio');
    const resHamCount = document.getElementById('resHamCount');
    const resThreatLevel = document.getElementById('resThreatLevel');
    const fileResultsBody = document.getElementById('fileResultsBody');
    const btnDownloadCSV = document.getElementById('btnDownloadCSV');

    let currentFileBatchResults = [];

    function handleFileSelection(file) {
        if (!file) return;
        selectedFileName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        selectedFileInfo.classList.remove('d-none');
        btnFileDetect.disabled = false;
        if (fileErrorAlert) fileErrorAlert.classList.add('d-none');
    }

    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files[0]) {
                handleFileSelection(e.target.files[0]);
            }
        });
    }

    if (dropZone) {
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add('border-cyan');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove('border-cyan');
            }, false);
        });

        dropZone.addEventListener('drop', (e) => {
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                fileInput.files = e.dataTransfer.files;
                handleFileSelection(e.dataTransfer.files[0]);
            }
        });
    }

    if (btnFileClear) {
        btnFileClear.addEventListener('click', () => {
            if (fileInput) fileInput.value = '';
            if (selectedFileInfo) selectedFileInfo.classList.add('d-none');
            if (btnFileDetect) btnFileDetect.disabled = true;
            if (fileErrorAlert) fileErrorAlert.classList.add('d-none');
            if (fileResultContainer) fileResultContainer.classList.add('d-none');
            currentFileBatchResults = [];
        });
    }

    if (fileDetectForm) {
        fileDetectForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (fileErrorAlert) fileErrorAlert.classList.add('d-none');
            if (fileResultContainer) fileResultContainer.classList.add('d-none');

            if (!fileInput || !fileInput.files || !fileInput.files[0]) {
                if (fileErrorAlert && fileErrorMessage) {
                    fileErrorMessage.textContent = "Please select a file to scan.";
                    fileErrorAlert.classList.remove('d-none');
                }
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            btnFileDetect.disabled = true;
            btnFileSpinner.classList.remove('d-none');
            btnFileIcon.classList.add('d-none');

            try {
                const response = await fetch('/predict-file', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || `Server error (${response.status})`);
                }

                currentFileBatchResults = data.results || [];

                // Render metrics
                resTotalScanned.textContent = data.total_scanned;
                resSpamCount.textContent = data.spam_count;
                resSpamRatio.textContent = `${data.spam_ratio}% threat ratio`;
                resHamCount.textContent = data.ham_count;

                resThreatLevel.textContent = data.threat_level;
                resThreatLevel.className = `fw-bold my-1 text-${data.badge_class}`;

                // Populate table
                fileResultsBody.innerHTML = '';
                currentFileBatchResults.forEach(item => {
                    const tr = document.createElement('tr');
                    const badge = item.is_spam 
                        ? `<span class="badge cyber-badge-spam"><i class="fa-solid fa-triangle-exclamation me-1"></i> Spam</span>`
                        : `<span class="badge cyber-badge-ham"><i class="fa-solid fa-check me-1"></i> Not Spam</span>`;

                    tr.innerHTML = `
                        <td class="text-muted-cyber small">#${item.index}</td>
                        <td class="text-white text-truncate" style="max-width: 450px;" title="${item.full_message.replace(/"/g, '&quot;')}">${item.message}</td>
                        <td>${badge}</td>
                        <td><span class="fw-semibold text-white">${item.confidence}%</span></td>
                    `;
                    fileResultsBody.appendChild(tr);
                });

                fileResultContainer.classList.remove('d-none');
                fileResultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

            } catch (err) {
                if (fileErrorAlert && fileErrorMessage) {
                    fileErrorMessage.textContent = err.message || "Failed to scan uploaded file.";
                    fileErrorAlert.classList.remove('d-none');
                }
            } finally {
                btnFileDetect.disabled = false;
                btnFileSpinner.classList.add('d-none');
                btnFileIcon.classList.remove('d-none');
            }
        });
    }

    // CSV Download
    if (btnDownloadCSV) {
        btnDownloadCSV.addEventListener('click', () => {
            if (!currentFileBatchResults.length) return;
            let csv = "Index,Verdict,Confidence,Message\n";
            currentFileBatchResults.forEach(r => {
                const cleanMsg = `"${r.full_message.replace(/"/g, '""')}"`;
                csv += `${r.index},${r.verdict},${r.confidence}%,${cleanMsg}\n`;
            });

            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `spam_scan_report_${Date.now()}.csv`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        });
    }

});
