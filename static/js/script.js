let currentPdfPath = null;

// ==================== Matrix Background ====================
function initMatrix() {
    const canvas = document.getElementById('matrix-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    const chars = '01アイウエオカキクケコ';
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array(Math.floor(columns)).fill(1);
    function draw() {
        ctx.fillStyle = 'rgba(0,0,0,0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00d4ff';
        ctx.font = fontSize + 'px monospace';
        drops.forEach((y, i) => {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, y * fontSize);
            if (y * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
            drops[i]++;
        });
    }
    setInterval(draw, 35);
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ==================== Cursor Glow ====================
function initCursorGlow() {
    const wrap = document.getElementById('cursor-glow-wrap');
    const spot = document.getElementById('cursor-glow-spot');
    if (!wrap || !spot) return;
    document.addEventListener('mousemove', (e) => {
        wrap.style.left = e.clientX + 'px';
        wrap.style.top  = e.clientY + 'px';
    });
}

// ==================== Scroll Progress ====================
function initScrollProgress() {
    const bar = document.getElementById('scroll-progress-bar');
    if (!bar) return;
    window.addEventListener('scroll', () => {
        const scrolled = (window.scrollY / (document.documentElement.scrollHeight - window.innerHeight)) * 100;
        bar.style.width = scrolled + '%';
    });
}

// ==================== Reveal on Scroll ====================
function initReveal() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); });
    }, { threshold: 0.1 });
    document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
}

// ==================== Navbar ====================
function initNavbar() {
    window.addEventListener('scroll', () => {
        const navbar = document.querySelector('.navbar');
        navbar.style.backgroundColor = window.scrollY > 50
            ? 'rgba(10,14,23,0.98)' : 'rgba(10,14,23,0.95)';
    });
}

// ==================== Scroll Helpers ====================
function scrollToUpload() { document.getElementById('upload').scrollIntoView({ behavior: 'smooth' }); }
function scrollToAbout()  { document.getElementById('about').scrollIntoView({ behavior: 'smooth' }); }

// ==================== File Upload ====================
function initFileUpload() {
    const fileInput = document.getElementById('fileInput');
    const uploadArea = document.getElementById('uploadArea');
    if (!fileInput) return;

    fileInput.addEventListener('change', (e) => {
        if (e.target.files[0]) showFileInfo(e.target.files[0]);
    });

    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.style.borderColor = 'var(--accent-color)';
    });
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.style.borderColor = 'rgba(0,212,255,0.3)';
    });
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.style.borderColor = 'rgba(0,212,255,0.3)';
        const file = e.dataTransfer.files[0];
        if (file && file.name.endsWith('.exe')) {
            fileInput.files = e.dataTransfer.files;
            showFileInfo(file);
        } else {
            showNotification('Please upload a .exe file only!', 'error');
        }
    });
}

function showFileInfo(file) {
    document.getElementById('uploadArea').style.display = 'none';
    document.getElementById('fileInfo').style.display = 'flex';
    document.getElementById('fileName').textContent = file.name;
    document.getElementById('fileSize').textContent = (file.size / 1024).toFixed(1) + ' KB';
}

// ==================== Analyze File ====================
async function analyzeFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if (!file) return;

    document.getElementById('progressCard').style.display = 'block';
    document.getElementById('analyzeBtn').disabled = true;
    animateSteps();

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/upload', { method: 'POST', body: formData });
        const data = await response.json();
        if (data.error) { showNotification(data.error, 'error'); return; }
        for (let i = 1; i <= 5; i++) markStepDone(i);
        setTimeout(() => displayResults(data), 500);
    } catch (err) {
        showNotification('Analysis failed: ' + err.message, 'error');
    } finally {
        document.getElementById('analyzeBtn').disabled = false;
    }
}

// ==================== Animate Steps ====================
let stepInterval;
function animateSteps() {
    let current = 0;
    [1,2,3,4,5].forEach(i => {
        const step = document.getElementById('step' + i);
        step.classList.remove('done', 'active');
        step.querySelector('.step-status').innerHTML = '<i class="fas fa-clock"></i>';
    });
    stepInterval = setInterval(() => {
        if (current > 0) markStepDone(current);
        current++;
        if (current <= 5) {
            const step = document.getElementById('step' + current);
            step.classList.add('active');
            step.querySelector('.step-status').innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        } else {
            clearInterval(stepInterval);
        }
    }, 8000);
}

function markStepDone(i) {
    const step = document.getElementById('step' + i);
    if (!step) return;
    step.classList.remove('active');
    step.classList.add('done');
    step.querySelector('.step-status').innerHTML = '<i class="fas fa-check-circle"></i>';
}

// ==================== Display Results ====================
function displayResults(data) {
    clearInterval(stepInterval);
    for (let i = 1; i <= 5; i++) markStepDone(i);

    const resultsSection = document.getElementById('results');
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });

    const verdict     = data.behavior_analysis?.verdict       || 'UNKNOWN';
    const threatLevel = data.behavior_analysis?.threat_level  || 'UNKNOWN';
    const sandboxSt   = data.behavior_analysis?.sandbox_status || 'Unknown';

    const verdictCard = document.getElementById('verdictCard');
    const verdictIcon = document.getElementById('verdictIcon');
    verdictCard.className = 'verdict-card';
    if (verdict === 'MALWARE') {
        verdictCard.classList.add('malware');
        verdictIcon.innerHTML = '<i class="fas fa-skull-crossbones"></i>';
    } else if (verdict === 'SUSPICIOUS') {
        verdictCard.classList.add('suspicious');
        verdictIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
    } else {
        verdictCard.classList.add('clean');
        verdictIcon.innerHTML = '<i class="fas fa-shield-alt"></i>';
    }

    document.getElementById('verdictText').textContent  = verdict;
    document.getElementById('threatLevel').textContent  = 'Threat Level: ' + threatLevel;
    document.getElementById('sandboxStatus').textContent = 'Sandbox: ' + sandboxSt;

    document.getElementById('resFilename').textContent     = data.filename || '--';
    document.getElementById('resSha256').textContent       = data.sha256   || '--';
    const pe = data.static_analysis?.pe_analysis || {};
    document.getElementById('resValidPE').textContent      = pe.is_valid_pe ? '✅ Yes' : '❌ No';
    document.getElementById('resPacked').textContent       = pe.is_packed   ? '⚠️ Yes' : '✅ No';
    document.getElementById('resTotalStrings').textContent = data.static_analysis?.total_strings || 0;

    const vt = data.virustotal || {};
    document.getElementById('vtMalicious').textContent = vt.malicious     || 0;
    document.getElementById('vtTotal').textContent     = vt.total_engines || 0;
    document.getElementById('vtClean').textContent     = vt.clean         || 0;
    document.getElementById('vtVerdict').textContent   = vt.verdict       || '--';
    if ((vt.malicious || 0) > 0) document.getElementById('vtGauge').classList.add('danger');

    const sandbox = data.sandbox || {};
    document.getElementById('sandboxStatusCard').textContent = sandbox.success ? '✅ Success' : '❌ Failed';
    document.getElementById('sandboxEvents').textContent     = sandbox.total_events || 0;

    const eventsList = document.getElementById('sandboxEventsList');
    eventsList.innerHTML = '';
    (sandbox.events || []).slice(0, 10).forEach(event => {
        const div  = document.createElement('div');
        const type = event.type || '';
        div.className = 'event-item ' + (
            type.includes('network')  ? 'network'  :
            type.includes('process')  ? 'process'  :
            type.includes('registry') ? 'registry' :
            type.includes('file')     ? 'file'     : '');
        div.textContent = type + (event.data?.remote_ip ? ' → ' + event.data.remote_ip : '');
        eventsList.appendChild(div);
    });

    const chains     = data.behavior_analysis?.dynamic_analysis?.detections || [];
    const chainsList = document.getElementById('chainsList');
    chainsList.innerHTML = '';
    if (!chains.length) {
        chainsList.innerHTML = '<p class="no-chains"><i class="fas fa-check-circle"></i> No attack chains detected</p>';
    } else {
        chains.forEach(chain => {
            const div = document.createElement('div');
            div.className = 'chain-item ' + (chain.chain_name === 'CRITICAL' ? 'critical' : '');
            div.innerHTML = `
                <div class="chain-name"><i class="fas fa-exclamation-triangle"></i> ${chain.chain_name}</div>
                <span class="chain-severity">${chain.matched_indicator}</span>
                <p class="chain-desc">${(chain.context || '').substring(0, 100)}</p>`;
            chainsList.appendChild(div);
        });
    }

    const strings     = data.static_analysis?.suspicious_strings || [];
    const stringsList = document.getElementById('stringsList');
    stringsList.innerHTML = '';
    if (!strings.length) {
        stringsList.innerHTML = '<p style="color:var(--success-color)">No suspicious strings found ✅</p>';
    } else {
        strings.forEach(s => {
            const span = document.createElement('span');
            span.className = 'string-tag';
            span.textContent = s.substring(0, 50);
            stringsList.appendChild(span);
        });
    }

    currentPdfPath = data.pdf_report || null;
}

// ==================== Download Report ====================
function downloadReport() {
    if (!currentPdfPath) { showNotification('No report available yet!', 'error'); return; }
    window.open('/download-report?path=' + encodeURIComponent(currentPdfPath), '_blank');
}

// ==================== Notification ====================
function showNotification(message, type = 'info') {
    const n = document.createElement('div');
    n.style.cssText = `
        position:fixed; top:100px; right:20px;
        background:var(--card-bg);
        border-left:4px solid ${type === 'error' ? 'var(--danger-color)' : 'var(--accent-color)'};
        border-radius:var(--border-radius);
        padding:1rem 1.5rem; max-width:400px;
        box-shadow:var(--box-shadow); z-index:10000;
        animation:slideIn .5s ease; color:var(--text-color);`;
    n.innerHTML = `<i class="fas fa-${type === 'error' ? 'times-circle' : 'info-circle'}"
        style="color:${type === 'error' ? 'var(--danger-color)' : 'var(--accent-color)'}"></i> ${message}`;
    document.body.appendChild(n);
    const s = document.createElement('style');
    s.textContent = `@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}`;
    document.head.appendChild(s);
    setTimeout(() => n.remove(), 4000);
}

// ==================== Init ====================
document.addEventListener('DOMContentLoaded', () => {
    initMatrix();
    initCursorGlow();
    initScrollProgress();
    initReveal();
    initNavbar();
    initFileUpload();
});

// ══════════════════════════════════════════════
//  URL SCANNER
// ══════════════════════════════════════════════
async function scanUrl() {
    const input   = document.getElementById('url-input');
    const url     = input ? input.value.trim() : '';
    if (!url) { showNotification('Please enter a URL to scan', 'error'); return; }

    const btn     = document.getElementById('scan-url-btn');
    const loading = document.getElementById('url-loading');
    const results = document.getElementById('url-results');

    if (btn)     btn.disabled = true;
    if (loading) loading.style.display = 'block';
    if (results) results.style.display = 'none';

    try {
        const response = await fetch('/scan-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();
        if (data.error) { showNotification(data.error, 'error'); return; }
        renderUrlResults(data);
    } catch (err) {
        showNotification('Failed to scan URL. Make sure the server is running.', 'error');
        console.error(err);
    } finally {
        if (btn)     btn.disabled = false;
        if (loading) loading.style.display = 'none';
    }
}

function renderUrlResults(data) {
    const results = document.getElementById('url-results');
    if (!results) return;

    const riskColors = {
        'Safe':     { bg:'rgba(46,213,115,0.15)',  border:'#2ed573', icon:'fa-shield-alt',           color:'#2ed573' },
        'Low':      { bg:'rgba(255,215,0,0.12)',   border:'#ffd700', icon:'fa-exclamation-circle',   color:'#ffd700' },
        'Medium':   { bg:'rgba(255,165,0,0.15)',   border:'#ffa502', icon:'fa-exclamation-triangle', color:'#ffa502' },
        'High':     { bg:'rgba(255,71,87,0.15)',   border:'#ff4757', icon:'fa-radiation',            color:'#ff4757' },
        'Critical': { bg:'rgba(255,0,0,0.2)',      border:'#ff0000', icon:'fa-skull-crossbones',     color:'#ff0000' },
    };
    const style  = riskColors[data.risk_level] || riskColors['Medium'];
    const banner = document.getElementById('url-risk-banner');
    if (banner) {
        banner.style.background = style.bg;
        banner.style.border     = `1px solid ${style.border}`;
        banner.style.color      = style.color;
    }

    const icon = document.getElementById('url-risk-icon');
    if (icon) icon.className = `fas ${style.icon}`;

    const label = document.getElementById('url-risk-label');
    if (label) label.textContent = `${data.risk_level} Risk`;

    const indicators = data.indicators || data.flags || [];
    const score = document.getElementById('url-risk-score');
    if (score) score.textContent = `Score: ${data.risk_score}/100 · ${indicators.length} indicator(s) found`;

    const domEl = document.getElementById('url-domain');
    if (domEl) domEl.textContent = data.domain_info?.domain || data.domain || '-';

    const ipEl = document.getElementById('url-ip');
    if (ipEl) ipEl.textContent = data.domain_info?.ip || data.ip_address || '-';

    const httpsEl = document.getElementById('url-https');
    if (httpsEl) {
        const isHttps = (data.url || '').startsWith('https');
        httpsEl.innerHTML = isHttps
            ? '<span style="color:#2ed573"><i class="fas fa-lock"></i> Yes (HTTPS)</span>'
            : '<span style="color:#ff4757"><i class="fas fa-lock-open"></i> No (HTTP)</span>';
    }

    const sslEl = document.getElementById('url-ssl');
    if (sslEl) {
        const isHttps = (data.url || '').startsWith('https');
        if (!isHttps) { sslEl.textContent = 'N/A'; }
        else if (data.ssl_valid) {
            sslEl.innerHTML = `<span style="color:#2ed573"><i class="fas fa-check-circle"></i> Valid (${data.ssl_expiry || 'unknown'})</span>`;
        } else {
            sslEl.innerHTML = `<span style="color:#ff4757"><i class="fas fa-times-circle"></i> Invalid / Unknown</span>`;
        }
    }

    const flagsContainer = document.getElementById('url-flags-container');
    const flagsList      = document.getElementById('url-flags-list');
    if (indicators.length > 0) {
        flagsList.innerHTML = indicators.map(f =>
            `<li style="background:rgba(255,165,0,0.08);border-left:3px solid var(--warning-color);
                padding:0.5rem 0.8rem;border-radius:4px;font-size:0.85rem;color:var(--text-color);">
             <i class="fas fa-flag" style="color:var(--warning-color);margin-right:6px;"></i>${f}</li>`
        ).join('');
        if (flagsContainer) flagsContainer.style.display = 'block';
    } else {
        if (flagsContainer) flagsContainer.style.display = 'none';
    }

    results.style.display = 'block';
    results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ══════════════════════════════════════════════
//  USB GUARD SCANNER
// ══════════════════════════════════════════════
async function scanUsb() {
    const btn      = document.getElementById('usb-scan-btn');
    const loading  = document.getElementById('usb-loading');
    const results  = document.getElementById('usb-results');
    const noDrives = document.getElementById('usb-no-drives');

    if (btn)      btn.disabled = true;
    if (loading)  loading.style.display = 'block';
    if (results)  results.style.display = 'none';
    if (noDrives) noDrives.style.display = 'none';

    try {
        const response = await fetch('/scan-usb', { method: 'POST' });
        const data     = await response.json();

        if (data.status === 'no_drives') {
            if (noDrives) noDrives.style.display = 'block';
            return;
        }
        renderUsbResults(data);

    } catch (err) {
        showNotification('USB scan failed: ' + err.message, 'error');
    } finally {
        if (btn)     btn.disabled = false;
        if (loading) loading.style.display = 'none';
    }
}

function renderUsbResults(data) {
    const resultsEl    = document.getElementById('usb-results');
    const bannerEl     = document.getElementById('usb-overall-banner');
    const bannerTitle  = document.getElementById('usb-banner-title');
    const bannerSub    = document.getElementById('usb-banner-sub');
    const bannerIcon   = document.getElementById('usb-banner-icon');
    const blockedBadge = document.getElementById('usb-blocked-badge');
    const drivesList   = document.getElementById('usb-drives-list');

    const drives    = data.drives || [];
    const isBlocked = data.blocked;

    const riskOrder = ['Critical','High','Medium','Low','Safe'];
    let overallRisk = 'Safe';
    for (const d of drives) {
        const r = d.overall_risk || 'Safe';
        if (riskOrder.indexOf(r) < riskOrder.indexOf(overallRisk)) overallRisk = r;
    }

    const bannerMap = {
        'Safe'    : { cls:'safe',     icon:'fa-shield-alt',           title:'All Drives Clean' },
        'Low'     : { cls:'low',      icon:'fa-exclamation-circle',   title:'Low Risk Detected' },
        'Medium'  : { cls:'medium',   icon:'fa-exclamation-triangle', title:'Medium Risk Detected' },
        'High'    : { cls:'high',     icon:'fa-radiation',            title:'High Risk — Threats Found!' },
        'Critical': { cls:'critical', icon:'fa-skull-crossbones',     title:'CRITICAL — Malware Detected!' },
    };
    const bm = bannerMap[overallRisk] || bannerMap['Medium'];

    bannerEl.className        = `usb-banner ${bm.cls}`;
    bannerIcon.className      = `fas ${bm.icon}`;
    bannerIcon.style.fontSize = '2.2rem';
    bannerTitle.textContent   = bm.title;
    bannerSub.textContent     = `${data.drives_found} drive(s) scanned  ·  ${data.message}`;
    blockedBadge.style.display = isBlocked ? 'flex' : 'none';

    drivesList.innerHTML = '';

    drives.forEach(drive => {
        const risk    = drive.overall_risk || 'Safe';
        const riskCls = risk.toLowerCase();

        const card = document.createElement('div');
        card.className = 'usb-drive-card';

        card.innerHTML = `
            <div class="usb-drive-header">
                <div class="usb-drive-title">
                    <i class="fas fa-hdd"></i>
                    Drive: <span style="letter-spacing:1px;">${drive.drive}</span>
                </div>
                <div class="usb-drive-meta">
                    <div class="usb-meta-item">
                        <strong>${drive.total_files}</strong><span>files</span>
                    </div>
                    <div class="usb-meta-item">
                        <strong>${drive.total_size}</strong><span>size</span>
                    </div>
                    <div class="usb-meta-item">
                        <strong>${(drive.scan_time || '--').split(' ')[1] || '--'}</strong>
                        <span>scanned</span>
                    </div>
                </div>
                <span class="usb-risk-badge ${riskCls}">${risk.toUpperCase()}</span>
            </div>
            <div class="usb-drive-body"></div>`;

        drivesList.appendChild(card);
        const body = card.querySelector('.usb-drive-body');

        if (drive.autorun_found) {
            body.innerHTML += `
                <div class="usb-autorun-alert">
                    <i class="fas fa-exclamation-circle" style="font-size:1.2rem;"></i>
                    <div><strong>autorun.inf detected!</strong> — Classic USB malware propagation technique.</div>
                </div>`;
        }

        if (drive.summary) {
            body.innerHTML += `<div class="usb-summary">${drive.summary}</div>`;
        }

        if (drive.error) {
            body.innerHTML += `
                <div class="usb-summary" style="border-color:var(--danger-color);color:var(--danger-color);">
                    <i class="fas fa-times-circle"></i> Error: ${drive.error}
                </div>`;
        }

        // Dangerous files
        if (drive.dangerous_files?.length) {
            const sec  = document.createElement('div');
            sec.className = 'usb-file-section';
            sec.innerHTML = `
                <div class="usb-file-section-title">
                    <i class="fas fa-skull" style="color:var(--danger-color);"></i>
                    Dangerous Files
                    <span style="color:var(--danger-color);">(${drive.dangerous_files.length})</span>
                </div>`;
            const list = document.createElement('div');
            list.className = 'usb-file-list';
            drive.dangerous_files.forEach(f => {
                const flags = (f.flags || []).map(fl =>
                    `<span class="usb-flag-tag">${fl.substring(0,50)}</span>`).join('');
                list.innerHTML += `
                    <div class="usb-file-item critical-file">
                        <i class="fas fa-file-code" style="color:var(--danger-color);margin-top:3px;flex-shrink:0;"></i>
                        <div style="flex:1;min-width:0;">
                            <div class="file-name">${f.name}</div>
                            <div class="file-path-small">${f.path}</div>
                            ${flags ? `<div class="usb-file-flags">${flags}</div>` : ''}
                        </div>
                        <span class="file-size-small">${f.size || ''}</span>
                    </div>`;
            });
            sec.appendChild(list);
            body.appendChild(sec);
        }

        // Suspicious files
        if (drive.suspicious_files?.length) {
            const sec  = document.createElement('div');
            sec.className = 'usb-file-section';
            sec.style.marginTop = '1rem';
            sec.innerHTML = `
                <div class="usb-file-section-title">
                    <i class="fas fa-exclamation-triangle" style="color:var(--warning-color);"></i>
                    Suspicious Files
                    <span style="color:var(--warning-color);">(${drive.suspicious_files.length})</span>
                </div>`;
            const list = document.createElement('div');
            list.className = 'usb-file-list';
            drive.suspicious_files.forEach(f => {
                const flags = (f.flags || []).map(fl =>
                    `<span class="usb-flag-tag warn">${fl.substring(0,50)}</span>`).join('');
                list.innerHTML += `
                    <div class="usb-file-item">
                        <i class="fas fa-file" style="color:var(--warning-color);margin-top:3px;flex-shrink:0;"></i>
                        <div style="flex:1;min-width:0;">
                            <div class="file-name">${f.name}</div>
                            <div class="file-path-small">${f.path}</div>
                            ${flags ? `<div class="usb-file-flags">${flags}</div>` : ''}
                        </div>
                        <span class="file-size-small">${f.size || ''}</span>
                    </div>`;
            });
            sec.appendChild(list);
            body.appendChild(sec);
        }

        // Clean
        if (!drive.dangerous_files?.length && !drive.suspicious_files?.length && !drive.error) {
            body.innerHTML += `
                <p style="color:var(--success-color);text-align:center;padding:1.2rem;">
                    <i class="fas fa-check-circle" style="font-size:1.4rem;"></i>
                    <br><span style="display:block;margin-top:0.5rem;">No threats found on this drive.</span>
                </p>`;
        }
    });

    resultsEl.style.display = 'block';
    resultsEl.scrollIntoView({ behavior: 'smooth' });
}
