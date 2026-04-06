/**
 * WiFi Sniffer Web Control Panel v4 – JavaScript
 * ================================================
 * v4: Shows real file size, secure DOM updates, SSH availability check.
 */

// ============== Configuration ==============
const WS_RECONNECT_INTERVAL = 3000;
const STATUS_UPDATE_INTERVAL = 3000;

// ============== State ==============
let socket = null;
let isConnected = false;
let _pollingStatusTimer = null;
let _pollingTimeTimer = null;
let _routerHost = null; // populated from API

// ============== WebSocket ==============
function initWebSocket() {
    // Always start polling for reliable status updates (duration, file size)
    startPolling();

    if (typeof io === 'undefined') {
        console.log('[WS] Socket.IO not available, using polling only');
        return;
    }

    try {
        socket = io({
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionDelay: WS_RECONNECT_INTERVAL
        });

        socket.on('connect', () => {
            console.log('[WS] Connected (polling also active as backup)');
            socket.emit('request_connection');
            socket.emit('request_status');
        });

        socket.on('disconnect', () => {
            console.log('[WS] Disconnected (polling still active)');
        });

        socket.on('status_update', (data) => {
            updateStatusDisplay(data);
        });

        socket.on('connection_update', (data) => {
            updateConnectionDisplay(data.connected, data.host);
            if (data.interfaces) {
                updateInterfaceDisplay(data.interfaces, data.detection_status);
            }
        });

        socket.on('connect_error', () => {
            console.log('[WS] Connection error (polling still active)');
        });
    } catch (e) {
        console.log('[WS] Init error, using polling only:', e);
    }
}

// ============== Polling Fallback ==============
function startPolling() {
    // Prevent stacking: clear any existing timers first
    if (_pollingStatusTimer) clearInterval(_pollingStatusTimer);

    _pollingStatusTimer = setInterval(async () => {
        try {
            const response = await fetch('/api/status');
            const data = await response.json();
            updateStatusDisplay(data);
        } catch (e) {
            console.error('[Polling] Status error:', e);
        }
    }, STATUS_UPDATE_INTERVAL);

    checkConnection();
}

// ============== Connection ==============
async function checkConnection() {
    const dot = document.getElementById('connectionDot');
    const text = document.getElementById('connectionText');

    if (dot) dot.className = 'status-dot checking';
    if (text) text.textContent = 'Checking connection...';

    try {
        const response = await fetch('/api/test_connection');
        const data = await response.json();

        // Store the host from the API so we never hard-code it
        if (data.host) _routerHost = data.host;

        updateConnectionDisplay(data.connected, data.host);

        if (data.connected && !window.interfacesDetected) {
            detectInterfaces();
        }
    } catch (e) {
        console.error('[Connection] Check failed:', e);
        updateConnectionDisplay(false);
    }
}

function updateConnectionDisplay(connected, host) {
    const dot = document.getElementById('connectionDot');
    const text = document.getElementById('connectionText');
    const displayHost = host || _routerHost || 'Router';

    if (dot) {
        dot.className = 'status-dot ' + (connected ? 'connected' : 'disconnected');
    }
    if (text) {
        text.textContent = connected
            ? displayHost + ' Connected'
            : displayHost + ' Disconnected - Click to diagnose';
    }
    isConnected = connected;
}

// ============== Interface Detection ==============
async function detectInterfaces() {
    try {
        const response = await fetch('/api/interface_mapping');
        const data = await response.json();

        if (data.interfaces) {
            updateInterfaceDisplay(data.interfaces, data.detection_status);
            window.interfacesDetected = true;

            if (data.channel_config) {
                updateChannelConfigUI(data.channel_config);
            }
        }
    } catch (e) {
        console.error('[Interfaces] Detection error:', e);
    }
}

function updateChannelConfigUI(config) {
    for (const [band, cfg] of Object.entries(config)) {
        const bandLower = band.toLowerCase();
        const channelSelect = document.getElementById('channel-' + bandLower);
        const bandwidthSelect = document.getElementById('bandwidth-' + bandLower);
        const channelLabel = document.getElementById('current-ch-' + bandLower);

        if (channelSelect && cfg.channel) {
            const channelValue = String(cfg.channel);
            let found = false;
            for (let option of channelSelect.options) {
                if (option.value === channelValue) {
                    channelSelect.value = channelValue;
                    found = true;
                    break;
                }
            }
            if (!found) {
                const opt = document.createElement('option');
                opt.value = channelValue;
                opt.textContent = 'CH ' + channelValue;
                channelSelect.appendChild(opt);
                channelSelect.value = channelValue;
            }
        }

        if (bandwidthSelect && cfg.bandwidth) {
            const bwValue = cfg.bandwidth;
            let found = false;
            for (let option of bandwidthSelect.options) {
                if (option.value === bwValue) {
                    bandwidthSelect.value = bwValue;
                    found = true;
                    break;
                }
            }
            if (!found) {
                const opt = document.createElement('option');
                opt.value = bwValue;
                opt.textContent = bwValue;
                bandwidthSelect.appendChild(opt);
                bandwidthSelect.value = bwValue;
            }
        }

        if (channelLabel) {
            channelLabel.textContent = 'CH ' + cfg.channel;
        }
    }
}

function updateInterfaceDisplay(interfaces, detectionStatus) {
    const mapping2G = document.getElementById('mapping2G');
    const mapping5G = document.getElementById('mapping5G');
    const mapping6G = document.getElementById('mapping6G');
    const badge = document.getElementById('detectionBadge');

    if (mapping2G) mapping2G.textContent = '2G=' + interfaces['2G'];
    if (mapping5G) mapping5G.textContent = '5G=' + interfaces['5G'];
    if (mapping6G) mapping6G.textContent = '6G=' + interfaces['6G'];

    if (badge && detectionStatus) {
        badge.textContent = detectionStatus.detected ? '\u2713 Auto-detected' : 'Default';
        badge.classList.toggle('detection-badge--detected', detectionStatus.detected);
    }

    const iface2g = document.getElementById('iface-2g');
    const iface5g = document.getElementById('iface-5g');
    const iface6g = document.getElementById('iface-6g');

    if (iface2g) iface2g.textContent = interfaces['2G'];
    if (iface5g) iface5g.textContent = interfaces['5G'];
    if (iface6g) iface6g.textContent = interfaces['6G'];
}

async function redetectInterfaces() {
    setLoading(true);
    try {
        const response = await fetch('/api/detect_interfaces', { method: 'POST' });
        const data = await response.json();

        if (data.success) {
            updateInterfaceDisplay(data.interfaces, data.detection_status);
            showNotification(data.message, 'success');
        } else {
            showNotification('Interface detection failed. Using default mapping.', 'error');
        }
    } catch (e) {
        showNotification('Detection error: ' + e.message, 'error');
    }
    setLoading(false);
}

// ============== Status Updates ==============
function updateStatusDisplay(data) {
    for (const [band, info] of Object.entries(data)) {
        const bandLower = band.toLowerCase();
        const statusEl = document.getElementById('status-' + bandLower);
        const durationEl = document.getElementById('duration-' + bandLower);
        const packetsEl = document.getElementById('packets-' + bandLower);

        if (statusEl) {
            statusEl.textContent = info.running ? 'CAPTURING' : 'IDLE';
            statusEl.className = 'status-badge ' + (info.running ? 'status-running' : 'status-idle');
        }
        if (durationEl) durationEl.textContent = info.duration || '--:--';
        if (packetsEl) packetsEl.textContent = info.file_size_display || '0 bytes';

        updateCaptureButtons(band, info.running);
    }
}

function updateCaptureButtons(band, running) {
    const bandLower = band.toLowerCase();
    const startBtn = document.querySelector('.card-' + bandLower + ' .btn-start');
    const stopBtn = document.querySelector('.card-' + bandLower + ' .btn-stop');

    if (startBtn) {
        startBtn.disabled = running;
        startBtn.classList.toggle('btn-disabled', running);
    }
    if (stopBtn) {
        stopBtn.disabled = !running;
        stopBtn.classList.toggle('btn-disabled', !running);
    }
}

// ============== Capture Controls ==============
async function startCapture(band) {
    setLoading(true);
    try {
        const response = await fetch('/api/start/' + band, { method: 'POST' });
        const data = await response.json();
        showNotification(data.message, data.success ? 'success' : 'error');
        if (data.success) setTimeout(refreshStatus, 500);
    } catch (e) {
        showNotification('Error: ' + e.message, 'error');
    }
    setLoading(false);
}

async function stopCapture(band) {
    setLoading(true);
    try {
        const response = await fetch('/api/stop/' + band, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                product_name: (document.getElementById('productName') || {}).value || '',
                sw_version: (document.getElementById('swVersion') || {}).value || ''
            })
        });
        const data = await response.json();
        showNotification(data.message, data.success ? 'success' : 'error');
        if (data.success) setTimeout(refreshStatus, 500);
    } catch (e) {
        showNotification('Error: ' + e.message, 'error');
    }
    setLoading(false);
}

async function startAll() {
    setLoading(true);
    try {
        const response = await fetch('/api/start_all', { method: 'POST' });
        const data = await response.json();
        showNotification('Started captures for: ' + Object.keys(data.results).join(', '), 'success');
        setTimeout(refreshStatus, 500);
    } catch (e) {
        showNotification('Error: ' + e.message, 'error');
    }
    setLoading(false);
}

async function stopAll() {
    setLoading(true);
    try {
        const response = await fetch('/api/stop_all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                product_name: (document.getElementById('productName') || {}).value || '',
                sw_version: (document.getElementById('swVersion') || {}).value || ''
            })
        });
        const data = await response.json();
        let savedBands = [];
        let noFileBands = [];
        let errorBands = [];

        const resultEntries = Object.entries(data.results);

        const allSshFailed = resultEntries.every(([, r]) =>
            r.message && r.message.includes('SSH error'));

        if (allSshFailed && resultEntries.length > 0) {
            showNotification('SSH connection to router failed. Check connection.', 'error');
            setTimeout(refreshStatus, 500);
            setLoading(false);
            return;
        }

        for (const [band, result] of resultEntries) {
            if (result.success && result.path) {
                savedBands.push(band);
            } else if (result.message && result.message.includes('No capture file')) {
                noFileBands.push(band);
            } else {
                errorBands.push(band);
            }
        }

        if (savedBands.length > 0) {
            let msg = 'Downloaded: ' + savedBands.join(', ');
            if (noFileBands.length > 0) msg += ' | No files: ' + noFileBands.join(', ');
            showNotification(msg, 'success');
        } else if (noFileBands.length === 3) {
            showNotification('No capture files on router (captures may not have been started)', 'warning');
        } else if (noFileBands.length > 0) {
            showNotification('No capture files found on router', 'warning');
        } else if (errorBands.length > 0) {
            showNotification('Download failed for: ' + errorBands.join(', '), 'error');
        } else {
            showNotification('Operation completed', 'info');
        }
        setTimeout(refreshStatus, 500);
    } catch (e) {
        showNotification('Error: ' + e.message, 'error');
    }
    setLoading(false);
}

// ============== Stop All Confirmation ==============
function confirmStopAllPrompt() {
    const modal = document.getElementById('stopAllModal');
    if (modal) modal.style.display = 'flex';
}

function closeStopAllModal() {
    const modal = document.getElementById('stopAllModal');
    if (modal) modal.style.display = 'none';
}

async function confirmStopAll() {
    closeStopAllModal();
    await stopAll();
}

// ============== Configuration ==============
async function applyConfig(band) {
    const channel = document.getElementById('channel-' + band.toLowerCase()).value;
    const bandwidth = document.getElementById('bandwidth-' + band.toLowerCase()).value;

    setLoading(true);
    try {
        const response = await fetch('/api/config/' + band, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ channel: channel, bandwidth: bandwidth })
        });
        const data = await response.json();
        showNotification(data.message + ' (Click "Apply Config & Restart WiFi" to commit)', data.success ? 'success' : 'error');
    } catch (e) {
        showNotification('Error: ' + e.message, 'error');
    }
    setLoading(false);
}

async function applyAllConfig() {
    const configPromises = ['2G', '5G', '6G'].map(band => {
        const channel = document.getElementById('channel-' + band.toLowerCase()).value;
        const bandwidth = document.getElementById('bandwidth-' + band.toLowerCase()).value;
        return fetch('/api/config/' + band, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ channel: channel, bandwidth: bandwidth })
        });
    });
    await Promise.all(configPromises);

    const modal = document.getElementById('configModal');
    const status = document.getElementById('configStatus');
    const spinner = document.getElementById('configSpinner');
    const complete = document.getElementById('configComplete');

    modal.style.display = 'flex';
    spinner.style.display = 'block';
    complete.style.display = 'none';
    status.innerHTML = '<div class="config-line info">Starting configuration...</div>';

    try {
        for (const band of ['2G', '5G', '6G']) {
            const ch = document.getElementById('channel-' + band.toLowerCase()).value;
            const bw = document.getElementById('bandwidth-' + band.toLowerCase()).value;
            status.innerHTML += '<div class="config-line">' + band + ': CH ' + ch + ', ' + bw + '</div>';
        }

        status.innerHTML += '<div class="config-line info">Sending to OpenWrt...</div>';

        const response = await fetch('/api/apply_config', { method: 'POST' });
        const data = await response.json();

        if (data.messages) {
            for (const msg of data.messages) {
                const cssClass = msg.includes('failed') || msg.includes('Failed') ? 'error' :
                    msg.includes('ready') || msg.includes('success') || msg.includes('Saved') ? 'success' : 'info';
                status.innerHTML += '<div class="config-line ' + cssClass + '">' + escapeHtml(msg) + '</div>';
            }
        }

        if (data.interface_status) {
            status.innerHTML += '<div class="config-line success">Interface Status:</div>';
            status.innerHTML += '<pre class="config-interface-status">' + escapeHtml(data.interface_status) + '</pre>';
        }

        spinner.style.display = 'none';
        complete.style.display = 'block';

        if (data.success) {
            status.innerHTML += '<div class="config-line success">All configurations applied successfully!</div>';
        } else {
            status.innerHTML += '<div class="config-line error">Configuration failed. Check messages above.</div>';
        }
    } catch (e) {
        status.innerHTML += '<div class="config-line error">Error: ' + e.message + '</div>';
        spinner.style.display = 'none';
        complete.style.display = 'block';
    }

    status.scrollTop = status.scrollHeight;
}

function closeConfigModal() {
    document.getElementById('configModal').style.display = 'none';
    refreshStatus();
}

// ============== Time Sync ==============
async function updateTimeDisplay() {
    try {
        const response = await fetch('/api/time_info');
        const data = await response.json();

        const pcTime = document.getElementById('pcTime');
        const openwrtTime = document.getElementById('openwrtTime');
        const badge = document.getElementById('timeOffsetBadge');

        if (pcTime) pcTime.textContent = data.pc_time ? data.pc_time.split(' ')[1] : '--:--:--';
        if (openwrtTime) openwrtTime.textContent = data.openwrt_time ? data.openwrt_time.split(' ')[1] : '--:--:--';

        if (badge && data.offset_seconds !== null) {
            const absOffset = Math.abs(data.offset_seconds);
            badge.classList.remove('time-badge--synced', 'time-badge--warning', 'time-badge--error');
            if (absOffset < 2) {
                badge.textContent = '\u2713 Synced';
                badge.classList.add('time-badge--synced');
            } else if (absOffset < 60) {
                badge.textContent = (data.offset_seconds > 0 ? '+' : '') + data.offset_seconds.toFixed(0) + 's';
                badge.classList.add('time-badge--warning');
            } else {
                const minutes = Math.round(absOffset / 60);
                badge.textContent = (data.offset_seconds > 0 ? '+' : '-') + minutes + 'm';
                badge.classList.add('time-badge--error');
            }
        }
    } catch (e) {
        console.error('[Time] Update failed:', e);
    }
}

async function manualSyncTime() {
    setLoading(true);
    try {
        const response = await fetch('/api/sync_time', { method: 'POST' });
        const data = await response.json();
        if (data.success) {
            showNotification('Time synchronized successfully!', 'success');
            updateTimeDisplay();
        } else {
            showNotification('Time sync failed: ' + data.message, 'error');
        }
    } catch (e) {
        showNotification('Time sync error: ' + e.message, 'error');
    }
    setLoading(false);
}

// ============== File Split ==============
async function loadFileSplitSettings() {
    try {
        const response = await fetch('/api/file_split');
        const data = await response.json();

        const checkbox = document.getElementById('fileSplitEnabled');
        const sizeSelect = document.getElementById('fileSplitSize');

        if (checkbox) checkbox.checked = data.enabled;
        if (sizeSelect) sizeSelect.value = data.size_mb;

        updateFileSplitUI(data.enabled, data.size_mb);
    } catch (e) {
        console.error('[FileSplit] Load error:', e);
    }
}

async function updateFileSplit() {
    const checkbox = document.getElementById('fileSplitEnabled');
    const sizeSelect = document.getElementById('fileSplitSize');

    const enabled = checkbox ? checkbox.checked : false;
    const size_mb = sizeSelect ? parseInt(sizeSelect.value) : 200;

    updateFileSplitUI(enabled, size_mb);

    try {
        const response = await fetch('/api/file_split', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled, size_mb: size_mb })
        });
        const data = await response.json();
        if (data.success) showNotification(data.message, 'success');
    } catch (e) {
        showNotification('Failed to update file split settings: ' + e.message, 'error');
    }
}

function updateFileSplitUI(enabled, size_mb) {
    const sizeContainer = document.getElementById('fileSplitSizeContainer');
    const statusDiv = document.getElementById('fileSplitStatus');
    const splitNote = document.getElementById('splitFileNote');

    if (sizeContainer) sizeContainer.style.opacity = enabled ? '1' : '0.5';

    if (statusDiv) {
        if (enabled) {
            statusDiv.innerHTML = 'Split enabled: <strong>' + size_mb + ' MB</strong> per file';
            statusDiv.className = 'file-split-status file-split-status--active';
        } else {
            statusDiv.textContent = 'Continuous capture (no split)';
            statusDiv.className = 'file-split-status';
        }
    }

    if (splitNote) splitNote.style.display = enabled ? 'block' : 'none';
}

// ============== Capture Info (Product Name / SW Version) ==============
const CAPTURE_INFO_REGEX = /^[a-zA-Z0-9._-]{0,30}$/;

async function loadCaptureInfo() {
    try {
        const response = await fetch('/api/capture_info');
        const data = await response.json();
        const productInput = document.getElementById('productName');
        const swInput = document.getElementById('swVersion');
        if (productInput && data.product_name) productInput.value = data.product_name;
        if (swInput && data.sw_version) swInput.value = data.sw_version;
        updateCaptureInfoStatus();
    } catch (e) {
        console.error('[CaptureInfo] Load error:', e);
    }
}

async function saveCaptureInfo() {
    const productInput = document.getElementById('productName');
    const swInput = document.getElementById('swVersion');
    const product = productInput ? productInput.value.trim() : '';
    const sw = swInput ? swInput.value.trim() : '';

    // Validate
    if (product && !CAPTURE_INFO_REGEX.test(product)) {
        showNotification('Product name contains invalid characters. Use only letters, numbers, dot, underscore, hyphen.', 'error');
        return;
    }
    if (sw && !CAPTURE_INFO_REGEX.test(sw)) {
        showNotification('Software version contains invalid characters. Use only letters, numbers, dot, underscore, hyphen.', 'error');
        return;
    }

    try {
        const response = await fetch('/api/capture_info', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ product_name: product, sw_version: sw })
        });
        const data = await response.json();
        if (data.success) {
            showNotification(data.message, 'success');
            updateCaptureInfoStatus();
        } else {
            showNotification(data.message || 'Failed to save capture info', 'error');
        }
    } catch (e) {
        showNotification('Error saving capture info: ' + e.message, 'error');
    }
}

function getCaptureInfoPrefix() {
    const product = (document.getElementById('productName') || {}).value || '';
    const sw = (document.getElementById('swVersion') || {}).value || '';
    const parts = [];
    if (product.trim()) parts.push(product.trim());
    if (sw.trim()) parts.push(sw.trim());
    return parts.join('_');
}

function updateCaptureInfoStatus() {
    const statusDiv = document.getElementById('captureInfoStatus');
    if (!statusDiv) return;
    const prefix = getCaptureInfoPrefix();
    if (prefix) {
        statusDiv.innerHTML = 'Filename format: <code class="code-inline">' +
            escapeHtml(prefix) + '_{Band}_sniffer_{timestamp}.pcap</code>';
    } else {
        statusDiv.innerHTML = 'Filename format: <code class="code-inline">{Band}_sniffer_{timestamp}.pcap</code>';
    }
}

// Auto-update filename preview on input change
document.addEventListener('DOMContentLoaded', () => {
    const productInput = document.getElementById('productName');
    const swInput = document.getElementById('swVersion');
    if (productInput) productInput.addEventListener('input', updateCaptureInfoStatus);
    if (swInput) swInput.addEventListener('input', updateCaptureInfoStatus);
});

// ============== WiFi Config ==============
async function loadCurrentWifiConfig() {
    try {
        const response = await fetch('/api/get_wifi_config');
        const data = await response.json();
        if (data.success && data.config) {
            updateChannelConfigUI(data.config);
            showNotification('Loaded current WiFi configuration from OpenWrt (UCI; runtime channel may differ after Apply Config)', 'success');
        }
    } catch (e) {
        console.error('[CONFIG] Load error:', e);
    }
}

async function refreshWifiConfig() {
    setLoading(true);
    try {
        const response = await fetch('/api/get_wifi_config');
        const data = await response.json();
        if (data.success && data.config) {
            updateChannelConfigUI(data.config);
            showNotification('WiFi configuration refreshed from OpenWrt (UCI; runtime channel may differ after Apply Config)', 'success');
        } else {
            showNotification('Failed to refresh WiFi config', 'error');
        }
    } catch (e) {
        showNotification('Error refreshing config: ' + e.message, 'error');
    }
    setLoading(false);
}

// ============== Diagnostics ==============
async function diagnoseConnection() {
    setLoading(true);
    try {
        const response = await fetch('/api/diagnose');
        const data = await response.json();

        const pwStatus = data.password_set
            ? '<span class="diagnose-value--ok">Yes</span>'
            : '<span class="diagnose-value--fail">No</span>';
        const keysStatus = data.ssh_keys_found && data.ssh_keys_found.length > 0
            ? '<span class="diagnose-value--ok">' + escapeHtml(data.ssh_keys_found.join(', ')) + '</span>'
            : '<span class="diagnose-value--neutral">None</span>';
        const pingStatus = data.ping_test
            ? '<span class="diagnose-value--ok">\u2713 OK</span>'
            : '<span class="diagnose-value--fail">\u2717 Failed</span>';
        const sshStatus = data.ssh_test
            ? '<span class="diagnose-value--ok">\u2713 OK</span>'
            : '<span class="diagnose-value--fail">\u2717 Failed</span>';
        const errorBlock = data.error
            ? '<div class="diagnose-error-block"><strong>Error:</strong> ' + escapeHtml(data.error) + '</div>'
            : '';

        const statusHtml = '<div class="diagnose-info-block">' +
            '<div class="diagnose-info-row"><strong>Host:</strong> ' + escapeHtml(data.host) + ':' + escapeHtml(String(data.port)) + '</div>' +
            '<div class="diagnose-info-row"><strong>User:</strong> ' + escapeHtml(data.user) + '</div>' +
            '<div class="diagnose-info-row"><strong>Password Set:</strong> ' + pwStatus + '</div>' +
            '<div class="diagnose-info-row"><strong>SSH Keys Found:</strong> ' + keysStatus + '</div>' +
            '<div class="diagnose-info-row"><strong>Ping Test:</strong> ' + pingStatus + '</div>' +
            '<div class="diagnose-info-row"><strong>SSH Test:</strong> ' + sshStatus + '</div>' +
            errorBlock +
            '</div>';

        let solutionHtml = '';
        if (!data.ssh_test && data.solution_text) {
            solutionHtml = '<div class="diagnose-solution-block">' +
                '<div class="diagnose-solution-title">Solution</div>' +
                '<div class="diagnose-solution-text">' + data.solution_text + '</div>' +
                '</div>';
        }

        showDiagnoseModal(statusHtml, solutionHtml, data.ssh_test);
    } catch (e) {
        alert('Diagnosis failed: ' + e.message);
    }
    setLoading(false);
}

function showDiagnoseModal(statusHtml, solutionHtml) {
    const existingModal = document.getElementById('diagnoseModal');
    if (existingModal) existingModal.remove();

    const modal = document.createElement('div');
    modal.id = 'diagnoseModal';
    modal.className = 'diagnose-modal-overlay';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-label', 'Connection Diagnosis');
    modal.innerHTML =
        '<div class="diagnose-modal-content">' +
        '<div class="diagnose-modal-header">' +
        '<h3 class="diagnose-modal-title">Connection Diagnosis</h3>' +
        '<button onclick="closeDiagnoseModal()" class="diagnose-modal-close" aria-label="Close">&times;</button>' +
        '</div>' +
        statusHtml +
        solutionHtml +
        '<div class="diagnose-modal-footer">' +
        '<button onclick="closeDiagnoseModal()" class="btn btn-refresh">OK</button>' +
        '</div>' +
        '</div>';
    document.body.appendChild(modal);
}

function closeDiagnoseModal() {
    const modal = document.getElementById('diagnoseModal');
    if (modal) modal.remove();
}

// ============== Utilities ==============

/**
 * Escape HTML special characters to prevent XSS when inserting API data.
 */
function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function showNotification(message, type) {
    type = type || 'success';
    const notif = document.getElementById('notification');
    const text = document.getElementById('notificationText');
    const progress = document.getElementById('notificationProgress');

    if (notif && text) {
        notif.className = 'notification ' + type;
        text.textContent = message;
        notif.style.display = 'block';

        if (progress) {
            progress.style.animation = 'none';
            void progress.offsetHeight;
            progress.style.animation = '';
        }

        clearTimeout(window._notifTimer);
        window._notifTimer = setTimeout(dismissNotification, 5000);
    }
}

function dismissNotification() {
    const notif = document.getElementById('notification');
    if (notif) notif.style.display = 'none';
    clearTimeout(window._notifTimer);
}

function setLoading(show) {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.classList.toggle('active', show);
}

async function refreshStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        updateStatusDisplay(data);
    } catch (e) {
        console.error('[Status] Refresh error:', e);
    }
}

// ============== Initialization ==============
document.addEventListener('DOMContentLoaded', () => {
    console.log('[App] Initializing v4...');

    initWebSocket();
    checkConnection();

    setTimeout(() => {
        loadCurrentWifiConfig();
        loadFileSplitSettings();
        loadCaptureInfo();
        updateTimeDisplay();
    }, 1000);

    // Clear any previous time-update interval before creating a new one
    if (_pollingTimeTimer) clearInterval(_pollingTimeTimer);
    _pollingTimeTimer = setInterval(updateTimeDisplay, 5000);

    console.log('[App] v4 Initialized');
});

// Export for HTML onclick handlers
window.startCapture = startCapture;
window.stopCapture = stopCapture;
window.startAll = startAll;
window.stopAll = stopAll;
window.confirmStopAllPrompt = confirmStopAllPrompt;
window.closeStopAllModal = closeStopAllModal;
window.confirmStopAll = confirmStopAll;
window.applyConfig = applyConfig;
window.applyAllConfig = applyAllConfig;
window.closeConfigModal = closeConfigModal;
window.refreshStatus = refreshStatus;
window.manualSyncTime = manualSyncTime;
window.updateFileSplit = updateFileSplit;
window.redetectInterfaces = redetectInterfaces;
window.diagnoseConnection = diagnoseConnection;
window.closeDiagnoseModal = closeDiagnoseModal;
window.loadCurrentWifiConfig = loadCurrentWifiConfig;
window.refreshWifiConfig = refreshWifiConfig;
window.dismissNotification = dismissNotification;
window.escapeHtml = escapeHtml;
window.saveCaptureInfo = saveCaptureInfo;
window.loadCaptureInfo = loadCaptureInfo;
