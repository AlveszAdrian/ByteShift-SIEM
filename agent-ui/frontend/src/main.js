import { LoadConfig, SaveConfig } from '../wailsjs/go/main/App.js';

let config = {
    manager_ip: 'localhost',
    file_paths: [],
    syslog_port: 0,
    win_events: ['System', 'Application', 'Security']
};

// ─── Navigation ───────────────────────────────────────────────────────────────
window.showSection = function(name, btnElement) {
    try {
        document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.getElementById('sec-' + name).classList.add('active');
        
        if (btnElement) {
            // If they click inside the span/icon, find the parent .nav-item
            const item = btnElement.closest('.nav-item') || btnElement;
            item.classList.add('active');
        } else {
            const fallback = document.querySelector(`a[onclick*="${name}"]`);
            if (fallback) fallback.classList.add('active');
        }
    } catch(err) {
        alert("Navigation Error: " + err);
    }
};

// ─── Tag management ───────────────────────────────────────────────────────────
window.addFilePath = function() {
    const input = document.getElementById('newFilePath');
    const val = input.value.trim();
    if (!val || config.file_paths.includes(val)) { input.value = ''; return; }
    config.file_paths.push(val);
    input.value = '';
    renderFilePaths();
};

window.removeFilePath = function(idx) {
    config.file_paths.splice(idx, 1);
    renderFilePaths();
};

function renderFilePaths() {
    const list = document.getElementById('filePathsList');
    list.innerHTML = config.file_paths.map((p, i) =>
        `<span class="tag"><span>${p}</span><span class="tag-x" onclick="removeFilePath(${i})">✕</span></span>`
    ).join('');
}

window.addWinEvent = function() {
    const input = document.getElementById('newWinEvent');
    const val = input.value.trim();
    if (!val || config.win_events.includes(val)) { input.value = ''; return; }
    config.win_events.push(val);
    input.value = '';
    renderWinEvents();
};

window.removeWinEvent = function(idx) {
    config.win_events.splice(idx, 1);
    renderWinEvents();
};

function renderWinEvents() {
    const list = document.getElementById('winEventsList');
    list.innerHTML = config.win_events.map((e, i) =>
        `<span class="tag"><span>${e}</span><span class="tag-x" onclick="removeWinEvent(${i})">✕</span></span>`
    ).join('');
}

// ─── Save & Connect ───────────────────────────────────────────────────────────
window.saveAndConnect = function() {
    try {
        const ip   = document.getElementById('managerIp').value.trim();
        const port = parseInt(document.getElementById('managerPort').value) || 50051;
        const syslogPort = parseInt(document.getElementById('syslogPort').value) || 0;

        config.manager_ip  = ip ? `${ip}:${port}` : 'localhost:50051';
        config.syslog_port = syslogPort;

        setStatus('connecting', `Connecting to ${config.manager_ip}…`);

        SaveConfig(config).then(msg => {
            const ok = msg.includes('success') || msg.includes('saved');
            const statusEl = document.getElementById('saveMsg');
            const statusEl2 = document.getElementById('saveMsgSources');
            
            if (statusEl) statusEl.textContent = msg;
            if (statusEl2) statusEl2.textContent = msg;

            if (ok) {
                setStatus('online', `Connected to ${config.manager_ip}`);
            } else {
                setStatus('offline', msg);
            }

            updateStatusTab();

            setTimeout(() => {
                if (statusEl) statusEl.textContent = '';
                if (statusEl2) statusEl2.textContent = '';
            }, 4000);
        }).catch(err => {
            setStatus('offline', String(err));
            alert("SaveConfig Backend Error: " + err);
        });
    } catch (err) {
        alert("UI Save Error: " + err);
    }
};

// ─── Status helpers ───────────────────────────────────────────────────────────
function setStatus(state, detail) {
    const dot  = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    const det  = document.getElementById('statusDetail');

    dot.className = 'dot';
    if (state === 'online')      { dot.classList.add('online');  text.textContent = 'Connected'; }
    else if (state === 'offline'){ dot.classList.add('offline'); text.textContent = 'Error'; }
    else                         { text.textContent = 'Connecting…'; }

    det.textContent = detail || '';
}

function updateStatusTab() {
    document.getElementById('statManager').textContent = config.manager_ip || '—';
    document.getElementById('statFiles').textContent   = config.file_paths.length;
    document.getElementById('statWin').textContent     = config.win_events.length;
    document.getElementById('statSyslog').textContent  = config.syslog_port > 0 ? `UDP:${config.syslog_port}` : 'Off';
}

// ─── Load on startup ──────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
    try {
        const saved = await LoadConfig();
        if (saved && saved.manager_ip) {
            config = saved;
            // Populate form fields
            const [ip, rawPort] = (saved.manager_ip || 'localhost:50051').split(':');
            document.getElementById('managerIp').value = ip || '';
            document.getElementById('managerPort').value = rawPort || '50051';
            document.getElementById('syslogPort').value = saved.syslog_port || '';
        }
    } catch(e) {
        console.error('LoadConfig failed:', e);
    }

    renderFilePaths();
    renderWinEvents();
    updateStatusTab();

    // If already configured, show as reconnecting
    if (config.manager_ip) {
        setStatus('online', `Configured: ${config.manager_ip}`);
    }
});

// Allow pressing Enter to add items
document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    if (document.activeElement.id === 'newFilePath') addFilePath();
    if (document.activeElement.id === 'newWinEvent') addWinEvent();
});
