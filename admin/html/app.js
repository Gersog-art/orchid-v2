// ORCHID Admin Panel JavaScript - Clean Version

var darkTheme = true;
var soundEnabled = true;
var blockedIpsMap = {};
var lastAttackCount = 0;
var defenseEnabled = false;
var autoDefenseEnabled = false;
var autoBlockEnabled = false;

const catAudio = document.getElementById('catSound');

const mlServices = [
    { name: 'Isolation Forest', port: 8001, url: '/api/ml/isolation/health' },
    { name: 'Random Forest', port: 8002, url: '/api/ml/random/health' },
    { name: 'DDoS Detector', port: 8005, url: '/api/ml/ddos/health' },
    { name: 'Exploit Analyzer', port: 8006, url: '/api/ml/exploit/health' },
    { name: 'Anomaly Detection', port: 8007, url: '/api/ml/anomaly/health' },
    { name: 'Attack Classifier', port: 8008, url: '/api/ml/classifier/health' },
    { name: 'NLP Analysis', port: 8009, url: '/api/ml/nlp/health' },
    { name: 'IP Reputation', port: 8010, url: '/api/ml/ip-reputation/health' },
    { name: 'Rate Limiter', port: 8011, url: '/api/ml/rate-limiter/health' },
    { name: 'Behavioral Analysis', port: 8012, url: '/api/ml/behavioral/health' },
    { name: 'Performance Monitor', port: 8013, url: '/api/ml/performance/health' },
    { name: 'Admin Backend', port: 8003, url: '/api/health' },
    { name: 'DDoS Backend', port: 8004, url: '/ddos-api/api/health' }
];

function updateClock() {
    document.getElementById('systemClock').textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

function toggleTheme() {
    darkTheme = !darkTheme;
    document.documentElement.setAttribute('data-theme', darkTheme ? 'dark' : 'light');
    document.getElementById('theme-toggle').querySelector('i').className = darkTheme ? 'fas fa-moon' : 'fas fa-sun';
}

function toggleSound() {
    soundEnabled = !soundEnabled;
    document.getElementById('sound-toggle').querySelector('i').className = soundEnabled ? 'fas fa-volume-high' : 'fas fa-volume-xmark';
    localStorage.setItem('orchid-sound', soundEnabled ? 'on' : 'off');
    addActivity(soundEnabled ? 'Sound enabled' : 'Muted', 'info');
}

function playCatSound() {
    if (!soundEnabled) return;
    try {
        catAudio.currentTime = 0;
        catAudio.volume = 0.5;
        catAudio.play().catch(function(e) { console.log('Sound error:', e); });
    } catch (e) { console.log('Sound error:', e); }
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
    event.target.closest('.tab-btn').classList.add('active');
    document.getElementById(tabId).classList.add('active');
    if (tabId === 'dashboard') loadDashboard();
    if (tabId === 'attacks') loadAttacks();
    if (tabId === 'exploits') loadExploits();
    if (tabId === 'ddos') loadDdos();
    if (tabId === 'ml') loadMLServices();
    if (tabId === 'system') loadSystemStatus();
}

function addActivity(text, type) {
    type = type || 'info';
    var feed = document.getElementById('activityFeed');
    var time = new Date().toLocaleTimeString();
    var icon = type === 'success' ? 'check-circle' : type === 'danger' ? 'exclamation-triangle' : 'info-circle';
    var item = document.createElement('div');
    item.className = 'activity-item';
    item.innerHTML = '<span class="activity-time">' + time + '</span><span class="activity-icon ' + type + '"><i class="fas fa-' + icon + '"></i></span><span class="activity-text">' + text + '</span>';
    feed.insertBefore(item, feed.firstChild);
    while (feed.children.length > 20) feed.removeChild(feed.lastChild);
}

async function loadDashboard() {
    await loadStats();
    await loadAttackTypes();
    addActivity('Dashboard refreshed', 'info');
}

async function loadStats() {
    try {
        var response = await fetch('/api/stats');
        var data = await response.json();
        document.getElementById('totalAttacks').textContent = (data.total_attacks || 0).toLocaleString();
        document.getElementById('detectedAttacks').textContent = (data.detected_attacks || 0).toLocaleString();
        document.getElementById('uniqueIps').textContent = (data.unique_ips || 0).toLocaleString();
        document.getElementById('blockedIps').textContent = (data.blocked_count || 0).toLocaleString();
        if (data.total_attacks > lastAttackCount && lastAttackCount > 0) {
            playCatSound();
            addActivity('New attacks! +' + (data.total_attacks - lastAttackCount), 'warning');
        }
        lastAttackCount = data.total_attacks;
    } catch (e) { console.log('Stats error:', e); }
}

async function loadAttackTypes() {
    var grid = document.getElementById('attackTypesGrid');
    try {
        var response = await fetch('/api/stats');
        var data = await response.json();
        var types = data.attack_types || {};
        var typeIcons = {
            'sqli':'fa-database', 'xss':'fa-code', 'rce':'fa-terminal', 'lfi':'fa-folder-open',
            'ddos':'fa-bomb', 'xxe':'fa-file-code', 'ssrf':'fa-globe', 'csrf':'fa-shield-alt',
            'ssti':'fa-brush', 'nosql':'fa-database', 'path_traversal':'fa-path',
            'command_injection':'fa-terminal', 'cors':'fa-exchange-alt', 'soap':'fa-soap',
            'unknown':'fa-question', 'ldap':'fa-sitemap', 'host_header':'fa-globe',
            'xml_injection':'fa-code', 'file_upload':'fa-upload', 'http_smuggling':'fa-exchange',
            'graphql':'fa-query', 'openid':'fa-openid'
        };
        var typeColors = {
            'sqli':'#ff6b81', 'xss':'#feca2a', 'rce':'#ff4757', 'lfi':'#ffa502',
            'ddos':'#ff6b81', 'xxe':'#ff7f50', 'ssrf':'#70a1ff', 'csrf':'#ff4757',
            'ssti':'#ff6b81', 'nosql':'#ff7f50', 'path_traversal':'#ffa502',
            'command_injection':'#ff4757', 'cors':'#70a1ff', 'soap':'#ff7f50',
            'unknown':'#a0a0a0', 'ldap':'#a55eea', 'host_header':'#45aaf2',
            'xml_injection':'#fd9644', 'file_upload':'#fa8231', 'http_smuggling':'#20bf6b',
            'graphql':'#eb3b5a', 'openid':'#8854d0'
        };
        grid.innerHTML = '';
        for (var type in types) {
            if (types.hasOwnProperty(type)) {
                var count = types[type];
                var card = document.createElement('div');
                card.className = 'attack-type-card';
                var icon = typeIcons[type.toLowerCase()] || 'fa-question';
                var color = typeColors[type.toLowerCase()] || '#a0a0a0';
                card.innerHTML = '<div class="attack-type-count" style="color:' + color + ';">' + count.toLocaleString() + '</div><div class="attack-type-name"><i class="fas ' + icon + '"></i> ' + type.replace(/_/g, ' ') + '</div>';
                grid.appendChild(card);
            }
        }
    } catch (e) {
        grid.innerHTML = '<div class="loading" style="color:var(--danger);">Error loading attack types</div>';
    }
}

function escapeHtml(text) {
    if (!text) return 'N/A';
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function loadAttacks() {
    var list = document.getElementById('attackList');
    try {
        var response = await fetch('/api/attacks/recent?limit=50');
        var data = await response.json();
        list.innerHTML = '';
        if (data.attacks && data.attacks.length > 0) {
            data.attacks.forEach(function(attack, idx) {
                var type = (attack.attack_type || 'unknown').toLowerCase();
                var item = document.createElement('div');
                item.className = 'attack-item';
                var isBlocked = blockedIpsMap[attack.source_ip] === true;
                var safePayload = escapeHtml(attack.payload);
                var safeEndpoint = escapeHtml(attack.endpoint);
                var safeFullUrl = escapeHtml(attack.full_url);
                item.innerHTML = '<div class="attack-header"><span class="attack-type-badge ' + type + '">' + escapeHtml(attack.attack_type || 'UNKNOWN') + '</span><div class="attack-info"><span class="attack-ip">' + escapeHtml(attack.source_ip || '0.0.0.0') + '</span> <span class="attack-time">' + new Date(attack.timestamp).toLocaleString() + '</span></div><div class="action-btn-row"><button class="action-btn block ' + (isBlocked ? 'blocked' : '') + '" onclick="toggleBlock(\'' + (attack.source_ip || '') + '\',this,event)"><i class="fas ' + (isBlocked ? 'fa-check' : 'fa-ban') + '"></i></button><button class="action-btn" onclick="toggleDetails(this)"><i class="fas fa-chevron-down"></i></button></div></div><div class="attack-details"><div class="detail-row"><span class="detail-label">Endpoint:</span><span class="detail-value">' + safeEndpoint + '</span></div><div class="detail-row"><span class="detail-label">Payload:</span><span class="detail-value">' + safePayload + '</span></div><div class="detail-row"><span class="detail-label">Full URL:</span><span class="detail-value">' + safeFullUrl + '</span></div><div class="detail-row"><span class="detail-label">Method:</span><span class="detail-value">' + escapeHtml(attack.http_method || 'GET') + '</span></div><div class="detail-row"><span class="detail-label">Detected:</span><span class="detail-value">' + (attack.detected ? 'Yes' : 'No') + '</span></div><div class="detail-row"><span class="detail-label">ML Service:</span><span class="detail-value">' + escapeHtml(attack.ml_service || 'N/A') + '</span></div></div>';
                list.appendChild(item);
            });
        } else {
            list.innerHTML = '<div class="loading"><i class="fas fa-radar"></i><p>No attacks</p></div>';
        }
    } catch (e) {
        list.innerHTML = '<div class="loading" style="color:var(--danger);">Error loading attacks</div>';
    }
}

function toggleDetails(btn) {
    var details = btn.closest('.attack-item').querySelector('.attack-details');
    var icon = btn.querySelector('i');
    if (details.classList.contains('expanded')) {
        details.classList.remove('expanded');
        icon.classList.remove('fa-chevron-up');
        icon.classList.add('fa-chevron-down');
    } else {
        details.classList.add('expanded');
        icon.classList.remove('fa-chevron-down');
        icon.classList.add('fa-chevron-up');
    }
}

async function loadExploits() {
    var list = document.getElementById('exploitList');
    try {
        var response = await fetch('/api/exploits?limit=100');
        var data = await response.json();
        list.innerHTML = '';
        if (data.exploits && data.exploits.length > 0) {
            data.exploits.forEach(function(exp) {
                var item = document.createElement('div');
                item.className = 'exploit-item';
                item.innerHTML = '<div><strong style="color:#f87171;">' + escapeHtml(exp.rule_name || 'Unknown') + '</strong><div style="font-size:0.85rem;color:var(--text-secondary);margin-top:0.3rem;">IP: ' + escapeHtml(exp.source_ip || 'unknown') + ' | ' + new Date(exp.end_time).toLocaleString() + '</div></div>';
                list.appendChild(item);
            });
        } else {
            list.innerHTML = '<div class="loading"><i class="fas fa-shield-check"></i><p>No exploits</p></div>';
        }
    } catch (e) {
        list.innerHTML = '<div class="loading" style="color:var(--danger);">Error loading exploits</div>';
    }
}

async function loadDdos() {
    var list = document.getElementById('ddosList');
    try {
        var response = await fetch('/ddos-api/api/stats');
        var stats = await response.json();
        defenseEnabled = stats.defense_active || false;
        autoDefenseEnabled = stats.auto_defense || false;
        document.getElementById('defenseStatus').textContent = defenseEnabled ? 'ENABLED' : 'DISABLED';
        document.getElementById('defenseStatus').style.color = defenseEnabled ? 'var(--success)' : 'var(--danger)';
        document.getElementById('autoDefenseLabel').textContent = autoDefenseEnabled ? 'ON' : 'OFF';
        document.getElementById('autoDefenseLabel').style.color = autoDefenseEnabled ? 'var(--success)' : 'var(--warning)';
        document.getElementById('autoDefenseStatus').textContent = autoDefenseEnabled ? 'ON' : 'OFF';
        document.getElementById('ddosActive').textContent = stats.attacks_logged || 0;
        document.getElementById('ddosRps').textContent = (stats.avg_rps || 0).toFixed(1);
        document.getElementById('ddosBlocked').textContent = stats.blocked_ips || 0;
        document.getElementById('btnEnableDefense').classList.toggle('active', defenseEnabled);
        document.getElementById('btnDisableDefense').classList.toggle('active', !defenseEnabled);
        document.getElementById('btnAutoDefense').classList.toggle('active', autoDefenseEnabled);
        
        response = await fetch('/api/attacks/recent?limit=100');
        data = await response.json();
        list.innerHTML = '';
        var ddosAttacks = (data.attacks || []).filter(function(a) { return a.attack_type === 'ddos' || (a.is_ddos == 1); });
        if (ddosAttacks.length > 0) {
            ddosAttacks.forEach(function(ddos) {
                var item = document.createElement('div');
                item.className = 'ddos-item';
                var rpsInfo = ddos.rps ? ' | RPS: ' + ddos.rps.toFixed(1) : ' | DDoS detected';
                item.innerHTML = '<div><strong style="color:#ec4899;"><i class="fas fa-bomb"></i> DDoS Attack</strong><div style="font-size:0.85rem;color:var(--text-secondary);margin-top:0.3rem;">IP: ' + escapeHtml(ddos.source_ip || 'unknown') + rpsInfo + '</div><div style="font-size:0.8rem;color:var(--text-dim);">' + new Date(ddos.timestamp).toLocaleString() + '</div></div>';
                list.appendChild(item);
            });
            addActivity('Loaded ' + ddosAttacks.length + ' DDoS attacks', 'success');
        } else {
            list.innerHTML = '<div class="loading"><i class="fas fa-shield-check"></i><p>No DDoS attacks</p></div>';
        }
    } catch (e) {
        list.innerHTML = '<div class="loading" style="color:var(--danger);">Error: ' + e.message + '</div>';
    }
}

async function toggleDefense(enable) {
    try {
        var url = enable ? '/ddos-api/api/defense/enable' : '/ddos-api/api/defense/disable';
        await fetch(url, { method: 'POST' });
        addActivity(enable ? 'DDoS Defense ENABLED' : 'DDoS Defense DISABLED', enable ? 'success' : 'warning');
        playCatSound();
        loadDdos();
    } catch (e) { addActivity('Defense toggle error: ' + e.message, 'danger'); }
}

async function toggleAutoDefense() {
    try {
        var url = autoDefenseEnabled ? '/ddos-api/api/auto-defense/disable' : '/ddos-api/api/auto-defense/enable';
        await fetch(url, { method: 'POST' });
        autoDefenseEnabled = !autoDefenseEnabled;
        addActivity(autoDefenseEnabled ? 'Auto Defense ENABLED' : 'Auto Defense DISABLED', autoDefenseEnabled ? 'success' : 'warning');
        loadDdos();
    } catch (e) { addActivity('Auto defense toggle error: ' + e.message, 'danger'); }
}

async function toggleBlock(ip, btn, event) {
    event.stopPropagation();
    if (!ip) return;
    var isBlocked = blockedIpsMap[ip] === true;
    try {
        if (isBlocked) {
            await fetch('/api/block/' + ip, { method: 'DELETE' });
            blockedIpsMap[ip] = false;
            btn.classList.remove('blocked');
            btn.querySelector('i').classList.remove('fa-check');
            btn.querySelector('i').classList.add('fa-ban');
            addActivity('IP ' + ip + ' unblocked', 'success');
        } else {
            await fetch('/api/block/' + ip, { method: 'POST' });
            blockedIpsMap[ip] = true;
            btn.classList.add('blocked');
            btn.querySelector('i').classList.remove('fa-ban');
            btn.querySelector('i').classList.add('fa-check');
            addActivity('IP ' + ip + ' blocked', 'success');
            playCatSound();
        }
        loadStats();
    } catch (e) { addActivity('Error: ' + e.message, 'danger'); }
}

async function loadSystemStatus() {
    var grid = document.getElementById('statusGrid');
    var services = [
        {name:'Admin Backend',url:'/api/health'},
        {name:'DDoS Backend',url:'/ddos-api/api/health'},
        {name:'Isolation ML',url:'/api/ml/isolation/health'},
        {name:'Random ML',url:'/api/ml/random/health'},
        {name:'DDoS ML',url:'/api/ml/ddos/health'},
        {name:'Exploit ML',url:'/api/ml/exploit/health'},
        {name:'Anomaly ML',url:'/api/ml/anomaly/health'},
        {name:'Classifier ML',url:'/api/ml/classifier/health'}
    ];
    grid.innerHTML = '';
    for (var i = 0; i < services.length; i++) {
        var svc = services[i];
        try {
            var r = await fetch(svc.url);
            var online = r.ok;
            var item = document.createElement('div');
            item.className = 'status-item';
            item.innerHTML = '<div class="status-indicator ' + (online ? 'online' : 'offline') + '"><i class="fas fa-' + (online ? 'check-circle' : 'times-circle') + '"></i></div><div class="status-label">' + svc.name + '</div>';
            grid.appendChild(item);
        } catch (e) {
            var item = document.createElement('div');
            item.className = 'status-item';
            item.innerHTML = '<div class="status-indicator offline"><i class="fas fa-times-circle"></i></div><div class="status-label">' + svc.name + '</div>';
            grid.appendChild(item);
        }
    }
    addActivity('System status refreshed', 'info');
}

async function clearAllData() {
    var sure = confirm('Clear all attacks?');
    if (!sure) return;
    try {
        await fetch('/api/attacks', { method: 'DELETE' });
        addActivity('All data cleared', 'success');
        loadDashboard();
    } catch (e) { addActivity('Error: ' + e.message, 'danger'); }
}

async function testManualAttack() {
    try {
        var testPayloads = ["' OR '1'='1", "<scr" + "ipt>alert('XSS')</scr" + "ipt>", "../../../etc/passwd"];
        var randomPayload = testPayloads[Math.floor(Math.random() * testPayloads.length)];
        var testUrl = 'http://localhost:3003/rest/products/search?q=' + encodeURIComponent(randomPayload);
        window.open(testUrl, '_blank');
        addActivity('Test attack sent to Juice Shop', 'info');
        setTimeout(function() { loadAttacks(); loadDashboard(); }, 3000);
    } catch (e) { addActivity('Error: ' + e.message, 'danger'); }
}

function exportExploits() {
    window.location.href = '/api/exploits?format=csv';
    addActivity('Exporting exploits...', 'info');
}

function exportDdosLogs() {
    window.location.href = '/ddos-api/api/attacks?limit=1000';
    addActivity('Exporting DDoS logs...', 'info');
}

async function loadMLServices() {
    var grid = document.getElementById('mlGrid');
    grid.innerHTML = '<div class="loading"><i class="fas fa-spinner"></i><p>Checking ML services...</p></div>';
    var online = 0, offline = 0;
    var results = [];
    for (var i = 0; i < mlServices.length; i++) {
        var svc = mlServices[i];
        try {
            var controller = new AbortController();
            var timeoutId = setTimeout(function() { controller.abort(); }, 2000);
            var r = await fetch(svc.url, { method: 'GET', signal: controller.signal });
            clearTimeout(timeoutId);
            var isOnline = r.ok;
            if (isOnline) { online++; } else { offline++; }
            results.push({ name: svc.name, port: svc.port, online: isOnline });
        } catch (e) {
            offline++;
            results.push({ name: svc.name, port: svc.port, online: false });
        }
    }
    document.getElementById('mlOnline').textContent = online;
    document.getElementById('mlOffline').textContent = offline;
    document.getElementById('mlTotal').textContent = mlServices.length;
    grid.innerHTML = '';
    results.forEach(function(svc) {
        var card = document.createElement('div');
        card.className = 'ml-card';
        var icon = 'fa-brain';
        if (svc.name.indexOf('Backend') >= 0) icon = 'fa-server';
        else if (svc.name.indexOf('DDoS') >= 0) icon = 'fa-shield-alt';
        else if (svc.name.indexOf('Forest') >= 0) icon = 'fa-tree';
        else if (svc.name.indexOf('Detector') >= 0) icon = 'fa-radar';
        else if (svc.name.indexOf('Analyzer') >= 0) icon = 'fa-microscope';
        else if (svc.name.indexOf('Classifier') >= 0) icon = 'fa-tags';
        else if (svc.name.indexOf('NLP') >= 0) icon = 'fa-language';
        else if (svc.name.indexOf('Reputation') >= 0) icon = 'fa-id-card';
        else if (svc.name.indexOf('Rate') >= 0) icon = 'fa-tachometer';
        else if (svc.name.indexOf('Behavioral') >= 0) icon = 'fa-user-clock';
        else if (svc.name.indexOf('Performance') >= 0) icon = 'fa-stopwatch';
        else if (svc.name.indexOf('Anomaly') >= 0) icon = 'fa-chart-line';
        card.innerHTML = '<div class="ml-card-header"><div class="ml-card-title"><i class="fas ' + icon + '"></i> ' + svc.name + '</div><div class="ml-card-port">Port ' + svc.port + '</div></div><div class="ml-card-status"><div class="ml-status-dot ' + (svc.online ? 'online' : 'offline') + '"></div><span class="ml-status-text ' + (svc.online ? 'online' : 'offline') + '">' + (svc.online ? 'Running' : 'Offline') + '</span></div><div class="ml-card-response">' + (svc.online ? 'Health check passed' : 'Connection failed') + '</div>';
        grid.appendChild(card);
    });
    addActivity('ML Services checked: ' + online + ' online, ' + offline + ' offline', online === mlServices.length ? 'success' : offline > 5 ? 'danger' : 'warning');
}

async function init() {
    var savedSound = localStorage.getItem('orchid-sound');
    if (savedSound) {
        soundEnabled = savedSound === 'on';
        document.getElementById('sound-toggle').querySelector('i').className = soundEnabled ? 'fas fa-volume-high' : 'fas fa-volume-xmark';
    }
    addActivity('ORCHID initialized', 'success');
    addActivity('Sound ready', 'info');
    addActivity('DDoS Protection ready', 'info');
    await loadDashboard();
    setInterval(loadStats, 3000);
    setInterval(loadAttackTypes, 5000);
}

init();
