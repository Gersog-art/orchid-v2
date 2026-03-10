// DDoS Metrics and Blocked IPs Display - FIXED v2

var autoBlockEnabled = false;
var blockedIpsList = [];
var metricsInterval = null;

async function loadBlockedIps() {
    try {
        var response = await fetch('/ddos-api/api/blocked');
        var data = await response.json();
        blockedIpsList = data.blocked_ips || [];
        var countEl = document.getElementById('ddosBlocked');
        if (countEl) {
            countEl.textContent = blockedIpsList.length;
        }
        return blockedIpsList;
    } catch (e) {
        console.log('Error loading blocked IPs:', e);
        return [];
    }
}

async function loadDdosWithMetrics() {
    var list = document.getElementById('ddosList');
    try {
        var statsResponse = await fetch('/ddos-api/api/stats');
        var stats = await statsResponse.json();
        defenseEnabled = stats.defense_active || false;
        autoDefenseEnabled = stats.auto_defense || false;
        autoBlockEnabled = stats.auto_block || false;
        
        document.getElementById('defenseStatus').textContent = defenseEnabled ? 'ENABLED' : 'DISABLED';
        document.getElementById('defenseStatus').style.color = defenseEnabled ? 'var(--success)' : 'var(--danger)';
        document.getElementById('autoDefenseLabel').textContent = autoDefenseEnabled ? 'ON' : 'OFF';
        document.getElementById('autoDefenseLabel').style.color = autoDefenseEnabled ? 'var(--success)' : 'var(--warning)';
        document.getElementById('autoDefenseStatus').textContent = autoBlockEnabled ? 'ON' : 'OFF';
        document.getElementById('autoDefenseStatus').style.color = autoBlockEnabled ? '#ffd700' : 'var(--warning)';
        document.getElementById('autoBlockStatus').textContent = autoBlockEnabled ? 'ON' : 'OFF';
        document.getElementById('autoBlockStatus').style.color = autoBlockEnabled ? '#ffd700' : 'var(--warning)';
        document.getElementById('ddosActive').textContent = stats.attacks_logged || 0;
        document.getElementById('ddosRps').textContent = (stats.avg_rps || 0).toFixed(1);
        document.getElementById('ddosBlocked').textContent = stats.blocked_ips || 0;
        
        await loadBlockedIps();
        
        document.getElementById('btnEnableDefense').classList.toggle('active', defenseEnabled);
        document.getElementById('btnDisableDefense').classList.toggle('active', !defenseEnabled);
        document.getElementById('btnAutoDefense').classList.toggle('active', autoDefenseEnabled);
        document.getElementById('btnAutoBlock').classList.toggle('active', autoBlockEnabled);
        
        var response = await fetch('/api/attacks/recent?limit=100');
        data = await response.json();
        list.innerHTML = '';
        var ddosAttacks = (data.attacks || []).filter(function(a) { return a.attack_type === 'ddos' || (a.is_ddos == 1); });
        
        if (ddosAttacks.length > 0) {
            ddosAttacks.forEach(function(ddos) {
                var item = document.createElement('div');
                item.className = 'ddos-item';
                var rpsInfo = ddos.rps && ddos.rps > 0 ? ' | RPS: ' + ddos.rps.toFixed(1) : ' | DDoS detected';
                var isBlocked = blockedIpsList.some(function(b) { return b.ip === ddos.source_ip; });
                var blockedInfo = isBlocked ? ' <span style="color:var(--success);">[BLOCKED]</span>' : '';
                item.innerHTML = '<div><strong style="color:#ec4899;"><i class="fas fa-bomb"></i> DDoS Attack</strong>' + blockedInfo + '<div style="font-size:0.85rem;color:var(--text-secondary);margin-top:0.3rem;">IP: ' + escapeHtml(ddos.source_ip || 'unknown') + rpsInfo + '</div><div style="font-size:0.8rem;color:var(--text-dim);">' + new Date(ddos.timestamp).toLocaleString() + '</div></div>';
                list.appendChild(item);
            });
        } else {
            list.innerHTML = '<div class="loading"><i class="fas fa-shield-check"></i><p>No DDoS attacks detected</p></div>';
        }
    } catch (e) {
        list.innerHTML = '<div class="loading" style="color:var(--danger);">Error: ' + e.message + '</div>';
    }
}

async function toggleAutoBlock() {
    try {
        var url = autoBlockEnabled ? '/ddos-api/api/auto-block/disable' : '/ddos-api/api/auto-block/enable';
        await fetch(url, { method: 'POST' });
        autoBlockEnabled = !autoBlockEnabled;
        addActivity(autoBlockEnabled ? 'Auto Block ENABLED - Will auto-block attacking IPs' : 'Auto Block DISABLED', autoBlockEnabled ? 'success' : 'warning');
        loadDdosWithMetrics();
    } catch (e) { addActivity('Auto block toggle error: ' + e.message, 'danger'); }
}

function startMetricsRefresh() {
    if (metricsInterval) clearInterval(metricsInterval);
    metricsInterval = setInterval(function() {
        loadDdosWithMetrics();
    }, 3000);
}

var originalLoadDdos = loadDdos;
loadDdos = function() {
    loadDdosWithMetrics();
    startMetricsRefresh();
};
