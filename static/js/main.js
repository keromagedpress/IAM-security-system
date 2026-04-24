/**
 * IAM Security System - Interactive Dashboard Analytics
 * Powered by Chart.js and D3.js
 */

document.addEventListener('DOMContentLoaded', () => {
    // Initialize all visualizations
    initLoginTimeline();
    initAuthStatus();
    initActiveUsers();
    initNetworkGraph();
    initOSMonitor(); // Start system health tracking
});

/**
 * 0. System Health / OS Monitor
 */
async function initOSMonitor() {
    const updateStats = async () => {
        try {
            const response = await fetch('/api/system-stats');
            if (!response.ok) return;
            const data = await response.json();

            const mapping = {
                'health-os': data.os,
                'health-cpu': data.cpu + '%',
                'health-memory': data.memory + '%',
                'health-uptime': data.uptime,
                'health-processes': data.processes,
                'health-timestamp': 'Last Pulse: ' + data.timestamp
            };

            for (const [id, val] of Object.entries(mapping)) {
                const el = document.getElementById(id);
                if (el) el.innerText = val;
            }
        } catch (err) { console.error('OS Monitor error:', err); }
    };

    updateStats(); // Initial check
    setInterval(updateStats, 10000); // 10s Refresh
}

// Global Theme Constants
const COLORS = {
    blue: '#00d4ff',
    blueGlow: 'rgba(0, 212, 255, 0.4)',
    green: '#10b981',
    red: '#ef4444',
    orange: '#f59e0b',
    text: '#94a3b8',
    bg: '#0a0e1a'
};

/**
 * 1. Login Logic Timeline (Line Chart)
 */
async function initLoginTimeline() {
    try {
        const response = await fetch('/api/chart/login-attempts');
        const data = await response.json();

        const ctx = document.getElementById('loginTimelineChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.map(d => d.day),
                datasets: [{
                    label: 'Login Attempts',
                    data: data.map(d => d.count),
                    borderColor: COLORS.blue,
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: COLORS.blue,
                    pointBorderColor: '#fff',
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 2000, easing: 'easeOutQuart' },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.9)',
                        titleColor: '#fff',
                        bodyColor: COLORS.text,
                        borderColor: COLORS.blue,
                        borderWidth: 1
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: COLORS.text }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: COLORS.text }
                    }
                }
            }
        });
    } catch (err) { console.error('Timeline fetch error:', err); }
}

/**
 * 2. Auth Success/Fail Rate (Doughnut Chart)
 */
async function initAuthStatus() {
    try {
        const response = await fetch('/api/chart/success-fail');
        const data = await response.json();

        const ctx = document.getElementById('authStatusChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Success', 'Failed'],
                datasets: [{
                    data: [data.success, data.failed],
                    backgroundColor: [COLORS.green, COLORS.red],
                    borderWidth: 0,
                    hoverOffset: 15
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '75%',
                animation: { animateScale: true, animateRotate: true, duration: 2000 },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: COLORS.text, padding: 20, font: { size: 12 } }
                    }
                }
            }
        });
    } catch (err) { console.error('Auth status fetch error:', err); }
}

/**
 * 3. Most Active Users (Bar Chart)
 */
async function initActiveUsers() {
    try {
        const response = await fetch('/api/chart/active-users');
        const data = await response.json();

        const ctx = document.getElementById('activeUsersChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.map(u => u.username),
                datasets: [{
                    label: 'Activity Count',
                    data: data.map(u => u.count),
                    backgroundColor: COLORS.blue,
                    borderRadius: 8,
                    hoverBackgroundColor: '#00b4ff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 2000, easing: 'easeOutElastic' },
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: COLORS.text }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: COLORS.text }
                    }
                }
            }
        });
    } catch (err) { console.error('Active users fetch error:', err); }
}

/**
 * 4. Network Graph Visualization (D3.js) - Panoramic Engine
 */
async function initNetworkGraph() {
    const container = document.getElementById('network-graph');
    if (!container) return;

    try {
        const response = await fetch('/api/network-graph');
        if (!response.ok) throw new Error(`API error: ${response.status}`);
        const data = await response.json();

        if (!data.nodes || data.nodes.length === 0) {
            container.innerHTML = '<p class="text-secondary text-center py-12 italic">No identity mapping data found.</p>';
            return;
        }

        // Logic for Redrawing on Resize
        const render = () => {
            container.innerHTML = '';
            const width = container.offsetWidth;
            const height = container.offsetHeight || 560;

            const svg = d3.select('#network-graph')
                .append('svg')
                .attr('width', width)
                .attr('height', height)
                .attr('viewBox', `0 0 ${width} ${height}`)
                .attr('preserveAspectRatio', 'xMidYMid meet');

            // Force Simulation Optimization for Stability
            const simulation = d3.forceSimulation(data.nodes)
                .force('link', d3.forceLink(data.links).id(d => d.id).distance(200))
                .force('charge', d3.forceManyBody().strength(-300)) // Reduced repulsion for stability
                .force('center', d3.forceCenter(width / 2, height / 2))
                .force('collision', d3.forceCollide(45));

            const link = svg.append('g')
                .selectAll('line')
                .data(data.links)
                .enter().append('line')
                .attr('stroke', 'rgba(59, 130, 246, 0.15)')
                .attr('stroke-width', 2);

            const node = svg.append('g')
                .selectAll('g')
                .data(data.nodes)
                .enter().append('g')
                .call(d3.drag()
                    .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
                    .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
                    .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));

            node.append('circle')
                .attr('r', d => d.type === 'role' ? 22 : 16)
                .attr('fill', d => {
                    if (d.type === 'role') return COLORS.orange;
                    if (d.role === 'admin') return COLORS.red;
                    return COLORS.blue;
                })
                .attr('stroke', 'rgba(255,255,255,0.2)')
                .attr('stroke-width', 2);

            node.append('text')
                .text(d => d.id)
                .attr('text-anchor', 'middle')
                .attr('y', d => d.type === 'role' ? 40 : 35)
                .attr('fill', '#f8fafc')
                .style('font-size', '12px')
                .style('font-weight', '500')
                .style('pointer-events', 'none')
                .style('text-shadow', '0 2px 4px rgba(0,0,0,0.5)');

            simulation.on('tick', () => {
                // Bounding Box Collision Logic
                const radius = 25;
                
                link
                    .attr('x1', d => d.source.x = Math.max(radius, Math.min(width - radius, d.source.x)))
                    .attr('y1', d => d.source.y = Math.max(radius, Math.min(height - radius, d.source.y)))
                    .attr('x2', d => d.target.x = Math.max(radius, Math.min(width - radius, d.target.x)))
                    .attr('y2', d => d.target.y = Math.max(radius, Math.min(height - radius, d.target.y)));

                node.attr('transform', d => {
                    d.x = Math.max(radius, Math.min(width - radius, d.x));
                    d.y = Math.max(radius, Math.min(height - radius, d.y));
                    return `translate(${d.x},${d.y})`;
                });
            });
        };

        // Initial Render
        render();

        // Responsive Resizing Handler
        window.addEventListener('resize', () => {
            // Simple throttle / clear and re-render
            render();
        });

    } catch (err) { console.error('Panoramic Graph Failure:', err); }
}

/**
 * 5. Network Infrastructure Monitoring
 */
async function initNetworkInfo() {
    try {
        const response = await fetch('/api/network-info');
        if (!response.ok) return;
        const data = await response.json();

        // Update Host & MAC
        document.getElementById('host-ip').textContent = data.ip;
        document.getElementById('sys-mac').textContent = data.mac;

        // Populate Interfaces
        const interfaceList = document.getElementById('interface-list');
        if (interfaceList) {
            interfaceList.innerHTML = data.interfaces.map(iface => `
                <div class="px-2 py-1 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono" style="font-size: 10px;">
                    ${iface.name}: ${iface.ip}
                </div>
            `).join('');
        }

        // Populate IP Origins
        const ipBody = document.getElementById('ip-origin-body');
        if (ipBody) {
            ipBody.innerHTML = data.connecting_ips.map(conn => `
                <tr class="border-b border-white/5">
                    <td class="py-2 text-slate-300 font-mono">${conn.ip}</td>
                    <td class="py-2 text-end">
                        <span class="px-2 py-0.5 rounded-full ${conn.type === 'Local' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'}" style="font-size: 9px;">
                            ${conn.type.toUpperCase()}
                        </span>
                    </td>
                </tr>
            `).join('');
        }
    } catch (err) {
        console.error('Network info fetch error:', err);
    }
}

// Global Initialization
document.addEventListener('DOMContentLoaded', () => {
    initOSMonitor();
    initNetworkGraph();
    initNetworkInfo();
    
    // Auto-refresh network info every 30s
    setInterval(initNetworkInfo, 30000);
});
