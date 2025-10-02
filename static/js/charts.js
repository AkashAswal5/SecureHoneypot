// Charts for the dashboard

// Initialize all charts with empty data
let attackDistributionChart = null;
let sourceIPChart = null;
let attackTimelineChart = null;

// Function to refresh all the dashboard data
function refreshDashboardData() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            updateDashboardCounts(data);
            updateRecentAttacksTable(data.recent_attacks);
            updateCharts(data);
        })
        .catch(error => {
            console.error('Error fetching dashboard data:', error);
        });
}

// Update the counts on the dashboard
function updateDashboardCounts(data) {
    document.getElementById('total-attacks').textContent = data.total_attacks;
    
    // Check if we need to hide the no-attacks message
    if (data.total_attacks > 0) {
        const noAttacksMessage = document.getElementById('no-attacks-message');
        if (noAttacksMessage) {
            noAttacksMessage.style.display = 'none';
        }
    }
}

// Update the recent attacks table
function updateRecentAttacksTable(recentAttacks) {
    const tableBody = document.getElementById('recent-attacks-table');
    
    // If there are no attacks, show the message
    if (!recentAttacks || recentAttacks.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center" id="no-attacks-message">
                    No attacks detected yet. Honeypot is waiting for connections.
                </td>
            </tr>
        `;
        return;
    }
    
    // Clear the table
    tableBody.innerHTML = '';
    
    // Add each attack to the table
    recentAttacks.forEach(attack => {
        const row = document.createElement('tr');
        
        // Format timestamp for display
        const timestamp = new Date(attack.timestamp);
        const formattedTime = timestamp.toLocaleTimeString();
        
        row.innerHTML = `
            <td>${formattedTime}</td>
            <td>${attack.source_ip}</td>
            <td>${attack.service}</td>
            <td>
                <span class="badge 
                    ${attack.attack_type === 'SQL Injection' ? 'bg-danger' : 
                    attack.attack_type === 'Command Injection' ? 'bg-warning' :
                    attack.attack_type === 'Cross-Site Scripting (XSS)' ? 'bg-info' :
                    attack.attack_type === 'Brute Force' ? 'bg-primary' :
                    attack.attack_type === 'Reconnaissance' ? 'bg-secondary' : 
                    'bg-light text-dark'}">
                    ${attack.attack_type}
                </span>
            </td>
        `;
        
        tableBody.appendChild(row);
    });
}

// Update all the charts with new data
function updateCharts(data) {
    // If there are no attacks, don't update the charts
    if (data.total_attacks === 0) {
        initializeEmptyCharts();
        return;
    }
    
    updateAttackDistributionChart(data.services);
    updateSourceIPChart(data.recent_attacks);
    updateTimelineChart(data.recent_attacks);
}

// Initialize empty charts when there's no data
function initializeEmptyCharts() {
    const emptyData = {
        labels: ['No Data'],
        datasets: [{
            data: [1],
            backgroundColor: ['#6c757d'],
            borderWidth: 0
        }]
    };
    
    // Attack Distribution Chart
    if (!attackDistributionChart) {
        const attackDistCtx = document.getElementById('attackDistributionChart').getContext('2d');
        attackDistributionChart = new Chart(attackDistCtx, {
            type: 'pie',
            data: emptyData,
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#ffffff'
                        }
                    },
                    title: {
                        display: true,
                        text: 'No Attack Data',
                        color: '#ffffff'
                    }
                }
            }
        });
    }
    
    // Source IP Chart
    if (!sourceIPChart) {
        const sourceIPCtx = document.getElementById('sourceIPChart').getContext('2d');
        sourceIPChart = new Chart(sourceIPCtx, {
            type: 'pie',
            data: emptyData,
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#ffffff'
                        }
                    },
                    title: {
                        display: true,
                        text: 'No Attack Data',
                        color: '#ffffff'
                    }
                }
            }
        });
    }
    
    // Timeline Chart
    if (!attackTimelineChart) {
        const timelineCtx = document.getElementById('attackTimelineChart').getContext('2d');
        attackTimelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: ['No Data'],
                datasets: [{
                    label: 'Attacks',
                    data: [0],
                    backgroundColor: 'rgba(0, 123, 255, 0.2)',
                    borderColor: 'rgba(0, 123, 255, 1)',
                    borderWidth: 2,
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#ffffff'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#ffffff'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                }
            }
        });
    }
}

// Update the attack distribution chart
function updateAttackDistributionChart(services) {
    const labels = Object.keys(services);
    const data = Object.values(services);
    
    // Generate colors based on the number of services
    const colors = generateColors(labels.length);
    
    if (!attackDistributionChart) {
        // Create the chart if it doesn't exist
        const ctx = document.getElementById('attackDistributionChart').getContext('2d');
        attackDistributionChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#ffffff'
                        }
                    },
                    title: {
                        display: true,
                        text: 'Attacks by Service',
                        color: '#ffffff'
                    }
                }
            }
        });
    } else {
        // Update the existing chart
        attackDistributionChart.data.labels = labels;
        attackDistributionChart.data.datasets[0].data = data;
        attackDistributionChart.data.datasets[0].backgroundColor = colors;
        attackDistributionChart.update();
    }
}

// Update the source IP chart
function updateSourceIPChart(recentAttacks) {
    // Count attacks by IP
    const ipCounts = {};
    recentAttacks.forEach(attack => {
        const ip = attack.source_ip;
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    });
    
    const labels = Object.keys(ipCounts);
    const data = Object.values(ipCounts);
    
    // Generate colors based on the number of IPs
    const colors = generateColors(labels.length);
    
    if (!sourceIPChart) {
        // Create the chart if it doesn't exist
        const ctx = document.getElementById('sourceIPChart').getContext('2d');
        sourceIPChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#ffffff'
                        }
                    },
                    title: {
                        display: true,
                        text: 'Attacks by Source IP',
                        color: '#ffffff'
                    }
                }
            }
        });
    } else {
        // Update the existing chart
        sourceIPChart.data.labels = labels;
        sourceIPChart.data.datasets[0].data = data;
        sourceIPChart.data.datasets[0].backgroundColor = colors;
        sourceIPChart.update();
    }
}

// Update the timeline chart
function updateTimelineChart(recentAttacks) {
    // Group attacks by hour
    const timeline = {};
    
    // Sort attacks by timestamp
    const sortedAttacks = [...recentAttacks].sort((a, b) => 
        new Date(a.timestamp) - new Date(b.timestamp)
    );
    
    // Format timestamps for the chart
    const timestamps = sortedAttacks.map(attack => {
        const date = new Date(attack.timestamp);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
    
    // Count attacks at each timestamp
    timestamps.forEach(time => {
        timeline[time] = (timeline[time] || 0) + 1;
    });
    
    const labels = Object.keys(timeline);
    const data = Object.values(timeline);
    
    if (!attackTimelineChart) {
        // Create the chart if it doesn't exist
        const ctx = document.getElementById('attackTimelineChart').getContext('2d');
        attackTimelineChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Attacks',
                    data: data,
                    backgroundColor: 'rgba(0, 123, 255, 0.2)',
                    borderColor: 'rgba(0, 123, 255, 1)',
                    borderWidth: 2,
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#ffffff'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#ffffff'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    },
                    title: {
                        display: true,
                        text: 'Attack Timeline',
                        color: '#ffffff'
                    }
                }
            }
        });
    } else {
        // Update the existing chart
        attackTimelineChart.data.labels = labels;
        attackTimelineChart.data.datasets[0].data = data;
        attackTimelineChart.update();
    }
}

// Helper function to generate colors for charts
function generateColors(count) {
    const colors = [
        '#007bff', // blue
        '#28a745', // green
        '#dc3545', // red
        '#ffc107', // yellow
        '#17a2b8', // cyan
        '#6610f2', // indigo
        '#fd7e14', // orange
        '#e83e8c', // pink
        '#6f42c1', // purple
        '#20c997'  // teal
    ];
    
    // If we need more colors than we have, repeat the colors
    const result = [];
    for (let i = 0; i < count; i++) {
        result.push(colors[i % colors.length]);
    }
    
    return result;
}

// Initialize the charts when the page loads
document.addEventListener('DOMContentLoaded', function() {
    initializeEmptyCharts();
});
