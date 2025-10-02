// This file handles notifications for new attack detections

// Request notification permission when the page loads
document.addEventListener('DOMContentLoaded', function() {
    requestNotificationPermission();
});

// Request permission to show notifications
function requestNotificationPermission() {
    if ("Notification" in window) {
        if (Notification.permission !== "granted" && Notification.permission !== "denied") {
            Notification.requestPermission().then(function (permission) {
                if (permission === "granted") {
                    console.log("Notification permission granted");
                }
            });
        }
    }
}

// Function to show a notification
function showAttackNotification(attackData) {
    if (Notification.permission === "granted") {
        const sourceIP = attackData.source_ip;
        const service = attackData.service;
        const attackType = attackData.attack_type;
        
        const notification = new Notification("Honeypot Attack Detected", {
            body: `New ${attackType} attack from ${sourceIP} on ${service} service`,
            icon: 'https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@5.15.3/svgs/solid/shield-alt.svg'
        });
        
        notification.onclick = function() {
            window.focus();
            window.location.href = '/logs';
        };
    }
}
