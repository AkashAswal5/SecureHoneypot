// Main dashboard functionality

document.addEventListener('DOMContentLoaded', function() {
    // Start the notification checker
    checkForNewAttacks();
    
    // Set up auto-refresh for the dashboard
    if (window.location.pathname === '/') {
        // Already handled in the dashboard.html page
    }
    
    // Handle service stop buttons
    setupServiceControls();
});

// Function to check for new attacks and show notifications
function checkForNewAttacks() {
    let lastAttackCount = parseInt(document.getElementById('total-attacks').textContent) || 0;
    
    // Check every 10 seconds
    setInterval(() => {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                const newAttackCount = data.total_attacks;
                
                // If we have new attacks, show a notification
                if (newAttackCount > lastAttackCount && lastAttackCount > 0) {
                    const newAttacks = newAttackCount - lastAttackCount;
                    showNotification(
                        'New Attack Detected',
                        `${newAttacks} new attack${newAttacks > 1 ? 's' : ''} detected!`,
                        '/logs'
                    );
                }
                
                // Update the last attack count
                lastAttackCount = newAttackCount;
            })
            .catch(error => {
                console.error('Error checking for new attacks:', error);
            });
    }, 10000);
}

// Function to show browser notifications
function showNotification(title, message, link) {
    // Check if the browser supports notifications
    if (!("Notification" in window)) {
        console.log("This browser does not support desktop notifications");
        return;
    }
    
    // Check permission
    if (Notification.permission === "granted") {
        createNotification(title, message, link);
    } else if (Notification.permission !== "denied") {
        Notification.requestPermission().then(permission => {
            if (permission === "granted") {
                createNotification(title, message, link);
            }
        });
    }
}

// Create the actual notification
function createNotification(title, message, link) {
    const notification = new Notification(title, {
        body: message,
        icon: 'https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@5.15.3/svgs/solid/shield-alt.svg'
    });
    
    // Open the link when the notification is clicked
    if (link) {
        notification.onclick = function() {
            window.open(link, '_blank');
        };
    }
    
    // Also show a toast notification for browsers that don't support notifications
    showToast(title, message);
}

// Show a Bootstrap toast notification
function showToast(title, message) {
    // Create the toast container if it doesn't exist
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    // Create the toast
    const toastId = 'toast-' + Date.now();
    const toastHtml = `
        <div id="${toastId}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header bg-danger text-white">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong class="me-auto">${title}</strong>
                <small>Just now</small>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    // Add the toast to the container
    toastContainer.innerHTML += toastHtml;
    
    // Initialize and show the toast
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, { autohide: true, delay: 5000 });
    toast.show();
    
    // Remove the toast when it's hidden
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

// Setup service control buttons
function setupServiceControls() {
    // Since these are forms submitted to the server, we don't need client-side handlers
    // for the stop service buttons.
}
