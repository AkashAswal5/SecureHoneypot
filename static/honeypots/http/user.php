<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f7f7f7;
            margin: 0;
            padding: 20px;
        }
        .profile-container {
            max-width: 800px;
            margin: 40px auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.1);
        }
        .profile-header {
            display: flex;
            align-items: center;
            margin-bottom: 30px;
        }
        .profile-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background-color: #e0e0e0;
            margin-right: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            color: #666;
        }
        .profile-info h1 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .profile-info p {
            margin: 0;
            color: #666;
        }
        .profile-details {
            margin-top: 30px;
        }
        .detail-row {
            padding: 10px 0;
            border-bottom: 1px solid #eee;
            display: flex;
        }
        .detail-label {
            width: 200px;
            font-weight: bold;
            color: #555;
        }
        .detail-value {
            flex: 1;
        }
        .action-buttons {
            margin-top: 30px;
            display: flex;
            gap: 10px;
        }
        .btn {
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }
        .btn-primary {
            background-color: #3498db;
            color: white;
        }
        .btn-danger {
            background-color: #e74c3c;
            color: white;
        }
        .admin-panel {
            margin-top: 30px;
            padding: 20px;
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
        }
        .sql-query {
            background: #f8f8f8;
            padding: 10px;
            border-left: 3px solid #ddd;
            font-family: monospace;
            margin: 20px 0;
            white-space: pre-wrap;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="profile-container">
        <div class="sql-query">
            EXECUTED QUERY: SELECT * FROM users WHERE id = <span id="user-id">1</span>
        </div>
        
        <div class="profile-header">
            <div class="profile-avatar" id="user-initial">J</div>
            <div class="profile-info">
                <h1 id="user-name">John Doe</h1>
                <p id="user-email">john.doe@example.com</p>
                <p id="user-status">Active Member</p>
            </div>
        </div>
        
        <div class="profile-details">
            <div class="detail-row">
                <div class="detail-label">Username:</div>
                <div class="detail-value" id="username">johndoe</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Account Type:</div>
                <div class="detail-value" id="account-type">Standard User</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Member Since:</div>
                <div class="detail-value">January 15, 2023</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Last Login:</div>
                <div class="detail-value">August 23, 2023 10:42 AM</div>
            </div>
        </div>
        
        <div class="action-buttons">
            <button class="btn btn-primary">Edit Profile</button>
            <button class="btn btn-danger">Delete Account</button>
        </div>
        
        <div class="admin-panel" id="admin-panel" style="display: none;">
            <h3>Admin Actions</h3>
            <p>You have advanced privileges to manage this user account.</p>
            <button class="btn btn-danger">Reset Password</button>
            <button class="btn btn-danger">Ban User</button>
            <button class="btn btn-primary">Grant Admin Access</button>
        </div>
    </div>

    <script>
        // Get user ID from URL parameter - intentionally vulnerable to SQL injection
        function getQueryParam(param) {
            var urlParams = new URLSearchParams(window.location.search);
            return urlParams.get(param);
        }
        
        var userId = getQueryParam('id') || '1';
        document.getElementById('user-id').textContent = userId;
        
        // Simulate different users based on ID
        var users = {
            '1': {
                name: 'John Doe',
                email: 'john.doe@example.com',
                username: 'johndoe',
                accountType: 'Standard User',
                initial: 'J'
            },
            '2': {
                name: 'Jane Smith',
                email: 'jane.smith@example.com',
                username: 'janesmith',
                accountType: 'Premium User',
                initial: 'J'
            },
            '3': {
                name: 'Admin User',
                email: 'admin@example.com',
                username: 'admin',
                accountType: 'Administrator',
                initial: 'A'
            }
        };
        
        // Update profile with user data or handle SQL injection simulation
        if (userId.includes("'") || userId.includes("--") || userId.includes(";")) {
            // Simulating SQL injection vulnerability
            document.getElementById('user-name').textContent = 'SQL Error';
            document.getElementById('user-email').textContent = 'Database error: syntax error near unexpected token';
            document.getElementById('username').textContent = 'Error';
            document.getElementById('account-type').textContent = 'Error';
            document.getElementById('user-initial').textContent = 'E';
            document.getElementById('user-status').textContent = 'Error';
            
            // For educational purposes - show what happens with SQL injection
            if (userId.includes("' OR '1'='1")) {
                // Simulate returning all users
                document.getElementById('user-name').textContent = 'SQL Injection Detected!';
                document.getElementById('user-email').textContent = 'All user records would be returned';
                document.getElementById('user-status').textContent = 'SECURITY BREACH';
                document.getElementById('user-initial').textContent = '!';
                
                // Show admin panel to simulate escalated privileges
                document.getElementById('admin-panel').style.display = 'block';
            }
        } else {
            // Normal user display
            var user = users[userId] || {
                name: 'Unknown User',
                email: 'unknown@example.com',
                username: 'unknown',
                accountType: 'Guest',
                initial: '?'
            };
            
            document.getElementById('user-name').textContent = user.name;
            document.getElementById('user-email').textContent = user.email;
            document.getElementById('username').textContent = user.username;
            document.getElementById('account-type').textContent = user.accountType;
            document.getElementById('user-initial').textContent = user.initial;
            
            // Show admin panel for admin user
            if (user.accountType === 'Administrator') {
                document.getElementById('admin-panel').style.display = 'block';
            }
        }
    </script>
</body>
</html>