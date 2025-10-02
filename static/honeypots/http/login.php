<!DOCTYPE html>
<html>
<head>
    <title>User Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
        }
        .login-container {
            max-width: 400px;
            margin: 50px auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h2 {
            text-align: center;
            color: #333;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 3px;
        }
        button {
            width: 100%;
            padding: 10px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        button:hover {
            background: #45a049;
        }
        .error {
            color: red;
            margin-bottom: 10px;
        }
        .notes {
            margin-top: 20px;
            font-size: 0.8em;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Member Login</h2>
        
        <!-- This div would show error messages if login failed -->
        <div class="error" id="error-message"></div>
        
        <form id="login-form" method="GET" action="login_process.php">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" placeholder="Enter your username">
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" placeholder="Enter your password">
            </div>
            
            <button type="submit">Login</button>
        </form>
        
        <div class="notes">
            <p>Default admin credentials: admin/password123</p>
            <p>Forgot password? Contact <a href="mailto:admin@example.com">admin@example.com</a></p>
        </div>
    </div>

    <script>
        // Vulnerable to XSS via URL parameters
        function getQueryParam(param) {
            var urlParams = new URLSearchParams(window.location.search);
            return urlParams.get(param);
        }
        
        // Display error message if provided in URL
        var error = getQueryParam('error');
        if (error) {
            document.getElementById('error-message').innerHTML = decodeURIComponent(error);
        }
        
        // Display username if remembered
        var rememberedUser = getQueryParam('remember');
        if (rememberedUser) {
            document.getElementById('username').value = rememberedUser;
        }
    </script>
</body>
</html>