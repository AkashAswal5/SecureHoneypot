<!DOCTYPE html>
<html>
<head>
    <title>Product Search</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f9f9f9;
            margin: 0;
            padding: 20px;
        }
        .search-container {
            max-width: 800px;
            margin: 40px auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h2 {
            color: #333;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .search-form {
            margin-bottom: 20px;
        }
        input[type="text"] {
            width: 70%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 3px;
        }
        button {
            padding: 10px 15px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        button:hover {
            background: #45a049;
        }
        .product {
            margin-bottom: 15px;
            padding: 15px;
            border-bottom: 1px solid #eee;
        }
        .product-name {
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }
        .product-description {
            color: #666;
            margin-bottom: 10px;
        }
        .product-price {
            color: #e74c3c;
            font-weight: bold;
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
    <div class="search-container">
        <h2>Product Search</h2>
        
        <div class="search-form">
            <form method="GET" action="search.php">
                <input type="text" name="q" placeholder="Search products..." 
                       value="<?php echo isset($_GET['q']) ? htmlspecialchars($_GET['q']) : ''; ?>">
                <button type="submit">Search</button>
            </form>
        </div>
        
        <div id="results">
            <!-- Intentionally vulnerable to SQL injection -->
            <div class="sql-query">
                EXECUTED QUERY: SELECT * FROM products WHERE name LIKE '%<span id="search-term">search term</span>%' OR description LIKE '%<span id="search-term2">search term</span>%'
            </div>
            
            <!-- Sample results -->
            <div class="product">
                <div class="product-name">HD Security Camera</div>
                <div class="product-description">1080p high-definition security camera with night vision</div>
                <div class="product-price">$129.99</div>
            </div>
            
            <div class="product">
                <div class="product-name">Smart Door Lock</div>
                <div class="product-description">WiFi-enabled door lock with fingerprint recognition</div>
                <div class="product-price">$199.99</div>
            </div>
            
            <div class="product">
                <div class="product-name">Motion Sensor</div>
                <div class="product-description">Wireless motion detection sensor with app integration</div>
                <div class="product-price">$49.99</div>
            </div>
        </div>
    </div>

    <script>
        // Get search term from URL and populate the query display
        // Intentionally vulnerable to XSS
        const urlParams = new URLSearchParams(window.location.search);
        const searchTerm = urlParams.get('q') || 'security';
        
        // Update the displayed SQL query with the search term (unescaped)
        document.getElementById('search-term').innerHTML = searchTerm;
        document.getElementById('search-term2').innerHTML = searchTerm;
        
        // A developer comment with "secret" information
        console.log("TODO: Fix the SQL injection vulnerability in search.php before production");
        console.log("Database credentials: dbuser/dbpass123 on localhost");
    </script>
</body>
</html>