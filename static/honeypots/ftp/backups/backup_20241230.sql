-- Database backup from 2024-12-30
-- Server: db.internal.example.com
-- Database: production_db

-- Users table structure
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(100) NOT NULL UNIQUE,
  password_hash VARCHAR(64) NOT NULL,
  first_name VARCHAR(50),
  last_name VARCHAR(50),
  role VARCHAR(20) DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP
);

-- Payment information table
CREATE TABLE payment_info (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  card_type VARCHAR(20),
  card_number VARCHAR(16),
  expiry_date VARCHAR(5),
  cvv VARCHAR(3),
  billing_address TEXT,
  is_default BOOLEAN DEFAULT FALSE
);

-- Sample user data (passwords are hashed)
INSERT INTO users (username, email, password_hash, first_name, last_name, role) VALUES
('admin', 'admin@example.com', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'System', 'Administrator', 'admin'),
('jsmith', 'john.smith@example.com', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'John', 'Smith', 'user'),
('mdavis', 'mary.davis@example.com', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'Mary', 'Davis', 'user'),
('bjohnson', 'bob.johnson@example.com', 'e172c5654dbc12d78ce1850a4f7956ba6e5a3d30f802b09d3ec4629163e1e962', 'Bob', 'Johnson', 'premium'),
('agarcia', 'alice.garcia@example.com', 'bc547750b92797f955b36112cc9bdd5cddf7d0862151d03a167ada8995aa24a9', 'Alice', 'Garcia', 'user');

-- Sample payment data (card numbers are partially redacted)
INSERT INTO payment_info (user_id, card_type, card_number, expiry_date, cvv, billing_address, is_default) VALUES
(1, 'VISA', '4532XXXXXXXX7412', '12/26', '123', '123 Admin St, Cityville, State, 12345', TRUE),
(2, 'MasterCard', '5678XXXXXXXX1234', '09/25', '456', '456 Oak Ave, Somewhere, USA, 23456', TRUE),
(3, 'Discover', '6011XXXXXXXX8901', '03/27', '789', '789 Pine St, Nowhere, USA, 34567', TRUE),
(4, 'VISA', '4111XXXXXXXX5678', '06/26', '012', '101 Cedar Ln, Anywhere, USA, 45678', FALSE),
(4, 'AMEX', '3782XXXXXXXX0123', '11/24', '3456', '101 Cedar Ln, Anywhere, USA, 45678', TRUE),
(5, 'MasterCard', '5555XXXXXXXX4444', '07/25', '789', '202 Elm St, Everywhere, USA, 56789', TRUE);