import socket
import threading
import time
import logging
import random

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define callback function placeholder
log_callback = None

def register_log_callback(callback):
    """Register a callback function to be called when an attack is detected."""
    global log_callback
    log_callback = callback

class HoneypotService:
    def __init__(self, service_type, port, service_id):
        """Initialize a honeypot service.
        
        Args:
            service_type (str): Type of service to emulate (e.g., 'ssh', 'ftp', 'telnet')
            port (int): Port to listen on
            service_id (int): Unique identifier for this service
        """
        self.service_type = service_type
        self.port = port
        self.service_id = service_id
        self.running = False
        self.server_socket = None
        self.clients = []
    
    def start(self):
        """Start the honeypot service."""
        if self.running:
            return
        
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            logger.info(f"[+] {self.service_type} honeypot listening on port {self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    self.clients.append(client_socket)
                    
                    # Start a new thread to handle this client
                    client_handler = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr)
                    )
                    client_handler.daemon = True
                    client_handler.start()
                except Exception as e:
                    if self.running:  # Only log errors if we're still supposed to be running
                        logger.error(f"Error accepting client: {e}")
        except Exception as e:
            logger.error(f"Error starting honeypot: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the honeypot service."""
        self.running = False
        
        # Close all client connections
        for client in self.clients:
            try:
                client.close()
            except:
                pass
        self.clients = []
        
        # Close the server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
        
        logger.info(f"[-] {self.service_type} honeypot on port {self.port} stopped")
    
    def handle_client(self, client_socket, addr):
        """Handle a client connection.
        
        Args:
            client_socket (socket): The client socket
            addr (tuple): The client address (ip, port)
        """
        source_ip, source_port = addr
        received_data = ""
        attack_type = "Unknown"
        
        try:
            # Send appropriate banner based on service type
            banner = self.get_service_banner()
            client_socket.send(banner.encode())
            
            # Receive initial data (typically username or command)
            buffer = client_socket.recv(4096)
            if buffer:
                received_data = buffer.decode('utf-8', errors='ignore')
                
                # Determine attack type based on received data
                attack_type = self.classify_attack(received_data)
                
                # Handle service-specific interactive sessions
                if self.service_type == 'ssh':
                    self._handle_ssh_session(client_socket, received_data, source_ip, attack_type)
                elif self.service_type == 'ftp':
                    self._handle_ftp_session(client_socket, received_data, source_ip, attack_type)
                elif self.service_type == 'telnet':
                    self._handle_telnet_session(client_socket, received_data, source_ip, attack_type)
                elif self.service_type == 'mysql':
                    self._handle_mysql_session(client_socket, received_data, source_ip, attack_type)
                elif self.service_type == 'smtp':
                    self._handle_smtp_session(client_socket, received_data, source_ip, attack_type)
                elif self.service_type == 'rdp':
                    self._handle_rdp_session(client_socket, received_data, source_ip, attack_type)
                else:
                    # Default handler for other services
                    # Send deceptive response
                    response = self.get_service_response()
                    client_socket.send(response.encode())
                    
                    # Log the attack
                    if log_callback:
                        log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
                        logger.info(f"Attack logged from {source_ip} on {self.service_type} service")
            else:
                # No data received, just log the connection
                if log_callback:
                    log_callback(self.service_type, source_ip, self.port, "Connection established but no data received", "Reconnaissance")
                    logger.info(f"Reconnaissance attempt logged from {source_ip} on {self.service_type} service")
                    
        except Exception as e:
            logger.error(f"Error handling client {source_ip}: {e}")
        
        finally:
            # Always log the connection if no data was received and not already logged
            if not received_data and log_callback:
                log_callback(self.service_type, source_ip, self.port, "Connection established but no data received", "Reconnaissance")
            
            # Close the client socket
            try:
                client_socket.close()
            except:
                pass
            
            if client_socket in self.clients:
                self.clients.remove(client_socket)
                
    def _handle_ssh_session(self, client_socket, username, source_ip, attack_type):
        """Handle an interactive SSH session with fake file system."""
        try:
            # Ask for password
            client_socket.send(b"Password: ")
            buffer = client_socket.recv(4096)
            
            if buffer:
                password = buffer.decode('utf-8', errors='ignore')
                received_data = f"Username: {username}\nPassword: {password}"
                
                # Log the credential attempt
                if log_callback:
                    log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
                
                # Simulate authentication process
                client_socket.send(b"Authenticating...\r\n")
                time.sleep(random.uniform(0.5, 1.0))
                
                # In 1 out of 5 attempts, let them in to explore our fake file system
                if random.random() < 0.2:  # 20% success rate
                    # Authentication success
                    client_socket.send(b"Last login: Mon Apr 01 09:23:19 2025 from 10.0.1.5\r\n")
                    client_socket.send(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)\r\n\r\n")
                    
                    # Simulate current directory
                    current_dir = f"/home/{username}"
                    client_socket.send(bytes(f"{username}@server:{current_dir.replace('/home/' + username, '~')}$ ", "utf-8"))
                    
                    # Start interactive session
                    buffer = b""
                    while True:
                        data = client_socket.recv(1024)
                        if not data:
                            break
                        
                        # Echo characters back to the client
                        client_socket.send(data)
                        
                        # Add to buffer and check if it's a complete command
                        buffer += data
                        if b"\r" in buffer or b"\n" in buffer:
                            command = buffer.decode("utf-8", errors="ignore").strip()
                            buffer = b""
                            
                            # Log the command with current directory context
                            log_data = f"SSH command executed: '{command}' in directory '{current_dir}'"
                            if log_callback:
                                log_callback('SSH-Command', source_ip, self.port, log_data, attack_type=attack_type)
                            
                            # Parse the command
                            cmd_parts = command.split()
                            base_cmd = cmd_parts[0].lower() if cmd_parts else ""
                            
                            # Send a fake response based on the command
                            if base_cmd == "ls":
                                if current_dir == "/home/admin":
                                    client_socket.send(b"\r\nDocuments\r\nDownloads\r\n.ssh\r\nconfig.yaml\r\nserver_access.txt\r\n.bash_history\r\n")
                                elif current_dir == "/home/admin/.ssh":
                                    client_socket.send(b"\r\nid_rsa\r\nid_rsa.pub\r\nauthorized_keys\r\nknown_hosts\r\n")
                                elif current_dir == "/home/admin/Documents":
                                    client_socket.send(b"\r\nproject_notes.txt\r\nservices.md\r\nadmin_guide.pdf\r\npasswords.kdbx\r\n")
                                elif current_dir == "/etc":
                                    client_socket.send(b"\r\npasswd\r\nshadow\r\nhosts\r\nssh\r\nsudo.conf\r\nfstab\r\ncrontab\r\n")
                                elif current_dir == "/var/log":
                                    client_socket.send(b"\r\nauth.log\r\nsyslog\r\napache2\r\nmysql\r\nfail2ban.log\r\n")
                                elif current_dir == "/root":
                                    client_socket.send(b"\r\n.bash_history\r\n.ssh\r\nbackups\r\nflag.txt\r\nsecret_configs\r\n")
                                elif current_dir == "/":
                                    client_socket.send(b"\r\nbin\r\nboot\r\ndev\r\netc\r\nhome\r\nlib\r\nmedia\r\nmnt\r\nopt\r\nproc\r\nroot\r\nrun\r\nsbin\r\nsrv\r\nsys\r\ntmp\r\nusr\r\nvar\r\n")
                                else:
                                    client_socket.send(b"\r\nNo files found\r\n")
                            elif base_cmd == "cd":
                                if len(cmd_parts) > 1:
                                    path = cmd_parts[1]
                                    # Handle navigation
                                    if path == "..":
                                        # Go up one directory
                                        if current_dir != "/":
                                            current_dir = "/".join(current_dir.split("/")[:-1]) or "/"
                                    elif path == "~" or path == "$HOME":
                                        current_dir = f"/home/{username}"
                                    elif path == "/":
                                        current_dir = "/"
                                    elif path.startswith("/"):
                                        # Absolute path
                                        current_dir = path
                                    else:
                                        # Relative path
                                        if current_dir == "/":
                                            current_dir = f"/{path}"
                                        else:
                                            current_dir = f"{current_dir}/{path}"
                            elif base_cmd == "cat":
                                if len(cmd_parts) > 1:
                                    filepath = cmd_parts[1]
                                    # Handle absolute paths
                                    if not filepath.startswith("/"):
                                        filepath = f"{current_dir}/{filepath}"
                                    
                                    # Handle specific files
                                    if "/etc/passwd" in filepath:
                                        # Read from our static file
                                        client_socket.send(b"\r\n")
                                        try:
                                            with open('static/honeypots/ssh/etc/passwd', 'rb') as f:
                                                client_socket.send(f.read())
                                        except:
                                            client_socket.send(b"root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:System Administrator:/home/admin:/bin/bash\n")
                                    elif "/home/admin/.ssh/id_rsa" in filepath:
                                        client_socket.send(b"\r\n")
                                        try:
                                            with open('static/honeypots/ssh/home/admin/.ssh/id_rsa', 'rb') as f:
                                                client_socket.send(f.read())
                                        except:
                                            client_socket.send(b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n...\n-----END RSA PRIVATE KEY-----\n")
                                    elif "/home/admin/server_access.txt" in filepath:
                                        client_socket.send(b"\r\nSSH Access Information:\n\nProduction Server (prod.example.com):\nUsername: admin\nPassword: Pr0duct!onAdm1n\n\nBackup Server (backup.example.com):\nUsername: backup-user\nPassword: B@ckup2023Server\n\nDatabase Server (db.example.com):\nUsername: db-admin\nPassword: DbAdm!n#2023\n")
                                    elif "/home/admin/Documents/passwords.kdbx" in filepath:
                                        client_socket.send(b"\r\nError: Cannot display binary file\r\n")
                                    elif "/home/admin/Documents/project_notes.txt" in filepath:
                                        client_socket.send(b"\r\nProject Falcon - Security Implementation\n\n1. Implement two-factor authentication for all admin accounts\n2. Rotate API keys and update in /etc/config/credentials.conf\n3. Patch SQL injection vulnerability in search form\n4. Move database credentials to vault instead of config files\n5. Update SSH keys and remove old ones from authorized_keys\n\nAPI Keys:\nStripe: sk_live_51HB0kXGTEkDgZs0gELk7S1d8nGmYKm5\nTwilio: ACd8e2ee6f9429c4e4f824d8c9517def33\nAWS: AKIAIOSFODNN7EXAMPLE\n\nRemember to schedule Q2 security review with client\n")
                                    elif "/root/flag.txt" in filepath and current_dir == "/root":
                                        client_socket.send(b"\r\n")
                                        log_data = f"Attacker found flag.txt! Possible root access"
                                        if log_callback:
                                            log_callback('SSH-Escalation', source_ip, self.port, log_data, attack_type="Root Access Attempt")
                                        client_socket.send(b"flag{r00t_acc3ss_achi3v3d}\n\nCongratulations on gaining root access to this server!\n")
                                    else:
                                        client_socket.send(b"\r\nNo such file or directory\r\n")
                            elif base_cmd == "whoami":
                                client_socket.send(bytes(f"\r\n{username}\r\n", "utf-8"))
                            elif base_cmd == "sudo":
                                client_socket.send(b"\r\n[sudo] password for " + bytes(username, "utf-8") + b": ")
                                # Wait for password input
                                password_data = client_socket.recv(1024)
                                if password_data:
                                    password = password_data.decode("utf-8", errors="ignore").strip()
                                    log_data = f"SSH sudo password attempt: {password}"
                                    if log_callback:
                                        log_callback('SSH-Password', source_ip, self.port, log_data, attack_type="Privilege Escalation Attempt")
                                    
                                    if command.startswith("sudo su") or command == "sudo -i":
                                        client_socket.send(b"\r\nPassword accepted. Switching to root user.\r\n")
                                        username = "root"
                                        current_dir = "/root"
                                    else:
                                        client_socket.send(b"\r\n" + bytes(username, "utf-8") + b" is not in the sudoers file. This incident will be reported.\r\n")
                            elif base_cmd == "id":
                                client_socket.send(bytes(f"\r\nuid=1000({username}) gid=1000({username}) groups=1000({username}),4(adm),24(cdrom),27(sudo)\r\n", "utf-8"))
                            elif base_cmd == "uname":
                                client_socket.send(b"\r\nLinux server 5.15.0-84-generic #93-Ubuntu SMP Tue Oct 10 13:25:37 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n")
                            elif base_cmd == "pwd":
                                client_socket.send(bytes(f"\r\n{current_dir}\r\n", "utf-8"))
                            elif base_cmd == "find":
                                # Simulate find command with fake results
                                client_socket.send(b"\r\nPermission denied\r\n")
                            elif base_cmd == "wget" or base_cmd == "curl":
                                # Log data exfiltration attempts
                                log_data = f"Possible data exfiltration attempt: {command}"
                                if log_callback:
                                    log_callback('SSH-Exfiltration', source_ip, self.port, log_data, attack_type="Data Exfiltration Attempt")
                                client_socket.send(b"\r\nconnect: Connection timed out\r\n")
                            elif base_cmd == "exit" or base_cmd == "logout":
                                client_socket.send(b"\r\nlogout\r\nConnection to server closed.\r\n")
                                break
                            else:
                                client_socket.send(b"\r\ncommand not found: " + bytes(command, "utf-8") + b"\r\n")
                            
                            # Display prompt with updated path
                            home_dir = f"/home/{username}"
                            prompt_path = current_dir.replace(home_dir, '~') if current_dir.startswith(home_dir) else current_dir
                            client_socket.send(bytes(f"\r\n{username}@server:{prompt_path}$ ", "utf-8"))
                else:
                    # Authentication always fails with a convincing message
                    client_socket.send(b"Access denied\r\n")
                    time.sleep(0.5)
                    
                    # Give them another try with a different message
                    client_socket.send(b"Permission denied, please try again.\r\nPassword: ")
                    buffer = client_socket.recv(4096)
                    
                    if buffer:
                        second_password = buffer.decode('utf-8', errors='ignore')
                        received_data += f"\nSecond password attempt: {second_password}"
                        
                        # Update the log with the second password attempt
                        if log_callback:
                            log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
                        
                        # Final rejection
                        client_socket.send(b"Access denied\r\n")
                        client_socket.send(b"Disconnecting: Too many authentication failures\r\n")
        except Exception as e:
            logger.error(f"Error in SSH session from {source_ip}: {e}")
    
    def _handle_ftp_session(self, client_socket, username, source_ip, attack_type):
        """Handle an interactive FTP session with fake file system."""
        try:
            # Ask for password
            client_socket.send(b"331 Password required for " + username.strip().encode() + b"\r\n")
            buffer = client_socket.recv(4096)
            
            if buffer:
                password = buffer.decode('utf-8', errors='ignore')
                received_data = f"Username: {username}\nPassword: {password}"
                
                # Log the credential attempt
                if log_callback:
                    log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
                
                # Sometimes let them in to access our fake files
                if random.random() < 0.3:  # 30% success rate
                    # Login successful
                    client_socket.send(b"230 Login successful. Welcome to FTP server.\r\n")
                    
                    # Initialize current directory to the root
                    current_dir = "/"
                    
                    # Process FTP commands with access to fake file system
                    while True:
                        try:
                            client_socket.settimeout(60)  # Longer timeout for interactive sessions
                            cmd_buffer = client_socket.recv(4096)
                            if not cmd_buffer:
                                break
                                
                            cmd = cmd_buffer.decode('utf-8', errors='ignore').strip().upper()
                            received_data += f"\nCommand: {cmd}"
                            
                            # Log the FTP command
                            if log_callback:
                                cmd_log = f"FTP command: {cmd} (in directory: {current_dir})"
                                log_callback('FTP-Command', source_ip, self.port, cmd_log, attack_type="File Access")
                            
                            # Extract command and arguments
                            cmd_parts = cmd.split()
                            base_cmd = cmd_parts[0] if cmd_parts else ""
                            args = ' '.join(cmd_parts[1:]) if len(cmd_parts) > 1 else ""
                            
                            # Handle different FTP commands
                            if base_cmd == "PWD" or base_cmd == "XPWD":
                                client_socket.send(f'257 "{current_dir}" is the current directory\r\n'.encode())
                            
                            elif base_cmd == "CWD" or base_cmd == "XCWD":
                                # Change directory command
                                path = args
                                if path.startswith("/"):
                                    # Absolute path
                                    new_dir = path
                                elif path == "..":
                                    # Go up one directory
                                    if current_dir == "/":
                                        new_dir = "/"
                                    else:
                                        new_dir = "/".join(current_dir.split("/")[:-1]) or "/"
                                else:
                                    # Relative path
                                    if current_dir == "/":
                                        new_dir = f"/{path}"
                                    else:
                                        new_dir = f"{current_dir}/{path}"
                                
                                # Check if the directory exists in our fake file system
                                if (new_dir == "/" or 
                                    new_dir == "/private" or 
                                    new_dir == "/public" or 
                                    new_dir == "/users" or
                                    new_dir == "/users/admin" or
                                    new_dir == "/users/developer" or
                                    new_dir == "/backups" or
                                    new_dir == "/config"):
                                    current_dir = new_dir
                                    client_socket.send(f'250 Directory changed to {current_dir}\r\n'.encode())
                                else:
                                    client_socket.send(b'550 Directory not found\r\n')
                            
                            elif base_cmd == "LIST" or base_cmd == "NLST":
                                # Send fake directory listing based on current directory
                                client_socket.send(b'150 Opening ASCII mode data connection for file list\r\n')
                                
                                # Different listings based on directory
                                if current_dir == "/":
                                    listing = "drwxr-xr-x 2 admin  admin  4096 Apr 01 10:15 private\r\n"
                                    listing += "drwxr-xr-x 2 admin  admin  4096 Apr 01 10:15 public\r\n"
                                    listing += "drwxr-xr-x 3 admin  admin  4096 Apr 01 10:15 users\r\n"
                                    listing += "drwxr-xr-x 2 admin  admin  4096 Apr 01 10:15 backups\r\n"
                                    listing += "drwxr-xr-x 2 admin  admin  4096 Apr 01 10:15 config\r\n"
                                elif current_dir == "/private":
                                    listing = "-rw-r--r-- 1 admin admin 2458 Apr 01 10:15 customer_data.csv\r\n"
                                    listing += "-rw-r--r-- 1 admin admin 1234 Apr 01 10:15 financial_report_2024.pdf\r\n"
                                    listing += "-rw-r--r-- 1 admin admin 5678 Apr 01 10:15 employee_salaries.xlsx\r\n"
                                elif current_dir == "/backups":
                                    listing = "-rw-r--r-- 1 admin admin 1245 Mar 30 22:00 backup_20241230.sql\r\n"
                                    listing += "-rw-r--r-- 1 admin admin 1367 Mar 20 22:00 backup_20240320.sql\r\n"
                                    listing += "-rw-r--r-- 1 admin admin 1089 Feb 15 22:00 backup_20240215.sql\r\n"
                                elif current_dir == "/config":
                                    listing = "-rw-r--r-- 1 admin admin 849 Apr 01 10:15 database.ini\r\n"
                                    listing += "-rw-r--r-- 1 admin admin 612 Apr 01 10:15 server.conf\r\n"
                                    listing += "-rw-r--r-- 1 admin admin 389 Apr 01 10:15 credentials.json\r\n"
                                elif current_dir == "/users":
                                    listing = "drwxr-xr-x 2 admin  admin  4096 Apr 01 10:15 admin\r\n"
                                    listing += "drwxr-xr-x 2 devel  devel  4096 Apr 01 10:15 developer\r\n"
                                elif current_dir == "/users/admin":
                                    listing = "-rw-r--r-- 1 admin admin 512 Apr 01 10:15 credentials.txt\r\n"
                                    listing += "-rw-r--r-- 1 admin admin 845 Apr 01 10:15 todo.txt\r\n"
                                    listing += "-rw-r--r-- 1 admin admin 124 Apr 01 10:15 notes.txt\r\n"
                                elif current_dir == "/users/developer":
                                    listing = "-rw-r--r-- 1 devel devel 845 Apr 01 10:15 project_notes.txt\r\n"
                                    listing += "-rw-r--r-- 1 devel devel 2134 Apr 01 10:15 api_keys.txt\r\n"
                                elif current_dir == "/public":
                                    listing = "-rw-r--r-- 1 admin admin 1450 Apr 01 10:15 readme.txt\r\n"
                                    listing += "-rw-r--r-- 1 admin admin 2580 Apr 01 10:15 public_data.csv\r\n"
                                    listing += "-rw-r--r-- 1 admin admin 3690 Apr 01 10:15 company_profile.pdf\r\n"
                                else:
                                    listing = ""
                                
                                client_socket.send(listing.encode())
                                client_socket.send(b'226 Transfer complete\r\n')
                            
                            elif base_cmd == "RETR":
                                # Download file command
                                filename = args.split('/')[-1] if '/' in args else args
                                filepath = f"{current_dir}/{filename}" if current_dir == '/' else f"{current_dir}/{filename}"
                                
                                # Log the file download attempt
                                if log_callback:
                                    file_log = f"FTP file download attempt: {filepath}"
                                    log_callback('FTP-Download', source_ip, self.port, file_log, attack_type="Data Theft")
                                
                                # Check if we have a prepared file for this path
                                if filepath == "/private/customer_data.csv":
                                    client_socket.send(b'150 Opening BINARY mode data connection\r\n')
                                    try:
                                        with open('static/honeypots/ftp/private/customer_data.csv', 'rb') as f:
                                            client_socket.send(f.read())
                                    except:
                                        client_socket.send(b'id,name,email,credit_card,ssn\n1,John Doe,john@example.com,4111-XXXX-XXXX-1111,123-XX-1234\n')
                                    client_socket.send(b'226 Transfer complete\r\n')
                                elif filepath == "/config/database.ini":
                                    client_socket.send(b'150 Opening BINARY mode data connection\r\n')
                                    try:
                                        with open('static/honeypots/ftp/config/database.ini', 'rb') as f:
                                            client_socket.send(f.read())
                                    except:
                                        client_socket.send(b'[database]\nhost=localhost\nuser=admin\npassword=password123\n')
                                    client_socket.send(b'226 Transfer complete\r\n')
                                elif filepath == "/users/admin/credentials.txt":
                                    client_socket.send(b'150 Opening BINARY mode data connection\r\n')
                                    try:
                                        with open('static/honeypots/ftp/users/admin/credentials.txt', 'rb') as f:
                                            client_socket.send(f.read())
                                    except:
                                        client_socket.send(b'admin:password123\nroot:toor\n')
                                    client_socket.send(b'226 Transfer complete\r\n')
                                elif filepath == "/backups/backup_20241230.sql":
                                    client_socket.send(b'150 Opening BINARY mode data connection\r\n')
                                    try:
                                        with open('static/honeypots/ftp/backups/backup_20241230.sql', 'rb') as f:
                                            client_socket.send(f.read())
                                    except:
                                        client_socket.send(b'-- Database backup\nCREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(50));\n')
                                    client_socket.send(b'226 Transfer complete\r\n')
                                else:
                                    client_socket.send(b'550 File not found or access denied\r\n')
                            
                            elif base_cmd == "SYST":
                                client_socket.send(b'215 UNIX Type: L8\r\n')
                            
                            elif base_cmd == "TYPE":
                                client_socket.send(b'200 Type set to I\r\n')
                                
                            elif base_cmd == "QUIT":
                                client_socket.send(b'221 Goodbye\r\n')
                                break
                                
                            else:
                                client_socket.send(b'500 Unknown command\r\n')
                                
                        except socket.timeout:
                            client_socket.send(b'421 Timeout, closing control connection\r\n')
                            break
                        except Exception as cmd_error:
                            logger.error(f"Error processing FTP command: {cmd_error}")
                            break
                else:
                    # Login failed
                    client_socket.send(b"530 Login incorrect.\r\n")
                    
                    # Wait for additional commands
                    client_socket.send(b"214-The following commands are recognized:\r\n")
                    client_socket.send(b" ABOR ACCT ALLO APPE CDUP CWD DELE HELP LIST MKD MODE NLST NOOP\r\n")
                    client_socket.send(b" PASS PASV PORT PWD QUIT REIN REST RETR RMD RNFR RNTO SITE SIZE\r\n")
                    client_socket.send(b" SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD XPWD XRMD\r\n")
                    client_socket.send(b"214 Help OK.\r\n")
                    
                    # Process a few more commands to make it seem realistic
                    for _ in range(3):
                        try:
                            client_socket.settimeout(10)
                            cmd_buffer = client_socket.recv(4096)
                            if cmd_buffer:
                                cmd = cmd_buffer.decode('utf-8', errors='ignore').strip()
                                received_data += f"\nCommand: {cmd}"
                                
                                # Update the log with the command
                                if log_callback:
                                    log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
                                
                                # Handle common FTP commands
                                if cmd.upper().startswith("LIST"):
                                    client_socket.send(b"150 Opening ASCII mode data connection for file list\r\n")
                                    time.sleep(1)
                                    client_socket.send(b"226 Transfer complete.\r\n")
                                elif cmd.upper().startswith("CWD"):
                                    client_socket.send(b"550 Failed to change directory.\r\n")
                                elif cmd.upper().startswith("RETR"):
                                    client_socket.send(b"550 Failed to open file.\r\n")
                                elif cmd.upper().startswith("STOR"):
                                    client_socket.send(b"553 Could not create file.\r\n")
                                elif cmd.upper() == "SYST":
                                    client_socket.send(b"215 UNIX Type: L8\r\n")
                                elif cmd.upper() == "FEAT":
                                    client_socket.send(b"211-Features:\r\n UTF8\r\n REST STREAM\r\n SIZE\r\n MDTM\r\n211 End\r\n")
                                else:
                                    client_socket.send(b"500 Unknown command.\r\n")
                        except socket.timeout:
                            break
                        except Exception as cmd_error:
                            logger.error(f"Error processing FTP command: {cmd_error}")
                            break
        except Exception as e:
            logger.error(f"Error in FTP session from {source_ip}: {e}")
    
    def _handle_telnet_session(self, client_socket, initial_data, source_ip, attack_type):
        """Handle an interactive Telnet session."""
        try:
            # Initial login prompt
            client_socket.send(b"\r\nLogin: ")
            buffer = client_socket.recv(4096)
            
            if buffer:
                username = buffer.decode('utf-8', errors='ignore')
                received_data = f"Username: {username}"
                
                # Ask for password
                client_socket.send(b"Password: ")
                buffer = client_socket.recv(4096)
                
                if buffer:
                    password = buffer.decode('utf-8', errors='ignore')
                    received_data += f"\nPassword: {password}"
                    
                    # Log the credential attempt
                    if log_callback:
                        log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
                    
                    # Login failed
                    client_socket.send(b"\r\nLogin incorrect\r\n")
                    time.sleep(1)
                    
                    # Second login attempt
                    client_socket.send(b"Login: ")
                    buffer = client_socket.recv(4096)
                    
                    if buffer:
                        username2 = buffer.decode('utf-8', errors='ignore')
                        received_data += f"\nSecond username attempt: {username2}"
                        
                        client_socket.send(b"Password: ")
                        buffer = client_socket.recv(4096)
                        
                        if buffer:
                            password2 = buffer.decode('utf-8', errors='ignore')
                            received_data += f"\nSecond password attempt: {password2}"
                            
                            # Update the log with the second attempt
                            if log_callback:
                                log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
                            
                            # Login failed again
                            client_socket.send(b"\r\nLogin incorrect\r\n")
                            client_socket.send(b"Maximum login attempts exceeded\r\n")
                            time.sleep(0.5)
                            client_socket.send(b"Connection closed by foreign host.\r\n")
        except Exception as e:
            logger.error(f"Error in Telnet session from {source_ip}: {e}")
    
    def _handle_mysql_session(self, client_socket, initial_data, source_ip, attack_type):
        """Handle an interactive MySQL session."""
        try:
            # MySQL typically responds first with a server greeting
            # Already sent in the banner, now expecting username/password
            
            # Log the connection attempt with any initial data
            received_data = f"Initial data: {initial_data}"
            if log_callback:
                log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
            
            # Send an error message regardless of the input
            error_msg = b"ERROR 1045 (28000): Access denied for user '{}' (using password: YES)\r\n"
            
            # Extract username if possible, or use a default
            username = "unknown"
            try:
                # Try to parse the username from MySQL protocol
                # This is a simplified approach as actual MySQL protocol is complex
                if len(initial_data) > 10:
                    potential_username = initial_data[10:30]
                    username = ''.join(c for c in potential_username if c.isalnum() or c in '_-.')
            except:
                pass
            
            client_socket.send(error_msg.replace(b"{}", username.encode()))
            
            # Wait briefly for any additional commands
            time.sleep(1)
            try:
                client_socket.settimeout(5)
                buffer = client_socket.recv(4096)
                if buffer:
                    additional_data = buffer.decode('utf-8', errors='ignore')
                    received_data += f"\nAdditional data: {additional_data}"
                    
                    # Update the log with additional data
                    if log_callback:
                        log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
                    
                    # Always send an error
                    client_socket.send(b"ERROR 1064 (42000): You have an error in your SQL syntax\r\n")
            except socket.timeout:
                pass
        except Exception as e:
            logger.error(f"Error in MySQL session from {source_ip}: {e}")
    
    def _handle_smtp_session(self, client_socket, initial_data, source_ip, attack_type):
        """Handle an interactive SMTP session."""
        try:
            # Log the initial connection data
            received_data = f"Initial data: {initial_data}"
            if log_callback:
                log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
            
            # Process SMTP commands
            for _ in range(5):  # Allow up to 5 command exchanges
                try:
                    client_socket.settimeout(10)
                    buffer = client_socket.recv(4096)
                    if not buffer:
                        break
                    
                    command = buffer.decode('utf-8', errors='ignore').strip()
                    received_data += f"\nCommand: {command}"
                    
                    # Update log with each command
                    if log_callback:
                        log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
                    
                    # Handle common SMTP commands
                    if command.upper().startswith("HELO") or command.upper().startswith("EHLO"):
                        client_socket.send(b"250 mail.example.com\r\n")
                    elif command.upper().startswith("MAIL FROM"):
                        client_socket.send(b"250 OK\r\n")
                    elif command.upper().startswith("RCPT TO"):
                        client_socket.send(b"250 OK\r\n")
                    elif command.upper() == "DATA":
                        client_socket.send(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                        # Wait for the message body and the terminating "."
                        message_buffer = b""
                        while True:
                            client_socket.settimeout(30)
                            data_chunk = client_socket.recv(4096)
                            if not data_chunk:
                                break
                            
                            message_buffer += data_chunk
                            if b"\r\n.\r\n" in message_buffer or b"\n.\n" in message_buffer:
                                break
                        
                        message_text = message_buffer.decode('utf-8', errors='ignore')
                        received_data += f"\nMessage body: {message_text}"
                        
                        # Log the complete email data
                        if log_callback:
                            log_callback(self.service_type, source_ip, self.port, received_data, "Email Injection")
                        
                        client_socket.send(b"250 OK: message queued\r\n")
                    elif command.upper() == "QUIT":
                        client_socket.send(b"221 mail.example.com closing connection\r\n")
                        break
                    elif command.upper() in ["VRFY", "EXPN"]:
                        client_socket.send(b"252 Cannot VRFY user, but will accept message and attempt delivery\r\n")
                    elif command.upper() == "RSET":
                        client_socket.send(b"250 OK\r\n")
                    elif command.upper() == "NOOP":
                        client_socket.send(b"250 OK\r\n")
                    elif command.upper() == "HELP":
                        client_socket.send(b"214-Commands supported:\r\n")
                        client_socket.send(b"214 HELO EHLO MAIL RCPT DATA RSET NOOP QUIT VRFY HELP\r\n")
                    else:
                        client_socket.send(b"500 Command not recognized\r\n")
                        
                except socket.timeout:
                    client_socket.send(b"421 mail.example.com connection timeout\r\n")
                    break
                except Exception as cmd_error:
                    logger.error(f"Error processing SMTP command: {cmd_error}")
                    break
        except Exception as e:
            logger.error(f"Error in SMTP session from {source_ip}: {e}")
    
    def _handle_rdp_session(self, client_socket, initial_data, source_ip, attack_type):
        """Handle an RDP session."""
        try:
            # Log the initial connection data
            received_data = f"Initial data: {initial_data}"
            if log_callback:
                log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
            
            # RDP is a binary protocol, so we'll simulate some binary data exchange
            client_socket.send(b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x00\x00\x00\x00")
            time.sleep(1)
            
            # Try to receive more data
            try:
                client_socket.settimeout(10)
                buffer = client_socket.recv(4096)
                if buffer:
                    # Convert binary data to hex for logging
                    hex_data = ' '.join(f'{b:02x}' for b in buffer)
                    received_data += f"\nAdditional binary data (hex): {hex_data}"
                    
                    # Update the log with additional data
                    if log_callback:
                        log_callback(self.service_type, source_ip, self.port, received_data, attack_type)
                    
                    # Send a simulated error response
                    client_socket.send(b"\x03\x00\x00\x09\x02\xf0\x80\x21\x80")
            except socket.timeout:
                pass
        except Exception as e:
            logger.error(f"Error in RDP session from {source_ip}: {e}")
    
    def get_service_banner(self):
        """Get a service-specific banner to send to clients."""
        banners = {
            'ssh': "SSH-2.0-OpenSSH_7.9p1 Ubuntu-10\r\n",
            'ftp': "220 (vsFTPd 3.0.3)\r\n",
            'telnet': "\r\nUbuntu 18.04.5 LTS\r\nlogin: ",
            'http': "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n",
            'smtp': "220 mail.example.com ESMTP Postfix\r\n",
            'mysql': "5.7.32-0ubuntu0.18.04.1\n",
            'rdp': "Remote Desktop Protocol Enabled\r\n",
            'http-admin': "HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n",
        }
        return banners.get(self.service_type, f"Welcome to {self.service_type} server\r\n")
    
    def get_service_response(self):
        """Get a service-specific response to send to clients."""
        responses = {
            'ssh': "Please wait...\r\n",
            'ftp': "331 Please specify the password.\r\n",
            'telnet': "",  # No response needed as we're asking for login
            'http': self._get_http_default_response(),
            'smtp': "250 mail.example.com\r\n",
            'mysql': "ERROR 1045 (28000): Access denied for user\r\n",
            'rdp': "Connection established. Waiting for authentication...\r\n",
            'http-admin': self._get_http_admin_response(),
        }
        return responses.get(self.service_type, "Processing request...\r\n")
        
    def _get_http_default_response(self):
        """Get a more realistic HTTP response for the default server page."""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Default Web Page</title>
</head>
<body>
    <h1>Server Default Page</h1>
    <p>This is the default page for this server.</p>
    <p>The web server is running correctly, but no content has been added yet.</p>
    <hr>
    <p><small>Apache/2.4.29 (Ubuntu) Server</small></p>
</body>
</html>
"""

    def _get_http_admin_response(self):
        """Get a fake admin login page for HTTP admin honeypot."""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
</head>
<body>
    <h1>System Administration</h1>
    <form>
        <label>Username:</label>
        <input type="text"><br>
        <label>Password:</label>
        <input type="password"><br>
        <button type="submit">Login</button>
    </form>
    <p><small>Secure Admin v2.1</small></p>
</body>
</html>
"""
    
    def classify_attack(self, data):
        """Classify the attack based on the received data."""
        data_lower = data.lower()
        
        # Check for HTTP specific patterns first
        if data_lower.startswith('get ') or data_lower.startswith('post ') or data_lower.startswith('head '):
            return self._classify_http_attack(data)
        
        # Check for common SQL injection patterns
        if any(pattern in data_lower for pattern in ['select ', 'union ', 'insert ', 'delete ', "' or '", "1=1", "--", "/*", "drop table", "exec sp_", "waitfor delay", "benchmark("]):
            return "SQL Injection"
        
        # Check for common command injection patterns
        elif any(pattern in data_lower for pattern in ['sh ', '/bin/', 'cat ', 'wget ', 'curl ', 'bash ', '& ', '&&', '|', ';', '/etc/passwd', '/etc/shadow', 'chmod ', 'crontab']):
            return "Command Injection"
        
        # Check for common XSS patterns
        elif any(pattern in data_lower for pattern in ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie', 'eval(', 'fromcharcode', 'img src=x']):
            return "Cross-Site Scripting (XSS)"
        
        # Check for common brute force patterns
        elif any(pattern in data_lower for pattern in ['admin', 'root', 'password', '123456', 'administrator', 'guest', 'default', 'qwerty', 'welcome']):
            return "Brute Force"
            
        # Check for path traversal attempts
        elif any(pattern in data_lower for pattern in ['../', '../', '..\\', '..\\']):
            return "Path Traversal"
            
        # Check for file inclusion attempts
        elif any(pattern in data_lower for pattern in ['include=', 'require=', 'include_once=', 'file=', 'document=', 'php://']):
            return "File Inclusion"
            
        # Check for SSRF attempts
        elif any(pattern in data_lower for pattern in ['http://', 'https://', 'ftp://', 'gopher://', 'file:///', '127.0.0.1', 'localhost']):
            return "Server-Side Request Forgery"
        
        # Check for scanning/enumeration
        elif len(data.strip()) < 5 or data_lower in ['help', 'info', 'status', 'ls', 'dir', 'test', 'ping', 'whoami']:
            return "Reconnaissance"
        
        # Default classification
        return "Unknown"
        
    def _classify_http_attack(self, data):
        """Classify HTTP-specific attacks based on the request data."""
        data_lower = data.lower()
        
        # Look for sensitive endpoints
        if any(path in data_lower for path in ['/admin', '/login', '/wp-admin', '/administrator', '/phpmyadmin', '/mysql', '/config']):
            return "Admin Access Attempt"
            
        # Look for vulnerability scanners and security tools
        if any(tool in data_lower for tool in ['nmap', 'nikto', 'gobuster', 'dirb', 'wpscan', 'sqlmap', 'metasploit', 'burpsuite']):
            return "Automated Scanner"
            
        # Look for SQLi in HTTP params
        if any(pattern in data_lower for pattern in ['?id=', '&id=', '?user=', '&user=', '?page=', '&page=']):
            if any(sqli in data_lower for sqli in ["'", '"', "--", "/*", "1=1", "or 1=", "union select"]):
                return "SQL Injection"
                
        # Look for XSS in HTTP params
        if any(pattern in data_lower for pattern in ['?', '&']):
            if any(xss in data_lower for xss in ["<script>", "javascript:", "onerror=", "onload=", "alert("]):
                return "Cross-Site Scripting (XSS)"
                
        # Look for LFI/RFI in HTTP params
        if any(pattern in data_lower for pattern in ['?file=', '&file=', '?page=', '&page=', '?include=', '&include=']):
            if any(lfi in data_lower for lfi in ["../", "..\\", "/etc/passwd", "c:\\windows", "file://"]):
                return "Path Traversal/File Inclusion"
                
        # Look for shell access attempts
        if any(pattern in data_lower for pattern in ['/cgi-bin/', '/bin/sh', 'cmd.exe']):
            return "Web Shell Attempt"
            
        # Check if this appears to be a user-agent check (could be scanners)
        if "user-agent:" in data_lower:
            ua = data_lower.split("user-agent:")[1].strip().split("\r\n")[0]
            if any(bot in ua for bot in ["bot", "spider", "crawler", "scan", "nikto", "nmap", "masscan"]):
                return "Bot/Scanner Detection"
                
        # Default for HTTP
        return "Web Reconnaissance"
