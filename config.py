import os
import time
import threading

PORT = 443

# name -> secret (32 hex chars)

USERS = {'tg': '00000000000000000000000000000001', 'autouser': '0e43c90aca5aef3ede5deb415553a993'}

MODES = {'classic': False, 'secure': False, 'tls': True}

# Prometheus exporter host and port for the dedicated endpoint
PROMETHEUS_HOST = "0.0.0.0"
PROMETHEUS_PORT = 9100

# Prometheus scrapers whitelist for safety
PROMETHEUS_SCRAPERS = ["127.0.0.1", "::1"]

def is_valid_secret(secret):
    """Validate if secret is a valid 32 character hex string"""
    if len(secret) != 32:
        return False
    try:
        int(secret, 16)
        return True
    except ValueError:
        return False

def add_user(username, secret):
    """Add a new user with their secret"""
    global USERS
    
    if not isinstance(username, str) or not username:
        raise ValueError("Username must be a non-empty string")
    
    if not is_valid_secret(secret):
        raise ValueError("Secret must be a 32 character hex string")
        
    USERS[username] = secret
    save_config()
    
    return True

def remove_user(username):
    """Remove a user"""
    global USERS
    
    if username not in USERS:
        raise ValueError(f"User {username} not found")
    
    del USERS[username]
    save_config()
    
    return True

def save_config():
    """Save current configuration to file"""
    import inspect
    
    # Get the current file content
    with open(__file__, 'r') as f:
        current_content = f.read()
    
    # Find where the actual code/functions start
    code_start = current_content.find('def is_valid_secret')
    if code_start == -1:
        code_start = len(current_content)
    
    # Prepare the new config values
    new_config = f"""import os
import time
import threading

PORT = {PORT}

# name -> secret (32 hex chars)
USERS = {repr(USERS)}

MODES = {repr(MODES)}

"""
    
    # Combine config values with the existing functions
    if code_start > 0:
        new_content = new_config + current_content[code_start:]
        with open(__file__, 'w') as f:
            f.write(new_content)

# Set up file monitoring for hot reload
_last_modified = os.path.getmtime(__file__)

def check_config_changed():
    """Check if config file has been modified"""
    global _last_modified
    try:
        current_mtime = os.path.getmtime(__file__)
        if current_mtime != _last_modified:
            _last_modified = current_mtime
            return True
    except Exception:
        pass
    return False

def reload_config():
    """Reload the configuration"""
    global PORT, USERS, MODES
    temp_module = {}
    with open(__file__, 'r') as f:
        exec(f.read(), temp_module)
    PORT = temp_module['PORT']
    USERS = temp_module['USERS']
    MODES = temp_module['MODES']
