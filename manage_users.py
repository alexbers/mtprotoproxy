#!/usr/bin/env python3

import sys
import config
import random

def generate_random_secret():
    """Generate a random 32 character hex string"""
    return ''.join(random.choice('0123456789abcdef') for _ in range(32))

def print_usage():
    print("Usage:")
    print("  Add user:    ./manage_users.py add <username> [secret]")
    print("  Remove user: ./manage_users.py remove <username>")
    print("  List users:  ./manage_users.py list")
    print("\nNote: If secret is not provided, a random one will be generated")

def main():
    if len(sys.argv) < 2:
        print_usage()
        return

    command = sys.argv[1]

    try:
        if command == "add":
            if len(sys.argv) < 3:
                print_usage()
                return
                
            username = sys.argv[2]
            if len(sys.argv) == 4:
                secret = sys.argv[3]
            else:
                secret = generate_random_secret()
                
            config.add_user(username, secret)
            print(f"User {username} added successfully with secret: {secret}")
            
        elif command == "remove" and len(sys.argv) == 3:
            username = sys.argv[2]
            config.remove_user(username)
            print(f"User {username} removed successfully")
            
        elif command == "list":
            print("Current users:")
            for username, secret in config.USERS.items():
                print(f"{username}: {secret}")
            
        else:
            print_usage()
            
    except ValueError as e:
        print(f"Error: {str(e)}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    main()
