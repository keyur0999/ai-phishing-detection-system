"""
manage.py
PhishGuard AI - Secure Server Owner Management CLI.

Provides owner-controlled administrative actions directly via the server shell:
  - Promote an existing user to Admin
  - Demote an Admin to Normal User
  - List all user accounts and their current roles
  - Create a new Admin account directly from server CLI

Usage:
  python manage.py promote-admin <username>
  python manage.py demote-admin <username>
  python manage.py list-users
  python manage.py create-admin <username> <email> <password>
"""

import sys
import os
from werkzeug.security import generate_password_hash
import database


def promote_admin(username):
    user = database.get_user_by_username(username)
    if not user:
        print(f"[ERROR] User '{username}' does not exist in database.")
        sys.exit(1)
    if user.get("role") == "admin":
        print(f"[INFO] User '{username}' is already an Admin.")
        return
    updated = database.promote_user(username, role="admin")
    if updated:
        print(f"[SUCCESS] User '{username}' (ID #{user['id']}) has been successfully promoted to ADMIN.")
    else:
        print(f"[ERROR] Failed to promote user '{username}'.")


def demote_admin(username):
    user = database.get_user_by_username(username)
    if not user:
        print(f"[ERROR] User '{username}' does not exist in database.")
        sys.exit(1)
    if user.get("role") == "user":
        print(f"[INFO] User '{username}' is already a Normal User.")
        return
    updated = database.demote_user(username)
    if updated:
        print(f"[SUCCESS] User '{username}' (ID #{user['id']}) has been demoted to NORMAL USER.")
    else:
        print(f"[ERROR] Failed to demote user '{username}'.")


def list_users():
    users = database.get_all_users(limit=200)
    print("=" * 75)
    print(f"{'ID':<6} {'USERNAME':<20} {'EMAIL':<25} {'ROLE':<10} {'LOGINS':<8}")
    print("=" * 75)
    if not users:
        print("No users registered.")
    for u in users:
        role_badge = "[ADMIN]" if u.get("role") == "admin" else "user"
        print(f"{u['id']:<6} {u['username']:<20} {str(u.get('email') or 'N/A'):<25} {role_badge:<10} {u.get('login_count', 0):<8}")
    print("=" * 75)


def create_admin(username, email, password):
    if len(username.strip()) < 3:
        print("[ERROR] Username must be at least 3 characters.")
        sys.exit(1)
    if len(password) < 6:
        print("[ERROR] Password must be at least 6 characters.")
        sys.exit(1)
    if database.get_user_by_username(username):
        print(f"[ERROR] Username '{username}' already exists. Use 'promote-admin {username}' instead.")
        sys.exit(1)

    hashed = generate_password_hash(password)
    user_id = database.create_user(username, email, hashed, role="admin")
    print(f"[SUCCESS] Admin account '{username}' (ID #{user_id}) created successfully.")


def print_help():
    print(__doc__)


def main():
    database.init_db()
    if len(sys.argv) < 2:
        print_help()
        sys.exit(0)

    cmd = sys.argv[1].lower().strip()
    if cmd in ("promote", "promote-admin"):
        if len(sys.argv) < 3:
            print("Usage: python manage.py promote-admin <username>")
            sys.exit(1)
        promote_admin(sys.argv[2])
    elif cmd in ("demote", "demote-admin"):
        if len(sys.argv) < 3:
            print("Usage: python manage.py demote-admin <username>")
            sys.exit(1)
        demote_admin(sys.argv[2])
    elif cmd in ("list", "list-users"):
        list_users()
    elif cmd in ("create-admin", "new-admin"):
        if len(sys.argv) < 5:
            print("Usage: python manage.py create-admin <username> <email> <password>")
            sys.exit(1)
        create_admin(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print(f"Unknown command: '{cmd}'")
        print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
