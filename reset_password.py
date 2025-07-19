#!/usr/bin/env python3

import sys
from app.database.connection import get_db
from app.database.models import User
from app.utils.auth import hash_password


def reset_user_password(email: str, new_password: str):
    try:
        with next(get_db()) as db:
            user = db.query(User).filter(User.email == email).first()

            if not user:
                print(f"❌ User with email {email} not found!")
                return False

            user.password_hash = hash_password(new_password)  # type: ignore
            db.commit()

            print(f"✅ Password updated successfully for user: {email}")
            print(f"   Username: {user.username}")
            print(f"   New Password: {new_password}")
            return True

    except Exception as e:
        print(f"❌ Error updating password: {e}")
        return False


def create_new_user(email: str, username: str, password: str):
    try:
        with next(get_db()) as db:
            existing_user = (
                db.query(User)
                .filter((User.email == email) | (User.username == username))
                .first()
            )

            if existing_user:
                print("❌ User already exists!")
                print(f"   Email: {existing_user.email}")
                print(f"   Username: {existing_user.username}")
                return False

            hashed_password = hash_password(password)
            new_user = User(
                username=username, email=email, password_hash=hashed_password
            )

            db.add(new_user)
            db.commit()

            print("✅ New user created successfully!")
            print(f"   Email: {email}")
            print(f"   Username: {username}")
            print(f"   Password: {password}")
            return True

    except Exception as e:
        print(f"❌ Error creating user: {e}")
        return False


def list_users():
    try:
        with next(get_db()) as db:
            users = db.query(User).all()

            if not users:
                print("📋 No users found in database")
                return

            print("📋 Current users in database:")
            print("-" * 50)
            for user in users:
                print(f"   Email: {user.email}")
                print(f"   Username: {user.username}")
                print(f"   ID: {user.id}")
                print("-" * 30)

    except Exception as e:
        print(f"❌ Error listing users: {e}")


if __name__ == "__main__":
    print("🔐 CVE Watcher - Password Reset Utility")
    print("=" * 50)

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python reset_password.py list")
        print("  python reset_password.py reset <email> <new_password>")
        print("  python reset_password.py create <email> <username> <password>")
        print("\nExamples:")
        print("  python reset_password.py list")
        print(
            "  python reset_password.py reset m.angrisano@namirial.com newpassword123"
        )
        print(
            "  python reset_password.py create m.angrisano@namirial.com mangrisano password123"
        )
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "list":
        list_users()

    elif command == "reset":
        if len(sys.argv) != 4:
            print("❌ Usage: python reset_password.py reset <email> <new_password>")
            sys.exit(1)

        email = sys.argv[2]
        password = sys.argv[3]
        reset_user_password(email, password)

    elif command == "create":
        if len(sys.argv) != 5:
            print(
                "❌ Usage: python reset_password.py create <email> <username> <password>"
            )
            sys.exit(1)

        email = sys.argv[2]
        username = sys.argv[3]
        password = sys.argv[4]
        create_new_user(email, username, password)

    else:
        print(f"❌ Unknown command: {command}")
        print("Available commands: list, reset, create")
        sys.exit(1)
