import bcrypt
import re

# -------------------------------
# Password strength validation
# -------------------------------
def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"

    return True, "Password is strong"


# -------------------------------
# Password hashing
# -------------------------------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


# -------------------------------
# Password verification
# -------------------------------
def verify_password(password: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)


# -------------------------------
# Main authentication flow
# -------------------------------
def main():
    print("=== USER REGISTRATION ===")

    while True:
        password = input("Create password: ")
        valid, message = validate_password(password)
        print(message)

        if valid:
            break

    stored_hash = hash_password(password)
    print("\nPassword stored securely.\n")

    print("=== USER LOGIN ===")
    login_password = input("Enter password: ")

    if verify_password(login_password, stored_hash):
        print("✅ Authentication successful")
    else:
        print("❌ Authentication failed")


if __name__ == "__main__":
    main()
