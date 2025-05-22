import pyotp

def main():
    secret = input("Enter the TOTP secret: ").strip()
    totp = pyotp.TOTP(secret)
    print("Current TOTP code:", totp.now())

if __name__ == "__main__":
    main()
