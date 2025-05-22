import os
import pymysql
import pyotp
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database connection parameters
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASSWORD = os.getenv('DB_PASSWORD', '')
DB_NAME = 'dataproject'

def reset_oauth_2fa_secrets():
    connection = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        with connection.cursor() as cursor:
            # Select OAuth users
            cursor.execute("SELECT id, username, auth_method FROM users WHERE auth_method IN ('github', 'google', 'facebook')")
            users = cursor.fetchall()
            print(f"Found {len(users)} OAuth users.")
            for user in users:
                new_secret = pyotp.random_base32()
                cursor.execute("UPDATE users SET totp_secret = %s WHERE id = %s", (new_secret, user['id']))
                print(f"User: {user['username']} ({user['auth_method']}) - New 2FA secret: {new_secret}")
            connection.commit()
    finally:
        connection.close()

if __name__ == "__main__":
    reset_oauth_2fa_secrets()
