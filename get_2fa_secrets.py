import os
import pymysql
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database connection parameters
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASSWORD = os.getenv('DB_PASSWORD', '')
DB_NAME = 'dataproject'

def get_2fa_secrets(emails):
    connection = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        with connection.cursor() as cursor:
            format_strings = ','.join(['%s'] * len(emails))
            query = f"SELECT email, totp_secret FROM users WHERE email IN ({format_strings})"
            cursor.execute(query, tuple(emails))
            results = cursor.fetchall()
            for row in results:
                print(f"Email: {row['email']} - 2FA Secret: {row['totp_secret']}")
    finally:
        connection.close()

if __name__ == "__main__":
    emails_to_check = [
        'ahmedlordacio@gmail.com',
        'A-Lordoz@users.noreply.github.com',
        'recoveryahmedlordacio@gmail.com',
        'hannahemad@gmail.com'
    ]
    get_2fa_secrets(emails_to_check)
