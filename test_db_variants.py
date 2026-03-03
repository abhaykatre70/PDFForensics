import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()
password = "yfm+kiD$63F8cgq"
project_id = "kzrkrzzdntbgmpzblhmj"

# Encoding password for URI
import urllib.parse
encoded_pass = urllib.parse.quote_plus(password)

# Variants to test
variants = [
    # 1. Direct Connection (Port 5432)
    {
        "name": "Direct Connection",
        "url": f"postgresql://postgres:{encoded_pass}@db.{project_id}.supabase.co:5432/postgres"
    },
    # 2. Pooler - Transaction Mode (Port 6543)
    {
        "name": "Pooler (Transaction)",
        "url": f"postgresql://postgres.{project_id}:{encoded_pass}@aws-0-ap-south-1.pooler.supabase.com:6543/postgres?sslmode=require"
    },
    # 3. Pooler - Session Mode (Port 5432)
    {
        "name": "Pooler (Session)",
        "url": f"postgresql://postgres.{project_id}:{encoded_pass}@aws-0-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require"
    }
]

print("Starting Supabase DB Connection Diagnostics...\n")

for v in variants:
    print(f"Testing {v['name']}...")
    try:
        # Use a short timeout
        engine = create_engine(v['url'].replace(encoded_pass, "********"), connect_args={'connect_timeout': 5})
        # Note: real engine needs real URL
        real_engine = create_engine(v['url'], connect_args={'connect_timeout': 5})
        with real_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            print(f"  SUCCESS!")
            print(f"  URL: {v['url']}")
    except Exception as e:
        print(f"  FAILED: {str(e)[:200]}")
    print("-" * 40)
