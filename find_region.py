import socket
import sqlalchemy
from sqlalchemy import create_engine, text
import urllib.parse

# Your project info
password = "yfm+kiD$63F8cgq"
project_id = "kzrkrzzdntbgmpzblhmj"
encoded_pass = urllib.parse.quote_plus(password)

# Regions to test (most likely first for India/Global)
regions = [
    "ap-south-1",      # Mumbai
    "ap-southeast-1",  # Singapore
    "eu-central-1",    # Frankfurt
    "us-east-1",       # N. Virginia
    "us-west-2",       # Oregon
    "ap-southeast-2",  # Sydney
    "eu-west-1",       # Ireland
]

print(f"Brute-forcing Supabase Region for project: {project_id}\n")

for region in regions:
    host = f"aws-0-{region}.pooler.supabase.com"
    # Port 6543 is Transaction mode (most common for pooler)
    url = f"postgresql://postgres.{project_id}:{encoded_pass}@{host}:6543/postgres?sslmode=require"
    
    print(f"Testing {region} ({host})...")
    try:
        # 5 second timeout to keep it fast
        engine = create_engine(url, connect_args={'connect_timeout': 5})
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            print(f"  >>> SUCCESS! Found the correct region: {region}")
            print(f"  DATABASE_URL=postgresql://postgres.{project_id}:[PASS]@{host}:6543/postgres?sslmode=require")
            # Create a flag file so I know which one worked
            with open("found_region.txt", "w") as f:
                f.write(region)
            break
    except Exception as e:
        err = str(e).lower()
        if "tenant" in err or "user not found" in err:
            print("  FAIL: Tenant not found (wrong region)")
        elif "timeout" in err:
            print("  FAIL: Connection timeout (check internet/firewall)")
        else:
            print(f"  FAIL: {err[:100]}")
    print("-" * 30)

print("\nDone.")
