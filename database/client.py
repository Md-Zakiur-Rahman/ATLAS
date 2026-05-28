import os
from supabase import create_client
from dotenv import load_dotenv
load_dotenv()

# python-dotenv is used in main.py to load these from a .env file
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    # This will cause a startup failure, which is intended if secrets are missing.
    # The user will see this in the logs and know to create a .env file.
    raise RuntimeError("Missing Supabase credentials. Ensure SUPABASE_URL and SUPABASE_KEY are in your .env file.")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)