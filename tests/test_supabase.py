from database.client import (
    supabase
)

response = (
    supabase.table("auth")
    .select("*")
    .execute()
)

print(response)