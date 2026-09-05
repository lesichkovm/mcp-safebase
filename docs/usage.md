# Usage Examples

SafeBase is schema-free — each file is an arbitrary JSON object. The caller decides the structure per bucket. Here are concrete examples.

## Contact Roster

A bucket for storing contact profiles, each as one encrypted JSON file.

```
# Create structure
create_database("mydb")
create_bucket("mydb", "contacts")

# Add a contact — a dialog appears to create the bucket password
put_file("mydb", "contacts", "person-001.json", {
    "name": "Jane Smith",
    "email": "jane@example.com",
    "role": "Advisor",
    "hourly_rate_usd": 50,
    "status": "active",
    "linkedin_url": "https://linkedin.com/in/janesmith",
    "notes": "Available weekdays."
})

# List all contacts (no dialog if key still in memory)
list_files("mydb", "contacts")
# → ["person-001.json"]

# Get one contact
get_file("mydb", "contacts", "person-001.json")

# Find all contacts with a specific status
query_bucket("mydb", "contacts", {"status": "active"})

# Update status (put_file overwrites the whole file)
put_file("mydb", "contacts", "person-001.json", {
    "name": "Jane Smith",
    "email": "jane@example.com",
    "role": "Advisor",
    "hourly_rate_usd": 50,
    "status": "inactive",
    "linkedin_url": "https://linkedin.com/in/janesmith",
    "notes": "Available weekdays. On sabbatical until Q4."
})
```

## Sales Leads (Different Bucket, Different Password)

A separate bucket in the same database, with its own password. Compromising one bucket's password does not compromise the other.

```
create_bucket("mydb", "leads")

# A dialog appears to create a DIFFERENT password for this bucket
put_file("mydb", "leads", "lead-001.json", {
    "title": "Acme Training Framework",
    "deadline": "2026-09-15",
    "value_usd": 50000,
    "status": "monitoring"
})

query_bucket("mydb", "leads", {"status": "monitoring"})
```

Same server, same tools, different bucket, different password.

## Personal Notes (Different Database)

A completely separate database for personal use.

```
create_database("personal")
create_bucket("personal", "notes")

put_file("personal", "notes", "note-001.json", {
    "title": "Ideas for Q4",
    "body": "..."
})
```

## Querying with Multiple Filters

`query_bucket` accepts multiple field-equality filters. All must match (AND logic):

```
query_bucket("mydb", "contacts", {
    "status": "inactive",
    "role": "Advisor"
})
```

Returns only contacts who are both inactive AND in the Advisor role.

## Nested Data

Files can contain nested JSON. `query_bucket` matches top-level fields only:

```
put_file("mydb", "contacts", "person-002.json", {
    "name": "John Doe",
    "status": "active",
    "education": [
        {"degree": "PhD", "institution": "MIT"},
        {"degree": "MSc", "institution": "Stanford"}
    ]
})

# This works (top-level field)
query_bucket("mydb", "contacts", {"status": "active"})

# This does NOT work (nested field — query_bucket matches top-level only)
# To filter by nested data, fetch all files and filter client-side.
```

## Editing a Secret Without Exposing It to the AI

`edit_file` lets the human rotate or update a stored secret without the new
value ever passing through the AI conversation. The AI only triggers the
dialog; the human edits the decrypted JSON directly on their screen.

```
# A secret is already stored (e.g. a production API key)
put_file("mydb", "contacts", "api-key.json", {
    "service": "reports-api",
    "key": "old-key-value"
})

# Time to rotate. The AI calls edit_file — it never sees the current or new key.
edit_file("mydb", "contacts", "api-key.json")
#   -> a tkinter editor opens on the human's screen, pre-filled with the JSON
#   -> the human edits "key" to the new value and clicks Save
#   -> the AI receives only: "File updated successfully"
#   -> on Cancel, the AI receives: "Edit cancelled by user"
```

This closes the gap where rotating a secret would otherwise require either
telling the AI the new value (exposing it in the conversation) or bypassing
SafeBase entirely.
