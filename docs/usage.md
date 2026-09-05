# Usage Examples

SafeBase is schema-free — each file is an arbitrary JSON object. The caller decides the structure per bucket. Here are concrete examples.

## SME Candidate Roster

A bucket for storing SME (Subject Matter Expert) candidate profiles, each as one encrypted JSON file.

```
# Create structure
create_database("coursethread")
create_bucket("coursethread", "sme-candidates")

# Add a candidate — a dialog appears to create the bucket password
put_file("coursethread", "sme-candidates", "cand-001.json", {
    "name": "Jane Smith",
    "email": "jane@example.com",
    "domain": "Cybersecurity",
    "per_course_price_usd": 50,
    "vetting_status": "applied",
    "linkedin_url": "https://linkedin.com/in/janesmith",
    "fact_check_approach": "I verify claims against peer-reviewed sources..."
})

# List all candidates (no dialog if key still in memory)
list_files("coursethread", "sme-candidates")
# → ["cand-001.json"]

# Get one candidate
get_file("coursethread", "sme-candidates", "cand-001.json")

# Find all candidates with a specific vetting status
query_bucket("coursethread", "sme-candidates", {"vetting_status": "applied"})

# Update vetting status (put_file overwrites the whole file)
put_file("coursethread", "sme-candidates", "cand-001.json", {
    "name": "Jane Smith",
    "email": "jane@example.com",
    "domain": "Cybersecurity",
    "per_course_price_usd": 50,
    "vetting_status": "md_reviewed",
    "linkedin_url": "https://linkedin.com/in/janesmith",
    "fact_check_approach": "I verify claims against peer-reviewed sources...",
    "vetting_notes": "Credentials verified via LinkedIn. Domain fit confirmed."
})
```

## Tender Leads (Different Bucket, Different Password)

A separate bucket in the same database, with its own password. Compromising one bucket's password does not compromise the other.

```
create_bucket("coursethread", "tender-leads")

# A dialog appears to create a DIFFERENT password for this bucket
put_file("coursethread", "tender-leads", "t-001.json", {
    "title": "NHS Digital Training Framework",
    "deadline": "2026-09-15",
    "value_gbp": 50000,
    "status": "monitoring"
})

query_bucket("coursethread", "tender-leads", {"status": "monitoring"})
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
query_bucket("coursethread", "sme-candidates", {
    "vetting_status": "md_reviewed",
    "domain": "Cybersecurity"
})
```

Returns only candidates who are both reviewed AND in the cybersecurity domain.

## Nested Data

Files can contain nested JSON. `query_bucket` matches top-level fields only:

```
put_file("coursethread", "sme-candidates", "cand-002.json", {
    "name": "John Doe",
    "vetting_status": "applied",
    "education": [
        {"degree": "PhD", "institution": "MIT"},
        {"degree": "MSc", "institution": "Stanford"}
    ]
})

# This works (top-level field)
query_bucket("coursethread", "sme-candidates", {"vetting_status": "applied"})

# This does NOT work (nested field — query_bucket matches top-level only)
# To filter by nested data, fetch all files and filter client-side.
```

## Editing a Secret Without Exposing It to the AI

`edit_file` lets the human rotate or update a stored secret without the new
value ever passing through the AI conversation. The AI only triggers the
dialog; the human edits the decrypted JSON directly on their screen.

```
# A secret is already stored (e.g. a production API key)
put_file("coursethread", "sme-candidates", "api-key.json", {
    "service": "reports-api",
    "key": "old-key-value"
})

# Time to rotate. The AI calls edit_file — it never sees the current or new key.
edit_file("coursethread", "sme-candidates", "api-key.json")
#   -> a tkinter editor opens on the human's screen, pre-filled with the JSON
#   -> the human edits "key" to the new value and clicks Save
#   -> the AI receives only: "File updated successfully"
#   -> on Cancel, the AI receives: "Edit cancelled by user"
```

This closes the gap where rotating a secret would otherwise require either
telling the AI the new value (exposing it in the conversation) or bypassing
SafeBase entirely.
