# CCConnect setup (Supabase)

This branch uses **Supabase**, not Firebase. It keeps the current CCConnect messaging tables and adds passwordless email-link login plus database-enforced restricted-account rules.

## 1. Create the four missing Auth users

In the Supabase dashboard for project `bclhrmwrkwrvzgufrmdy`, open **Authentication → Users** and choose **Add user / Invite user**. Invite these four email addresses so their Auth accounts exist:

- `mchiba@gmail.com` — Abba
- `sschiba786@gmail.com` — Mom
- `abdulqadir@gmail.com` — Abdulqadir
- `ajaby786@gmail.com` — Ajab

The following three Auth accounts already exist in the project, so do not create duplicates:

- `musti2152@gmail.com` — Mustafa (admin)
- `zahrahalai296@gmail.com` — Zahra (restricted)
- `arsenalfan5253@gmail.com` — ArsenalFan (restricted)

## 2. Configure Auth redirect URLs

Open **Authentication → URL Configuration**.

Set **Site URL** to:

`https://arsenalfan5253-rgb.github.io/cconect5253/`

Add that exact URL to **Redirect URLs** as well, then save. Keep email sign-in / Magic Link enabled. The app calls `signInWithOtp` with `shouldCreateUser: false`, so users must already exist in Authentication.

## 3. Run the SQL setup

Open **SQL Editor → New query**. Open `SUPABASE_SETUP.sql` in this branch, copy the entire file into the editor, and run it.

This script is re-runnable. It updates the profile names/roles from the approved allowlist, adds profile rows for approved Auth users that exist, locks down row-level access, protects the admin flags from client-side changes, and changes the media policies to use the same conversation authorization rules. It does not delete old messages.

**Important:** the SQL cannot create or invite Auth users. Invite the four missing accounts first, then run this script. If you invite them later, run it again.

## 4. Verify the profiles

Run this query in SQL Editor:

```sql
select email, display_name, is_admin, dm_admin_only
from public.profiles
where lower(email) in (
  'musti2152@gmail.com',
  'mchiba@gmail.com',
  'sschiba786@gmail.com',
  'abdulqadir@gmail.com',
  'ajaby786@gmail.com',
  'zahrahalai296@gmail.com',
  'arsenalfan5253@gmail.com'
)
order by email;
```

You should get seven rows. Mustafa should have `is_admin = true`; Zahra and ArsenalFan should have `dm_admin_only = true`; the other four should have both flags false. If fewer than seven rows appear, check Authentication → Users and re-run the SQL after inviting the missing users.

## 5. Deploy the HTML

The changes are on the branch `ccconnect-passwordless-privacy` so they do not replace the live site automatically. After the SQL and redirects are configured, download the branch's `index.html` and replace `index.html` on GitHub's `main` branch, or merge the branch into `main`.

Use only the Supabase project URL and publishable key in browser code. **Never** put a Supabase service-role key or other secret key in `index.html`.

## Privacy behavior

- Admin account: Mustafa.
- Standard family accounts: see other standard accounts and the admin.
- Restricted accounts: see only themselves and the admin profile, and land in their DM with Mustafa.
- Restricted accounts cannot open each other's DM, access group chats, read restricted conversation messages, or create signed media URLs for those conversations.
- Group creation and membership are admin-controlled.
- Nicknames are stored locally in the browser and backed up in Supabase where available.

This is still a static single-file app, so use Supabase Auth and RLS as the security boundary; UI filtering alone is not a security measure.
