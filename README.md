# ccconnect — Firebase-free realtime chat

This is a static HTML chat frontend using **Supabase Auth + Postgres + Realtime** instead of Firebase. The `index.html` file is the website; `supabase_setup.sql` configures the database and access policies; the GitHub Actions workflow publishes the static site to GitHub Pages.

## Important security change

The original page stored login passcodes directly in JavaScript, where anyone could inspect them. This version uses Supabase Authentication, uses database Row Level Security (RLS), escapes message text rather than inserting it as HTML, and does not put account passwords or a service-role key in the page source.

The old passcodes will **not** work in this version. Set new passwords for the users in Supabase Authentication. Do not enable public sign-ups for this invite-only app.

## Current setup status

The Supabase project has already been created for this deployment (`ccconnect`, Mumbai region). Its database tables, Row Level Security policies, DM RPC, and Realtime publication entries have been applied and verified. The website `index.html` has also been configured with this project URL and its browser-safe publishable key. Do not create a second project or rerun setup unless you intend to.

## 1. Create allowed user accounts

1. Open the [Supabase Dashboard](https://supabase.com/dashboard/project/bclhrmwrkwrvzgufrmdy).
2. Open **Authentication → Users** and create one account for each allowed person. Use their email and a new password for that person. Do not reuse the passcodes from the old HTML file because they were visible in the source.
3. Open **Authentication → Users** and create one account for each allowed person. Use their email and a new password for that person. Do not reuse the passcodes from the old HTML file because they were visible in the source.
4. Open **Table Editor → profiles**. After all accounts have been created, edit the matching rows:
   - Set `is_admin` to `true` for the account that is allowed to create group chats.
   - Set `dm_admin_only` to `true` for any account that should only be able to start/receive direct messages with the admin.
   - Set `display_name` to each person's desired name.


Only use the publishable/anon key in the browser. **Never put the `service_role` key or a secret key in `index.html`.** The database policies in the SQL file are part of the security boundary, so do not remove them.

## 2. Supabase configuration

The supplied `index.html` is already configured with the project URL and publishable key. No secret/service-role key is included. The following configuration lines are already filled in:

```js
const SUPABASE_URL = 'https://bclhrmwrkwrvzgufrmdy.supabase.co';
const SUPABASE_PUBLISHABLE_KEY = '(configured in index.html)';
```

Replace the two placeholder values with the Project URL and publishable key from your Supabase dashboard. Keep the single quotes around each value. This key is designed to be public; database access is limited by RLS policies.

## 3. Publish without running anything locally

1. Create a GitHub repository for this family chat if you do not already have one. Note: GitHub Pages is available on GitHub Free only for public repositories, and a Pages site is publicly reachable even when its source repository is private; see the [GitHub Pages docs](https://docs.github.com/en/pages/quickstart). If you do not want a publicly reachable website, choose a host with private deployment/access controls instead.
2. Upload `index.html`, `supabase_setup.sql`, `README.md`, and the `.github/workflows/deploy.yml` file while keeping the `.github/workflows` folder structure. GitHub's website supports uploading files directly; you do not need a local development environment.
3. In the repository, open **Settings → Pages** and choose **GitHub Actions** as the build/deployment source if it is not already selected.
4. Open the **Actions** tab. The “Deploy ccconnect to GitHub Pages” workflow should run on the first push. When it completes successfully, GitHub shows the live website URL in the workflow run and under **Settings → Pages**.

The site is static-hosted; Supabase supplies the shared database and realtime event delivery. The users can open the same published URL on different devices and exchange messages.

## 4. Verify realtime messaging

1. Sign in from two different browsers/devices using two accounts created in Supabase Authentication.
2. Open each other's direct-message conversation and send a test message.
3. A newly sent message should appear on the other device without reloading the page. If it does not, check the browser console and Supabase's Realtime/Database logs; make sure you ran the SQL setup in the same project whose URL/key you put in `index.html`.
4. Create a group chat from the admin account, add at least one other member, then verify that the group appears on the other member's sidebar.

## Notes

- Nicknames are saved in that browser's local storage and are not shared with other users.
- The page displays the last 500 messages for the selected conversation.
- GitHub Pages publishes a publicly reachable website. The login screen is not the security boundary by itself: Supabase Auth and the SQL RLS policies protect conversations and messages. Anyone can inspect the HTML and its publishable key, so never add passwords, service-role keys, or other secrets to the source. If you need the website itself to be access-restricted, use a host that supports private site access.
- This setup uses a free-tier hosted backend, subject to Supabase and GitHub Pages' current limits and policies.


## Hosting status

The Supabase backend is configured, but the site is not yet published to a public URL. Upload this folder to a GitHub repository, enable GitHub Pages, and allow GitHub Actions to run the included `.github/workflows/deploy.yml`. Then test sign-in and messaging using two separate accounts in different browsers.
