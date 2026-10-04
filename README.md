# UNITED KERALAM

1. `createdb united_keralam`
- Tournament Champions: new database gets them from `schema.sql`; an existing database needs `psql $DATABASE_URL -f migration_champions.sql` once.
- Awards + Results & fixtures: new database gets them from `schema.sql`; an existing database needs `psql $DATABASE_URL -f migration_awards_fixtures.sql` once. Footer / social links are saved in the `settings` table (no extra step).
- Team rankings: new database gets it from `schema.sql`; an existing database just needs `psql $DATABASE_URL -f migration_team_rankings.sql` once.
2. New database: `psql $DATABASE_URL -f schema.sql`  |  Existing database: `psql $DATABASE_URL -f migration.sql` (run it once; it keeps your data, gives every player a unique ID like UKP0001, moves stats to per-team rows and creates the news table)
3. Copy `.env.example` to `.env` and fill it in (JWT_SECRET is required)
4. Put `index.html` inside a folder named `public/` next to `server.js`
5. `npm install` then `npm start` and open http://localhost:3000
6. Sign up with the ADMIN_IDENT email/mobile, then Menu > Settings > Edit mode to add, edit and delete.

Existing accounts keep working with their old password. If you only want to test the OTP flow locally, set `OTP_DEV=true` and read the code in the server console.

Opening `index.html` without the server runs a local-only demo (localStorage, admin PIN 2026). Demo accounts are not secure; use the server for real users.

## Mobile OTP (SMS)
Set `SMS_PROVIDER` in `.env` to `msg91`, `2factor`, `fast2sms` or `twilio` and fill that provider's keys (see `.env.example`). Indian SMS providers usually need DLT registration / an approved OTP template for reliable delivery; check your provider's dashboard. For local testing use `OTP_DEV=true`.


## Profile/UI update
- Player career is shown below the player photo/logo area.
- Player and team profiles have a top-right Share action.
- Results & Fixtures has Overall / Test / ODI / T20 format filters.
- Team Overview has Overall / Test / ODI / T20 plus a Year selector for year-wise player stats.
- Team profiles use a reference-style hero, logo, info cards, tabs and CRUD actions.
- Players use large background cards with Edit/Delete CRUD controls in Edit mode.

### Database migration
If you are using PostgreSQL/server mode, run `migration_team_profile.sql` once after the existing migrations. It adds the team profile fields used by the new team hero and CRUD form.


### Awards + Legendary Track Record migration
Run `migration_awards_player_track_record.sql` once on an existing PostgreSQL database after `migration_awards_fixtures.sql`. It links awards to player profiles and allows custom/special award types.

## Latest UI/data update
- Added multilingual Venue navigation and responsive Venue pages.
- Added PostgreSQL `venues` table with additive migration only: name, location, home team, capacity, established year.
- Added admin-protected Venue CRUD API and UI.
- Team Overview venue now links to the matching Venue profile when a venue is assigned.
- Localized Tickets CRUD, Photos CRUD, and Player Compare controls for English, Malayalam, Tamil, Hindi, and Arabic.
- Existing Tickets/Photos CRUD APIs and existing cricket data are preserved.


### Latest automation/update changes
- Teams and players are returned alphabetically (case-insensitive).
- Tournaments are returned by year descending, then creation/id ascending; same-year creation order is preserved.
- The server updates an `Auto Update` news item every hour from current player/team/venue/ticket/run/wicket data.
- The browser refreshes its live bootstrap snapshot every hour.
- An idempotent demo series pack creates 5 T20 + 3 ODI + 2 Test matches per team (70 matches with the default 14 teams), using CRUD-compatible fixtures.
- Team Profile → Matches displays scoreboard-style result cards with admin Edit/Delete controls.

### Hourly News Auto Update
- Only the News feed is automatically refreshed every 60 minutes.
- The server updates one `Auto Update` news record using the current database values.
- The browser fetches `/api/news` hourly only.
- Players, teams, venues, tickets, matches, runs, wickets, rankings and tournaments are not modified by the hourly news job.
- CRUD remains the way to manually change those records.


## OpenAI AI Newsroom
The server can use the OpenAI Responses API with web search to create verified, current cricket news for the News tab. The API key stays server-side in `.env`; never put it in `public/index.html`.

1. Run `npm install` (this installs the official `openai` JavaScript SDK).
2. Add `OPENAI_API_KEY=...` to `.env`. Optionally set `OPENAI_MODEL=gpt-6-luna`.
3. Restart with `npm start`.
4. The server automatically refreshes AI newsroom stories hourly when the key is configured. Admins can also POST `/api/ai/news` to refresh immediately.

The newsroom uses OpenAI's Responses API and web search, and stores source URLs with generated stories.
