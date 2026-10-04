-- Only for a database created with the previous schema.sql
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS innings INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS fifties INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS hundreds INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS double_hundreds INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS triple_hundreds INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS sixes INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS fours INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS sr NUMERIC DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS bowl_inn INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS best TEXT DEFAULT '-';
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS w3 INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS w5 INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS econ NUMERIC DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS bowl_avg NUMERIC DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS catches INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS runouts INT DEFAULT 0;
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS stumpings INT DEFAULT 0;

-- v3: tournaments, tournament stats, sponsors

CREATE TABLE IF NOT EXISTS tournaments(id SERIAL PRIMARY KEY, name TEXT NOT NULL, year INT, format TEXT DEFAULT 'T20I');
CREATE TABLE IF NOT EXISTS tournament_stats(id SERIAL PRIMARY KEY, tour_id INT REFERENCES tournaments ON DELETE CASCADE, player_id INT REFERENCES players ON DELETE CASCADE, matches INT DEFAULT 0, runs INT DEFAULT 0, wickets INT DEFAULT 0, hs INT DEFAULT 0, innings INT DEFAULT 0, fifties INT DEFAULT 0, hundreds INT DEFAULT 0, sixes INT DEFAULT 0, fours INT DEFAULT 0, sr NUMERIC DEFAULT 0, bowl_inn INT DEFAULT 0, best TEXT DEFAULT '-', w3 INT DEFAULT 0, w5 INT DEFAULT 0, econ NUMERIC DEFAULT 0, bowl_avg NUMERIC DEFAULT 0, catches INT DEFAULT 0, runouts INT DEFAULT 0, stumpings INT DEFAULT 0, UNIQUE(tour_id,player_id));
CREATE TABLE IF NOT EXISTS sponsors(id SERIAL PRIMARY KEY, name TEXT NOT NULL, tier TEXT NOT NULL, color TEXT DEFAULT '#00195f');
INSERT INTO tournaments(name,year,format) SELECT * FROM (VALUES ('Kerala Premier League T20',2026,'T20I'),('Malabar Cup',2026,'ODI'),('Travancore Trophy',2025,'ODI'),('Freedom Trophy T20',2025,'T20I')) v WHERE NOT EXISTS (SELECT 1 FROM tournaments);
INSERT INTO sponsors(name,tier,color) SELECT * FROM (VALUES ('Broadcaster One','broadcaster','#0a1f5c'),('Broadcaster Two','broadcaster','#c2185b'),('Partner One','bpartner','#1a1a1a'),('Partner Two','bpartner','#b71c1c'),('Partner Three','bpartner','#4a90d9'),('Premier One','premier','#c62828'),('Premier Two','premier','#2e9b48'),('Premier Three','premier','#1c2f6b'),('Global One','global','#b71c1c'),('Global Two','global','#d4a017'),('Global Three','global','#1f6f6b'),('Supporter One','supporter','#7a1c1c'),('Supporter Two','supporter','#1f3f8f')) v WHERE NOT EXISTS (SELECT 1 FROM sponsors);

-- v4: player profile fields for comparison
ALTER TABLE players ADD COLUMN IF NOT EXISTS dob TEXT;
ALTER TABLE players ADD COLUMN IF NOT EXISTS bat_style TEXT;
ALTER TABLE players ADD COLUMN IF NOT EXISTS bowl_style TEXT;

-- v5: team logos, trophies, tickets, settings
ALTER TABLE teams ADD COLUMN IF NOT EXISTS logo TEXT;

CREATE TABLE IF NOT EXISTS trophies(id SERIAL PRIMARY KEY, team_id INT REFERENCES teams ON DELETE CASCADE, name TEXT NOT NULL, year TEXT, img TEXT, photo TEXT);
CREATE TABLE IF NOT EXISTS matches(id SERIAL PRIMARY KEY, venue TEXT NOT NULL, team_a INT REFERENCES teams ON DELETE CASCADE, team_b INT REFERENCES teams ON DELETE CASCADE, match_date TEXT, format TEXT DEFAULT 'T20I', base_price INT DEFAULT 300, capacity INT DEFAULT 10000, sold INT DEFAULT 0, hype INT DEFAULT 50);
CREATE TABLE IF NOT EXISTS bookings(id SERIAL PRIMARY KEY, match_id INT REFERENCES matches ON DELETE CASCADE, user_id INT REFERENCES users ON DELETE CASCADE, category TEXT, qty INT, amount INT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);

-- v6: grouped trophies with photos, safer OTP
ALTER TABLE trophies ADD COLUMN IF NOT EXISTS photo TEXT;
ALTER TABLE trophies ALTER COLUMN year TYPE TEXT USING year::text;
ALTER TABLE otps ADD COLUMN IF NOT EXISTS attempts INT DEFAULT 0;
ALTER TABLE otps ADD COLUMN IF NOT EXISTS created TIMESTAMPTZ DEFAULT now();

-- v7: accounts with several identifiers, purpose-bound OTP, lockout, unique Player ID, stats per team, news
ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_ver INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now();
CREATE TABLE IF NOT EXISTS user_idents(ident TEXT PRIMARY KEY, user_id INT NOT NULL REFERENCES users ON DELETE CASCADE, kind TEXT NOT NULL, created TIMESTAMPTZ DEFAULT now());
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='ident') THEN
    INSERT INTO user_idents(user_id,ident,kind) SELECT id, ident, CASE WHEN ident LIKE '%@%' THEN 'email' ELSE 'mobile' END FROM users WHERE ident IS NOT NULL ON CONFLICT DO NOTHING;
    ALTER TABLE users DROP COLUMN ident;
  END IF;
END $$;
-- one-time codes are short lived, so they are simply recreated with the purpose column
DROP TABLE IF EXISTS otps;
CREATE TABLE otps(ident TEXT NOT NULL, purpose TEXT NOT NULL, code TEXT, exp TIMESTAMPTZ, attempts INT DEFAULT 0, created TIMESTAMPTZ DEFAULT now(), PRIMARY KEY(ident,purpose));

CREATE SEQUENCE IF NOT EXISTS player_code_seq;
ALTER TABLE players ADD COLUMN IF NOT EXISTS code TEXT;
DO $$ DECLARE base INT; BEGIN
  SELECT COALESCE(MAX(substring(code from 4)::int),0) INTO base FROM players WHERE code ~ '^UKP[0-9]+$';
  UPDATE players p SET code='UKP'||lpad((base+n.rn)::text,4,'0') FROM (SELECT id, row_number() OVER (ORDER BY id) rn FROM players WHERE code IS NULL) n WHERE n.id=p.id;
  PERFORM setval('player_code_seq', (SELECT COALESCE(MAX(substring(code from 4)::int),0)+1 FROM players WHERE code ~ '^UKP[0-9]+$'), false);
END $$;
ALTER TABLE players ALTER COLUMN code SET DEFAULT 'UKP'||lpad(nextval('player_code_seq')::text,4,'0');
ALTER TABLE players ALTER COLUMN code SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS players_code_key ON players(code);

ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS team_id INT REFERENCES teams ON DELETE CASCADE;
UPDATE season_stats s SET team_id=p.team_id FROM players p WHERE p.id=s.player_id AND s.team_id IS NULL;
DELETE FROM season_stats WHERE team_id IS NULL;
ALTER TABLE season_stats ALTER COLUMN team_id SET NOT NULL;
ALTER TABLE season_stats DROP CONSTRAINT IF EXISTS season_stats_player_id_format_year_key;
CREATE UNIQUE INDEX IF NOT EXISTS season_stats_pfyt ON season_stats(player_id,format,year,team_id);

CREATE TABLE IF NOT EXISTS news(id SERIAL PRIMARY KEY, title TEXT NOT NULL, tag TEXT DEFAULT 'News', img TEXT, body TEXT, created_at TIMESTAMPTZ DEFAULT now());

-- v8: team rankings (Test / ODI / T20I)
CREATE TABLE IF NOT EXISTS team_ratings(id SERIAL PRIMARY KEY, team_id INT NOT NULL REFERENCES teams ON DELETE CASCADE, format TEXT NOT NULL CHECK (format IN ('Test','ODI','T20I')), wins INT NOT NULL DEFAULT 0 CHECK (wins>=0), losses INT NOT NULL DEFAULT 0 CHECK (losses>=0), draws INT NOT NULL DEFAULT 0 CHECK (draws>=0), UNIQUE(team_id,format));

-- v9: awards, results & fixtures
CREATE TABLE IF NOT EXISTS awards(id SERIAL PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('month','year')), title TEXT NOT NULL, period TEXT, status TEXT DEFAULT 'Winner announced', name TEXT NOT NULL, team_id INT REFERENCES teams ON DELETE SET NULL, photo TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS fixtures(id SERIAL PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('Result','Fixture')), series TEXT, venue TEXT, match_date TEXT NOT NULL, match_time TEXT DEFAULT '', format TEXT DEFAULT 'T20I', team_a INT NOT NULL REFERENCES teams ON DELETE CASCADE, team_b INT NOT NULL REFERENCES teams ON DELETE CASCADE, score_a TEXT, score_b TEXT, result TEXT, highlights TEXT, centre TEXT);
