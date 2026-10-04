-- Additive migration: does not rebuild or delete existing UNITED KERALAM data.
CREATE TABLE IF NOT EXISTS venues(
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  location TEXT DEFAULT '',
  home_team_id INT REFERENCES teams(id) ON DELETE SET NULL,
  capacity INT NOT NULL DEFAULT 0,
  established_year INT,
  matches_count INT NOT NULL DEFAULT 0,
  rating NUMERIC(3,1) NOT NULL DEFAULT 7.5,
  reviews INT NOT NULL DEFAULT 0
);

-- Additive migration for fan rating and review count
ALTER TABLE venues ADD COLUMN IF NOT EXISTS rating NUMERIC(3,1) NOT NULL DEFAULT 7.5;
ALTER TABLE venues ADD COLUMN IF NOT EXISTS reviews INT NOT NULL DEFAULT 0;

ALTER TABLE venues ADD COLUMN IF NOT EXISTS matches_count INT NOT NULL DEFAULT 0;

-- Preserve existing match totals when adding the new editable venue match-count field.
UPDATE venues v SET matches_count = COALESCE((SELECT COUNT(*) FROM matches m WHERE lower(trim(m.venue)) = lower(trim(v.name))), 0) WHERE COALESCE(v.matches_count,0)=0;
