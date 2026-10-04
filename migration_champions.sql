-- UNITED KERALAM: tournament champions / runners by year
-- Run once on an existing PostgreSQL database.
CREATE TABLE IF NOT EXISTS champions(
  id SERIAL PRIMARY KEY,
  tournament_id INT NOT NULL REFERENCES tournaments ON DELETE CASCADE,
  year INT NOT NULL,
  winner_team_id INT NOT NULL REFERENCES teams ON DELETE CASCADE,
  runner_team_id INT REFERENCES teams ON DELETE SET NULL,
  trophy TEXT DEFAULT '',
  img TEXT,
  note TEXT DEFAULT '',
  UNIQUE(tournament_id, year)
);
