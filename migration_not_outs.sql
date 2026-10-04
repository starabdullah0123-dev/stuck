-- Safe migration: adds Not outs to existing stats without deleting or rebuilding data.
ALTER TABLE season_stats ADD COLUMN IF NOT EXISTS not_outs INT DEFAULT 0;
ALTER TABLE tournament_stats ADD COLUMN IF NOT EXISTS not_outs INT DEFAULT 0;
