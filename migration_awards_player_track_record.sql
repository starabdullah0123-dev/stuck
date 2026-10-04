-- Run once on an existing database to add player-linked awards and the legendary team track record.
ALTER TABLE awards ADD COLUMN IF NOT EXISTS player_id INT REFERENCES players ON DELETE SET NULL;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'awards'::regclass AND conname = 'awards_kind_check'
  ) THEN
    ALTER TABLE awards DROP CONSTRAINT awards_kind_check;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'awards'::regclass AND conname = 'awards_kind_check_v2'
  ) THEN
    ALTER TABLE awards ADD CONSTRAINT awards_kind_check_v2 CHECK (kind IN ('month','year','other'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS awards_player_id_idx ON awards(player_id);
CREATE INDEX IF NOT EXISTS trophies_team_id_idx ON trophies(team_id);
