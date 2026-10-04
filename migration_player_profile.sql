-- UNITED KERALAM player profile extension
ALTER TABLE players ADD COLUMN IF NOT EXISTS playing_role TEXT;
ALTER TABLE players ADD COLUMN IF NOT EXISTS career TEXT;
