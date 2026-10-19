-- Server roles. users.role replaces the is_admin flag: 'admin', 'member', or
-- 'viewer' (a viewer account reads what is shared with it and writes
-- nothing). Every current administrator becomes 'admin' and everyone else
-- 'member'.

ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member', 'viewer'));

UPDATE users SET role = 'admin' WHERE is_admin = 1;

ALTER TABLE users DROP COLUMN is_admin;
