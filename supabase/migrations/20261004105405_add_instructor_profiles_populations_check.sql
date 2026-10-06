-- Adds a CHECK constraint on instructor_profiles.populations so the DB
-- itself rejects any value outside the 3 valid populations, closing the gap
-- found during audit: RLS (instructor_profiles_smat_all) only checks the
-- caller's role, not the content of `populations`, and - unlike
-- trainee_profiles.population (already protected by
-- trainee_profiles_population_check) - this column had no CHECK constraint
-- at all, so a direct write (e.g. from an authenticated smat session's
-- browser console) could save an invalid value with nothing in the DB to
-- stop it.
--
-- Verified read-only against the live data before writing this migration:
-- all 9 existing instructor_profiles rows already satisfy this constraint
-- (0 rows with an out-of-list value, 0 with an empty array, 0 with
-- duplicates) - no data cleanup needed.
--
-- Deliberately permissive, matching trainee_profiles_population_check's own
-- permissiveness:
--   - an empty array ('{}', the column's own default) is NOT blocked - this
--     is not a "populations required" constraint, only a "no unknown
--     values" constraint.
--   - duplicate values within the array are NOT blocked.
--   - the column is already NOT NULL at the schema level, so NULL is not a
--     case this constraint needs to (or can) address.
--
-- Not touched by this migration: RLS policies, triggers, any other table or
-- column, any data in instructor_profiles.

ALTER TABLE public.instructor_profiles
  ADD CONSTRAINT instructor_profiles_populations_check
  CHECK (populations <@ ARRAY['airCrew','controllers','scouts']::text[]);
