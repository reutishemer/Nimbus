-- Fix: infinite recursion detected in policy for relation "feedbacks"
-- (42P17), found via live testing of the population-based migration
-- (20260924072934_population_based_instructor_access.sql).
--
-- Root cause: the EXISTS subqueries added in that migration referenced the
-- protected table by its explicit name - `feedbacks.trainee_id` - inside a
-- policy defined ON `feedbacks` itself. Even though trainee_profiles/
-- instructor_profiles (the subquery's FROM tables) don't carry a trainee_id
-- column, so there is no real ambiguity, an explicit self-qualified
-- reference back to the table a policy is attached to makes Postgres treat
-- it as needing to re-resolve that table's own row security to obtain the
-- value, re-invoking the same policy - infinite recursion.
--
-- Fix: reference the row's own column unqualified (bare `trainee_id`)
-- instead of `feedbacks.trainee_id`. Inside the EXISTS subquery this still
-- resolves unambiguously to the outer `feedbacks` row being checked (no
-- other table in scope has a `trainee_id` column), but no longer triggers
-- the recursive re-check. This is a pure syntax fix - every other condition
-- (role, instructor_id = auth.uid(), status, population match, trainee
-- approved, WITH CHECK) is byte-for-byte identical to the previous
-- migration.
--
-- Scope: only the 3 policies below. Does not touch:
--   - feedbacks_smat_all, feedbacks_select_kahad, feedbacks_select_trainee
--   - profiles_select_linked_for_instructor, profiles_select_linked_for_trainee,
--     profiles_select_kahad, profiles_select_self, profiles_smat_all, profiles_update_self
--   - trainee_profiles_select_linked_instructor, trainee_profiles_select_kahad,
--     trainee_profiles_select_self, trainee_profiles_smat_all
--   - instructor_profiles (any policy), instructor_trainees (table/policies/triggers)
--   - any table, column, trigger, or function
--
-- Does not change the logic from the prior migration: instructor-only,
-- trainee_profiles.population = ANY(instructor_profiles.populations),
-- INSERT requires instructor_id = auth.uid() AND status = 'pending' AND the
-- trainee is approved, UPDATE requires the instructor to be the row's own
-- instructor_id AND status <> 'approved', WITH CHECK on UPDATE stays
-- status = 'pending'.

-- 1. feedbacks_select_instructor (SELECT)
DROP POLICY IF EXISTS "feedbacks_select_instructor" ON public.feedbacks;
CREATE POLICY "feedbacks_select_instructor" ON public.feedbacks
FOR SELECT
USING (
  has_role('instructor'::text) AND EXISTS (
    SELECT 1
    FROM public.trainee_profiles tp
    JOIN public.instructor_profiles ip ON ip.profile_id = auth.uid()
    WHERE tp.profile_id = trainee_id
      AND tp.population = ANY (ip.populations)
  )
);

-- 2. feedbacks_insert_instructor (INSERT)
DROP POLICY IF EXISTS "feedbacks_insert_instructor" ON public.feedbacks;
CREATE POLICY "feedbacks_insert_instructor" ON public.feedbacks
FOR INSERT
WITH CHECK (
  has_role('instructor'::text)
  AND instructor_id = auth.uid()
  AND status = 'pending'::text
  AND EXISTS (
    SELECT 1
    FROM public.trainee_profiles tp
    JOIN public.instructor_profiles ip ON ip.profile_id = auth.uid()
    WHERE tp.profile_id = trainee_id
      AND tp.population = ANY (ip.populations)
  )
  AND EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = trainee_id AND p.status = 'approved'::text
  )
);

-- 3. feedbacks_update_instructor (UPDATE)
DROP POLICY IF EXISTS "feedbacks_update_instructor" ON public.feedbacks;
CREATE POLICY "feedbacks_update_instructor" ON public.feedbacks
FOR UPDATE
USING (
  has_role('instructor'::text)
  AND instructor_id = auth.uid()
  AND status <> 'approved'::text
  AND EXISTS (
    SELECT 1
    FROM public.trainee_profiles tp
    JOIN public.instructor_profiles ip ON ip.profile_id = auth.uid()
    WHERE tp.profile_id = trainee_id
      AND tp.population = ANY (ip.populations)
  )
)
WITH CHECK (status = 'pending'::text);
