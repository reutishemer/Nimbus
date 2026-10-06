-- Fix: 42P17 infinite recursion on feedbacks INSERT (as instructor).
--
-- Root cause (confirmed via read-only diagnosis against the live DB):
-- feedbacks_insert_instructor's WITH CHECK ran a direct, non-bypassed
-- EXISTS (SELECT ... FROM public.profiles WHERE p.id = trainee_id AND
-- p.status = 'approved') - this subquery is subject to profiles' own RLS,
-- which includes profiles_select_linked_for_trainee:
--   EXISTS (SELECT 1 FROM feedbacks f WHERE f.trainee_id = auth.uid()
--     AND f.instructor_id = profiles.id)
-- That policy runs a direct, non-bypassed SELECT on feedbacks - while
-- feedbacks' own RLS is still being resolved for the original INSERT.
-- Two tables referencing each other's RLS (feedbacks -> profiles ->
-- feedbacks) is exactly what Postgres's row-security planner rejects with
-- "infinite recursion detected in policy for relation feedbacks".
--
-- Fix: move the "is this profile approved" check behind a SECURITY DEFINER
-- function (same pattern as the already-existing has_role/current_role/
-- current_status/is_approved - all owned by postgres, which bypasses RLS
-- entirely for the SELECT inside the function body). This breaks the
-- feedbacks->profiles leg of the cycle without touching the profiles->
-- feedbacks leg (profiles_select_linked_for_trainee, explicitly NOT
-- touched here - the trainee still needs it to see which instructor wrote
-- their feedback).
--
-- Explicitly NOT touched by this migration:
--   - profiles_select_linked_for_trainee (left exactly as-is, per instruction)
--   - feedbacks_select_instructor, feedbacks_update_instructor (neither
--     references profiles, so neither is part of this cycle - no change needed)
--   - feedbacks_smat_all, feedbacks_select_kahad, feedbacks_select_trainee
--   - profiles_select_linked_for_instructor, profiles_select_kahad,
--     profiles_select_self, profiles_smat_all, profiles_update_self
--   - trainee_profiles (any policy), instructor_profiles (any policy)
--   - instructor_trainees (table/policies/triggers)
--   - population-based access logic itself (role/instructor_id/status/
--     population-match conditions are byte-for-byte unchanged)
--   - any other table, column, trigger, or function

-- 1. New SECURITY DEFINER helper - mirrors the existing has_role/
-- current_role/current_status/is_approved functions exactly: same owner,
-- same search_path pinning, same STABLE marking, same restricted grants.
-- Read-only (a single SELECT), fail-closed (COALESCE(..., false) so a
-- missing/unknown profile id is never treated as approved).
CREATE OR REPLACE FUNCTION public.is_profile_approved(_profile_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT COALESCE(
    (SELECT status = 'approved' FROM public.profiles WHERE id = _profile_id),
    false
  );
$function$;

ALTER FUNCTION public.is_profile_approved(uuid) OWNER TO postgres;

REVOKE ALL ON FUNCTION public.is_profile_approved(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_profile_approved(uuid) TO authenticated, service_role;

-- 2. feedbacks_insert_instructor - only the "trainee approved" check
-- changes (direct profiles EXISTS -> is_profile_approved call). Every
-- other condition is identical to the previous migration: instructor
-- role, instructor_id = auth.uid(), status = 'pending', and the
-- population-match EXISTS against trainee_profiles/instructor_profiles
-- (untouched - neither of those tables' policies reference profiles or
-- feedbacks in a way that creates a cycle).
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
  AND public.is_profile_approved(trainee_id)
);
