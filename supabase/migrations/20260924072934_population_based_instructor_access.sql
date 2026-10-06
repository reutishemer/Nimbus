-- Population-based instructor access (replaces instructor_trainees as the
-- authorization source for these 6 policies only).
--
-- Model: an instructor may access a trainee when
--   trainee_profiles.population = ANY(instructor_profiles.populations)
-- for that instructor. feedbacks.instructor_id keeps meaning "who wrote it" -
-- unchanged everywhere (smat may still pick any instructor for any trainee
-- when creating a feedback via feedbacks_smat_all, unaffected by this).
--
-- Explicitly NOT touched by this migration:
--   - instructor_trainees (table, rows, foreign keys, triggers, policies)
--   - feedbacks_select_kahad, feedbacks_select_trainee, feedbacks_smat_all
--   - profiles_select_kahad, profiles_select_self, profiles_smat_all, profiles_update_self
--   - trainee_profiles_select_kahad, trainee_profiles_select_self, trainee_profiles_smat_all
--   - instructor_profiles_select_kahad, instructor_profiles_select_self,
--     instructor_profiles_select_linked_trainee, instructor_profiles_smat_all
--   - any trigger, function, or column
--
-- Verified against the live policies on this project (via `supabase db query
-- --linked`, read-only) immediately before writing this file - table/policy
-- names below match exactly what exists in production today.

-- 1. feedbacks_select_instructor (SELECT)
-- Old: qual referenced instructor_trainees (instructor_id = auth.uid() AND
-- trainee_id = feedbacks.trainee_id).
-- New: instructor sees every feedback for a trainee in one of their
-- populations, from any instructor (unchanged behavior, new condition).
DROP POLICY IF EXISTS "feedbacks_select_instructor" ON public.feedbacks;
CREATE POLICY "feedbacks_select_instructor" ON public.feedbacks
FOR SELECT
USING (
  has_role('instructor'::text) AND EXISTS (
    SELECT 1
    FROM public.trainee_profiles tp
    JOIN public.instructor_profiles ip ON ip.profile_id = auth.uid()
    WHERE tp.profile_id = feedbacks.trainee_id
      AND tp.population = ANY (ip.populations)
  )
);

-- 2. feedbacks_insert_instructor (INSERT)
-- Old with_check required an instructor_trainees row for (auth.uid(), trainee_id).
-- New: requires the trainee's population to be one of the instructor's.
-- instructor_id/status/trainee-approved conditions are unchanged.
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
    WHERE tp.profile_id = feedbacks.trainee_id
      AND tp.population = ANY (ip.populations)
  )
  AND EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = feedbacks.trainee_id AND p.status = 'approved'::text
  )
);

-- 3. feedbacks_update_instructor (UPDATE)
-- Old qual required an instructor_trainees row; with_check (status='pending')
-- and the instructor_id = auth.uid() / status <> 'approved' conditions in
-- qual are unchanged.
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
    WHERE tp.profile_id = feedbacks.trainee_id
      AND tp.population = ANY (ip.populations)
  )
)
WITH CHECK (status = 'pending'::text);

-- 4. profiles_select_linked_for_instructor (SELECT on profiles)
-- Old: instructor_trainees row required. New: population match.
DROP POLICY IF EXISTS "profiles_select_linked_for_instructor" ON public.profiles;
CREATE POLICY "profiles_select_linked_for_instructor" ON public.profiles
FOR SELECT
USING (
  has_role('instructor'::text) AND EXISTS (
    SELECT 1
    FROM public.trainee_profiles tp
    JOIN public.instructor_profiles ip ON ip.profile_id = auth.uid()
    WHERE tp.profile_id = profiles.id
      AND tp.population = ANY (ip.populations)
  )
);

-- 5. trainee_profiles_select_linked_instructor (SELECT on trainee_profiles)
-- Old: instructor_trainees row required. New: population match.
DROP POLICY IF EXISTS "trainee_profiles_select_linked_instructor" ON public.trainee_profiles;
CREATE POLICY "trainee_profiles_select_linked_instructor" ON public.trainee_profiles
FOR SELECT
USING (
  has_role('instructor'::text) AND EXISTS (
    SELECT 1 FROM public.instructor_profiles ip
    WHERE ip.profile_id = auth.uid()
      AND trainee_profiles.population = ANY (ip.populations)
  )
);

-- 6. profiles_select_linked_for_trainee (SELECT on profiles)
-- Deliberately NOT population-based: smat may assign an instructor outside
-- the trainee's population, and the trainee must still be able to see that
-- instructor's name. New condition: the instructor actually wrote a
-- feedback for this trainee (feedbacks.instructor_id = "who wrote it").
DROP POLICY IF EXISTS "profiles_select_linked_for_trainee" ON public.profiles;
CREATE POLICY "profiles_select_linked_for_trainee" ON public.profiles
FOR SELECT
USING (
  has_role('trainee'::text) AND EXISTS (
    SELECT 1 FROM public.feedbacks f
    WHERE f.trainee_id = auth.uid() AND f.instructor_id = profiles.id
  )
);

-- 7. instructor_profiles_select_linked_trainee - intentionally NOT changed.
-- No frontend trainee-side query reads instructor_profiles directly (trainee
-- gets instructor names via profiles, resolved separately) - left as-is per
-- explicit instruction not to clean up RLS beyond what this migration needs.
