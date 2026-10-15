-- Private, per-user feedback drafts - lets an instructor/smat save an
-- in-progress feedback form permanently, resumable across devices, without
-- touching `feedbacks` or its RLS/status values at all.
--
-- Deliberately a SEPARATE table rather than a new `feedbacks.status`
-- value: `feedbacks_select_instructor` has no status condition at all (an
-- instructor sees every feedback for a trainee in their population,
-- regardless of who wrote it - by design), and `feedbacks_smat_all`/
-- `feedbacks_select_kahad` see everything unconditionally. A `draft` status
-- on that table would leak straight through all three the moment a row
-- existed, and `feedbacks.instructor_id` is nullable/optional for smat, so
-- there is no existing column that could safely double as "who is
-- currently drafting this." A dedicated table with its own `created_by`
-- and its own minimal RLS avoids both problems and touches zero existing,
-- already-audited `feedbacks` policies.
--
-- `payload` carries the entire evalForm snapshot (free-form jsonb) - a
-- draft is intentionally allowed to be incomplete (no NOT NULL requirements
-- the way `feedbacks` itself has), since a half-filled form is exactly what
-- this exists to preserve.
create table if not exists public.feedback_drafts (
  id uuid primary key default gen_random_uuid(),
  created_by uuid not null references public.profiles(id) on delete cascade,
  -- NULL = a brand-new feedback, never yet saved OR an edit-draft whose
  -- source feedback was since deleted (see ON DELETE SET NULL below). NOT
  -- NULL = an in-progress edit of that existing feedbacks row - the
  -- original row is never touched by anything in this table; only the
  -- real save flow in onSaveEval (unchanged) ever writes to `feedbacks`.
  --
  -- ON DELETE SET NULL, not CASCADE: deleting the source feedback must
  -- never silently destroy the instructor's/smat's in-progress edit
  -- content - that defeats the entire point of this table. payload.
  -- feedbackId (the client's own copy, frozen at draft-save time) still
  -- remembers which feedback this *was* an edit of even after this column
  -- goes NULL, so the client can tell "orphaned edit-draft" apart from "a
  -- genuinely brand-new draft" and show a clear message instead of ever
  -- treating it as a new feedback - see openDraftForEdit() in
  -- Nimbus.dc.html.
  feedback_id uuid references public.feedbacks(id) on delete set null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Postgres unique indexes/constraints treat every NULL as distinct from
-- every other NULL, so a plain UNIQUE(created_by, feedback_id) would NOT
-- stop the same user from creating any number of duplicate brand-new
-- drafts (feedback_id IS NULL) - it would only ever block a second EDIT
-- draft for the same (user, feedback) pair, which is exactly the one case
-- that needs blocking. A brand-new draft's own one-time-generated id (see
-- Nimbus.dc.html) is what the client upserts by instead - this partial
-- index only needs to cover the edit case.
create unique index if not exists feedback_drafts_owner_feedback_uidx
  on public.feedback_drafts (created_by, feedback_id)
  where feedback_id is not null;

-- Helpful for "load all my drafts for the feedbacks-list filter" and for
-- "does an edit-draft already exist for this feedback" lookups.
create index if not exists feedback_drafts_created_by_idx
  on public.feedback_drafts (created_by, updated_at desc);

alter table public.feedback_drafts enable row level security;

-- Ownership enforced on every operation, in BOTH directions where that
-- operation has one - never a single catch-all `FOR ALL` policy, so each
-- clause is explicit about which check applies to which action. No smat
-- carve-out anywhere: smat's own drafts are reachable only through the
-- exact same `created_by = auth.uid()` condition as anyone else's, and
-- smat has no visibility into other users' drafts via this table at all.
create policy feedback_drafts_select_own on public.feedback_drafts
  for select
  using (created_by = auth.uid());

-- Ownership of the draft row (created_by) is necessary but not sufficient:
-- without the second clause below, a caller could tag their own private
-- draft with any feedback_id at all, including one they have no editing
-- right to on `feedbacks` itself. This does NOT let a draft bypass
-- feedbacks' own RLS (the real save in onSaveEval always re-checks
-- feedbacks_update_instructor/feedbacks_smat_all independently, regardless
-- of what a draft's feedback_id claims) - it only keeps feedback_drafts
-- itself internally consistent with who may legitimately reference what.
--
-- The instructor branch below reproduces feedbacks_update_instructor's own
-- USING clause verbatim (has_role/instructor_id/status/population-match -
-- verified live against the actual policy, not assumed), so a draft can
-- never be linked more broadly than the instructor could really edit that
-- feedback anyway. smat stays unrestricted, matching feedbacks_smat_all.
-- (Earlier drafts of this migration first omitted status, then omitted
-- population - both closed now: matching the app's real editing rule
-- exactly takes precedence over any autosave-friendliness shortcut.
-- openDraftForEdit()/editFeedback() in Nimbus.dc.html already show a clear
-- message at open-time if a draft's source becomes ineligible for any of
-- these reasons, independently of this policy.)
--
-- Every EXISTS below is a direct, non-bypassed query, run as the caller -
-- safe from the recursion this schema has hit before (feedbacks <->
-- profiles): none of feedbacks/trainee_profiles/instructor_profiles have a
-- policy that references feedback_drafts, so there is no cycle, only a
-- one-way chain. The inner trainee_profiles/instructor_profiles lookup is
-- itself still subject to ITS OWN RLS (trainee_profiles_select_linked_
-- instructor/instructor_profiles_select_self) under the caller's role -
-- this doesn't double-block anything: if population doesn't match, that
-- RLS already makes the row invisible to this subquery, EXISTS correctly
-- returns false either way, so the explicit population condition here is
-- consistent defense-in-depth, not a second, different gate. has_role() is
-- the existing SECURITY DEFINER function already used everywhere else in
-- this schema - no new function was added, and no RLS/trigger on
-- `feedbacks` (or any other existing table) was touched.
create policy feedback_drafts_insert_own on public.feedback_drafts
  for insert
  with check (
    created_by = auth.uid()
    and (
      feedback_id is null
      or exists (
        select 1 from public.feedbacks f
        where f.id = feedback_id
          and (
            public.has_role('smat')
            or (
              f.instructor_id = auth.uid()
              and f.status <> 'approved'
              and exists (
                select 1 from public.trainee_profiles tp
                join public.instructor_profiles ip on ip.profile_id = auth.uid()
                where tp.profile_id = f.trainee_id
                  and tp.population = any (ip.populations)
              )
            )
          )
      )
    )
  );

create policy feedback_drafts_update_own on public.feedback_drafts
  for update
  using (created_by = auth.uid())
  with check (
    created_by = auth.uid()
    and (
      feedback_id is null
      or exists (
        select 1 from public.feedbacks f
        where f.id = feedback_id
          and (
            public.has_role('smat')
            or (
              f.instructor_id = auth.uid()
              and f.status <> 'approved'
              and exists (
                select 1 from public.trainee_profiles tp
                join public.instructor_profiles ip on ip.profile_id = auth.uid()
                where tp.profile_id = f.trainee_id
                  and tp.population = any (ip.populations)
              )
            )
          )
      )
    )
  );

create policy feedback_drafts_delete_own on public.feedback_drafts
  for delete
  using (created_by = auth.uid());

-- Reuses the existing generic trigger function (already used elsewhere in
-- this schema) - no new function needed.
create trigger trg_feedback_drafts_updated_at
  before update on public.feedback_drafts
  for each row execute function public.set_updated_at();
