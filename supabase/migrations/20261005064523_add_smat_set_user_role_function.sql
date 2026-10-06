-- Atomic role-change RPC for smat, replacing the 3 separate client-side
-- Supabase calls that onConfirmRoleModal() used to make (profiles.update,
-- then trainee_profiles.upsert OR instructor_profiles.upsert). A single RPC
-- call is wrapped by PostgREST in one transaction, so any failure partway
-- through this function rolls back everything it already did in this call -
-- no more "role updated but extension row missing" partial state.
--
-- SECURITY INVOKER (not DEFINER) on purpose: the calling smat already has
-- every permission this function needs via the existing RLS policies
-- (profiles_smat_all / trainee_profiles_smat_all / instructor_profiles_smat_all,
-- all `has_role('smat')`) - atomicity comes from this being one function
-- call, not from privilege escalation. This does not introduce any new
-- authorization surface; it only groups already-permitted writes together.
--
-- Not touched by this migration: RLS policies, triggers, any other
-- function, any table, column, or data.
CREATE OR REPLACE FUNCTION public.smat_set_user_role(
  _target_id uuid,
  _mode text,
  _role text,
  _population text DEFAULT NULL,
  _populations text[] DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path TO 'public'
AS $function$
begin
  if not public.has_role('smat') then
    raise exception 'Only an approved smat may perform this action';
  end if;

  if _mode not in ('approve', 'change', 'complete') then
    raise exception 'Invalid mode: %', _mode;
  end if;

  if _role not in ('smat', 'instructor', 'trainee', 'kahad') then
    raise exception 'Invalid role: %', _role;
  end if;

  -- 'approve'/'change': update profiles.role (and status, only for
  -- 'approve') - exactly the patch onConfirmRoleModal() used to build itself.
  -- 'complete' never touches role/status - it only repairs a profile that is
  -- already approved with the right role but is missing its extension row -
  -- so instead it verifies the target's current role actually matches
  -- _role, to avoid provisioning the wrong extension table for it.
  if _mode <> 'complete' then
    update public.profiles
    set role = _role,
        status = case when _mode = 'approve' then 'approved' else status end
    where id = _target_id;

    if not found then
      raise exception 'Target profile not found';
    end if;
  else
    if not exists (
      select 1 from public.profiles where id = _target_id and role = _role
    ) then
      raise exception 'Target profile role does not match the requested role';
    end if;
  end if;

  -- Provisioning (extension table) only for 'approve'/'complete', matching
  -- the previous `provisioning = mode==='approve' || mode==='complete'`
  -- behavior exactly - 'change' never writes an extension table. smat and
  -- kahad have no extension table at all, so neither branch below runs for
  -- them. ON CONFLICT DO UPDATE matches the previous .upsert() calls -
  -- never deletes an existing trainee_profiles/instructor_profiles row,
  -- only updates it if present or creates it if missing.
  if _mode in ('approve', 'complete') and _role = 'trainee' then
    if _population is null or _population = '' then
      raise exception 'population is required for trainee';
    end if;
    -- Invalid (non-NULL, out-of-list) values are also still rejected by
    -- trainee_profiles_population_check regardless of this check.
    insert into public.trainee_profiles (profile_id, population)
    values (_target_id, _population)
    on conflict (profile_id) do update set population = excluded.population;
  end if;

  if _mode in ('approve', 'complete') and _role = 'instructor' then
    if _populations is null or array_length(_populations, 1) is null then
      raise exception 'at least one population is required for instructor';
    end if;
    -- Invalid values are also still rejected by
    -- instructor_profiles_populations_check regardless of this check.
    insert into public.instructor_profiles (profile_id, populations)
    values (_target_id, _populations)
    on conflict (profile_id) do update set populations = excluded.populations;
  end if;
end;
$function$;

REVOKE ALL ON FUNCTION public.smat_set_user_role(uuid, text, text, text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.smat_set_user_role(uuid, text, text, text, text[]) TO authenticated;
