-- IT ACADEMY · schema v2
-- Ідемпотентний: можна запускати і на новому проєкті, і поверх попередньої версії (v1). Виконуйте в Supabase → SQL Editor.

------------------------------------------------------------------ ТАБЛИЦІ
create table if not exists profiles(id uuid primary key references auth.users on delete cascade,email text,name text default '',avatar text default '#5685FF',
  role text not null default 'user',blocked boolean not null default false,blocked_until timestamptz,
  created_at timestamptz default now(),last_seen timestamptz default now());
create table if not exists subjects(id uuid primary key default gen_random_uuid(),user_id uuid not null references profiles on delete cascade default auth.uid(),
  name text not null check(char_length(name) between 1 and 60),unique(user_id,name));
create table if not exists grades(id uuid primary key default gen_random_uuid(),user_id uuid not null references profiles on delete cascade default auth.uid(),
  subject_id uuid not null references subjects on delete cascade,value int not null check(value between 1 and 12),
  date date not null default current_date,comment text default '' check(char_length(comment)<=300),created_at timestamptz default now());
create table if not exists goals(id uuid primary key default gen_random_uuid(),user_id uuid not null references profiles on delete cascade default auth.uid(),
  title text not null check(char_length(title)<=80),kind text not null check(kind in('avg','count')),target numeric not null check(target>0),created_at timestamptz default now());
create table if not exists events(id bigint generated always as identity primary key,user_id uuid not null references profiles on delete cascade default auth.uid(),
  type text not null,payload jsonb default '{}',created_at timestamptz default now());
create table if not exists announcements(id uuid primary key default gen_random_uuid(),title text not null check(char_length(title)<=120),body text default '' check(char_length(body)<=1000),created_at timestamptz default now());
create table if not exists messages(id uuid primary key default gen_random_uuid(),to_id uuid not null references profiles on delete cascade,from_id uuid,
  title text not null check(char_length(title)<=120),body text default '' check(char_length(body)<=1000),created_at timestamptz default now(),read_at timestamptz);
-- історія блокувань (пише лише RPC)
create table if not exists bans(id uuid primary key default gen_random_uuid(),user_id uuid not null references profiles on delete cascade,by_id uuid,by_name text,
  reason text not null,created_at timestamptz default now(),until timestamptz,lifted_at timestamptz,lifted_by uuid,lift_kind text);
-- захищений журнал адміністративних дій (пише лише серверний код, незмінний)
create table if not exists audit_log(id bigint generated always as identity primary key,actor_id uuid,actor_name text,actor_role text,action text not null,
  target_id uuid,target_name text,details jsonb default '{}',created_at timestamptz default now());
create index if not exists i_gr on grades(user_id);create index if not exists i_bn on bans(user_id);create index if not exists i_ev on events(created_at desc);create index if not exists i_au on audit_log(created_at desc);

-- Предмет і оцінка завжди мають належати одному користувачу.
create unique index if not exists subjects_id_user_uidx on subjects(id,user_id);
create or replace function guard_grade_subject_owner() returns trigger language plpgsql security definer set search_path=public as $$
begin
  if not exists(select 1 from subjects s where s.id=new.subject_id and s.user_id=new.user_id) then
    raise exception 'Предмет не належить цьому користувачу';
  end if;
  return new;
end $$;
drop trigger if exists grade_subject_owner on grades;
create trigger grade_subject_owner before insert or update of subject_id,user_id on grades
for each row execute function guard_grade_subject_owner();

do $$ begin
  if not exists(select 1 from pg_constraint where conname='grades_subject_owner_fk' and conrelid='public.grades'::regclass)
     and not exists(select 1 from grades g join subjects s on s.id=g.subject_id where s.user_id<>g.user_id) then
    alter table grades add constraint grades_subject_owner_fk
      foreign key(subject_id,user_id) references subjects(id,user_id) on delete cascade;
  end if;
end $$;


-- міграція з v1: ролі student → user, нові стовпці
alter table profiles add column if not exists blocked_until timestamptz;
alter table profiles drop constraint if exists profiles_role_check;
update profiles set role='user' where role not in('admin','moderator');
alter table profiles alter column role set default 'user';
alter table profiles add constraint profiles_role_check check(role in('admin','moderator','user'));
alter table profiles drop constraint if exists profiles_name_len;
alter table profiles add constraint profiles_name_len check(char_length(name)<=60);

------------------------------------------------------------------ ДОПОМІЖНІ ФУНКЦІЇ (роль того, хто викликає; заблокований = без ролі)
create or replace function my_role() returns text language sql security definer stable set search_path=public as
$$ select role from profiles where id=auth.uid() and not(blocked and (blocked_until is null or blocked_until>now())) $$;
create or replace function is_admin() returns boolean language sql security definer stable set search_path=public as $$ select coalesce(my_role()='admin',false) $$;
create or replace function is_mod() returns boolean language sql security definer stable set search_path=public as $$ select coalesce(my_role()='moderator',false) $$;
create or replace function active() returns boolean language sql security definer stable set search_path=public as $$ select my_role() is not null $$;

create or replace function log_action(act text,tgt uuid,det jsonb default '{}') returns void language plpgsql security definer set search_path=public as $$
declare a profiles; t text;
begin
  select * into a from profiles where id=auth.uid();
  if tgt is not null then select coalesce(nullif(name,''),email) into t from profiles where id=tgt; end if;
  insert into audit_log(actor_id,actor_name,actor_role,action,target_id,target_name,details)
  values(auth.uid(),coalesce(nullif(a.name,''),a.email),a.role,act,tgt,t,coalesce(det,'{}'));
end $$;
revoke execute on function log_action(text,uuid,jsonb) from public,anon,authenticated;

create or replace function new_user() returns trigger language plpgsql security definer set search_path=public as
$$ begin
  insert into profiles(id,email,name) values(new.id,new.email,left(coalesce(nullif(new.raw_user_meta_data->>'name',''),split_part(new.email,'@',1)),60));
  insert into events(user_id,type,payload) values(new.id,'register','{}'::jsonb);
  return new;
end $$;
drop trigger if exists on_signup on auth.users;
create trigger on_signup after insert on auth.users for each row execute function new_user();

------------------------------------------------------------------ ЗАХИСТ ПРОФІЛІВ: role / blocked / email змінюються ЛИШЕ через RPC нижче
create or replace function guard_profile() returns trigger language plpgsql security definer set search_path=public as $$
begin
  if auth.uid() is not null and coalesce(current_setting('app.rpc',true),'')<>'on'
     and (new.role is distinct from old.role or new.blocked is distinct from old.blocked or new.blocked_until is distinct from old.blocked_until
          or new.email is distinct from old.email or new.id<>old.id or new.created_at is distinct from old.created_at
          or new.last_seen is distinct from old.last_seen)
  then raise exception 'Системні поля профілю змінюються лише сервером'; end if;
  return new;
end $$;
drop trigger if exists guard on profiles;
create trigger guard before update on profiles for each row execute function guard_profile();

create or replace function audit_immutable() returns trigger language plpgsql as $$ begin raise exception 'Журнал незмінний'; end $$;
drop trigger if exists audit_lock on audit_log;
create trigger audit_lock before update or delete on audit_log for each row execute function audit_immutable();

------------------------------------------------------------------ RPC (перевірка прав на сервері)
-- Призначення / зняття модератора: тільки admin, не себе, не іншого admin
create or replace function set_role(target uuid,new_role text) returns void language plpgsql security definer set search_path=public as $$
declare t profiles;
begin
  if not is_admin() then raise exception 'Недостатньо прав'; end if;
  if new_role not in('user','moderator') then raise exception 'Недопустима роль'; end if;
  select * into t from profiles where id=target;
  if not found then raise exception 'Користувача не знайдено'; end if;
  if t.id=auth.uid() or t.role='admin' then raise exception 'Роль адміністратора змінити не можна'; end if;
  perform set_config('app.rpc','on',true);
  update profiles set role=new_role where id=target;
  perform log_action('set_role',target,jsonb_build_object('from',t.role,'to',new_role));
end $$;

-- Блокування: admin — будь-кого крім себе; moderator — лише role='user'
create or replace function ban_user(target uuid,why text,until_ts timestamptz default null) returns void language plpgsql security definer set search_path=public as $$
declare me text:=my_role(); t profiles; w text:=btrim(coalesce(why,''));
begin
  if me is null or me not in('admin','moderator') then raise exception 'Недостатньо прав'; end if;
  if char_length(w) not between 3 and 300 then raise exception 'Причина: від 3 до 300 символів'; end if;
  if until_ts is not null and until_ts<=now() then raise exception 'Термін має бути в майбутньому'; end if;
  select * into t from profiles where id=target;
  if not found then raise exception 'Користувача не знайдено'; end if;
  if t.id=auth.uid() then raise exception 'Не можна блокувати себе'; end if;
  if me='moderator' and t.role<>'user' then raise exception 'Модератор може блокувати лише звичайних користувачів'; end if;
  perform set_config('app.rpc','on',true);
  update bans set lifted_at=now(),lifted_by=auth.uid(),lift_kind='replaced' where user_id=target and lifted_at is null;
  update profiles set blocked=true,blocked_until=until_ts where id=target;
  insert into bans(user_id,by_id,by_name,reason,until)
  values(target,auth.uid(),(select coalesce(nullif(name,''),email) from profiles where id=auth.uid()),w,until_ts);
  perform log_action('ban',target,jsonb_build_object('reason',w,'until',until_ts));
end $$;

create or replace function unban_user(target uuid) returns void language plpgsql security definer set search_path=public as $$
declare me text:=my_role(); t profiles;
begin
  if me is null or me not in('admin','moderator') then raise exception 'Недостатньо прав'; end if;
  select * into t from profiles where id=target;
  if not found then raise exception 'Користувача не знайдено'; end if;
  if me='moderator' and t.role<>'user' then raise exception 'Модератор може керувати лише звичайними користувачами'; end if;
  if not t.blocked then raise exception 'Користувач не заблокований'; end if;
  perform set_config('app.rpc','on',true);
  update profiles set blocked=false,blocked_until=null where id=target;
  update bans set lifted_at=now(),lifted_by=auth.uid(),lift_kind='manual' where user_id=target and lifted_at is null;
  perform log_action('unban',target,'{}');
end $$;

-- Пульс: оновлює last_seen, автоматично завершує тимчасові блокування, повертає роль і статус (для виходу заблокованих)
create or replace function heartbeat() returns jsonb language plpgsql security definer set search_path=public as $$
declare p profiles; r text;
begin
  if auth.uid() is null then return null; end if;
  perform set_config('app.rpc','on',true);
  with e as(update profiles set blocked=false,blocked_until=null where blocked and blocked_until is not null and blocked_until<=now() returning id)
  update bans set lifted_at=now(),lift_kind='expired' where lifted_at is null and user_id in(select id from e);
  update profiles set last_seen=now() where id=auth.uid();
  select * into p from profiles where id=auth.uid();
  if not found then return null; end if;
  select reason into r from bans where user_id=auth.uid() and lifted_at is null order by created_at desc limit 1;
  return jsonb_build_object('role',p.role,'blocked',p.blocked,'until',p.blocked_until,'reason',r);
end $$;

create or replace function mark_messages_read() returns void language sql security definer set search_path=public as
$$ update messages set read_at=now() where to_id=auth.uid() and read_at is null and active() $$;

revoke execute on function set_role(uuid,text),ban_user(uuid,text,timestamptz),unban_user(uuid),heartbeat(),mark_messages_read() from public,anon;
grant execute on function set_role(uuid,text),ban_user(uuid,text,timestamptz),unban_user(uuid),heartbeat(),mark_messages_read() to authenticated;

-- аудит оголошень і повідомлень (автоматично, на сервері)
create or replace function trg_audit() returns trigger language plpgsql security definer set search_path=public as $$
begin
  if tg_table_name='announcements' then
    if tg_op='INSERT' then perform log_action('announcement_create',null,jsonb_build_object('title',new.title)); return new;
    else perform log_action('announcement_delete',null,jsonb_build_object('title',old.title)); return old; end if;
  else perform log_action('message_send',new.to_id,jsonb_build_object('title',new.title)); return new; end if;
end $$;
drop trigger if exists aud_ann on announcements;create trigger aud_ann after insert or delete on announcements for each row execute function trg_audit();
drop trigger if exists aud_msg on messages;create trigger aud_msg after insert on messages for each row execute function trg_audit();

-- Достовірні події навчальних змін створюються тригерами БД, а не браузером.
create or replace function capture_user_event() returns trigger language plpgsql security definer set search_path=public as $$
begin
  if tg_table_name='grades' then
    insert into events(user_id,type,payload) values(new.user_id,case when tg_op='INSERT' then 'grade_add' else 'grade_edit' end,jsonb_build_object('value',new.value));
  elsif tg_table_name='goals' then
    insert into events(user_id,type,payload) values(new.user_id,'goal_add',jsonb_build_object('title',new.title));
  elsif tg_table_name='profiles' then
    if new.name is distinct from old.name or new.avatar is distinct from old.avatar then
      insert into events(user_id,type,payload) values(new.id,'profile_update','{}'::jsonb);
    end if;
  end if;
  return new;
end $$;
drop trigger if exists event_grade_change on grades;
create trigger event_grade_change after insert or update on grades for each row execute function capture_user_event();
drop trigger if exists event_goal_create on goals;
create trigger event_goal_create after insert on goals for each row execute function capture_user_event();
drop trigger if exists event_profile_change on profiles;
create trigger event_profile_change after update on profiles for each row execute function capture_user_event();

------------------------------------------------------------------ RLS
alter table profiles enable row level security;alter table subjects enable row level security;alter table grades enable row level security;alter table goals enable row level security;
alter table events enable row level security;alter table announcements enable row level security;alter table messages enable row level security;
alter table bans enable row level security;alter table audit_log enable row level security;

do $$ declare r record; begin for r in select policyname,tablename from pg_policies where schemaname='public' and tablename in
 ('profiles','subjects','grades','goals','events','announcements','messages','bans','audit_log') loop execute format('drop policy %I on %I',r.policyname,r.tablename); end loop; end $$;

-- профілі: свій; admin — усі; moderator — лише звичайні користувачі. Оновлювати можна лише власний (role/blocked захищає тригер)
create policy p_sel on profiles for select using(id=auth.uid() or is_admin() or (is_mod() and role='user'));
create policy p_upd on profiles for update using(id=auth.uid()) with check(id=auth.uid());
-- дані учня: власні (і лише якщо не заблокований); admin — читання всіх. Модератор оцінок НЕ бачить
create policy s_own on subjects for all using(user_id=auth.uid() and active()) with check(user_id=auth.uid() and active());
create policy s_adm on subjects for select using(is_admin());
create policy g_own on grades for all using(user_id=auth.uid() and active()) with check(user_id=auth.uid() and active());
create policy g_adm on grades for select using(is_admin());
create policy l_own on goals for all using(user_id=auth.uid() and active()) with check(user_id=auth.uid() and active());
create policy l_adm on goals for select using(is_admin());
create policy e_sel on events for select using(is_admin());
create policy a_sel on announcements for select using(active());
create policy a_ins on announcements for insert with check(is_admin());
create policy a_del on announcements for delete using(is_admin());
create policy m_sel on messages for select using(is_admin() or (to_id=auth.uid() and active()));
create policy m_ins on messages for insert with check(is_admin() and from_id=auth.uid());
-- блокування й журнал: запису з клієнта немає взагалі
create policy b_sel on bans for select using(is_admin() or (is_mod() and (by_id=auth.uid() or exists(select 1 from profiles t where t.id=bans.user_id and t.role='user'))));
create policy au_sel on audit_log for select using(is_admin() or (is_mod() and actor_id=auth.uid()));
revoke insert,update,delete on bans,audit_log,events from anon,authenticated;
revoke all on bans,audit_log,messages,profiles,subjects,grades,goals,events,announcements from anon;

------------------------------------------------------------------ REALTIME
do $$ declare t text; begin foreach t in array array['events','announcements','profiles','messages','audit_log'] loop
 begin execute format('alter publication supabase_realtime add table %I',t); exception when duplicate_object then null; end; end loop; end $$;

------------------------------------------------------------------ ПЕРШИЙ АДМІН (після реєстрації свого акаунта; в SQL Editor тригер-захист не діє)
-- update profiles set role='admin' where email='ВАШ@EMAIL';
