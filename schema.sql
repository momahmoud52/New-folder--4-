-- =====================================================================
-- نظام الموارد البشرية الداخلي - قاعدة البيانات والصلاحيات (Supabase)
-- الإصدار 3.5 — آمن لإعادة التشغيل: يمكنك لصقه كاملاً فوق الإصدار القديم.
-- الصقه كاملاً في: SQL Editor ثم اضغط Run
-- 3.1: عمود تاريخ الميلاد (birth_date).
-- 3.4: البريد الإلكتروني (email) + تقييم الأداء لكل مسؤول إدخال لأعضائه فقط. (العمر يُحسب من تاريخ الميلاد ولا يُخزَّن.)
-- 3.5: تأكيد الاسم الحقيقي بالعربية عند أول دخول (profiles.name_confirmed_at).
-- 3.2: الجنس، المحافظة التابع لها بالاتحاد، طالب/خريج، المرحلة التعليمية، اسم المدرسة/الجامعة.
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- 1) الحسابات والأدوار
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  full_name  text,
  email      text,
  role       text not null default 'member' check (role in ('admin','member')),
  created_at timestamptz not null default now()
);

create or replace function public.is_admin()
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

-- إنشاء ملف تعريف تلقائياً عند إضافة أي مستخدم (دائماً بدور member)
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1))
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

alter table public.profiles enable row level security;

drop policy if exists "profiles_select" on public.profiles;
create policy "profiles_select" on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.is_admin());

drop policy if exists "profiles_update_admin" on public.profiles;
create policy "profiles_update_admin" on public.profiles
  for update to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- كل مستخدم يعدّل ملفه هو (الاسم المعروض)، والحارس أدناه يمنعه من تغيير الدور
drop policy if exists "profiles_update_self" on public.profiles;
create policy "profiles_update_self" on public.profiles
  for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

create or replace function public.guard_profile_update()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- auth.uid() فارغ عند التشغيل من SQL Editor، فيُسمح للمالك بتعديل أي شيء
  if auth.uid() is not null and not public.is_admin() then
    new.id         := old.id;
    new.role       := old.role;
    new.email      := old.email;
    new.created_at := old.created_at;
  end if;

  -- لا يجوز ترك النظام بلا مسؤول
  if old.role = 'admin' and new.role <> 'admin'
     and not exists (select 1 from public.profiles where role = 'admin' and id <> old.id) then
    raise exception 'لا يمكن إزالة آخر مسؤول في النظام';
  end if;
  return new;
end;
$$;

-- [جديد 3.5] تأكيد الاسم عند أول دخول: فارغ = لم يؤكد اسمه بعد، فتظهر له نافذة مرة واحدة.
-- الحسابات الموجودة قبل 3.5 تبقى فارغة، فيُطلب من كل واحد منها تأكيد اسمه مرة واحدة.
alter table public.profiles add column if not exists name_confirmed_at timestamptz;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'profiles_name_chk') then
    alter table public.profiles add constraint profiles_name_chk
      check (name_confirmed_at is null
             or (char_length(full_name) <= 80 and full_name ~ '^[ء-ي]+( [ء-ي]+)+$')) not valid;
  end if;
end $$;

drop trigger if exists profiles_guard on public.profiles;
create trigger profiles_guard
  before update on public.profiles
  for each row execute function public.guard_profile_update();

-- ---------------------------------------------------------------------
-- 2) الأعضاء (البيانات + مسارات الصور)
--    رقم العضوية + المحافظة + العنوان + رقم البطاقة + الصفة + اللجنة
--    [الإصدار 3.1] + تاريخ الميلاد.  [الإصدار 3.4] + البريد الإلكتروني (email).
--    العمر يُحسب تلقائياً من تاريخ الميلاد فلا يتقادم.
--    عمودا القسم والانضمام القديمان يبقيان في الجدول حتى لا تضيع بياناتك.
-- ---------------------------------------------------------------------
create table if not exists public.employees (
  id            uuid primary key default gen_random_uuid(),
  membership_no text unique,
  full_name     text not null,
  phone         text,
  governorate   text,
  address       text,
  national_id   text,
  birth_date    date,
  gender        text,
  union_governorate text,
  study_status  text,
  edu_stage     text,
  institution   text,
  capacity      text,
  committee     text,
  status        text not null default 'active' check (status in ('active','inactive')),
  photo_path    text,
  id_doc_path   text,
  consent       boolean not null default false,
  created_by    uuid not null default auth.uid() references auth.users(id),
  created_at    timestamptz not null default now(),
  -- أعمدة قديمة (غير مستخدمة في الواجهة)
  department    text,
  email         text,
  join_date     date
);

-- ترقية جدول قديم: تحويل employee_code إلى membership_no مع الإبقاء على القيم
do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'employees' and column_name = 'employee_code')
     and not exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'employees' and column_name = 'membership_no') then
    alter table public.employees rename column employee_code to membership_no;
  end if;
end $$;

alter table public.employees add column if not exists membership_no text;
alter table public.employees add column if not exists governorate   text;
alter table public.employees add column if not exists address       text;
alter table public.employees add column if not exists national_id   text;
alter table public.employees add column if not exists birth_date    date;   -- [3.1]
alter table public.employees add column if not exists gender        text;   -- [جديد 3.2] ذكر / أنثى
alter table public.employees add column if not exists union_governorate text; -- [جديد 3.2] المحافظة التابع لها بالاتحاد
alter table public.employees add column if not exists study_status  text;   -- [جديد 3.2] طالب / خريج
alter table public.employees add column if not exists edu_stage     text;   -- [جديد 3.2] المرحلة التعليمية
alter table public.employees add column if not exists institution   text;   -- [جديد 3.2] اسم المدرسة / الجامعة
alter table public.employees add column if not exists capacity      text;
alter table public.employees add column if not exists committee     text;
alter table public.employees add column if not exists department    text;
alter table public.employees add column if not exists email         text;
alter table public.employees add column if not exists join_date     date;

alter table public.employees enable row level security;

-- عضو الفريق يرى ما أدخله هو فقط، والمسؤول يرى كل شيء
-- (وبالتالي تصدير Excel لعضو الفريق يضم بياناته هو فقط)
drop policy if exists "employees_select" on public.employees;
create policy "employees_select" on public.employees
  for select to authenticated
  using (created_by = auth.uid() or public.is_admin());

drop policy if exists "employees_insert" on public.employees;
create policy "employees_insert" on public.employees
  for insert to authenticated
  with check (created_by = auth.uid());

drop policy if exists "employees_update" on public.employees;
create policy "employees_update" on public.employees
  for update to authenticated
  using (created_by = auth.uid() or public.is_admin())
  with check (created_by = auth.uid() or public.is_admin());

drop policy if exists "employees_delete" on public.employees;
create policy "employees_delete" on public.employees
  for delete to authenticated
  using (public.is_admin());

-- ---------------------------------------------------------------------
-- 3) المهام وتسليمها
-- ---------------------------------------------------------------------
create table if not exists public.tasks (
  id            uuid primary key default gen_random_uuid(),
  title         text not null,
  description   text,
  assigned_to   uuid not null references public.profiles(id) on delete cascade,
  due_date      date,
  status        text not null default 'pending' check (status in ('pending','delivered')),
  delivered_at  timestamptz,
  delivery_link text,
  delivery_note text,
  created_by    uuid default auth.uid() references auth.users(id),
  created_at    timestamptz not null default now()
);

alter table public.tasks enable row level security;

drop policy if exists "tasks_select" on public.tasks;
create policy "tasks_select" on public.tasks
  for select to authenticated
  using (assigned_to = auth.uid() or public.is_admin());

drop policy if exists "tasks_insert_admin" on public.tasks;
create policy "tasks_insert_admin" on public.tasks
  for insert to authenticated
  with check (public.is_admin());

drop policy if exists "tasks_update" on public.tasks;
create policy "tasks_update" on public.tasks
  for update to authenticated
  using (assigned_to = auth.uid() or public.is_admin())
  with check (assigned_to = auth.uid() or public.is_admin());

drop policy if exists "tasks_delete_admin" on public.tasks;
create policy "tasks_delete_admin" on public.tasks
  for delete to authenticated
  using (public.is_admin());

-- عضو الفريق لا يستطيع تعديل غير التسليم (العنوان/الموعد/المسؤول محمية)
create or replace function public.guard_task_update()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is not null and not public.is_admin() then
    new.title       := old.title;
    new.description := old.description;
    new.assigned_to := old.assigned_to;
    new.due_date    := old.due_date;
    new.created_by  := old.created_by;
    new.created_at  := old.created_at;
    if old.status = 'delivered' then
      -- لا يُعاد تسليم مهمة سُلّمت سابقاً
      new.status        := old.status;
      new.delivered_at  := old.delivered_at;
      new.delivery_link := old.delivery_link;
      new.delivery_note := old.delivery_note;
    else
      new.status       := 'delivered';
      new.delivered_at := now();
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists tasks_guard on public.tasks;
create trigger tasks_guard
  before update on public.tasks
  for each row execute function public.guard_task_update();

-- ---------------------------------------------------------------------
-- 4) تقييم الأداء: المسؤول لكل الأعضاء، ومسؤول الإدخال لأعضائه فقط
-- ---------------------------------------------------------------------
create table if not exists public.performance (
  id             uuid primary key default gen_random_uuid(),
  employee_id    uuid not null references public.employees(id) on delete cascade,
  month          date not null,
  manager_rating int check (manager_rating between 1 and 5),
  quality_rating int check (quality_rating between 1 and 5),
  notes          text,
  created_by     uuid default auth.uid() references auth.users(id),
  created_at     timestamptz not null default now(),
  unique (employee_id, month)
);

alter table public.performance enable row level security;

drop policy if exists "performance_admin_all" on public.performance;
create policy "performance_admin_all" on public.performance
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- [جديد 3.4] مسؤول الإدخال: يرى ويضيف ويعدّل ويحذف التقييمات التي كتبها هو،
-- وفقط لأعضاء أدخل بياناتهم هو (employees.created_by = auth.uid()).
-- يرى كذلك تقييمات المسؤول لأعضائه (قراءة فقط) حتى لا يتعارض معها.
drop policy if exists "performance_member_select" on public.performance;
create policy "performance_member_select" on public.performance
  for select to authenticated
  using (exists (select 1 from public.employees e
                 where e.id = performance.employee_id and e.created_by = auth.uid()));

drop policy if exists "performance_member_insert" on public.performance;
create policy "performance_member_insert" on public.performance
  for insert to authenticated
  with check (created_by = auth.uid()
              and exists (select 1 from public.employees e
                          where e.id = performance.employee_id and e.created_by = auth.uid()));

drop policy if exists "performance_member_update" on public.performance;
create policy "performance_member_update" on public.performance
  for update to authenticated
  using (created_by = auth.uid()
         and exists (select 1 from public.employees e
                     where e.id = performance.employee_id and e.created_by = auth.uid()))
  with check (created_by = auth.uid()
              and exists (select 1 from public.employees e
                          where e.id = performance.employee_id and e.created_by = auth.uid()));

drop policy if exists "performance_member_delete" on public.performance;
create policy "performance_member_delete" on public.performance
  for delete to authenticated
  using (created_by = auth.uid()
         and exists (select 1 from public.employees e
                     where e.id = performance.employee_id and e.created_by = auth.uid()));

-- ---------------------------------------------------------------------
-- 5) التفاعل الأسبوعي
-- ---------------------------------------------------------------------
create table if not exists public.engagement (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  week_start   date not null,
  satisfaction int not null check (satisfaction between 1 and 5),
  workload     int not null check (workload between 1 and 5),
  comment      text,
  created_at   timestamptz not null default now(),
  unique (user_id, week_start)
);

alter table public.engagement enable row level security;

drop policy if exists "engagement_select" on public.engagement;
create policy "engagement_select" on public.engagement
  for select to authenticated
  using (user_id = auth.uid() or public.is_admin());

drop policy if exists "engagement_insert" on public.engagement;
create policy "engagement_insert" on public.engagement
  for insert to authenticated
  with check (user_id = auth.uid());

drop policy if exists "engagement_update" on public.engagement;
create policy "engagement_update" on public.engagement
  for update to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- ---------------------------------------------------------------------
-- 6) سجل الوصول لصور الهوية (من فتح/نزّل ماذا ومتى) — للإضافة والقراءة فقط
-- ---------------------------------------------------------------------
create table if not exists public.access_log (
  id          bigint generated always as identity primary key,
  user_id     uuid not null default auth.uid() references auth.users(id),
  employee_id uuid references public.employees(id) on delete set null,
  action      text not null,
  at          timestamptz not null default now()
);

alter table public.access_log enable row level security;

drop policy if exists "access_log_insert" on public.access_log;
create policy "access_log_insert" on public.access_log
  for insert to authenticated
  with check (user_id = auth.uid());

drop policy if exists "access_log_select_admin" on public.access_log;
create policy "access_log_select_admin" on public.access_log
  for select to authenticated
  using (public.is_admin());

-- ---------------------------------------------------------------------
-- 7) قيود على الإدخال (تُطبَّق على الصفوف الجديدة والمعدَّلة)
-- ---------------------------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'tasks_delivery_link_http') then
    alter table public.tasks add constraint tasks_delivery_link_http
      check (delivery_link is null or delivery_link ~* '^https?://') not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'tasks_title_len') then
    alter table public.tasks add constraint tasks_title_len
      check (char_length(title) between 1 and 200) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'tasks_text_len') then
    alter table public.tasks add constraint tasks_text_len
      check (coalesce(char_length(description),0) <= 2000 and coalesce(char_length(delivery_note),0) <= 1000) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'employees_name_len') then
    alter table public.employees add constraint employees_name_len
      check (char_length(full_name) between 1 and 120) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'engagement_comment_len') then
    alter table public.engagement add constraint engagement_comment_len
      check (comment is null or char_length(comment) <= 1000) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'performance_notes_len') then
    alter table public.performance add constraint performance_notes_len
      check (notes is null or char_length(notes) <= 2000) not valid;
  end if;

  -- رقم البطاقة 14 رقماً
  if not exists (select 1 from pg_constraint where conname = 'employees_nid_chk') then
    alter table public.employees add constraint employees_nid_chk
      check (national_id is null or national_id ~ '^[0-9]{14}$') not valid;
  end if;
  -- الهاتف أرقام فقط (مع + اختيارية)
  if not exists (select 1 from pg_constraint where conname = 'employees_phone_chk') then
    alter table public.employees add constraint employees_phone_chk
      check (phone is null or phone ~ '^\+?[0-9]{8,15}$') not valid;
  end if;
  -- حدود أطوال العنوان ورقم العضوية
  if not exists (select 1 from pg_constraint where conname = 'employees_text_len') then
    alter table public.employees add constraint employees_text_len
      check (coalesce(char_length(address),0) <= 300 and coalesce(char_length(membership_no),0) <= 40) not valid;
  end if;
  -- الصفة
  if not exists (select 1 from pg_constraint where conname = 'employees_capacity_chk') then
    alter table public.employees add constraint employees_capacity_chk
      check (capacity is null or capacity in ('رئيس','نائب','عضو','عضو مركزي','ممثل')) not valid;
  end if;
  -- اللجنة / جهة التمثيل
  if not exists (select 1 from pg_constraint where conname = 'employees_committee_chk') then
    alter table public.employees add constraint employees_committee_chk
      check (committee is null or committee in (
        'لجنة المكتب الإعلامي',
        'لجنة الموارد البشرية',
        'لجنة التنظيم والمراسم',
        'لجنة التدريب والتطوير',
        'لجنة العلاقات العامة والدولية',
        'لجنة الاستدامة والتحول الأخضر',
        'لجنة السياحة والثقافة',
        'لجنة التخطيط والمتابعة',
        'ممثل مكتب المشروعات',
        'ممثل المكتب الفني'
      )) not valid;
  end if;
  -- المحافظة (27 محافظة)
  if not exists (select 1 from pg_constraint where conname = 'employees_governorate_chk') then
    alter table public.employees add constraint employees_governorate_chk
      check (governorate is null or governorate in (
        'القاهرة','الجيزة','الإسكندرية','القليوبية','الشرقية','الدقهلية','الغربية','المنوفية',
        'البحيرة','كفر الشيخ','دمياط','بورسعيد','الإسماعيلية','السويس','شمال سيناء','جنوب سيناء',
        'الفيوم','بني سويف','المنيا','أسيوط','سوهاج','قنا','الأقصر','أسوان',
        'البحر الأحمر','الوادي الجديد','مطروح'
      )) not valid;
  end if;
  -- [جديد 3.1] تاريخ الميلاد: لا يسبق 1900 ولا يكون في المستقبل البعيد
  -- (التحقق من «ليس في المستقبل» يتم في الواجهة، لأن current_date لا يصلح داخل CHECK)
  if not exists (select 1 from pg_constraint where conname = 'employees_birth_chk') then
    alter table public.employees add constraint employees_birth_chk
      check (birth_date is null or birth_date between date '1900-01-01' and date '2100-01-01') not valid;
  end if;

  -- [جديد 3.2] الجنس
  if not exists (select 1 from pg_constraint where conname = 'employees_gender_chk') then
    alter table public.employees add constraint employees_gender_chk
      check (gender is null or gender in ('ذكر','أنثى')) not valid;
  end if;
  -- [جديد 3.2] طالب / خريج
  if not exists (select 1 from pg_constraint where conname = 'employees_study_chk') then
    alter table public.employees add constraint employees_study_chk
      check (study_status is null or study_status in ('طالب','خريج')) not valid;
  end if;
  -- [جديد 3.2] المرحلة التعليمية
  if not exists (select 1 from pg_constraint where conname = 'employees_edu_chk') then
    alter table public.employees add constraint employees_edu_chk
      check (edu_stage is null or edu_stage in ('إعدادي','ثانوي','دبلوم / معهد','جامعي','دراسات عليا','دكتوراه')) not valid;
  end if;
  -- [جديد 3.2] اسم المدرسة / الجامعة
  if not exists (select 1 from pg_constraint where conname = 'employees_inst_len') then
    alter table public.employees add constraint employees_inst_len
      check (institution is null or char_length(institution) <= 150) not valid;
  end if;
  -- [جديد 3.2] المحافظة التابع لها بالاتحاد (نفس قائمة المحافظات الـ27)
  if not exists (select 1 from pg_constraint where conname = 'employees_union_gov_chk') then
    alter table public.employees add constraint employees_union_gov_chk
      check (union_governorate is null or union_governorate in (
        'القاهرة','الجيزة','الإسكندرية','القليوبية','الشرقية','الدقهلية','الغربية','المنوفية',
        'البحيرة','كفر الشيخ','دمياط','بورسعيد','الإسماعيلية','السويس','شمال سيناء','جنوب سيناء',
        'الفيوم','بني سويف','المنيا','أسيوط','سوهاج','قنا','الأقصر','أسوان',
        'البحر الأحمر','الوادي الجديد','مطروح'
      )) not valid;
  end if;

  -- [جديد 3.4] البريد الإلكتروني
  if not exists (select 1 from pg_constraint where conname = 'employees_email_chk') then
    alter table public.employees add constraint employees_email_chk
      check (email is null or (char_length(email) <= 150 and email ~* '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]{2,}$')) not valid;
  end if;
end $$;

-- ---------------------------------------------------------------------
-- 8) فهارس لتسريع الاستعلامات مع نمو البيانات
-- ---------------------------------------------------------------------
create index if not exists employees_created_by_idx on public.employees (created_by);
create index if not exists employees_created_at_idx on public.employees (created_at desc);
-- منع تسجيل نفس رقم البطاقة مرتين
create unique index if not exists employees_national_id_uq on public.employees (national_id) where national_id is not null;
create index if not exists tasks_assigned_idx       on public.tasks (assigned_to);
create index if not exists tasks_status_due_idx     on public.tasks (status, due_date);
create index if not exists engagement_week_idx      on public.engagement (week_start);
create index if not exists performance_month_idx    on public.performance (month);
create index if not exists access_log_at_idx        on public.access_log (at desc);
create index if not exists access_log_employee_idx  on public.access_log (employee_id);

-- ---------------------------------------------------------------------
-- 9) تخزين الصور: buckets خاصة (غير عامة) بحد 2MB وصيغ صور فقط
-- ---------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
  ('photos', 'photos', false, 2097152, array['image/jpeg','image/png','image/webp']),
  ('ids',    'ids',    false, 2097152, array['image/jpeg','image/png','image/webp'])
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- الرفع: داخل مجلد باسم المستخدم فقط
drop policy if exists "hr_files_insert" on storage.objects;
create policy "hr_files_insert" on storage.objects
  for insert to authenticated
  with check (
    bucket_id in ('photos','ids')
    and (storage.foldername(name))[1] = auth.uid()::text
  );

-- القراءة: صاحب الملف أو المسؤول
drop policy if exists "hr_files_select" on storage.objects;
create policy "hr_files_select" on storage.objects
  for select to authenticated
  using (
    bucket_id in ('photos','ids')
    and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin())
  );

-- الحذف: المسؤول فقط
drop policy if exists "hr_files_delete" on storage.objects;
create policy "hr_files_delete" on storage.objects
  for delete to authenticated
  using (
    bucket_id in ('photos','ids')
    and public.is_admin()
  );

-- =====================================================================
-- إعلام Supabase بتحديث ذاكرة الجداول فوراً (يمنع خطأ: Could not find the column ... in the schema cache)
notify pgrst, 'reload schema';

-- =====================================================================
-- بعد التشغيل لأول مرة: سجّل حسابك أولاً (Authentication > Users > Add user)،
-- ثم اجعله مسؤولاً بتشغيل هذا الأمر (بدّل البريد ببريدك):
--
--   update public.profiles set role = 'admin' where email = 'your@email.com';
--
-- إذا كنت تُرقّي نظاماً قائماً: يكفي تشغيل هذا الملف مرة أخرى، ولا حاجة لشيء آخر.
-- الأعضاء المسجَّلون سابقاً يظهر عليهم وسم «بيانات ناقصة» حتى تُستكمل الحقول الجديدة.
-- =====================================================================
