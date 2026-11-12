-- =====================================================================
-- نظام الموارد البشرية الداخلي - قاعدة البيانات والصلاحيات (Supabase)
-- الإصدار 3.21 — آمن لإعادة التشغيل: يمكنك لصقه كاملاً فوق الإصدار القديم.
-- الصقه كاملاً في: SQL Editor ثم اضغط Run
-- 3.1: عمود تاريخ الميلاد (birth_date).
-- 3.4: البريد الإلكتروني (email) + تقييم الأداء لكل مسؤول إدخال لأعضائه فقط. (العمر يُحسب من تاريخ الميلاد ولا يُخزَّن.)
-- 3.5: تأكيد الاسم الحقيقي بالعربية عند أول دخول (profiles.name_confirmed_at).
-- 3.6: صفتان جديدتان (منسق / نائب منسق) واختيار محافظتهما من 27 محافظة.
-- 3.7: تقييم الأداء من 10 بأربعة معايير (التفاعل، تسليم المهام في الموعد، الجودة، حضور الاجتماعات).
-- 3.8: نموذج تسجيل ذاتي عام (بدون دخول) + طلبات تُراجَع وتُقبل أو تُرفض (جدول registrations).
-- 3.9: الطلبات تظهر للمسؤول ولأعضاء الفريق، ومن يوافق على طلب يصبح المسؤول عن بيانات العضو.
-- 3.21: لا تغيير في قاعدة البيانات (روابط الصور في Excel من الواجهة فقط)
-- 3.20: مساعد / مستشار / غير ذلك بلا لجنة (الصفة الكاملة فقط) فصار committee اختيارياً في registrations؛ حُذف «ممثل مكتب المشروعات» و«ممثل المكتب الفني» من الواجهة (تبقى مقبولة في القاعدة حفاظاً على بيانات قديمة)، وأُضيفت «وحدة التسويق المركزي».
-- 3.19: صفحة التقييمات ثلاثة أقسام: الأعضاء (كما هي) + المنسقون ونوابهم + المكتب التنفيذي (رؤساء اللجان المركزية)
--       جدولان جديدان للمسؤول فقط: eval_people (الأشخاص) وeval_reviews (التقييم الشهري، المعايير داخل jsonb فلا يلزم تعديل القاعدة عند تغييرها).
-- 3.18: لا تغيير في قاعدة البيانات (مرشّحات متعددة الاختيار في الواجهة فقط).
-- 3.17: ضغط الصور عند الرفع (≈100KB للشخصية و≈150KB للهوية) وخفض حد الـ bucket إلى 512KB.
-- 3.16: صفات جديدة (مساعد / مستشار / غير ذلك) مع عمود «الصفة كاملة» capacity_detail، وجهات إضافية للرئيس والنائب (رئيس الاتحاد، وحدة التحول الرقمي، لجنة الحوكمة، المجلس الرقابي، الأمين العام للمكتب الفني ونائبه). حذف الطلبات للمسؤول (الصلاحية موجودة).
-- 3.15: إسناد/نقل أعضاء موجودين إلى مسؤول بيانات (دالة assign_members).
-- 3.14: استيراد الأعضاء من Excel (دالة import_members): إضافة وتحديث بدون تكرار وتوزيع على الفريق.
-- 3.13: التنبيهات داخل الموقع (جدول notifications + دالة send_notification + محفّزات تلقائية). غير النشطين: واجهة فقط.
-- 3.12: لا تغيير في قاعدة البيانات (لوحة عضو الفريق في الواجهة فقط).
-- 3.11: رقم العضوية يكتبه العضو في نموذج التسجيل الذاتي (إلزامي للطلبات الجديدة)؛ لا تغيير آخر في الجداول.
-- 3.10: صفحة عامة «تقييمي»: العضو يدخل رقم العضوية ورقم البطاقة فيرى درجات تقييماته فقط (دالة my_evaluations).
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
alter table public.employees add column if not exists capacity_detail text;   -- [جديد 3.16] الصفة كاملة (لمساعد / مستشار / غير ذلك)
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

-- [جديد 3.7] تقييم من 10 بأربعة معايير. العمودان القديمان (من 5) يبقيان كما هما.
alter table public.performance add column if not exists interaction_score int check (interaction_score between 1 and 10);
alter table public.performance add column if not exists ontime_score      int check (ontime_score      between 1 and 10);
alter table public.performance add column if not exists quality_score     int check (quality_score     between 1 and 10);
alter table public.performance add column if not exists meetings_score    int check (meetings_score    between 1 and 10);

-- نقل تقييمات الجودة القديمة (من 5) إلى المقياس الجديد (من 10)؛ آمن للإعادة
update public.performance set quality_score = quality_rating * 2
 where quality_score is null and quality_rating is not null;

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
  -- [3.6] تُحذف وتُنشأ من جديد حتى تلتقط القيم الجديدة في القواعد القديمة
  alter table public.employees drop constraint if exists employees_capacity_chk;
  alter table public.employees add constraint employees_capacity_chk
    check (capacity is null or capacity in ('رئيس','نائب','منسق','نائب منسق','عضو','عضو مركزي','ممثل','مساعد','مستشار','غير ذلك')) not valid;
  -- اللجنة / جهة التمثيل
  -- (للمنسق ونائب المنسق تُخزَّن المحافظة هنا بصيغة «محافظة القاهرة»)
  alter table public.employees drop constraint if exists employees_committee_chk;
  alter table public.employees add constraint employees_committee_chk
    check (committee is null or committee in (
      'لجنة المكتب الإعلامي',
      'لجنة الموارد البشرية',
      'لجنة التنظيم والمراسم',
      'لجنة التدريب والتطوير',
      'لجنة العلاقات العامة والدولية',
      'لجنة الاستدامة والتحول الأخضر',
      'لجنة السياحة والثقافة',
      'وحدة التسويق المركزي',
      'لجنة التخطيط والمتابعة',
      'ممثل مكتب المشروعات',
      'ممثل المكتب الفني',
      'رئيس الاتحاد',
      'نائب رئيس الاتحاد',
      'وحدة التحول الرقمي',
      'لجنة الحوكمة',
      'المجلس الرقابي',
      'الأمين العام للمكتب الفني',
      'نائب الأمين العام للمكتب الفني',
      'محافظة القاهرة',
      'محافظة الجيزة',
      'محافظة الإسكندرية',
      'محافظة القليوبية',
      'محافظة الشرقية',
      'محافظة الدقهلية',
      'محافظة الغربية',
      'محافظة المنوفية',
      'محافظة البحيرة',
      'محافظة كفر الشيخ',
      'محافظة دمياط',
      'محافظة بورسعيد',
      'محافظة الإسماعيلية',
      'محافظة السويس',
      'محافظة شمال سيناء',
      'محافظة جنوب سيناء',
      'محافظة الفيوم',
      'محافظة بني سويف',
      'محافظة المنيا',
      'محافظة أسيوط',
      'محافظة سوهاج',
      'محافظة قنا',
      'محافظة الأقصر',
      'محافظة أسوان',
      'محافظة البحر الأحمر',
      'محافظة الوادي الجديد',
      'محافظة مطروح'
    )) not valid;
  -- المنسق ونائبه يختاران محافظة، وبقية الصفات تختار لجنة (لا خلط بين النوعين)
  alter table public.employees drop constraint if exists employees_cap_unit_chk;
  alter table public.employees add constraint employees_cap_unit_chk
    check (capacity is null or committee is null
           or ((capacity in ('منسق','نائب منسق')) = (committee like 'محافظة %'))) not valid;
  -- [3.16] الجهات الإضافية (رئيس الاتحاد، المجلس الرقابي…) للرئيس والنائب فقط
  alter table public.employees drop constraint if exists employees_lead_unit_chk;
  alter table public.employees add constraint employees_lead_unit_chk
    check (capacity is null or committee is null or committee not in ('رئيس الاتحاد','نائب رئيس الاتحاد','وحدة التحول الرقمي','لجنة الحوكمة','المجلس الرقابي','الأمين العام للمكتب الفني','نائب الأمين العام للمكتب الفني') or capacity in ('رئيس','نائب')) not valid;
  -- [3.16] الصفة كاملة: مطلوبة (حتى 100 حرف) لمساعد / مستشار / غير ذلك، ومحظورة لغيرها
  alter table public.employees drop constraint if exists employees_cap_detail_chk;
  alter table public.employees add constraint employees_cap_detail_chk
    check ((capacity in ('مساعد','مستشار','غير ذلك') and char_length(btrim(coalesce(capacity_detail, ''))) between 1 and 100)
           or ((capacity is null or capacity not in ('مساعد','مستشار','غير ذلك')) and capacity_detail is null)) not valid;
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
-- 9) تخزين الصور: buckets خاصة (غير عامة) بحد 512KB وصيغ صور فقط (الواجهة تضغط الصورة الشخصية إلى ≈100KB والهوية إلى ≈150KB)
-- ---------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
  ('photos', 'photos', false, 524288, array['image/jpeg','image/png','image/webp']),
  ('ids',    'ids',    false, 524288, array['image/jpeg','image/png','image/webp'])
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

-- ---------------------------------------------------------------------
-- 10) [جديد 3.8] التسجيل الذاتي: العضو يملأ بياناته بنفسه من رابط عام (#register)
--     • الطلبات تُحفظ في جدول منفصل (registrations) بحالة «قيد المراجعة».
--     • الزائر (anon) يستطيع الإدراج فقط: لا يقرأ ولا يعدّل ولا يحذف أي شيء.
--     • المسؤول وحده يراجع الطلب ثم يوافق (ينتقل إلى جدول الأعضاء) أو يرفض.
--     • حماية من الإساءة: تحقق كامل من القيم، حد 10 طلبات/ساعة لكل IP، وسقف عام 200 طلب/ساعة.
-- ---------------------------------------------------------------------
create table if not exists public.registrations (
  id                uuid primary key default gen_random_uuid(),
  membership_no     text,
  full_name         text not null,
  phone             text not null,
  email             text not null,
  national_id       text not null,
  birth_date        date not null,
  gender            text not null,
  governorate       text not null,
  union_governorate text not null,
  address           text not null,
  capacity          text not null,
  committee         text not null,
  study_status      text not null,
  edu_stage         text not null,
  institution       text not null,
  photo_path        text,
  id_doc_path       text,
  consent           boolean not null default false,
  status            text not null default 'pending' check (status in ('pending','approved','rejected')),
  submit_ip         text,
  reviewed_by       uuid references auth.users(id),
  reviewed_at       timestamptz,
  review_note       text,
  employee_id       uuid references public.employees(id) on delete set null,
  created_at        timestamptz not null default now()
);

alter table public.registrations add column if not exists capacity_detail text;   -- [جديد 3.16]
alter table public.registrations alter column committee drop not null;              -- [جديد 3.20] مساعد/مستشار/غير ذلك بلا لجنة

do $$
begin
  alter table public.registrations drop constraint if exists registrations_values_chk;
  alter table public.registrations add constraint registrations_values_chk check (
        char_length(full_name) <= 120 and full_name ~ '^[ء-ي]+( [ء-ي]+){2,}$'
    and phone ~ '^\+?[0-9]{8,15}$'
    and national_id ~ '^[0-9]{14}$'
    and char_length(email) <= 150 and email ~* '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]{2,}$'
    and gender in ('ذكر','أنثى')
    and governorate in ('القاهرة', 'الجيزة', 'الإسكندرية', 'القليوبية', 'الشرقية', 'الدقهلية', 'الغربية', 'المنوفية', 'البحيرة', 'كفر الشيخ', 'دمياط', 'بورسعيد', 'الإسماعيلية', 'السويس', 'شمال سيناء', 'جنوب سيناء', 'الفيوم', 'بني سويف', 'المنيا', 'أسيوط', 'سوهاج', 'قنا', 'الأقصر', 'أسوان', 'البحر الأحمر', 'الوادي الجديد', 'مطروح')
    and union_governorate in ('القاهرة', 'الجيزة', 'الإسكندرية', 'القليوبية', 'الشرقية', 'الدقهلية', 'الغربية', 'المنوفية', 'البحيرة', 'كفر الشيخ', 'دمياط', 'بورسعيد', 'الإسماعيلية', 'السويس', 'شمال سيناء', 'جنوب سيناء', 'الفيوم', 'بني سويف', 'المنيا', 'أسيوط', 'سوهاج', 'قنا', 'الأقصر', 'أسوان', 'البحر الأحمر', 'الوادي الجديد', 'مطروح')
    and char_length(address) between 1 and 300
    and capacity in ('رئيس','نائب','منسق','نائب منسق','عضو','عضو مركزي','ممثل','مساعد','مستشار','غير ذلك')
    and ((committee is not null and committee in ('لجنة المكتب الإعلامي', 'لجنة الموارد البشرية', 'لجنة التنظيم والمراسم', 'لجنة التدريب والتطوير', 'لجنة العلاقات العامة والدولية', 'لجنة الاستدامة والتحول الأخضر', 'لجنة السياحة والثقافة', 'لجنة التخطيط والمتابعة', 'وحدة التسويق المركزي', 'ممثل مكتب المشروعات', 'ممثل المكتب الفني', 'رئيس الاتحاد', 'نائب رئيس الاتحاد', 'وحدة التحول الرقمي', 'لجنة الحوكمة', 'المجلس الرقابي', 'الأمين العام للمكتب الفني', 'نائب الأمين العام للمكتب الفني', 'محافظة القاهرة', 'محافظة الجيزة', 'محافظة الإسكندرية', 'محافظة القليوبية', 'محافظة الشرقية', 'محافظة الدقهلية', 'محافظة الغربية', 'محافظة المنوفية', 'محافظة البحيرة', 'محافظة كفر الشيخ', 'محافظة دمياط', 'محافظة بورسعيد', 'محافظة الإسماعيلية', 'محافظة السويس', 'محافظة شمال سيناء', 'محافظة جنوب سيناء', 'محافظة الفيوم', 'محافظة بني سويف', 'محافظة المنيا', 'محافظة أسيوط', 'محافظة سوهاج', 'محافظة قنا', 'محافظة الأقصر', 'محافظة أسوان', 'محافظة البحر الأحمر', 'محافظة الوادي الجديد', 'محافظة مطروح')) or (committee is null and capacity in ('مساعد','مستشار','غير ذلك')))
    and ((capacity in ('منسق','نائب منسق')) = (committee like 'محافظة %'))
    and (committee not in ('رئيس الاتحاد','نائب رئيس الاتحاد','وحدة التحول الرقمي','لجنة الحوكمة','المجلس الرقابي','الأمين العام للمكتب الفني','نائب الأمين العام للمكتب الفني') or capacity in ('رئيس','نائب'))
    and ((capacity in ('مساعد','مستشار','غير ذلك') and char_length(btrim(coalesce(capacity_detail, ''))) between 1 and 100) or (capacity not in ('مساعد','مستشار','غير ذلك') and capacity_detail is null))
    and study_status in ('طالب','خريج')
    and edu_stage in ('إعدادي','ثانوي','دبلوم / معهد','جامعي','دراسات عليا','دكتوراه')
    and char_length(institution) between 1 and 150
    and coalesce(char_length(membership_no), 0) <= 40
    and coalesce(char_length(review_note), 0) <= 500
    and (photo_path  is null or photo_path  ~ '^reg/[0-9a-f-]{36}\.jpg$')
    and (id_doc_path is null or id_doc_path ~ '^reg/[0-9a-f-]{36}\.jpg$')
  );
end $$;

-- قبل كل إدراج: يفرض الحالة الأولى، يتحقق من تاريخ الميلاد، ويطبّق حد المعدل
create or replace function public.registrations_before_insert()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  hdr json; ip text; n int;
begin
  begin hdr := nullif(current_setting('request.headers', true), '')::json; exception when others then hdr := null; end;
  ip := nullif(trim(split_part(coalesce(hdr->>'cf-connecting-ip', hdr->>'x-forwarded-for', ''), ',', 1)), '');

  new.status := 'pending'; new.reviewed_by := null; new.reviewed_at := null;
  new.review_note := null; new.employee_id := null; new.created_at := now();
  new.submit_ip := ip;
  new.email := lower(trim(new.email));
  new.full_name := regexp_replace(trim(new.full_name), '\s+', ' ', 'g');
  new.capacity_detail := nullif(regexp_replace(trim(coalesce(new.capacity_detail, '')), '\s+', ' ', 'g'), '');
  new.membership_no := nullif(trim(coalesce(new.membership_no, '')), '');
  if new.membership_no is null then raise exception 'رقم العضوية مطلوب'; end if;   -- [3.11] يكتبه العضو بنفسه

  if new.birth_date < date '1900-01-01' or new.birth_date > current_date then
    raise exception 'تاريخ الميلاد غير صالح';
  end if;

  if not public.is_admin() then
    if ip is not null then
      select count(*) into n from public.registrations where submit_ip = ip and created_at > now() - interval '1 hour';
      if n >= 10 then raise exception 'تم تجاوز عدد المحاولات المسموح بها. حاول بعد ساعة.'; end if;
    end if;
    select count(*) into n from public.registrations where created_at > now() - interval '1 hour';
    if n >= 200 then raise exception 'النظام مشغول الآن، حاول لاحقاً.'; end if;
  end if;
  return new;
end;
$$;

drop trigger if exists registrations_guard on public.registrations;
create trigger registrations_guard
  before insert on public.registrations
  for each row execute function public.registrations_before_insert();

alter table public.registrations enable row level security;

-- أي زائر: إدراج فقط، وبشرط الإقرار بالموافقة
drop policy if exists "registrations_public_insert" on public.registrations;
create policy "registrations_public_insert" on public.registrations
  for insert to anon, authenticated
  with check (consent = true);

-- المسؤول: كل شيء (مراجعة، رفض، حذف)
drop policy if exists "registrations_admin_all" on public.registrations;
create policy "registrations_admin_all" on public.registrations
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- [3.9] عضو الفريق يرى الطلبات «قيد المراجعة» (ليوافق عليها) والطلبات التي وافق عليها هو.
--       لا يعدّل ولا يحذف ولا يرفض: الموافقة تتم عبر الدالة approve_registration فقط، والرفض للمسؤول.
drop policy if exists "registrations_member_select" on public.registrations;
create policy "registrations_member_select" on public.registrations
  for select to authenticated
  using (status = 'pending' or reviewed_by = auth.uid());

revoke all on public.registrations from anon, authenticated;
grant insert on public.registrations to anon;
-- القراءة بأعمدة محددة: عمود submit_ip (عنوان IP) لا يقرؤه أحد، يستخدمه الحد الأقصى للمعدل فقط
grant select (id, membership_no, full_name, phone, email, national_id, birth_date, gender, governorate, union_governorate,
              address, capacity, capacity_detail, committee, study_status, edu_stage, institution, photo_path, id_doc_path, consent,
              status, reviewed_by, reviewed_at, review_note, employee_id, created_at)
  on public.registrations to authenticated;
grant insert, update, delete on public.registrations to authenticated;

-- سجل الوصول يشمل فتح صورة هوية داخل طلب تسجيل لم يُعتمد بعد
alter table public.access_log add column if not exists registration_id uuid references public.registrations(id) on delete set null;

create index if not exists registrations_status_idx on public.registrations (status, created_at desc);
create index if not exists registrations_ip_idx     on public.registrations (submit_ip, created_at desc);
-- لا يُقبل أكثر من طلب «قيد المراجعة» لنفس رقم البطاقة (يمنع تكرار الإرسال)
create unique index if not exists registrations_pending_nid on public.registrations (national_id) where status = 'pending';

-- الموافقة: تنقل الطلب إلى جدول الأعضاء وتُغلقه. [3.9] يستطيع أي حساب في الفريق أن يوافق، ومن يوافق يصبح
-- المسؤول عن بيانات العضو (created_by). المسؤول وحده يستطيع تعيين عضو آخر من الفريق مسؤولاً (p_owner).
drop function if exists public.approve_registration(uuid, text);
create or replace function public.approve_registration(p_id uuid, p_membership_no text default null, p_owner uuid default null)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  r public.registrations;
  mno text;
  new_id uuid;
  owner_id uuid;
begin
  if auth.uid() is null or not exists (select 1 from public.profiles where id = auth.uid()) then
    raise exception 'ليست لديك صلاحية لهذه العملية';
  end if;
  owner_id := coalesce(p_owner, auth.uid());
  if owner_id <> auth.uid() then
    if not public.is_admin() then raise exception 'ليست لديك صلاحية لهذه العملية'; end if;
    if not exists (select 1 from public.profiles where id = owner_id) then raise exception 'المسؤول المختار غير موجود'; end if;
  end if;
  select * into r from public.registrations where id = p_id for update;
  if not found then raise exception 'الطلب غير موجود'; end if;
  if r.status <> 'pending' then raise exception 'تمت مراجعة هذا الطلب مسبقاً'; end if;
  if exists (select 1 from public.employees where national_id = r.national_id) then
    raise exception 'رقم البطاقة مسجَّل مسبقاً في سجل الأعضاء';
  end if;
  mno := nullif(trim(coalesce(p_membership_no, r.membership_no, '')), '');
  if mno is not null and exists (select 1 from public.employees where membership_no = mno) then
    raise exception 'رقم العضوية مستخدم مسبقاً';
  end if;

  insert into public.employees
    (membership_no, full_name, phone, email, national_id, birth_date, gender, governorate, union_governorate,
     address, capacity, capacity_detail, committee, study_status, edu_stage, institution, photo_path, id_doc_path, consent, status, created_by)
  values
    (mno, r.full_name, r.phone, r.email, r.national_id, r.birth_date, r.gender, r.governorate, r.union_governorate,
     r.address, r.capacity, r.capacity_detail, r.committee, r.study_status, r.edu_stage, r.institution, r.photo_path, r.id_doc_path, true, 'active', owner_id)
  returning id into new_id;

  update public.registrations
     set status = 'approved', reviewed_by = auth.uid(), reviewed_at = now(), employee_id = new_id, membership_no = mno
   where id = p_id;
  return new_id;
end;
$$;
revoke all on function public.approve_registration(uuid, text, uuid) from public, anon;
grant execute on function public.approve_registration(uuid, text, uuid) to authenticated;

-- [3.9] قراءة ملفات reg/ لأعضاء الفريق: صور الطلبات «قيد المراجعة» (للمراجعة قبل الموافقة)،
-- وصور الأعضاء الذين صاروا تحت مسؤوليتهم بعد الموافقة. غير ذلك لا يقرؤه إلا المسؤول.
drop policy if exists "hr_files_select_reg" on storage.objects;
create policy "hr_files_select_reg" on storage.objects
  for select to authenticated
  using (
    bucket_id in ('photos','ids')
    and name like 'reg/%'
    and (
      exists (select 1 from public.registrations r
              where r.status = 'pending' and (r.photo_path = name or r.id_doc_path = name))
      or exists (select 1 from public.employees e
                 where e.created_by = auth.uid() and (e.photo_path = name or e.id_doc_path = name))
    )
  );

-- رفع الصور من النموذج العام: إدراج فقط داخل المجلد reg/ وباسم UUID وصيغة jpg (يضغطها المتصفح).
-- لا قراءة ولا تعديل ولا حذف للزائر. الحد 512KB وصيغ الصور مفروضان على الـ bucket نفسه.
drop policy if exists "hr_files_public_insert" on storage.objects;
create policy "hr_files_public_insert" on storage.objects
  for insert to anon, authenticated
  with check (
    bucket_id in ('photos','ids')
    and name ~ '^reg/[0-9a-f-]{36}\.jpg$'
  );


-- ---------------------------------------------------------------------
-- 11) [جديد 3.10] «تقييمي»: العضو يرى درجات تقييماته بدون حساب
--     • الاستعلام عبر دالة واحدة فقط (my_evaluations)، ولا يستطيع الزائر قراءة أي جدول.
--     • يتطلب رقم العضوية + رقم البطاقة معاً (رقم العضوية وحده قابل للتخمين).
--     • تعيد الدرجات والأشهر فقط: لا ملاحظات المقيِّم ولا اسمه ولا أي بيانات أخرى.
--     • حدود: 10 محاولات خاطئة/15 دقيقة لكل IP، و8 لكل رقم عضوية، و200 عالمياً.
-- ---------------------------------------------------------------------
create table if not exists public.lookup_attempts (
  id            bigint generated always as identity primary key,
  ip            text,
  membership_no text,
  at            timestamptz not null default now()
);
alter table public.lookup_attempts enable row level security;
revoke all on public.lookup_attempts from anon, authenticated;
create index if not exists lookup_attempts_at_idx on public.lookup_attempts (at);

create or replace function public.my_evaluations(p_membership_no text, p_national_id text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  hdr json; v_ip text; mno text; nid text; n int; e public.employees; res jsonb;
begin
  begin hdr := nullif(current_setting('request.headers', true), '')::json; exception when others then hdr := null; end;
  v_ip := nullif(trim(split_part(coalesce(hdr->>'cf-connecting-ip', hdr->>'x-forwarded-for', ''), ',', 1)), '');
  mno := left(trim(coalesce(p_membership_no, '')), 40);
  nid := trim(coalesce(p_national_id, ''));

  delete from public.lookup_attempts where at < now() - interval '1 day';

  -- الحدود تُرجع نتيجة بدل رفع استثناء، حتى يُحفظ سجل المحاولات
  if v_ip is not null then
    select count(*) into n from public.lookup_attempts where ip = v_ip and at > now() - interval '15 minutes';
    if n >= 10 then return jsonb_build_object('ok', false, 'error', 'too_many'); end if;
  end if;
  select count(*) into n from public.lookup_attempts where membership_no = mno and at > now() - interval '15 minutes';
  if n >= 8 then return jsonb_build_object('ok', false, 'error', 'too_many'); end if;
  select count(*) into n from public.lookup_attempts where at > now() - interval '15 minutes';
  if n >= 200 then return jsonb_build_object('ok', false, 'error', 'too_many'); end if;

  select * into e from public.employees where membership_no = mno and national_id = nid and mno <> '' limit 1;
  if not found then
    insert into public.lookup_attempts (ip, membership_no) values (v_ip, mno);
    return jsonb_build_object('ok', false, 'error', 'not_found');   -- نفس الرد لخطأ الرقم أو خطأ البطاقة
  end if;

  select jsonb_build_object(
           'ok', true,
           'name', e.full_name,
           'membership_no', e.membership_no,
           'rows', coalesce((
             select jsonb_agg(jsonb_build_object(
                      'month', p.month, 'interaction', p.interaction_score, 'ontime', p.ontime_score,
                      'quality', p.quality_score, 'meetings', p.meetings_score) order by p.month desc)
               from public.performance p
              where p.employee_id = e.id
                and coalesce(p.interaction_score, p.ontime_score, p.quality_score, p.meetings_score) is not null
           ), '[]'::jsonb))
    into res;
  return res;
end;
$$;
revoke all on function public.my_evaluations(text, text) from public;
grant execute on function public.my_evaluations(text, text) to anon, authenticated;

-- =====================================================================
-- 12) [جديد 3.13] التنبيهات داخل الموقع (جرس في الأعلى)
--     • كل مستخدم يقرأ تنبيهاته هو فقط ويعلّمها «مقروءة» أو يحذفها. لا أحد يُدرج مباشرةً في الجدول.
--     • الإدراج عبر: دالة send_notification (للمسؤول فقط: للجميع أو لشخص بعينه)،
--       ومحفّزات تلقائية: طلب تسجيل جديد (للجميع)، إسناد مهمة / إعادة فتحها (للمكلَّف)، تسليم مهمة (للمسؤولين).
-- =====================================================================
create table if not exists public.notifications (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references public.profiles(id) on delete cascade,
  kind       text not null default 'info' check (kind in ('info','task','request')),
  title      text not null check (char_length(title) between 1 and 120),
  body       text check (body is null or char_length(body) <= 600),
  link       text check (link is null or link in ('dashboard','registrations','employees','tasks','engagement','performance')),
  n          int  not null default 1,
  created_by uuid references auth.users(id) on delete set null default auth.uid(),
  read_at    timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists notifications_user_idx on public.notifications (user_id, created_at desc);

alter table public.notifications enable row level security;

drop policy if exists "notifications_select_own" on public.notifications;
create policy "notifications_select_own" on public.notifications
  for select to authenticated using (user_id = auth.uid());
drop policy if exists "notifications_update_own" on public.notifications;
create policy "notifications_update_own" on public.notifications
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists "notifications_delete_own" on public.notifications;
create policy "notifications_delete_own" on public.notifications
  for delete to authenticated using (user_id = auth.uid());

revoke all on public.notifications from anon, authenticated;
grant select on public.notifications to authenticated;
grant update (read_at) on public.notifications to authenticated;    -- لا يمكن تعديل نص التنبيه، فقط تعليمه مقروءاً
grant delete on public.notifications to authenticated;

-- إرسال تنبيه يدوي (مسؤول فقط). p_to = null يعني: كل أعضاء الفريق عدا المرسِل. يرجع عدد المستلمين.
create or replace function public.send_notification(p_to uuid, p_title text, p_body text default null, p_link text default null)
returns int
language plpgsql
security definer
set search_path = public
as $$
declare n int;
begin
  if auth.uid() is null or not public.is_admin() then raise exception 'ليست لديك صلاحية لهذه العملية'; end if;
  p_title := trim(coalesce(p_title, '')); p_body := nullif(trim(coalesce(p_body, '')), ''); p_link := nullif(trim(coalesce(p_link, '')), '');
  if p_title = '' or char_length(p_title) > 120 then raise exception 'عنوان التنبيه مطلوب (حتى 120 حرفاً)'; end if;
  if p_body is not null and char_length(p_body) > 600 then raise exception 'نص التنبيه طويل (الحد 600 حرف)'; end if;
  if p_to is not null and not exists (select 1 from public.profiles where id = p_to) then raise exception 'المستلم غير موجود'; end if;
  delete from public.notifications where created_at < now() - interval '90 days';
  insert into public.notifications (user_id, kind, title, body, link)
  select id, 'info', p_title, p_body, p_link from public.profiles
   where (p_to is null and id <> auth.uid()) or id = p_to;
  get diagnostics n = row_count;
  return n;
end;
$$;
revoke all on function public.send_notification(uuid, text, text, text) from public, anon;
grant execute on function public.send_notification(uuid, text, text, text) to authenticated;

-- طلب تسجيل جديد → تنبيه لكل الفريق (تنبيه واحد غير مقروء يتجمّع: «N طلبات جديدة»)
create or replace function public.notify_new_registration()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.notifications where created_at < now() - interval '90 days';
  update public.notifications set n = n + 1, body = new.full_name, created_at = now()
   where kind = 'request' and link = 'registrations' and read_at is null;
  insert into public.notifications (user_id, kind, title, body, link, created_by)
  select p.id, 'request', 'طلب تسجيل جديد', new.full_name, 'registrations', null
    from public.profiles p
   where not exists (select 1 from public.notifications x
                      where x.user_id = p.id and x.kind = 'request' and x.link = 'registrations' and x.read_at is null);
  return null;
end;
$$;
drop trigger if exists registrations_notify on public.registrations;
create trigger registrations_notify
  after insert on public.registrations
  for each row execute function public.notify_new_registration();

-- المهام: إسناد جديد أو تغيير المكلَّف أو إعادة فتح → للمكلَّف. التسليم → للمسؤولين.
create or replace function public.notify_task()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if tg_op = 'INSERT' then
    if new.assigned_to is distinct from auth.uid() then
      insert into public.notifications (user_id, kind, title, body, link)
      values (new.assigned_to, 'task', 'مهمة جديدة لك', new.title, 'tasks');
    end if;
  else
    if new.assigned_to is distinct from old.assigned_to then
      if new.assigned_to is distinct from auth.uid() then
        insert into public.notifications (user_id, kind, title, body, link)
        values (new.assigned_to, 'task', 'مهمة جديدة لك', new.title, 'tasks');
      end if;
    elsif old.status = 'delivered' and new.status = 'pending' then
      if new.assigned_to is distinct from auth.uid() then
        insert into public.notifications (user_id, kind, title, body, link)
        values (new.assigned_to, 'task', 'أُعيد فتح مهمة', new.title, 'tasks');
      end if;
    elsif old.status = 'pending' and new.status = 'delivered' then
      insert into public.notifications (user_id, kind, title, body, link)
      select p.id, 'task', 'سُلّمت مهمة', new.title || ' — ' || coalesce((select full_name from public.profiles where id = new.assigned_to), ''), 'tasks'
        from public.profiles p where p.role = 'admin' and p.id is distinct from auth.uid();
    end if;
  end if;
  return null;
end;
$$;
drop trigger if exists tasks_notify on public.tasks;
create trigger tasks_notify
  after insert or update on public.tasks
  for each row execute function public.notify_task();

-- =====================================================================
-- 13) [جديد 3.14] استيراد الأعضاء من Excel: إضافة الجدد وتحديث الموجودين بدون تكرار
--     • المطابقة برقم البطاقة أولاً ثم رقم العضوية. الخلية الفارغة لا تمسح بيانات موجودة.
--     • عضو الفريق يضيف ويحدّث أعضاءه هو فقط. المسؤول يوزّع الأعضاء على أي عضو في الفريق.
--     • p_dry = true: معاينة بنفس المنطق تماماً (يُنفَّذ كل صف ثم يُتراجع عنه) بلا أي تغيير فعلي.
--     • لا صور ولا هويات: الملف بيانات نصية فقط (تُرفع الصور من نموذج العضو).
-- =====================================================================
create or replace function public.import_members(
  p_rows jsonb, p_owner uuid default null, p_mode text default 'upsert',
  p_reassign boolean default false, p_dry boolean default false)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  uid uuid := auth.uid();
  adm boolean;
  res jsonb := '[]'::jsonb;
  cnt jsonb := '{}'::jsonb;
  r jsonb; k record;
  idx int; o uuid; nid text; mno text;
  e_n public.employees; e_m public.employees; e public.employees;
  f_n boolean; f_m boolean;
  act text; msg text; eid uuid; cname text; moved boolean;
begin
  if uid is null or not exists (select 1 from public.profiles where id = uid) then
    raise exception 'ليست لديك صلاحية لهذه العملية';
  end if;
  adm := public.is_admin();
  if p_mode not in ('upsert', 'new_only', 'update_only') then raise exception 'وضع الاستيراد غير معروف'; end if;
  if p_rows is null or jsonb_typeof(p_rows) <> 'array' then raise exception 'بيانات غير صالحة'; end if;
  if jsonb_array_length(p_rows) > 300 then raise exception 'الحد الأقصى 300 صف في الدفعة الواحدة'; end if;
  if p_owner is not null and p_owner <> uid then
    if not adm then raise exception 'ليست لديك صلاحية لهذه العملية'; end if;
    if not exists (select 1 from public.profiles where id = p_owner) then raise exception 'المسؤول المختار غير موجود'; end if;
  end if;

  for r in select value from jsonb_array_elements(p_rows) loop
    idx := coalesce((r->>'i')::int, 0); act := null; msg := null; eid := null; moved := false;
    begin
      nid := nullif(trim(coalesce(r->>'national_id', '')), '');
      mno := nullif(trim(coalesce(r->>'membership_no', '')), '');
      o := coalesce(p_owner, uid);
      if adm and nullif(r->>'owner', '') is not null then
        o := (r->>'owner')::uuid;
        if not exists (select 1 from public.profiles where id = o) then raise exception 'المسؤول المحدّد للصف غير موجود'; end if;
      end if;

      f_n := false; f_m := false;
      if nid is not null then select * into e_n from public.employees where national_id = nid; f_n := found; end if;
      if mno is not null then select * into e_m from public.employees where membership_no = mno; f_m := found; end if;

      if f_n and f_m and e_n.id <> e_m.id then
        act := 'error'; msg := 'رقم البطاقة ورقم العضوية يخصّان عضوين مختلفين في السجل';
      elsif f_n or f_m then
        e := case when f_n then e_n else e_m end;
        if p_mode = 'new_only' then
          act := 'skip'; msg := 'موجود مسبقاً (تم التخطّي)';
        elsif not adm and e.created_by <> uid then
          act := 'denied'; msg := 'مسجَّل لدى مسؤول آخر ولا يمكنك تحديثه';
        else
          update public.employees set
            membership_no     = coalesce(mno, membership_no),
            national_id       = coalesce(nid, national_id),
            full_name         = coalesce(nullif(trim(r->>'full_name'), ''), full_name),
            phone             = coalesce(nullif(trim(r->>'phone'), ''), phone),
            email             = coalesce(nullif(lower(trim(r->>'email')), ''), email),
            birth_date        = coalesce(nullif(trim(r->>'birth_date'), '')::date, birth_date),
            gender            = coalesce(nullif(trim(r->>'gender'), ''), gender),
            governorate       = coalesce(nullif(trim(r->>'governorate'), ''), governorate),
            union_governorate = coalesce(nullif(trim(r->>'union_governorate'), ''), union_governorate),
            address           = coalesce(nullif(trim(r->>'address'), ''), address),
            capacity          = coalesce(nullif(trim(r->>'capacity'), ''), capacity),
            capacity_detail   = case
              when nullif(trim(r->>'capacity'), '') is not null then
                case when trim(r->>'capacity') in ('مساعد','مستشار','غير ذلك')
                     then coalesce(nullif(trim(r->>'capacity_detail'), ''), case when capacity = trim(r->>'capacity') then capacity_detail end)
                     else null end
              else coalesce(nullif(trim(r->>'capacity_detail'), ''), capacity_detail) end,
            committee         = case when trim(r->>'capacity') in ('مساعد','مستشار','غير ذلك') then null
                                     else coalesce(nullif(trim(r->>'committee'), ''), committee) end,
            study_status      = coalesce(nullif(trim(r->>'study_status'), ''), study_status),
            edu_stage         = coalesce(nullif(trim(r->>'edu_stage'), ''), edu_stage),
            institution       = coalesce(nullif(trim(r->>'institution'), ''), institution),
            status            = coalesce(nullif(trim(r->>'status'), ''), status),
            created_by        = case when adm and p_reassign then o else created_by end
          where id = e.id;
          act := 'update'; eid := e.id; moved := adm and p_reassign and e.created_by <> o;
        end if;
      else
        if p_mode = 'update_only' then
          act := 'skip'; msg := 'غير موجود في السجل (تم التخطّي)';
        elsif nid is null or mno is null or nullif(trim(coalesce(r->>'full_name', '')), '') is null then
          act := 'error'; msg := 'الاسم ورقم البطاقة ورقم العضوية مطلوبة للعضو الجديد';
        else
          insert into public.employees
            (membership_no, national_id, full_name, phone, email, birth_date, gender, governorate, union_governorate,
             address, capacity, capacity_detail, committee, study_status, edu_stage, institution, status, created_by)
          values
            (mno, nid, trim(r->>'full_name'), nullif(trim(r->>'phone'), ''), nullif(lower(trim(r->>'email')), ''),
             nullif(trim(r->>'birth_date'), '')::date, nullif(trim(r->>'gender'), ''), nullif(trim(r->>'governorate'), ''),
             nullif(trim(r->>'union_governorate'), ''), nullif(trim(r->>'address'), ''), nullif(trim(r->>'capacity'), ''),
             case when trim(r->>'capacity') in ('مساعد','مستشار','غير ذلك') then nullif(trim(r->>'capacity_detail'), '') end,
             case when trim(r->>'capacity') in ('مساعد','مستشار','غير ذلك') then null else nullif(trim(r->>'committee'), '') end, nullif(trim(r->>'study_status'), ''), nullif(trim(r->>'edu_stage'), ''),
             nullif(trim(r->>'institution'), ''), coalesce(nullif(trim(r->>'status'), ''), 'active'), o)
          returning id into eid;
          act := 'insert'; moved := true;
        end if;
      end if;

      if p_dry and act in ('insert', 'update') then raise exception '__dry__'; end if;
      if moved and o <> uid then cnt := jsonb_set(cnt, array[o::text], to_jsonb(coalesce((cnt->>o::text)::int, 0) + 1)); end if;
    exception when others then
      if sqlerrm = '__dry__' then
        null;                                    -- معاينة: المتغيرات تبقى والتغيير في القاعدة يُتراجع عنه
      else
        get stacked diagnostics cname = constraint_name;
        act := 'error'; eid := null;
        msg := case
          when sqlstate = '23505' then 'رقم البطاقة أو رقم العضوية مستخدم لعضو آخر'
          when cname = 'employees_cap_detail_chk' then 'اكتب «الصفة كاملة» لمساعد / مستشار / غير ذلك (حتى 100 حرف)'
          when cname = 'employees_lead_unit_chk' then 'هذه الجهة متاحة للرئيس والنائب فقط'
          when cname = 'employees_cap_unit_chk' then 'الصفة لا تتوافق مع اللجنة (المنسق ونائبه يختاران محافظة، وغيرهما لجنة)'
          when sqlstate = '23514' then 'قيمة غير مسموحة في أحد الحقول (' || coalesce(cname, '') || ')'
          when sqlstate in ('22P02', '22007', '22008') then 'صيغة تاريخ أو قيمة غير صالحة'
          else sqlerrm end;
      end if;
    end;
    res := res || jsonb_build_object('i', idx, 'a', act, 'm', msg, 'id', eid);
  end loop;

  -- إشعار كل مسؤول أُسندت إليه سجلات جديدة (غير المرسِل)
  if not p_dry then
    for k in select key, value from jsonb_each_text(cnt) loop
      insert into public.notifications (user_id, kind, title, body, link)
      values (k.key::uuid, 'info', 'أعضاء أُسندوا إليك', 'أُسند إليك ' || k.value || ' ' || case when k.value::int = 1 then 'عضو' else 'أعضاء' end || ' من ملف Excel', 'employees');
    end loop;
  end if;
  return res;
end;
$$;
revoke all on function public.import_members(jsonb, uuid, text, boolean, boolean) from public, anon;
grant execute on function public.import_members(jsonb, uuid, text, boolean, boolean) to authenticated;

-- =====================================================================
-- 14) [جديد 3.15] إسناد/نقل أعضاء موجودين إلى مسؤول بيانات (للمسؤول فقط)
--     يغيّر «المسؤول عن بيانات العضو» (created_by) لمجموعة أعضاء، ويُنبّه المستلم بعدد من أُسند إليه.
-- =====================================================================
create or replace function public.assign_members(p_ids uuid[], p_owner uuid)
returns int
language plpgsql
security definer
set search_path = public
as $$
declare n int;
begin
  if auth.uid() is null or not public.is_admin() then raise exception 'ليست لديك صلاحية لهذه العملية'; end if;
  if p_ids is null or coalesce(array_length(p_ids, 1), 0) = 0 then return 0; end if;
  if array_length(p_ids, 1) > 1000 then raise exception 'الحد الأقصى 1000 عضو في المرة الواحدة'; end if;
  if p_owner is null or not exists (select 1 from public.profiles where id = p_owner) then raise exception 'المسؤول المختار غير موجود'; end if;
  update public.employees set created_by = p_owner where id = any (p_ids) and created_by is distinct from p_owner;
  get diagnostics n = row_count;
  if n > 0 and p_owner <> auth.uid() then
    insert into public.notifications (user_id, kind, title, body, link)
    values (p_owner, 'info', 'أعضاء أُسندوا إليك', 'أُسند إليك ' || n || ' ' || case when n = 1 then 'عضو' else 'أعضاء' end, 'employees');
  end if;
  return n;
end;
$$;
revoke all on function public.assign_members(uuid[], uuid) from public, anon;
grant execute on function public.assign_members(uuid[], uuid) to authenticated;

-- ---------------------------------------------------------------------
-- 15) [3.19] تقييم المنسقين ونوابهم والمكتب التنفيذي (للمسؤول فقط)
--     eval_people  : الأشخاص الذين يضيفهم المسؤول في كل قسم (kind = coord | exec)
--     eval_reviews : تقييم شهري لكل شخص. الدرجات في scores (jsonb) والأرقام في metrics (jsonb)،
--                    فتغيير المعايير لاحقاً يتم من الواجهة فقط ولا يحتاج تعديلاً هنا.
--     أقسام الأعضاء تبقى في جدول performance كما هي دون أي تغيير.
-- ---------------------------------------------------------------------
create table if not exists public.eval_people (
  id          uuid primary key default gen_random_uuid(),
  kind        text not null check (kind in ('coord', 'exec')),
  full_name   text not null check (char_length(btrim(full_name)) between 2 and 120),
  title       text check (title is null or char_length(title) <= 80),
  scope       text check (scope is null or char_length(scope) <= 120),
  employee_id uuid references public.employees(id) on delete set null,
  active      boolean not null default true,
  notes       text check (notes is null or char_length(notes) <= 1000),
  created_by  uuid default auth.uid() references auth.users(id),
  created_at  timestamptz not null default now()
);
create index if not exists eval_people_kind_idx on public.eval_people (kind, active);
create unique index if not exists eval_people_emp_uq on public.eval_people (kind, employee_id) where employee_id is not null;

create or replace function public.eval_scores_ok(j jsonb) returns boolean
language sql immutable as $$
  select jsonb_typeof(j) = 'object' and not exists (
    select 1 from jsonb_each(j) e
    where jsonb_typeof(e.value) <> 'number' or (e.value #>> '{}')::numeric not between 1 and 10);
$$;
create or replace function public.eval_metrics_ok(j jsonb) returns boolean
language sql immutable as $$
  select jsonb_typeof(j) = 'object' and not exists (
    select 1 from jsonb_each(j) e
    where jsonb_typeof(e.value) <> 'number' or (e.value #>> '{}')::numeric not between 0 and 1000000);
$$;

create table if not exists public.eval_reviews (
  id         uuid primary key default gen_random_uuid(),
  person_id  uuid not null references public.eval_people(id) on delete cascade,
  month      date not null check (extract(day from month) = 1),
  scores     jsonb not null default '{}'::jsonb check (public.eval_scores_ok(scores)),
  metrics    jsonb not null default '{}'::jsonb check (public.eval_metrics_ok(metrics)),
  executed   text check (executed is null or char_length(executed) <= 4000),
  notes      text check (notes is null or char_length(notes) <= 2000),
  created_by uuid default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  unique (person_id, month)
);
create index if not exists eval_reviews_month_idx on public.eval_reviews (month);

alter table public.eval_people  enable row level security;
alter table public.eval_reviews enable row level security;

drop policy if exists "eval_people_admin_all" on public.eval_people;
create policy "eval_people_admin_all" on public.eval_people
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "eval_reviews_admin_all" on public.eval_reviews;
create policy "eval_reviews_admin_all" on public.eval_reviews
  for all to authenticated using (public.is_admin()) with check (public.is_admin());

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
