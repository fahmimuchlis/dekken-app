-- =====================================================================
-- Dekken: RUANG ESCAPE. Jalankan SETELAH ruang.sql, ruang-taut.sql, purge.sql dan gambar-link.sql. Aman dijalankan ulang.
-- Siapa pun yang login bisa membuat satu ruang escape, mengunci dengan kode, dan membagikan kode itu.
-- Di ruang escape: pembuat hanya boleh memasang kartu timer; anggota hanya boleh membalas.
-- Dosen melihat dan menutup semuanya; menutup ruang escape menghapus ruang dan kartunya (salinan masuk arsip).
-- Kartu di ruang terkunci hanya terbaca oleh pembuat, anggota, dan dosen (diatur di server lewat RLS).
-- =====================================================================

alter table public.ruang add column if not exists jenis text not null default 'biasa';
alter table public.ruang add column if not exists terkunci boolean not null default false;
alter table public.ruang drop constraint if exists ruang_jenis_cek;
alter table public.ruang add constraint ruang_jenis_cek check (jenis in ('biasa', 'escape'));

-- data rahasia (tidak bisa dibaca klien; hanya lewat fungsi di bawah)
create table if not exists public.ruang_rahasia (
  ruang_id text primary key references public.ruang (id) on delete cascade,
  pemilik  uuid not null,
  kode     text not null
);
create unique index if not exists ruang_rahasia_pemilik_uniq on public.ruang_rahasia (pemilik);

create table if not exists public.ruang_anggota (
  ruang_id text not null references public.ruang (id) on delete cascade,
  uid      uuid not null,
  nama     text not null default '',
  masuk    timestamptz not null default now(),
  primary key (ruang_id, uid)
);

create table if not exists public.ruang_coba (
  uid     uuid primary key,
  salah   int not null default 0,
  terakhir timestamptz not null default now()
);

alter table public.ruang_rahasia enable row level security;
alter table public.ruang_anggota enable row level security;
alter table public.ruang_coba enable row level security;
revoke all on public.ruang_rahasia, public.ruang_anggota, public.ruang_coba from anon, authenticated;

-- ---------- Siapa boleh melihat isi ruang ini? ----------
create or replace function public.ruang_boleh(p_id text) returns boolean
language sql stable security definer set search_path = public as $$
  select case when p_id is null then true else coalesce((
    select (r.jenis <> 'escape' or not r.terkunci
            or exists (select 1 from ruang_rahasia s where s.ruang_id = r.id and s.pemilik = auth.uid())
            or exists (select 1 from ruang_anggota a where a.ruang_id = r.id and a.uid = auth.uid())
            or coalesce(public.adalah_dosen(auth.jwt() ->> 'email'), false))
    from ruang r where r.id = p_id), true) end
$$;
grant execute on function public.ruang_boleh(text) to anon, authenticated;

-- ---------- Aturan baca kartu: kartu di ruang terkunci hanya untuk yang berhak ----------
drop policy if exists posts_baca on public.posts;
create policy posts_baca on public.posts for select to anon, authenticated
  using (((habis is null) or (habis > kini_ms())) and public.ruang_boleh(ruang_id));

-- ---------- Penjaga tulis: berlaku untuk semua jalur (kirim, polling, dst.) ----------
create or replace function public.escape_jaga() returns trigger
language plpgsql security definer set search_path = public as $$
declare r public.ruang; s uuid;
begin
  if new.ruang_id is null then return new; end if;
  select * into r from ruang where id = new.ruang_id;
  if not found or r.jenis <> 'escape' then return new; end if;
  if coalesce(public.adalah_dosen(auth.jwt() ->> 'email'), false) then return new; end if;
  if not public.ruang_boleh(r.id) then raise exception 'Ruang escape ini terkunci. Masukkan kode untuk bergabung.'; end if;
  if new.parent_id is null then
    select pemilik into s from ruang_rahasia where ruang_id = r.id;
    if s is distinct from auth.uid() then raise exception 'Di ruang escape, kartu baru hanya bisa dipasang oleh pembuat ruang. Kamu bisa membalas.'; end if;
    if new.bentuk <> 'waktu' or new.polling is not null then raise exception 'Pembuat ruang escape hanya bisa memakai kartu timer.'; end if;
  end if;
  return new;
end $$;
drop trigger if exists posts_escape_jaga on public.posts;
create trigger posts_escape_jaga before insert on public.posts for each row execute function public.escape_jaga();

-- ---------- kode acak 6 karakter (tanpa huruf/angka yang mirip) ----------
create or replace function public.kode_baru() returns text
language sql volatile set search_path = public as $$
  select string_agg(substr('ABCDEFGHJKMNPQRSTUVWXYZ23456789', 1 + (get_byte(decode(replace(gen_random_uuid()::text, '-', ''), 'hex'), i) % 31), 1), '')
  from generate_series(1, 6) i
$$;

-- ---------- Buat ruang escape (siapa pun yang login; satu per orang) ----------
create or replace function public.buat_escape(p_nama text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := public.wajib_login(); v_nama text := left(trim(coalesce(p_nama, '')), 30); baris public.ruang; v_kode text;
begin
  perform public.cek_akses();
  perform pg_advisory_xact_lock(hashtext('ruang'));
  if v_nama = '' then raise exception 'Isi nama ruang escape.'; end if;
  if exists (select 1 from ruang_rahasia where pemilik = v_uid) then raise exception 'Kamu sudah punya satu ruang escape.'; end if;
  if (select count(*) from ruang where jenis = 'escape') >= 20 then raise exception 'Ruang escape sudah penuh (maksimal 20). Minta dosen menutup yang lama.'; end if;
  if exists (select 1 from ruang where lower(nama) = lower(v_nama)) then raise exception 'Nama ruang ini sudah dipakai.'; end if;
  v_kode := public.kode_baru();
  insert into ruang (nama, jenis, terkunci) values (v_nama, 'escape', false) returning * into baris;
  insert into ruang_rahasia (ruang_id, pemilik, kode) values (baris.id, v_uid, v_kode);
  return jsonb_build_object('ruang', to_jsonb(baris), 'kode', v_kode);
end $$;

-- ---------- Kunci / buka kunci (pembuat atau dosen) ----------
create or replace function public.kunci_escape(p_id text, p_kunci boolean, p_ganti boolean default false) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := public.wajib_login(); s public.ruang_rahasia;
begin
  perform public.cek_akses();
  select * into s from ruang_rahasia where ruang_id = p_id;
  if not found then raise exception 'Ruang escape tidak ditemukan.'; end if;
  if s.pemilik <> v_uid and not coalesce(public.adalah_dosen(public.email_saya()), false) then raise exception 'Hanya pembuat ruang yang bisa mengunci.'; end if;
  if p_ganti then update ruang_rahasia set kode = public.kode_baru() where ruang_id = p_id returning * into s; end if;
  update ruang set terkunci = coalesce(p_kunci, false) where id = p_id;
  return jsonb_build_object('terkunci', coalesce(p_kunci, false), 'kode', s.kode);
end $$;

-- ---------- Masuk dengan kode. Salah 5 kali = tunggu 5 menit. ----------
create or replace function public.masuk_escape(p_id text, p_kode text, p_nama text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := public.wajib_login(); s public.ruang_rahasia; c public.ruang_coba; v_n int;
begin
  perform public.cek_akses();
  select * into s from ruang_rahasia where ruang_id = p_id;
  if not found then return jsonb_build_object('ok', false, 'pesan', 'Ruang escape tidak ditemukan.'); end if;
  select * into c from ruang_coba where uid = v_uid;
  if found and c.salah >= 5 and c.terakhir > now() - interval '5 minutes' then
    return jsonb_build_object('ok', false, 'pesan', 'Terlalu banyak salah. Coba lagi beberapa menit lagi.');
  end if;
  if upper(trim(coalesce(p_kode, ''))) = s.kode then
    select count(*) into v_n from ruang_anggota where ruang_id = p_id;
    if v_n >= 60 then return jsonb_build_object('ok', false, 'pesan', 'Ruang ini sudah penuh.'); end if;
    insert into ruang_anggota (ruang_id, uid, nama) values (p_id, v_uid, left(trim(coalesce(p_nama, '')), 20))
      on conflict (ruang_id, uid) do update set nama = excluded.nama;
    delete from ruang_coba where uid = v_uid;
    return jsonb_build_object('ok', true);
  end if;
  insert into ruang_coba (uid, salah, terakhir) values (v_uid, 1, now())
    on conflict (uid) do update set salah = case when ruang_coba.terakhir > now() - interval '5 minutes' then ruang_coba.salah + 1 else 1 end, terakhir = now();
  return jsonb_build_object('ok', false, 'pesan', 'Kode salah.');
end $$;

-- ---------- Keluarkan anggota (pembuat atau dosen) ----------
create or replace function public.keluarkan_escape(p_id text, p_uid uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := public.wajib_login(); s public.ruang_rahasia;
begin
  perform public.cek_akses();
  select * into s from ruang_rahasia where ruang_id = p_id;
  if not found then raise exception 'Ruang escape tidak ditemukan.'; end if;
  if s.pemilik <> v_uid and not coalesce(public.adalah_dosen(public.email_saya()), false) then raise exception 'Hanya pembuat ruang yang bisa mengeluarkan anggota.'; end if;
  delete from ruang_anggota where ruang_id = p_id and uid = p_uid;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- Daftar anggota (pembuat atau dosen) ----------
create or replace function public.anggota_escape(p_id text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := public.wajib_login(); s public.ruang_rahasia;
begin
  select * into s from ruang_rahasia where ruang_id = p_id;
  if not found then raise exception 'Ruang escape tidak ditemukan.'; end if;
  if s.pemilik <> v_uid and not coalesce(public.adalah_dosen(public.email_saya()), false) then raise exception 'Hanya pembuat ruang yang bisa melihat anggota.'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('uid', uid, 'nama', nama) order by masuk) from ruang_anggota where ruang_id = p_id), '[]'::jsonb);
end $$;

-- ---------- Status saya: ruang escape milikku (beserta kode) dan ruang yang kuikuti ----------
create or replace function public.escape_saya() returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := public.wajib_login(); m public.ruang_rahasia;
begin
  select * into m from ruang_rahasia where pemilik = v_uid;
  return jsonb_build_object(
    'milik', case when found then jsonb_build_object('id', m.ruang_id, 'kode', m.kode) end,
    'anggota', coalesce((select jsonb_agg(ruang_id) from ruang_anggota where uid = v_uid), '[]'::jsonb));
end $$;

-- ---------- Buat set ruang (dosen): batas 30 hanya menghitung ruang biasa ----------
create or replace function public.buat_ruang(p jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_nama text[];
  v_awalan text := left(trim(coalesce(p ->> 'awalan', 'Ruang')), 24);
  v_n int := case when coalesce(p ->> 'jumlah', '') ~ '^\d+$' then (p ->> 'jumlah')::int end;
  x text; baris public.ruang; hasil jsonb := '[]';
begin
  perform public.wajib_login();
  perform public.cek_akses();
  if not public.adalah_dosen(public.email_saya()) then raise exception 'Ruang hanya bisa dibuat oleh dosen.'; end if;
  perform pg_advisory_xact_lock(hashtext('ruang'));
  if jsonb_typeof(p -> 'nama') = 'array' then
    select coalesce(array_agg(left(trim(t), 30)) filter (where trim(t) <> ''), '{}') into v_nama
      from jsonb_array_elements_text(p -> 'nama') as q(t);
  else
    if v_awalan = '' then v_awalan := 'Ruang'; end if;
    if v_n is null or v_n < 1 or v_n > 20 then raise exception 'Jumlah ruang harus 1 sampai 20.'; end if;
    select array_agg(v_awalan || ' ' || i order by i) into v_nama from generate_series(1, v_n) i;
  end if;
  if coalesce(array_length(v_nama, 1), 0) = 0 then raise exception 'Isi nama ruang.'; end if;
  if (select count(*) from ruang where jenis = 'biasa') + array_length(v_nama, 1) > 30 then raise exception 'Maksimal 30 ruang sekaligus.'; end if;
  foreach x in array v_nama loop
    if exists (select 1 from ruang where lower(nama) = lower(x)) then raise exception 'Ruang "%" sudah ada.', x; end if;
    insert into ruang (nama) values (x) returning * into baris;
    hasil := hasil || to_jsonb(baris);
  end loop;
  return jsonb_build_object('ruang', hasil);
end $$;


-- ---------- Tutup ruang (dosen). Ruang biasa: kartu digabung ke papan utama. Ruang escape: ruang dan kartunya dihapus (masuk arsip). ----------
create or replace function public.tutup_ruang(p_id text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n int; k int; e int := 0;
begin
  perform public.wajib_login();
  perform public.cek_akses();
  if not public.adalah_dosen(public.email_saya()) then raise exception 'Ruang hanya bisa ditutup oleh dosen.'; end if;
  perform pg_advisory_xact_lock(hashtext('ruang'));
  select count(*) into k from posts p join ruang r on r.id = p.ruang_id where r.jenis = 'biasa' and (p_id is null or p.ruang_id = p_id);
  insert into arsip (alasan, data) select '(ruang escape ditutup)', to_jsonb(x) from posts x join ruang r on r.id = x.ruang_id
    where r.jenis = 'escape' and (p_id is null or x.ruang_id = p_id);
  get diagnostics e = row_count;
  delete from posts where ruang_id in (select id from ruang where jenis = 'escape' and (p_id is null or id = p_id));
  delete from ruang where p_id is null or id = p_id;
  get diagnostics n = row_count;
  if n = 0 then raise exception 'Ruang tidak ditemukan.'; end if;
  return jsonb_build_object('tutup', n, 'kartu_digabung', k, 'kartu_escape_dihapus', e);
end $$;

-- ---------- izin eksekusi ----------
revoke execute on function public.buat_escape(text) from public, anon, authenticated;
revoke execute on function public.kunci_escape(text, boolean, boolean) from public, anon, authenticated;
revoke execute on function public.masuk_escape(text, text, text) from public, anon, authenticated;
revoke execute on function public.keluarkan_escape(text, uuid) from public, anon, authenticated;
revoke execute on function public.anggota_escape(text) from public, anon, authenticated;
revoke execute on function public.escape_saya() from public, anon, authenticated;
revoke execute on function public.buat_ruang(jsonb) from public, anon, authenticated;
revoke execute on function public.tutup_ruang(text) from public, anon, authenticated;
grant execute on function public.buat_escape(text) to authenticated;
grant execute on function public.kunci_escape(text, boolean, boolean) to authenticated;
grant execute on function public.masuk_escape(text, text, text) to authenticated;
grant execute on function public.keluarkan_escape(text, uuid) to authenticated;
grant execute on function public.anggota_escape(text) to authenticated;
grant execute on function public.escape_saya() to authenticated;
grant execute on function public.buat_ruang(jsonb) to authenticated;
grant execute on function public.tutup_ruang(text) to authenticated;
