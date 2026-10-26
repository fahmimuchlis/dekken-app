-- =====================================================================
-- Dekken: jatah ruang escape diatur dosen. Jalankan SETELAH escape.sql. Aman dijalankan ulang.
-- Jatah 0 (bawaan) = mahasiswa belum bisa membuat ruang escape. Dosen mengatur jumlah maksimal (0 sampai 30).
-- Menurunkan jatah tidak menghapus ruang yang sudah ada; hanya menghentikan pembuatan baru.
-- =====================================================================
create table if not exists public.escape_atur (
  id    int primary key default 1 check (id = 1),
  batas int not null default 0 check (batas between 0 and 30)
);
insert into public.escape_atur (id, batas) values (1, 0) on conflict (id) do nothing;
alter table public.escape_atur enable row level security;
revoke all on public.escape_atur from anon, authenticated;
grant select on public.escape_atur to anon, authenticated;
drop policy if exists escape_atur_baca on public.escape_atur;
create policy escape_atur_baca on public.escape_atur for select to anon, authenticated using (true);

create or replace function public.atur_escape(p_batas int) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  perform public.wajib_login();
  perform public.cek_akses();
  if not coalesce(public.adalah_dosen(public.email_saya()), false) then raise exception 'Hanya dosen yang bisa mengatur jatah ruang escape.'; end if;
  if p_batas is null or p_batas < 0 or p_batas > 30 then raise exception 'Jatah harus antara 0 dan 30.'; end if;
  update escape_atur set batas = p_batas where id = 1;
  return jsonb_build_object('batas', p_batas);
end $$;
revoke execute on function public.atur_escape(int) from public, anon, authenticated;
grant  execute on function public.atur_escape(int) to authenticated;

create or replace function public.buat_escape(p_nama text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_uid uuid := public.wajib_login(); v_nama text := left(trim(coalesce(p_nama, '')), 30); baris public.ruang; v_kode text;
        v_dosen boolean; v_batas int; v_n int;
begin
  perform public.cek_akses();
  perform pg_advisory_xact_lock(hashtext('ruang'));
  v_dosen := coalesce(public.adalah_dosen(public.email_saya()), false);
  select batas into v_batas from escape_atur where id = 1;
  select count(*) into v_n from ruang where jenis = 'escape';
  if v_nama = '' then raise exception 'Isi nama ruang escape.'; end if;
  if exists (select 1 from ruang_rahasia where pemilik = v_uid) then raise exception 'Kamu sudah punya satu ruang escape.'; end if;
  if not v_dosen then
    if coalesce(v_batas, 0) <= 0 then raise exception 'Ruang escape belum dibuka oleh dosen.'; end if;
    if v_n >= v_batas then raise exception 'Jatah ruang escape sudah penuh (% dari %). Minta dosen menambah jatah.', v_n, v_batas; end if;
  elsif v_n >= 30 then raise exception 'Ruang escape sudah mencapai 30.'; end if;
  if exists (select 1 from ruang where lower(nama) = lower(v_nama)) then raise exception 'Nama ruang ini sudah dipakai.'; end if;
  v_kode := public.kode_baru();
  insert into ruang (nama, jenis, terkunci) values (v_nama, 'escape', false) returning * into baris;
  insert into ruang_rahasia (ruang_id, pemilik, kode) values (baris.id, v_uid, v_kode);
  return jsonb_build_object('ruang', to_jsonb(baris), 'kode', v_kode);
end $$;
revoke execute on function public.buat_escape(text) from public, anon, authenticated;
grant  execute on function public.buat_escape(text) to authenticated;
