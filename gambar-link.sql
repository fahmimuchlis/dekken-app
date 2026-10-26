-- Gambar lewat link: kartu boleh membawa satu URL gambar (https). Yang disimpan hanya URL-nya.
alter table public.posts add column if not exists gambar text;
alter table public.posts drop constraint if exists posts_gambar_cek;
alter table public.posts add constraint posts_gambar_cek check (gambar is null or (char_length(gambar) between 12 and 500 and gambar ~ '^https://[^[:space:]"''<>]+$'));

create or replace function public.kirim(p jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  c_segel constant text := E'\U0001F512';
  v_uid uuid := public.wajib_login();
  v_email text := public.email_saya();
  v_bentuk text := lower(coalesce(p ->> 'bentuk', ''));
  v_batas int;
  v_menit int := case when coalesce(p ->> 'menit', '') ~ '^\d+$' then (p ->> 'menit')::int end;
  v_u text; v_t text;
  v_parent text := trim(coalesce(p ->> 'parent', ''));
  v_membalas text := trim(coalesce(p ->> 'membalas', ''));
  v_game boolean := coalesce(p ->> 'game', '') = 'true';
  v_gambar text := nullif(trim(coalesce(p ->> 'gambar', '')), '');
  v_nama_balas text := null; v_ke text := null;
  v_dosen boolean; v_warna text; v_kartu text; v_habis bigint;
  v_id text; v_jeda int;
  v_ruang text := nullif(trim(coalesce(p ->> 'ruang', '')), '');
  induk public.posts; tujuan public.posts; baris public.posts;
begin
  perform public.cek_akses();
  perform pg_advisory_xact_lock(hashtext(v_uid::text));

  -- gambar lewat link: hanya URL https, disimpan sebagai teks (gambarnya sendiri tidak disimpan di sini)
  if v_gambar is not null then
    if char_length(v_gambar) not between 12 and 500 or v_gambar !~ '^https://[^[:space:]"''<>]+$' then
      raise exception 'Link gambar harus diawali https:// dan tanpa spasi.';
    end if;
    if v_bentuk = 'waktu' then raise exception 'Kartu timer tidak bisa memuat gambar.'; end if;
    if v_game then raise exception 'Kartu game tidak bisa memuat gambar.'; end if;
    v_bentuk := 'persegi';   -- thumbnail hanya cocok di kartu persegi
  end if;

  v_batas := case v_bentuk when 'persegi' then 200 when 'lingkaran' then 120 when 'enam' then 120
                           when 'lima' then 100 when 'tumpul' then 120 when 'ledak' then 80
                           when 'waktu' then 120 else null end;
  if v_batas is null then v_bentuk := 'persegi'; v_batas := 200; end if;

  if v_bentuk = 'waktu' then
    if v_parent <> '' then raise exception 'Kartu timer tidak bisa dipakai untuk balasan.'; end if;
    if v_menit is null or v_menit not in (5, 15, 30) then raise exception 'Lama timer tidak valid.'; end if;
  end if;

  v_u := left(trim(coalesce(p ->> 'username', '')), 20);
  v_t := left(trim(coalesce(p ->> 'teks', '')), v_batas);
  if v_u = '' or v_t = '' then raise exception 'Username dan teks wajib diisi.'; end if;

  v_jeda := coalesce(public.atur('jeda_detik'), '8')::int;
  if v_jeda > 0 and exists (select 1 from pemilik where uid = v_uid
                              and waktu > now() - make_interval(secs => v_jeda)) then
    raise exception 'Terlalu cepat, tunggu beberapa detik.';
  end if;

  if v_game and v_parent = '' then raise exception 'Kartu game hanya untuk balasan.'; end if;

  if v_parent <> '' then
    select * into induk from posts where id = v_parent;
    if not found then raise exception 'Postingan induk tidak ditemukan.'; end if;
    if induk.parent_id is not null then raise exception 'Balasan hanya untuk postingan utama.'; end if;
    if induk.polling is not null then raise exception 'Kartu polling tidak bisa dibalas.'; end if;
    if coalesce(induk.habis, 0) > 0 and induk.habis <= public.kini_ms() then
      raise exception 'Kartu ini sudah kedaluwarsa.';
    end if;
    -- di kartu game yang berjalan, balasan orang lain selalu tersegel
    if not v_game and induk.game = 1 and not public.pemilik_kartu(v_parent, v_uid) and v_membalas = '' then
      v_game := true;
    end if;
    if v_game then
      if induk.game <> 1 then raise exception 'Tidak ada game yang berjalan di kartu ini.'; end if;
      if public.pemilik_kartu(v_parent, v_uid) then
        raise exception 'Penanya tidak ikut menjawab ronde miliknya sendiri.';
      end if;
      if exists (select 1 from posts c join pemilik o on o.post_id = c.id
                  where c.parent_id = v_parent and c.game > 0 and o.uid = v_uid) then
        raise exception 'Kamu sudah mengirim kartu game di ronde ini.';
      end if;
      if v_membalas <> '' then raise exception 'Kartu game membalas kartu utama, bukan balasan lain.'; end if;
    end if;
    if v_membalas <> '' then
      select * into tujuan from posts where id = v_membalas and parent_id = v_parent;
      if not found then raise exception 'Balasan yang dituju tidak ditemukan.'; end if;
      if tujuan.game = 1 then raise exception 'Kartu game belum terbuka.'; end if;
      v_nama_balas := left(tujuan.username, 20);
      v_ke := v_membalas;
    end if;
  end if;

  -- balasan selalu ikut ruang kartu induknya; kartu utama ikut ruang yang dipilih pengirim
  if v_parent <> '' then v_ruang := induk.ruang_id;
  elsif v_ruang is not null and not exists (select 1 from ruang where id = v_ruang) then
    raise exception 'Ruang ini sudah ditutup. Kartumu belum terkirim.';
  end if;

  v_dosen := public.adalah_dosen(v_email);
  if not v_dosen and v_u ~* 'dosen|verified|✓|✔' then
    raise exception 'Username ini dicadangkan untuk akun dosen.';
  end if;
  v_warna := lower(coalesce(p ->> 'warna', ''));
  v_kartu := lower(coalesce(p ->> 'kartu', ''));
  -- kartu timer selalu teks putih (tampilan merah diatur klien)
  v_warna := case when v_bentuk = 'waktu' then '#ffffff'
                  when v_warna in ('#000000', '#ffffff', '#1e3a8a', '#991b1b', '#166534') then v_warna
                  else '#000000' end;
  v_kartu := case when v_kartu in ('kuning', 'pink', 'biru', 'hijau', 'ungu') then v_kartu else 'kuning' end;
  v_habis := case when v_bentuk = 'waktu' then public.kini_ms() + v_menit * 60000 end;
  v_id := public.id_baru();

  insert into posts (id, parent_id, username, teks, warna, kartu, bentuk, dosen, membalas, ke, habis, game, ruang_id, gambar)
  values (v_id, nullif(v_parent, ''), v_u, case when v_game then c_segel else v_t end,
          v_warna, v_kartu, v_bentuk, v_dosen, v_nama_balas, v_ke, v_habis, case when v_game then 1 else 0 end, v_ruang, v_gambar)
  returning * into baris;
  insert into pemilik (post_id, uid, email) values (v_id, v_uid, v_email);
  if v_game then insert into segel (post_id, uid, teks) values (v_id, v_uid, v_t); end if;

  return jsonb_build_object('post', to_jsonb(baris)) ||
         case when v_game then jsonb_build_object('segel', v_t) else '{}'::jsonb end;
end $$;
