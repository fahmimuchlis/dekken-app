/* Service worker Dekken: cangkang aplikasi disimpan agar cepat dibuka; data kartu selalu dari jaringan. */
const VERSI = 'dekken-v88';
const CANGKANG = ['./', 'index.html', 'vendor/supabase.js', 'manifest.webmanifest', 'icons/icon-192.png', 'icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VERSI).then(c => c.addAll(CANGKANG)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== VERSI).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin) return;   // Supabase, Google Fonts, dan lainnya langsung ke jaringan
  if (r.mode === 'navigate') {   // halaman: utamakan jaringan (selalu versi terbaru), cadangan dari simpanan
    e.respondWith(fetch(r).then(res => { const salin = res.clone(); caches.open(VERSI).then(c => c.put('index.html', salin)); return res; })
      .catch(() => caches.match('index.html')));
    return;
  }
  e.respondWith(caches.match(r).then(m => m || fetch(r).then(res => { const salin = res.clone(); caches.open(VERSI).then(c => c.put(r, salin)); return res; })));
});
