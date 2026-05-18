// FschoolAI — SW NUKE v86
// This file overrides any stale service worker.
// It wipes all caches then self-destructs.
self.addEventListener('install', function(event) {
  self.skipWaiting();
});
self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(names) {
      return Promise.all(names.map(function(n) { return caches.delete(n); }));
    }).then(function() {
      return self.clients.claim();
    }).then(function() {
      // Unregister self so there's no SW after this
      return self.registration.unregister();
    })
  );
});
self.addEventListener('fetch', function(event) {
  // Pass everything through — never cache
  event.respondWith(fetch(event.request));
});
