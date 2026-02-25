const CACHE_NAME = 'chatter-media-cache-v1';
const MEDIA_URLS = [
  '/static/uploads/profiles/',
  '/static/uploads/covers/',
  '/static/uploads/posts/',
  '/static/uploads/reels/',
  '/static/uploads/statuses/'
];

// Install event – cache static assets (optional)
self.addEventListener('install', event => {
  console.log('Service Worker installing.');
  // You can pre-cache essential static files here if needed
  self.skipWaiting();
});

// Activate event – clean up old caches
self.addEventListener('activate', event => {
  console.log('Service Worker activating.');
  event.waitUntil(
    caches.keys().then(keys => {
      return Promise.all(
        keys.filter(key => key !== CACHE_NAME)
          .map(key => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

// Fetch event – cache media files (images/videos) and serve from cache
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Check if the request is for media (image/video) from our uploads
  const isMedia = MEDIA_URLS.some(path => url.pathname.startsWith(path));
  const isImage = event.request.destination === 'image';
  const isVideo = event.request.destination === 'video';

  if (isMedia || isImage || isVideo) {
    event.respondWith(
      caches.open(CACHE_NAME).then(cache => {
        return cache.match(event.request).then(cachedResponse => {
          if (cachedResponse) {
            fetch(event.request).then(networkResponse => {
              cache.put(event.request, networkResponse.clone());
            }).catch(() => {});
            return cachedResponse;
          }
          // Not cached – fetch from network and cache
          return fetch(event.request).then(networkResponse => {
            // Cache a clone for future offline use
            cache.put(event.request, networkResponse.clone());
            return networkResponse;
          }).catch(error => {
            console.error('Offline media fetch failed:', error);
            // Optionally return a fallback offline image
         
          });
        });
      })
    );
  } else {
    // For non-media requests (HTML, API, etc.), do not cache (or use network-only)
    event.respondWith(fetch(event.request).catch(() => {
  
      return new Response('Offline', { status: 503, statusText: 'Service Unavailable' });
    }));
  }
});