self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  clients.claim();
});

// Поки що без офлайн-кешу, просто пропускаємо всі запити в мережу
self.addEventListener('fetch', (event) => {
  // Якщо захочеш — потім можна додати кешування
});
