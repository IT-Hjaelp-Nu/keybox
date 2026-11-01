"use strict";

// Shows Key-Box' notifications. It handles no page loads, so it cannot cache
// or change the page. A notification carries no address: tapping it always
// opens Key-Box' own page, where everything still needs the passkey.

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  let note = {};
  try {
    note = event.data.json();
  } catch {
    // Shown anyway: the browser requires a notification for every push.
  }
  const text = (value, otherwise) => (typeof value === "string" ? value : otherwise);
  event.waitUntil(
    self.registration.showNotification(text(note.title, "Key-Box"), {
      body: text(note.body, "Noget venter på dig."),
      tag: text(note.tag, "keybox"),
      renotify: true,
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const pages = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const page of pages) {
        if ("focus" in page) return page.focus();
      }
      return self.clients.openWindow("/");
    })(),
  );
});
