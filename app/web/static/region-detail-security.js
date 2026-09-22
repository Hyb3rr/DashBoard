// Defense-in-depth for source links rendered from persisted provider metadata.
document.addEventListener('click', event => {
  const link = event.target.closest?.('a.source-link');
  if (!link) return;
  try {
    const url = new URL(link.href, window.location.origin);
    if (!['http:', 'https:'].includes(url.protocol)) event.preventDefault();
  } catch (_) {
    event.preventDefault();
  }
});
