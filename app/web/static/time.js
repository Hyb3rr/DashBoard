(() => {
  const formatVnTime = (value) => {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    const parts = Object.fromEntries(new Intl.DateTimeFormat('vi-VN', {
      timeZone: 'Asia/Ho_Chi_Minh', day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', hour12: false,
    }).formatToParts(date).map((part) => [part.type, part.value]));
    return `${parts.hour}:${parts.minute} ${parts.day}/${parts.month}/${parts.year}`;
  };
  window.formatVnTime = formatVnTime;
  window.vnTime = formatVnTime;
})();
