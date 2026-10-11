/**
 * Triggers a browser file download reliably across Chromium, Firefox, Edge on Windows.
 *
 * Fixes:
 *  - Uses dispatchEvent(MouseEvent) instead of .click() — more reliable in Chrome security contexts
 *  - Revokes the blob URL after 30s to give the browser enough time to start the download
 *  - Falls back to window.open() if the anchor approach fails
 *  - Forces application/octet-stream for binary types so Chrome doesn't block them
 */
export function downloadFile(
  content: string | Blob,
  filename: string,
  mimeType = 'text/plain;charset=utf-8;'
): void {
  try {
    // Force octet-stream for binary types — avoids Chrome's "dangerous file" block
    const safeMime = ['application/msword', 'application/vnd.openxmlformats'].some(m =>
      mimeType.startsWith(m)
    ) ? 'application/octet-stream' : mimeType;

    const blob =
      typeof content === 'string'
        ? new Blob([content], { type: safeMime })
        : new Blob([content], { type: safeMime });

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    // Position off-screen rather than display:none — display:none can block click in some browsers
    a.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0;pointer-events:none;';
    a.href = url;
    a.setAttribute('download', filename);
    document.body.appendChild(a);

    // dispatchEvent is more reliable than .click() in Chrome sandboxed contexts
    a.dispatchEvent(
      new MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: window,
      })
    );

    // 30s revoke window — large HTML reports can take a moment for Chrome to pick up
    setTimeout(() => {
      try {
        if (a.parentNode) a.parentNode.removeChild(a);
        URL.revokeObjectURL(url);
      } catch (_) { /* ignore cleanup errors */ }
    }, 30_000);
  } catch (err) {
    console.error('[downloadFile] Primary download failed, trying fallback:', err);
    // Fallback: open blob in new tab so user can Ctrl+S to save
    try {
      const blob =
        typeof content === 'string'
          ? new Blob([content], { type: mimeType })
          : content;
      const fallbackUrl = URL.createObjectURL(blob);
      window.open(fallbackUrl, '_blank');
      setTimeout(() => URL.revokeObjectURL(fallbackUrl), 60_000);
    } catch (fallbackErr) {
      console.error('[downloadFile] Fallback also failed:', fallbackErr);
      alert(`Download failed. Please check your browser's download settings and try again.\n\nFile: ${filename}`);
    }
  }
}
