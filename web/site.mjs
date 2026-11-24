for (const button of document.querySelectorAll('[data-copy]')) {
  if (!navigator.clipboard?.writeText) break;
  const command = document.getElementById(button.dataset.copy);
  const status = document.getElementById('copy-status');
  button.hidden = false;
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(command.textContent);
      button.firstChild.textContent = 'Copied';
      status.textContent = 'Command copied to the clipboard.';
    } catch {
      const range = document.createRange();
      range.selectNodeContents(command);
      const selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = 'Command selected. Use your device’s copy shortcut.';
    }
  });
}
