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

const switcher = document.querySelector('.sample-switcher');
const scenarios = [...switcher.querySelectorAll('button[data-scenario]')];
switcher.hidden = false;
for (const button of scenarios) {
  button.addEventListener('click', () => {
    for (const choice of scenarios) {
      const active = choice === button;
      choice.setAttribute('aria-pressed', String(active));
      document.getElementById(choice.dataset.scenario).hidden = !active;
    }
  });
}
