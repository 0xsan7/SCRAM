// Appearance is intentionally session-only; report data never enters these controls.
export const GLASS_PRESETS = Object.freeze({
  clear: { blur: 8, opacity: .62, saturation: 1.1, edge: .7, tint: '#9abbd1' },
  frosted: { blur: 22, opacity: .82, saturation: 1.2, edge: .6, tint: '#9abbd1' },
  solid: { blur: 0, opacity: 1, saturation: 1, edge: .35, tint: '#9abbd1' },
});

export function normalizeGlass(value = {}) {
  const defaults = GLASS_PRESETS.frosted;
  const bound = (key, min, max) => Number.isFinite(value[key]) ? Math.min(max, Math.max(min, value[key])) : defaults[key];
  return {
    blur: bound('blur', 0, 40), opacity: bound('opacity', .58, 1),
    saturation: bound('saturation', .5, 1.6), edge: bound('edge', 0, 1),
    tint: typeof value.tint === 'string' && /^#[0-9a-f]{6}$/i.test(value.tint) ? value.tint : defaults.tint,
  };
}

if (typeof document !== 'undefined') {
  const $ = id => document.getElementById(id);
  const disclosure = $('glass-settings');
  let material = normalizeGlass();
  const scales = { blur: 1, opacity: 100, saturation: 100, edge: 100 };
  function apply(value, preset = '') {
    material = normalizeGlass(value);
    const style = document.documentElement.style;
    style.setProperty('--glass-blur', `${material.blur}px`);
    style.setProperty('--glass-opacity', material.opacity);
    style.setProperty('--glass-saturation', material.saturation);
    style.setProperty('--glass-edge', material.edge);
    style.setProperty('--glass-tint', material.tint);
    document.documentElement.dataset.glass = preset;
    for (const [key, scale] of Object.entries(scales)) {
      $(`glass-${key}`).value = material[key] * scale;
      $(`glass-${key}-value`).textContent = key === 'blur' ? `${Math.round(material.blur)} px` : `${Math.round(material[key] * 100)}%`;
    }
    $('glass-tint').value = material.tint;
    disclosure.querySelectorAll('[data-glass-preset]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.glassPreset === preset)));
  }
  function close() { disclosure.open = false; disclosure.querySelector('summary').focus(); }
  $('close-glass').addEventListener('click', close);
  document.addEventListener('keydown', event => { if (event.key === 'Escape' && disclosure.open) close(); });
  document.addEventListener('pointerdown', event => { if (disclosure.open && !disclosure.contains(event.target)) disclosure.open = false; });
  disclosure.querySelectorAll('[data-glass-preset]').forEach(button => button.addEventListener('click', () => apply(GLASS_PRESETS[button.dataset.glassPreset], button.dataset.glassPreset)));
  for (const [key, scale] of Object.entries(scales)) $(`glass-${key}`).addEventListener('input', event => apply({ ...material, [key]: Number(event.target.value) / scale }));
  $('glass-tint').addEventListener('input', event => apply({ ...material, tint: event.target.value }));
  $('reset-glass').addEventListener('click', () => apply(GLASS_PRESETS.frosted, 'frosted'));
  const reduced = matchMedia('(prefers-reduced-transparency: reduce)');
  const forced = matchMedia('(forced-colors: active)');
  function respectPreferences() {
    const solid = reduced.matches || forced.matches;
    if (solid) apply(GLASS_PRESETS.solid, 'solid');
    disclosure.querySelectorAll('input, [data-glass-preset], #reset-glass').forEach(control => { control.disabled = solid; });
    disclosure.querySelector('.glass-access-note').textContent = solid
      ? 'Your browser accessibility preference uses solid surfaces. Appearance controls are disabled.'
      : 'Solid mode removes blur and transparency. Appearance resets when you reload.';
  }
  reduced.addEventListener('change', respectPreferences);
  forced.addEventListener('change', respectPreferences);
  apply(GLASS_PRESETS.frosted, 'frosted');
  respectPreferences();
}
