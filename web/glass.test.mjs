import test from 'node:test';
import assert from 'node:assert/strict';
import { GLASS_PRESETS, normalizeGlass } from './glass.mjs';

test('appearance settings stay bounded and cannot inject CSS from tint values', () => {
  assert.deepEqual(normalizeGlass(), GLASS_PRESETS.frosted);
  assert.deepEqual(normalizeGlass({ blur: 999, opacity: -1, saturation: NaN, edge: Infinity, tint: 'url(https://example.com)' }), {
    blur: 40, opacity: .58, saturation: 1.2, edge: .6, tint: '#9abbd1',
  });
  assert.deepEqual(normalizeGlass(GLASS_PRESETS.solid), GLASS_PRESETS.solid);
  assert.equal(normalizeGlass({ tint: '#F4BA63' }).tint, '#F4BA63');
});
