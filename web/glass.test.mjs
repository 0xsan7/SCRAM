import test from 'node:test';
import assert from 'node:assert/strict';
import { GLASS_PRESETS, normalizeGlass } from './glass.mjs';

test('appearance settings stay bounded and cannot inject CSS from tint values', () => {
  assert.deepEqual(normalizeGlass(), GLASS_PRESETS.frosted);
  assert.deepEqual(normalizeGlass({ blur: 999, opacity: -1, saturation: NaN, edge: Infinity, tint: 'url(https://example.com)' }), {
    blur: 40, opacity: .08, saturation: 1.2, edge: .6, tint: '#eadbc7',
  });
  assert.deepEqual(normalizeGlass(GLASS_PRESETS.solid), GLASS_PRESETS.solid);
  assert.equal(normalizeGlass({ tint: '#F4BA63' }).tint, '#F4BA63');
  assert.deepEqual(normalizeGlass({ blur: -1, opacity: 9, saturation: 99, edge: -1 }), {
    blur: 0, opacity: 1, saturation: 2, edge: 0, tint: '#eadbc7',
  });
  assert.equal(normalizeGlass({ saturation: -1 }).saturation, .5);
});
