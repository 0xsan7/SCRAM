import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = join(root, 'dist/viewer');
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
for (const file of ['index.html', 'viewer.html', '404.html', '_headers', 'styles.css', 'landing.css', 'footer.css', 'footer.mjs', 'site.mjs', 'glass-reveal.mjs', 'app.mjs', 'report.mjs']) await cp(join(root, 'web', file), join(output, file));
await cp(join(root, 'web/assets'), join(output, 'assets'), { recursive: true });
await cp(join(root, 'examples/report-viewer/fixtures'), join(output, 'fixtures'), { recursive: true });
const html = await readFile(join(output, 'viewer.html'), 'utf8');
if (!html.includes('src="app.mjs"')) throw new Error('Viewer entry module is missing.');
await writeFile(join(output, '.nojekyll'), '');
console.log(`SCRAM viewer prepared at ${output}`);
