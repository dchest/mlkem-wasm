/* eslint-disable no-undef */
import { build } from 'esbuild';

build({
  entryPoints: ['src/mlkem.ts'], // change if api.ts lives elsewhere
  bundle: true,
  format: 'esm',
  outfile: 'dist/mlkem.js',
  platform: 'neutral',
  target: ['esnext'],
  sourcemap: false,
  legalComments: 'none',
  logLevel: 'info',
}).catch(() => process.exit(1));
