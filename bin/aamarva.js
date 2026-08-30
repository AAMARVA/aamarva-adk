#!/usr/bin/env node

import { runCli } from '../dist/cli.js';

runCli().catch((err) => {
  const msg = err && err.message ? err.message : String(err);
  console.error('Fatal AAMARVA CLI Error:', msg);
  process.exit(1);
});
