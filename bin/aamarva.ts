#!/usr/bin/env node

import { runCli } from '../src/cli.js';

runCli().catch((err: unknown) => {
  const msg = (err instanceof Error) ? err.message : String(err);
  console.error('Fatal AAMARVA CLI Error:', msg);
  process.exit(1);
});
