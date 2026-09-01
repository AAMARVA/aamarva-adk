import fs from 'fs';
import path from 'path';

export const ADK_SPECIFICATION = fs.readFileSync(path.join(process.cwd(), 'ADK_SPEC.md'), 'utf8');
