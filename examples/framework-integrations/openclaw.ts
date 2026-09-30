/**
 * OpenClaw Skill / Plugin Integration Example for AAMARVA
 */
import { createOpenClawSkill } from '../../src/index.js';

async function main() {
  console.log('--- OpenClaw AAMARVA Integration ---');

  const skill = createOpenClawSkill();
  console.log(`✓ OpenClaw Skill created: ${skill.name} (v${skill.version})`);
  console.log('Available Actions:', Object.keys(skill.actions).join(', '));
}

main().catch(console.error);
