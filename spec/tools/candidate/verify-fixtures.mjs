import { verifyOnDiskFixtures } from './semantic-verify.mjs';

const result = verifyOnDiskFixtures();
console.log(`on-disk semantic verification passed: ${result.codec} rotation records, ${result.nonce} durable nonce events, ${result.rotationClient} client refresh cases, ${result.rotationEvents} clock/server events`);
