import { MessageChannel } from 'node:worker_threads';

const mode = process.argv[2];
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const request = JSON.parse(input);
  const response = `${JSON.stringify({ results: request.operations.map(({ id }) => ({ id, ok: true })) })}\n`;
  switch (mode) {
    case 'good': process.stdout.write(response); break;
    case 'exit2': process.stdout.write(response); process.exitCode = 2; break;
    case 'truncated': process.stdout.write('{"results":\n'); break;
    case 'invalid': process.stdout.write('invalid\n'); break;
    case 'no-newline': process.stdout.write(response.slice(0, -1)); break;
    case 'extra-output': process.stdout.write(`${response}extra\n`); break;
    case 'invalid-utf8': process.stdout.write(Buffer.from([0xff, 0x0a])); break;
    case 'overflow': process.stdout.write(Buffer.alloc(2 * 1024 * 1024 + 1, 0x41)); break;
    case 'stderr-secret': process.stderr.write('TRANSFER-LIFECYCLE-SECRET'); process.exitCode = 2; break;
    case 'hang': {
      const channel = new MessageChannel();
      channel.port1.on('message', () => {});
      channel.port2.on('message', () => {});
      break;
    }
    case 'final-chunks': {
      const split = Math.floor(response.length / 2);
      process.stdout.write(response.slice(0, split), () => process.stdout.write(response.slice(split), () => {}));
      break;
    }
    default: process.exitCode = 3;
  }
});
