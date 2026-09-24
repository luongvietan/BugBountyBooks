export const BROKER_VERSION = '0.1.0';

export function runBroker(): never {
  throw new Error('Authentication Broker is not operational until setup and acceptance checks are complete');
}

if (process.argv[1] && new URL(import.meta.url).pathname.toLowerCase().endsWith('/src/index.ts')) {
  runBroker();
}
