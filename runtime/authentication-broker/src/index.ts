import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAuthenticationBroker } from './runtime/create-runtime.js';

export const BROKER_VERSION = '0.1.0';

export async function runBroker(): Promise<void> {
  const runtime = await createAuthenticationBroker();
  await runtime.start();
  console.log('Authentication Broker listening on http://127.0.0.1:8765/mcp');
  console.log('Researcher control routes: http://127.0.0.1:8765/researcher/*');

  let stopping = false;
  const stop = (): void => {
    if (stopping) return;
    stopping = true;
    void runtime.close().then(
      () => { process.exitCode = 0; },
      () => { console.error('Authentication Broker stopped with a local cleanup error.'); process.exitCode = 1; }
    );
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

function safeStartupError(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (/^(?:LOCALAPPDATA must be an absolute path|Broker runtime data must be outside the repository and OneDrive|Policy file is unavailable or invalid|Policy file is unavailable or not safe for runtime use|Broker proxy listener is not exact loopback|Egress protection is not verified|MCP listener is not exact loopback|Broker runtime could not start safely|MCP listener could not start: [A-Z0-9_]{1,64})$/.test(message)) return message;
  return 'Broker runtime startup failed safely; no target capability was enabled.';
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  void runBroker().catch((error: unknown) => {
    console.error(`Authentication Broker: ${safeStartupError(error)}`);
    process.exitCode = 1;
  });
}
