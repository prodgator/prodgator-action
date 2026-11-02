import { defineConfig } from 'vitest/config';

export default defineConfig({ define: { ACTION_VERSION: JSON.stringify('0.0.0-test') }, test: { include: ['src/**/*.test.ts'], environment: 'node' } });
