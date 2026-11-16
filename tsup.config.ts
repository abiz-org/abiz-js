import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts', node: 'src/node.ts', cli: 'src/cli.ts' },
  format: ['esm'],
  target: 'es2022',
  dts: { entry: { index: 'src/index.ts', node: 'src/node.ts' } },
  sourcemap: false,
  clean: true,
  splitting: true,
  treeshake: true,
  removeNodeProtocol: false,
});
