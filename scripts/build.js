const { execSync } = require('child_process');
const path = require('path');

const root = path.resolve(__dirname, '..');

const steps = [
  ['go vet',       'go vet ./...'],
  ['go test',      'go test -count=1 ./...'],
  ['go build',     'go build ./...'],
  ['WASM',         'go build -o ../official/issuer.wasm .', { cwd: 'wasm', env: { GOOS: 'js', GOARCH: 'wasm' } }],
  ['examples',     'go build ./examples/...'],
];

for (const [label, cmd, opts] of steps) {
  console.log(`\n=== ${label} ===`);
  const cwd = opts?.cwd ? path.join(root, opts.cwd) : root;
  const env = opts?.env ? { ...process.env, ...opts.env } : undefined;
  execSync(cmd, { cwd, env, stdio: 'inherit' });
}

console.log('\n=== all done ===');