const MASK64 = (1n << 64n) - 1n;
const ROT = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

function rotate(value: bigint, bits: number): bigint {
  if (!bits) return value & MASK64;
  const b = BigInt(bits);
  return ((value << b) | (value >> (64n - b))) & MASK64;
}

function permute(a: bigint[]): void {
  for (const rc of RC) {
    const c = new Array<bigint>(5), d = new Array<bigint>(5), b = new Array<bigint>(25).fill(0n);
    for (let x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    for (let x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ rotate(c[(x + 1) % 5], 1);
    for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) {
      const nx = y, ny = (2 * x + 3 * y) % 5;
      b[nx + 5 * ny] = rotate(a[x + 5 * y] ^ d[x], ROT[x + 5 * y]);
    }
    for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) {
      a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
    }
    a[0] ^= rc;
  }
}

/** Ethereum Keccak-256 (legacy 0x01 padding), not FIPS SHA3-256. */
export function keccak256Utf8(input: string): string {
  const bytes = [...Buffer.from(input, 'utf8')];
  const rate = 136;
  bytes.push(0x01);
  while (bytes.length % rate !== rate - 1) bytes.push(0);
  bytes.push(0x80);
  const state = new Array<bigint>(25).fill(0n);
  for (let offset = 0; offset < bytes.length; offset += rate) {
    for (let i = 0; i < rate; i++) state[Math.floor(i / 8)] ^= BigInt(bytes[offset + i]) << BigInt((i % 8) * 8);
    permute(state);
  }
  let output = '';
  for (let i = 0; i < 32; i++) output += Number((state[Math.floor(i / 8)] >> BigInt((i % 8) * 8)) & 0xffn).toString(16).padStart(2, '0');
  return `0x${output}`;
}

export function selectorForSignature(signature: string): string { return keccak256Utf8(signature).slice(0, 10); }
