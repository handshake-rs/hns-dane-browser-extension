const RATE_BYTES = 136;
const MASK_64 = (1n << 64n) - 1n;
const ROTATION_OFFSETS = Object.freeze([
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14
]);
const ROUND_CONSTANTS = Object.freeze([
  0x0000000000000001n, 0x0000000000008082n,
  0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n,
  0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn,
  0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n,
  0x0000000080000001n, 0x8000000080008008n
]);

// hns-covenants::hash_name is SHA3-256 over the raw canonical name bytes.
// Canonical Handshake names fit in one SHA3-256 rate block.
export function hnsNameHash(name) {
  const input = new TextEncoder().encode(name);
  if (input.length > 63 || input.some((byte) => byte > 0x7f)) {
    throw new TypeError("canonical Handshake name required");
  }

  const block = new Uint8Array(RATE_BYTES);
  block.set(input);
  block[input.length] = 0x06;
  block[RATE_BYTES - 1] |= 0x80;

  const state = Array(25).fill(0n);
  for (let lane = 0; lane < RATE_BYTES / 8; lane += 1) {
    let value = 0n;
    for (let byte = 0; byte < 8; byte += 1) {
      value |= BigInt(block[lane * 8 + byte]) << BigInt(byte * 8);
    }
    state[lane] ^= value;
  }
  keccakF1600(state);

  let encoded = "";
  for (let index = 0; index < 32; index += 1) {
    const lane = state[Math.floor(index / 8)];
    const byte = Number((lane >> BigInt((index % 8) * 8)) & 0xffn);
    encoded += byte.toString(16).padStart(2, "0");
  }
  return encoded;
}

function keccakF1600(state) {
  for (const roundConstant of ROUND_CONSTANTS) {
    const columns = Array(5).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        columns[x] ^= state[x + 5 * y];
      }
    }
    for (let x = 0; x < 5; x += 1) {
      const delta = columns[(x + 4) % 5] ^ rotateLeft(columns[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y += 1) {
        state[x + 5 * y] = (state[x + 5 * y] ^ delta) & MASK_64;
      }
    }

    const rotated = Array(25).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const source = x + 5 * y;
        const target = y + 5 * ((2 * x + 3 * y) % 5);
        rotated[target] = rotateLeft(state[source], ROTATION_OFFSETS[source]);
      }
    }

    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const index = x + 5 * y;
        const next = (x + 1) % 5 + 5 * y;
        const nextAgain = (x + 2) % 5 + 5 * y;
        state[index] = (rotated[index] ^ (~rotated[next] & rotated[nextAgain])) & MASK_64;
      }
    }
    state[0] = (state[0] ^ roundConstant) & MASK_64;
  }
}

function rotateLeft(value, shift) {
  const bits = BigInt(shift);
  return ((value << bits) | (value >> (64n - bits))) & MASK_64;
}
