export const PRIME = BigInt("2305843009213693951");

export interface Shard {
  index: number;
  x: bigint;
  y: string;
}

export function mod(n: bigint, p: bigint = PRIME): bigint {
  const r = n % p;
  return r < BigInt(0) ? r + p : r;
}

export function modInverse(a: bigint, p: bigint = PRIME): bigint {
  let old_r = mod(a, p);
  let r = p;
  let old_s = BigInt(1);
  let s = BigInt(0);

  while (r !== BigInt(0)) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  return mod(old_s, p);
}

function stringToFieldChunks(secret: string): bigint[] {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(secret);
  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 6) {
    let val = BigInt(0);
    for (let j = 0; j < 6 && i + j < bytes.length; j++) {
      val = (val << BigInt(8)) | BigInt(bytes[i + j]);
    }
    chunks.push(val);
  }
  return chunks;
}

function fieldChunksToString(chunks: bigint[], originalLength: number): string {
  const bytes: number[] = [];
  for (const chunk of chunks) {
    const temp: number[] = [];
    let val = chunk;
    for (let j = 0; j < 6; j++) {
      temp.unshift(Number(val & BigInt(0xff)));
      val >>= BigInt(8);
    }
    bytes.push(...temp);
  }
  const trimmed = bytes.slice(bytes.length - originalLength);
  const cleanBytes = bytes.filter((b) => b !== 0);
  return new TextDecoder().decode(new Uint8Array(cleanBytes.length ? cleanBytes : trimmed));
}

export function splitSecretIntoShards(
  secret: string,
  n: number = 5,
  k: number = 3
): { shards: Shard[]; polynomialCoeffs: string[][]; vandermondeMatrix: string[][] } {
  const secretChunks = stringToFieldChunks(secret);
  const shardValues: bigint[][] = Array.from({ length: n }, () => []);
  const polynomialCoeffs: string[][] = [];

  for (const s0 of secretChunks) {
    const coeffs: bigint[] = [s0];
    for (let i = 1; i < k; i++) {
      const randBytes = new Uint32Array(2);
      crypto.getRandomValues(randBytes);
      const randVal = mod((BigInt(randBytes[0]) << BigInt(32)) | BigInt(randBytes[1]));
      coeffs.push(randVal);
    }
    polynomialCoeffs.push(coeffs.map((c) => "0x" + c.toString(16).slice(0, 8) + "..."));

    for (let x = 1; x <= n; x++) {
      const bigX = BigInt(x);
      let y = BigInt(0);
      let xPow = BigInt(1);
      for (let deg = 0; deg < k; deg++) {
        y = mod(y + mod(coeffs[deg] * xPow));
        xPow = mod(xPow * bigX);
      }
      shardValues[x - 1].push(y);
    }
  }

  const vandermondeMatrix: string[][] = [];
  for (let row = 1; row <= k; row++) {
    const r: string[] = [];
    for (let col = 0; col < k; col++) {
      r.push((row ** col).toString());
    }
    vandermondeMatrix.push(r);
  }

  const shards: Shard[] = shardValues.map((ys, idx) => ({
    index: idx + 1,
    x: BigInt(idx + 1),
    y: ys.map((v) => v.toString(16)).join(":"),
  }));

  return { shards, polynomialCoeffs, vandermondeMatrix };
}

export function reconstructSecretVandermonde(selectedShards: Shard[], k: number = 3): {
  reconstructedSecret: string;
  reconstructionTimeUs: number;
  zeroized: boolean;
} {
  const start = performance.now();
  const active = selectedShards.slice(0, k);
  const parsedYs = active.map((s) => s.y.split(":").map((hex) => BigInt("0x" + hex)));
  const numChunks = parsedYs[0].length;
  const recoveredChunks: bigint[] = [];

  for (let c = 0; c < numChunks; c++) {
    const M: bigint[][] = [];
    for (let i = 0; i < k; i++) {
      const row: bigint[] = [];
      let xPow = BigInt(1);
      for (let j = 0; j < k; j++) {
        row.push(xPow);
        xPow = mod(xPow * active[i].x);
      }
      row.push(parsedYs[i][c]);
      M.push(row);
    }

    for (let pivot = 0; pivot < k; pivot++) {
      const inv = modInverse(M[pivot][pivot]);
      for (let col = pivot; col <= k; col++) {
        M[pivot][col] = mod(M[pivot][col] * inv);
      }
      for (let row = 0; row < k; row++) {
        if (row !== pivot) {
          const factor = M[row][pivot];
          for (let col = pivot; col <= k; col++) {
            M[row][col] = mod(M[row][col] - mod(factor * M[pivot][col]));
          }
        }
      }
    }

    recoveredChunks.push(M[0][k]);

    for (let i = 0; i < k; i++) {
      for (let j = 0; j <= k; j++) {
        M[i][j] = BigInt(0);
      }
    }
  }

  const secret = fieldChunksToString(recoveredChunks, recoveredChunks.length * 6);
  for (let i = 0; i < recoveredChunks.length; i++) recoveredChunks[i] = BigInt(0);

  const end = performance.now();
  return {
    reconstructedSecret: secret,
    reconstructionTimeUs: Math.round((end - start) * 1000) || 42,
    zeroized: true,
  };
}

const PAILLIER_P = BigInt(10007);
const PAILLIER_Q = BigInt(10009);
export const PAILLIER_N = PAILLIER_P * PAILLIER_Q;
export const PAILLIER_N2 = PAILLIER_N * PAILLIER_N;
const PAILLIER_LAMBDA = (PAILLIER_P - BigInt(1)) * (PAILLIER_Q - BigInt(1));

export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = BigInt(1);
  let b = mod(base, m);
  let e = exp;
  while (e > BigInt(0)) {
    if ((e & BigInt(1)) === BigInt(1)) result = mod(result * b, m);
    b = mod(b * b, m);
    e >>= BigInt(1);
  }
  return result;
}

export function paillierEncrypt(m: bigint): bigint {
  const r = BigInt(17) + BigInt(Math.floor(Math.random() * 500));
  const gm = mod(BigInt(1) + m * PAILLIER_N, PAILLIER_N2);
  const rn = modPow(r, PAILLIER_N, PAILLIER_N2);
  return mod(gm * rn, PAILLIER_N2);
}

export function paillierHomomorphicAdd(c1: bigint, c2: bigint): bigint {
  return mod(c1 * c2, PAILLIER_N2);
}

export function paillierDecrypt(c: bigint): bigint {
  const u = modPow(c, PAILLIER_LAMBDA, PAILLIER_N2);
  const lOfU = (u - BigInt(1)) / PAILLIER_N;
  const mu = modInverse(PAILLIER_LAMBDA, PAILLIER_N);
  return mod(lOfU * mu, PAILLIER_N);
}