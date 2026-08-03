const MAX_RESPONSE_BYTES = 16 * 1024;
const MAX_HNSA_HEX_LENGTH = 2 * 1024;
const MAX_SNAPSHOT_HEX_LENGTH = 2 * 512;
const REQUEST_TIMEOUT_MS = 5_000;
const PROFILE_ID = 0xff00;
const MODES = ["Bootstrapping", "Mining", "Degraded", "Fallback", "Draining", "Stopped"];

export async function fetchPoolStats(endpoint, fetchImpl = fetch) {
  const url = poolStatsUrl(endpoint);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetchImpl(url, {
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`Pool endpoint returned HTTP ${response.status}`);
    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
      throw new Error("Pool response exceeds the size limit");
    }
    const bytes = await readBoundedBody(response, MAX_RESPONSE_BYTES);
    return {
      endpoint: url.origin,
      snapshot: parsePoolStatsDocument(JSON.parse(new TextDecoder().decode(bytes)))
    };
  } finally {
    clearTimeout(timeout);
  }
}

export function parsePoolStatsDocument(document) {
  if (
    !document ||
    document.schema !== "meshmine-pool-stats-v1" ||
    document.service_name !== "pool-stats" ||
    document.profile_id !== PROFILE_ID
  ) {
    throw new Error("Unsupported MeshMine pool document");
  }
  boundedHex(document.service_authorization, MAX_HNSA_HEX_LENGTH, "service authorization");
  boundedHex(document.endpoint_delegation, MAX_HNSA_HEX_LENGTH, "endpoint delegation");
  const bytes = boundedHex(document.snapshot, MAX_SNAPSHOT_HEX_LENGTH, "snapshot");
  return decodeSnapshot(bytes);
}

export function poolStatsUrl(endpoint) {
  const url = new URL(endpoint);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error("Use an HTTP or HTTPS pool endpoint without embedded credentials");
  }
  url.hash = "";
  url.search = "";
  url.pathname = "/api/v1/pool-stats";
  return url;
}

async function readBoundedBody(response, maximum) {
  if (!response.body?.getReader) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > maximum) throw new Error("Pool response exceeds the size limit");
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > maximum) {
      await reader.cancel();
      throw new Error("Pool response exceeds the size limit");
    }
    chunks.push(value);
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function boundedHex(value, maximumLength, field) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    value.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(value)
  ) {
    throw new Error(`Invalid ${field}`);
  }
  return Uint8Array.from(value.match(/../g), (byte) => Number.parseInt(byte, 16));
}

function decodeSnapshot(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  const need = (length) => {
    if (offset + length > bytes.length) throw new Error("Truncated pool snapshot");
  };
  const u8 = () => {
    need(1);
    return view.getUint8(offset++);
  };
  const u16 = () => {
    need(2);
    const value = view.getUint16(offset, true);
    offset += 2;
    return value;
  };
  const u32 = () => {
    need(4);
    const value = view.getUint32(offset, true);
    offset += 4;
    return value;
  };
  const u64 = () => {
    need(8);
    const value = view.getBigUint64(offset, true);
    offset += 8;
    return value;
  };
  const hex = (length) => {
    need(length);
    const result = [...bytes.slice(offset, offset + length)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    offset += length;
    return result;
  };

  if (u8() !== 1) throw new Error("Unsupported pool snapshot version");
  const networkMagic = u32();
  if (u16() !== PROFILE_ID) throw new Error("Pool snapshot profile mismatch");
  const authorizationId = hex(32);
  const delegationId = hex(32);
  const endpointSequence = u64();
  const sequence = u64();
  const generatedAt = u64();
  const expiresAt = u64();
  const operatorId = hex(32);
  const tipHeight = u32();
  const tipHash = hex(32);
  const connectedMiners = u32();
  const connectedMeshPeers = u32();
  const acceptedShares = u64();
  const rejectedShares = u64();
  const pendingCaptures = u32();
  const found = u8();
  if (found === 1) {
    u32();
    hex(32);
  } else if (found !== 0) {
    throw new Error("Invalid last-block option");
  }
  const modeValue = u8();
  const productionValue = u8();
  const signatureLength = u8();
  if (signatureLength === 0 || signatureLength > 80) throw new Error("Invalid snapshot signature");
  hex(signatureLength);
  if (offset !== bytes.length) throw new Error("Trailing pool snapshot bytes");
  if (
    !MODES[modeValue] ||
    productionValue > 1 ||
    /^0+$/.test(authorizationId) ||
    /^0+$/.test(delegationId) ||
    /^0+$/.test(operatorId) ||
    endpointSequence === 0n ||
    sequence === 0n
  ) {
    throw new Error("Invalid pool snapshot fields");
  }
  if (expiresAt <= generatedAt || expiresAt - generatedAt > 120n) {
    throw new Error("Invalid pool snapshot lifetime");
  }
  return {
    verified: false,
    networkMagic,
    endpointSequence,
    sequence,
    generatedAt,
    expiresAt,
    operatorId,
    tipHeight,
    tipHash,
    connectedMiners,
    connectedMeshPeers,
    acceptedShares,
    rejectedShares,
    pendingCaptures,
    mode: MODES[modeValue],
    productionEligible: productionValue === 1
  };
}
