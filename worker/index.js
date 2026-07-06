// Cloudflare Worker — License 查询端点
//
// 端点：
//   GET /v1/query?machine_id=xxx
//   → 从 KV 读取 CData → ECDSA 签名 → 返回 LicenseSign JSON
//
// 环境变量（通过 wrangler secret put 设置）：
//   PRIVATE_KEY — PEM 格式的 ECC 私钥（SEC1 或 PKCS8）
//
// KV 绑定：
//   LICENSES — key=machine_id, value=CData 字符串

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 路由：GET /v1/query?machine_id=xxx
    if (url.pathname === '/v1/query' && request.method === 'GET') {
      const machineID = url.searchParams.get('machine_id');
      if (!machineID) {
        return new Response(JSON.stringify({ error: '缺少 machine_id' }), {
          status: 400, headers: { 'Content-Type': 'application/json' },
        });
      }

      // 从 KV 读取 CData
      const cdata = await env.LICENSES.get(machineID);
      if (!cdata) {
        return new Response(JSON.stringify({ error: 'license 不存在' }), {
          status: 404, headers: { 'Content-Type': 'application/json' },
        });
      }

      // 生成签名
      const timestamp = Math.floor(Date.now() / 1000);
      const payload = `${cdata}|${timestamp}`;
      const signature = await signPEM(env.PRIVATE_KEY, payload);

      // 返回 LicenseSign JSON
      const ls = { c_data: cdata, timestamp, signature, revoked: false };
      return new Response(JSON.stringify(ls), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};

// signPEM 使用 PEM 私钥对 payload 进行 ECDSA P-256 签名。
// 返回 ASN.1 DER 编码 + base64 StdEncoding 的签名字符串。
async function signPEM(pem, payload) {
  const keyData = pemToDer(pem);
  const key = await crypto.subtle.importKey(
    'pkcs8', keyData,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['sign']
  );
  const data = new TextEncoder().encode(payload);
  const sigP1363 = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, data
  );
  const sigDER = p1363ToDER(new Uint8Array(sigP1363));
  return btoa(String.fromCharCode(...sigDER));
}

// pemToDer 解析 PEM 格式的私钥，返回 PKCS8 DER 字节。
// 支持 SEC1（EC PRIVATE KEY）和 PKCS8（PRIVATE KEY）两种块，
// 自动跳过 EC PARAMETERS 块。
function pemToDer(pem) {
  const lines = pem.split('\n');
  let derLines = [], capture = false, skipParam = false;
  for (const line of lines) {
    const t = line.trim();
    if (t === '-----BEGIN EC PRIVATE KEY-----') { capture = true; continue; }
    if (t === '-----BEGIN PRIVATE KEY-----') { capture = true; continue; }
    if (t === '-----END EC PRIVATE KEY-----' || t === '-----END PRIVATE KEY-----') { break; }
    if (t === '-----BEGIN EC PARAMETERS-----') { skipParam = true; continue; }
    if (t === '-----END EC PARAMETERS-----') { skipParam = false; continue; }
    if (capture && !skipParam) derLines.push(t);
  }
  const derB64 = derLines.join('');
  const binaryStr = atob(derB64);
  const bytes = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
  return bytes;
}

// p1363ToDER 将 ECDSA P-1363 签名格式（r||s）转为 ASN.1 DER。
// 输入：64 字节的 Uint8Array（r=32, s=32）
// 输出：ASN.1 DER 编码的 Uint8Array
function p1363ToDER(sig) {
  const r = removeLeadingZeros(sig.slice(0, 32));
  const s = removeLeadingZeros(sig.slice(32));
  return encodeSEQUENCE([encodeINTEGER(r), encodeINTEGER(s)]);
}

function removeLeadingZeros(bytes) {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) start++;
  const result = bytes.slice(start);
  // 如果最高位 >= 0x80，需要加 0x00 前缀（DER INTEGER 有符号编码）
  if (result.length > 0 && result[0] >= 0x80) {
    const padded = new Uint8Array(result.length + 1);
    padded[0] = 0x00;
    padded.set(result, 1);
    return padded;
  }
  return result.length > 0 ? result : new Uint8Array([0x00]);
}

function encodeINTEGER(bytes) {
  const tag = 0x02;
  const len = bytes.length;
  return concatBytes([tag, len], bytes);
}

function encodeSEQUENCE(children) {
  const content = concatBytes(...children);
  const tag = 0x30;
  const len = content.length;
  if (len < 128) return concatBytes([tag, len], content);
  // 对于 P-256 签名，长度总是 < 128，所以不需要处理长编码
  return concatBytes([tag, len], content);
}

function concatBytes(...arrays) {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}