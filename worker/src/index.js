// T08 내 소개 페이지에 패스키 달기 — 비밀번호 없이 나만 들어가기
// 외부 라이브러리 없음: WebAuthn 검증(CBOR 해석, authData 파싱, 서명 확인)을 Workers 내장 Web Crypto로 직접 구현.
// 비밀키 없음: 세션은 서명이 필요 없는 무작위 토큰을 서버 DB에 저장하는 방식.

const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 일회용 질문 유효시간 5분
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7일
const ALG_ES256 = -7;
const ALG_RS256 = -257;

// ---------------- 공통 ----------------

function json(data, status, extraHeaders) {
  const headers = Object.assign({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }, extraHeaders || {});
  return new Response(JSON.stringify(data), { status: status || 200, headers });
}
function badRequest(message) { return json({ error: message }, 400); }
function unauthorized(message) { return json({ error: message || "패스키로 로그인해야 볼 수 있습니다." }, 401); }
function forbidden(message) { return json({ error: message || "권한이 없습니다." }, 403); }
function notFound() { return json({ error: "not found" }, 404); }
function newId() { return crypto.randomUUID(); }
function nowIso() { return new Date().toISOString(); }
async function readJson(request) {
  try { return await request.json(); } catch (e) { return null; }
}
function cleanText(v, max) {
  if (typeof v !== "string") return "";
  return v.trim().slice(0, max);
}

// ---------------- base64url / 바이트 ----------------

function b64urlEncode(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  if (typeof str !== "string" || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error("base64url 형식이 아닙니다.");
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function randomB64url(n) { return b64urlEncode(crypto.getRandomValues(new Uint8Array(n))); }
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }

// ---------------- CBOR (WebAuthn에 필요한 만큼만) ----------------
// 반환: { value, offset } — offset은 다음 항목이 시작되는 위치 (authData 안의 공개키 뒤에 확장 데이터가 붙을 수 있어서 필요)

function cborDecode(bytes, start) {
  let pos = start || 0;
  function readLength(info) {
    if (info < 24) return info;
    let n = 0, size = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
    if (!size) throw new Error("CBOR: 지원하지 않는 길이 형식");
    if (pos + size > bytes.length) throw new Error("CBOR: 데이터가 잘렸습니다");
    for (let i = 0; i < size; i++) n = n * 256 + bytes[pos++];
    return n;
  }
  function item(depth) {
    if (depth > 16) throw new Error("CBOR: 너무 깊음");
    if (pos >= bytes.length) throw new Error("CBOR: 데이터가 잘렸습니다");
    const first = bytes[pos++];
    const major = first >> 5, info = first & 31;
    if (major === 7) {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      throw new Error("CBOR: 지원하지 않는 값");
    }
    const len = readLength(info);
    switch (major) {
      case 0: return len;
      case 1: return -1 - len;
      case 2: {
        if (pos + len > bytes.length) throw new Error("CBOR: 데이터가 잘렸습니다");
        const v = bytes.slice(pos, pos + len); pos += len; return v;
      }
      case 3: {
        if (pos + len > bytes.length) throw new Error("CBOR: 데이터가 잘렸습니다");
        const v = new TextDecoder().decode(bytes.slice(pos, pos + len)); pos += len; return v;
      }
      case 4: { const arr = []; for (let i = 0; i < len; i++) arr.push(item(depth + 1)); return arr; }
      case 5: { const m = new Map(); for (let i = 0; i < len; i++) { const k = item(depth + 1); m.set(k, item(depth + 1)); } return m; }
      default: throw new Error("CBOR: 지원하지 않는 형식");
    }
  }
  const value = item(0);
  return { value, offset: pos };
}

// ---------------- authenticatorData 파싱 ----------------
// [rpIdHash 32][flags 1][signCount 4][ (AT 플래그면) aaguid 16 | credIdLen 2 | credId | COSE 공개키 ]

const FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_AT = 0x40;

function parseAuthData(authData) {
  if (authData.length < 37) throw new Error("authData가 너무 짧습니다.");
  const out = {
    rpIdHash: authData.slice(0, 32),
    flags: authData[32],
    signCount: ((authData[33] << 24) >>> 0) + (authData[34] << 16) + (authData[35] << 8) + authData[36]
  };
  if (out.flags & FLAG_AT) {
    let p = 37;
    if (authData.length < p + 18) throw new Error("authData의 자격 증명 부분이 잘렸습니다.");
    p += 16; // aaguid
    const idLen = (authData[p] << 8) + authData[p + 1]; p += 2;
    if (authData.length < p + idLen) throw new Error("credential ID가 잘렸습니다.");
    out.credentialId = authData.slice(p, p + idLen); p += idLen;
    const decoded = cborDecode(authData, p);
    out.coseKey = decoded.value;
  }
  return out;
}

// COSE 공개키 → Web Crypto에 넣을 수 있는 JWK
function coseToJwk(cose) {
  if (!(cose instanceof Map)) throw new Error("공개키 형식이 올바르지 않습니다.");
  const kty = cose.get(1), alg = cose.get(3);
  if (kty === 2 && alg === ALG_ES256 && cose.get(-1) === 1) {
    const x = cose.get(-2), y = cose.get(-3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) throw new Error("EC 공개키 좌표가 올바르지 않습니다.");
    return { alg, jwk: { kty: "EC", crv: "P-256", x: b64urlEncode(x), y: b64urlEncode(y) } };
  }
  if (kty === 3 && alg === ALG_RS256) {
    const n = cose.get(-1), e = cose.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) throw new Error("RSA 공개키가 올바르지 않습니다.");
    return { alg, jwk: { kty: "RSA", n: b64urlEncode(n), e: b64urlEncode(e) } };
  }
  throw new Error("지원하지 않는 패스키 알고리즘입니다 (ES256, RS256만 지원).");
}

// ECDSA 서명: WebAuthn은 DER(ASN.1) 형식, Web Crypto는 r||s 64바이트 형식을 받으므로 변환
function derToRawEcdsa(der) {
  let p = 0;
  if (der[p++] !== 0x30) throw new Error("서명 형식 오류");
  if (der[p] & 0x80) p += 1 + (der[p] & 0x7f); else p += 1;
  function readInt() {
    if (der[p++] !== 0x02) throw new Error("서명 형식 오류");
    const len = der[p++];
    let v = der.slice(p, p + len); p += len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) throw new Error("서명 형식 오류");
    const out = new Uint8Array(32); out.set(v, 32 - v.length);
    return out;
  }
  const r = readInt(), s = readInt();
  return concatBytes(r, s);
}

async function verifySignature(alg, jwk, signature, data) {
  if (alg === ALG_ES256) {
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRawEcdsa(signature), data);
  }
  if (alg === ALG_RS256) {
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
  }
  return false;
}

// clientDataJSON: 브라우저가 "어느 사이트(origin)에서, 어떤 질문(challenge)에, 무슨 동작(type)으로" 서명했는지 적은 것
function checkClientData(clientDataBytes, expectedType, expectedChallenge, expectedOrigin) {
  let cd;
  try { cd = JSON.parse(new TextDecoder().decode(clientDataBytes)); } catch (e) { throw new Error("clientDataJSON을 읽을 수 없습니다."); }
  if (cd.type !== expectedType) throw new Error("요청 종류가 맞지 않습니다.");
  if (cd.challenge !== expectedChallenge) throw new Error("질문(challenge) 값이 서버가 보낸 것과 다릅니다.");
  if (cd.origin !== expectedOrigin) throw new Error("다른 사이트에서 만든 응답입니다.");
  return cd;
}

// ---------------- 일회용 질문(challenge) ----------------

async function issueChallenge(env, kind, extra) {
  await env.DB.prepare("DELETE FROM challenges WHERE expires_at < ?").bind(nowIso()).run(); // 만료된 것 정리
  const flowId = newId();
  const challenge = randomB64url(32);
  const expires = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();
  await env.DB.prepare("INSERT INTO challenges (id, kind, challenge, user_id, username, webauthn_user_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(flowId, kind, challenge, extra.userId || null, extra.username || null, extra.webauthnUserId || null, expires).run();
  return { flowId, challenge };
}
// 꺼내면서 바로 지운다 → 같은 질문으로 두 번째 요청이 오면 행이 없어서 거절됨
async function consumeChallenge(env, flowId, kind) {
  if (typeof flowId !== "string" || !flowId) return null;
  const row = await env.DB.prepare("DELETE FROM challenges WHERE id = ? RETURNING *").bind(flowId).first();
  if (!row || row.kind !== kind) return null;
  if (row.expires_at < nowIso()) return null;
  return row;
}

// ---------------- 세션(쿠키) ----------------

function parseCookies(request) {
  const out = {};
  (request.headers.get("cookie") || "").split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    if (k) out[k] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}
function sessionCookie(token, maxAge, isHttps) {
  return `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}` + (isHttps ? "; Secure" : "");
}
async function createSession(env, userId, credentialId) {
  const token = randomB64url(32);
  const expires = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
  await env.DB.prepare("INSERT INTO sessions (id, user_id, credential_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
    .bind(token, userId, credentialId, nowIso(), expires).run();
  return token;
}
async function getSessionUser(env, request) {
  const token = parseCookies(request).session;
  if (!token) return null;
  const row = await env.DB.prepare(
    "SELECT s.id AS session_id, s.expires_at, s.credential_id, u.id AS user_id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?"
  ).bind(token).first();
  if (!row) return null;
  if (row.expires_at < nowIso()) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(token).run();
    return null;
  }
  return { sessionId: row.session_id, userId: row.user_id, username: row.username, credentialId: row.credential_id };
}

// ---------------- 등록 (계정 만들기 + 첫 패스키) ----------------

function creationOptions(ctx, challenge, webauthnUserId, username, exclude) {
  return {
    challenge,
    rp: { id: ctx.rpId, name: "김유빈 소개 페이지" },
    user: { id: webauthnUserId, name: username, displayName: username },
    pubKeyCredParams: [{ type: "public-key", alg: ALG_ES256 }, { type: "public-key", alg: ALG_RS256 }],
    timeout: CHALLENGE_TTL_MS,
    attestation: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
    excludeCredentials: exclude || []
  };
}

async function registerOptions(env, ctx, body) {
  const username = cleanText(body && body.username, 30);
  if (!/^[0-9A-Za-z가-힣_.-]{2,30}$/.test(username)) return badRequest("별명은 2~30자(한글·영문·숫자·_.-)로 정해 주세요.");
  const taken = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
  if (taken) return json({ error: "이미 있는 별명입니다." }, 409);
  const webauthnUserId = randomB64url(16);
  const { flowId, challenge } = await issueChallenge(env, "register", { username, webauthnUserId });
  return json({ flow_id: flowId, options: creationOptions(ctx, challenge, webauthnUserId, username, []) });
}

// 등록 응답 검증 공통: 질문·사이트·rpId 확인 후 공개키를 꺼낸다
async function verifyRegistration(ctx, challengeRow, credential) {
  if (!credential || !credential.response) throw new Error("패스키 응답이 비어 있습니다.");
  const clientData = b64urlDecode(credential.response.clientDataJSON);
  checkClientData(clientData, "webauthn.create", challengeRow.challenge, ctx.origin);
  const att = cborDecode(b64urlDecode(credential.response.attestationObject)).value;
  if (!(att instanceof Map) || !(att.get("authData") instanceof Uint8Array)) throw new Error("attestationObject 형식 오류");
  // attestation: "none"으로 요청했으므로 기기 제조사 증명(attStmt)은 검사하지 않는다 (설명서 ⑥ 참고)
  const auth = parseAuthData(att.get("authData"));
  if (!bytesEqual(auth.rpIdHash, await sha256(new TextEncoder().encode(ctx.rpId)))) throw new Error("다른 사이트용 패스키입니다.");
  if (!(auth.flags & FLAG_UP)) throw new Error("사용자 확인(UP)이 없습니다.");
  if (!auth.credentialId || !auth.coseKey) throw new Error("공개키가 들어 있지 않습니다.");
  const credentialId = b64urlEncode(auth.credentialId);
  if (credential.id !== credentialId) throw new Error("credential ID가 맞지 않습니다.");
  const { alg, jwk } = coseToJwk(auth.coseKey);
  const transports = Array.isArray(credential.response.transports) ? credential.response.transports.filter((t) => typeof t === "string").slice(0, 8) : [];
  return { credentialId, alg, jwk, signCount: auth.signCount, transports, userVerified: !!(auth.flags & FLAG_UV) };
}

async function saveCredential(env, userId, v, name) {
  const exists = await env.DB.prepare("SELECT id FROM credentials WHERE id = ?").bind(v.credentialId).first();
  if (exists) throw new Error("이미 등록된 패스키입니다.");
  await env.DB.prepare("INSERT INTO credentials (id, user_id, name, public_key_jwk, alg, sign_count, transports, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(v.credentialId, userId, name, JSON.stringify(v.jwk), v.alg, v.signCount, JSON.stringify(v.transports), nowIso()).run();
}

async function registerVerify(env, ctx, body) {
  const name = cleanText(body && body.passkey_name, 40) || "내 패스키";
  const row = await consumeChallenge(env, body && body.flow_id, "register");
  if (!row) return badRequest("질문이 없거나 이미 쓰였거나 만료되었습니다. 처음부터 다시 해 주세요.");
  let v;
  try { v = await verifyRegistration(ctx, row, body.credential); } catch (e) { return badRequest("패스키 등록 실패: " + e.message); }
  const taken = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(row.username).first();
  if (taken) return json({ error: "이미 있는 별명입니다." }, 409);
  const userId = newId();
  await env.DB.prepare("INSERT INTO users (id, username, webauthn_user_id, created_at) VALUES (?, ?, ?, ?)")
    .bind(userId, row.username, row.webauthn_user_id, nowIso()).run();
  try { await saveCredential(env, userId, v, name); }
  catch (e) {
    await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
    return badRequest(e.message);
  }
  const token = await createSession(env, userId, v.credentialId);
  return json({ ok: true, username: row.username, passkey: { id: v.credentialId, name } }, 201, { "set-cookie": sessionCookie(token, SESSION_TTL_SECONDS, ctx.isHttps) });
}

// 등록 도중 취소: 보관해 둔 질문까지 지워서 서버에 아무것도 남지 않게 한다
async function registerCancel(env, body) {
  if (body && typeof body.flow_id === "string") {
    await env.DB.prepare("DELETE FROM challenges WHERE id = ? AND kind IN ('register', 'add')").bind(body.flow_id).run();
  }
  return json({ ok: true });
}

// ---------------- 로그인 ----------------

async function loginOptions(env, ctx) {
  const { flowId, challenge } = await issueChallenge(env, "login", {});
  // allowCredentials를 비워 두면 기기가 이 사이트용 패스키를 직접 골라 준다(별명 입력도 필요 없음)
  return json({ flow_id: flowId, options: { challenge, rpId: ctx.rpId, timeout: CHALLENGE_TTL_MS, userVerification: "preferred", allowCredentials: [] } });
}

async function loginVerify(env, ctx, body) {
  const row = await consumeChallenge(env, body && body.flow_id, "login");
  if (!row) return unauthorized("질문이 없거나 이미 쓰였거나 만료되었습니다. 다시 로그인해 주세요.");
  const credential = body.credential;
  try {
    if (!credential || !credential.response || typeof credential.id !== "string") throw new Error("패스키 응답이 비어 있습니다.");
    const stored = await env.DB.prepare("SELECT * FROM credentials WHERE id = ?").bind(credential.id).first();
    if (!stored) throw new Error("등록되지 않은(또는 지워진) 패스키입니다.");
    const clientData = b64urlDecode(credential.response.clientDataJSON);
    checkClientData(clientData, "webauthn.get", row.challenge, ctx.origin);
    const authData = b64urlDecode(credential.response.authenticatorData);
    const auth = parseAuthData(authData);
    if (!bytesEqual(auth.rpIdHash, await sha256(new TextEncoder().encode(ctx.rpId)))) throw new Error("다른 사이트용 패스키입니다.");
    if (!(auth.flags & FLAG_UP)) throw new Error("사용자 확인(UP)이 없습니다.");
    if (credential.response.userHandle) {
      const owner = await env.DB.prepare("SELECT webauthn_user_id FROM users WHERE id = ?").bind(stored.user_id).first();
      if (!owner || owner.webauthn_user_id !== credential.response.userHandle) throw new Error("패스키 주인이 맞지 않습니다.");
    }
    // 서명 대상 = authenticatorData || SHA-256(clientDataJSON). 저장해 둔 "공개키"로만 확인한다.
    const signed = concatBytes(authData, await sha256(clientData));
    const ok = await verifySignature(stored.alg, JSON.parse(stored.public_key_jwk), b64urlDecode(credential.response.signature), signed);
    if (!ok) throw new Error("서명이 공개키와 맞지 않습니다.");
    // 서명 횟수: 둘 중 하나라도 0이 아니면 반드시 늘어나야 함(복제된 패스키 감지). 구글 비밀번호 관리자처럼 항상 0인 곳도 있음.
    if ((auth.signCount > 0 || stored.sign_count > 0) && auth.signCount <= stored.sign_count) throw new Error("서명 횟수가 줄었습니다(복제 의심).");
    await env.DB.prepare("UPDATE credentials SET sign_count = ?, last_used_at = ? WHERE id = ?").bind(auth.signCount, nowIso(), stored.id).run();
    const user = await env.DB.prepare("SELECT username FROM users WHERE id = ?").bind(stored.user_id).first();
    const token = await createSession(env, stored.user_id, stored.id);
    return json({ ok: true, username: user.username, passkey: { id: stored.id, name: stored.name } }, 200, { "set-cookie": sessionCookie(token, SESSION_TTL_SECONDS, ctx.isHttps) });
  } catch (e) {
    return unauthorized("로그인 실패: " + e.message);
  }
}

async function logout(env, ctx, request) {
  const token = parseCookies(request).session;
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(token).run(); // 서버에서 세션 행 자체를 지움
  return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0, ctx.isHttps) });
}

// ---------------- 로그인 후: 내 정보·패스키 관리 ----------------

async function listMyPasskeys(env, auth) {
  const { results } = await env.DB.prepare("SELECT id, name, created_at, last_used_at FROM credentials WHERE user_id = ? ORDER BY created_at ASC").bind(auth.userId).all();
  return results;
}
async function me(env, auth) {
  return json({ username: auth.username, current_passkey_id: auth.credentialId, passkeys: await listMyPasskeys(env, auth) });
}

async function addPasskeyOptions(env, ctx, auth) {
  const user = await env.DB.prepare("SELECT webauthn_user_id FROM users WHERE id = ?").bind(auth.userId).first();
  const { results } = await env.DB.prepare("SELECT id, transports FROM credentials WHERE user_id = ?").bind(auth.userId).all();
  // 이미 등록한 패스키는 제외하라고 기기에 알려 줌(같은 기기에 중복 등록 방지)
  const exclude = results.map((c) => ({ type: "public-key", id: c.id, transports: JSON.parse(c.transports || "[]") }));
  const { flowId, challenge } = await issueChallenge(env, "add", { userId: auth.userId });
  return json({ flow_id: flowId, options: creationOptions(ctx, challenge, user.webauthn_user_id, auth.username, exclude) });
}

async function addPasskeyVerify(env, ctx, auth, body) {
  const name = cleanText(body && body.passkey_name, 40) || "추가 패스키";
  const row = await consumeChallenge(env, body && body.flow_id, "add");
  if (!row || row.user_id !== auth.userId) return badRequest("질문이 없거나 이미 쓰였거나 만료되었습니다. 다시 시도해 주세요.");
  try {
    const v = await verifyRegistration(ctx, row, body.credential);
    await saveCredential(env, auth.userId, v, name);
    return json({ ok: true, passkey: { id: v.credentialId, name } }, 201);
  } catch (e) {
    return badRequest("패스키 추가 실패: " + e.message);
  }
}

async function deletePasskey(env, auth, credentialId) {
  const target = await env.DB.prepare("SELECT id FROM credentials WHERE id = ? AND user_id = ?").bind(credentialId, auth.userId).first();
  if (!target) return notFound(); // 남의 패스키는 "없는 것"과 똑같이 응답
  const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?").bind(auth.userId).first();
  if (count.n <= 1) return json({ error: "마지막 패스키는 지울 수 없습니다. 지우면 이 계정에 다시 들어올 방법이 없어집니다. 먼저 다른 패스키를 추가하세요." }, 409);
  await env.DB.prepare("DELETE FROM credentials WHERE id = ? AND user_id = ?").bind(credentialId, auth.userId).run();
  await env.DB.prepare("DELETE FROM sessions WHERE credential_id = ?").bind(credentialId).run(); // 그 패스키로 열린 세션도 끊음
  return json({ ok: true, logged_out: credentialId === auth.credentialId });
}

// ---------------- 비공개 자리 ----------------
// 모든 조회·추가·삭제의 기준은 "세션의 user_id" 하나뿐. 주소나 본문에 다른 계정을 적어도 무시된다.

async function listPrivate(env, auth) {
  const { results } = await env.DB.prepare("SELECT id, title, body, created_at FROM private_items WHERE user_id = ? ORDER BY created_at ASC").bind(auth.userId).all();
  return json({ owner: auth.username, count: results.length, items: results });
}
async function createPrivate(env, auth, body) {
  const title = cleanText(body && body.title, 80);
  const text = cleanText(body && body.body, 1000);
  if (!title) return badRequest("제목을 적어 주세요.");
  const id = newId();
  await env.DB.prepare("INSERT INTO private_items (id, user_id, title, body, created_at) VALUES (?, ?, ?, ?, ?)").bind(id, auth.userId, title, text, nowIso()).run();
  return json({ item: { id, title, body: text } }, 201);
}
async function deletePrivate(env, auth, id) {
  const res = await env.DB.prepare("DELETE FROM private_items WHERE id = ? AND user_id = ?").bind(id, auth.userId).run();
  if (!res.meta.changes) return notFound();
  return json({ ok: true });
}

// ---------------- 라우터 ----------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    if (!path.startsWith("/api/")) return notFound(); // 정적 파일(public/)은 assets가 먼저 처리함

    const ctx = { rpId: url.hostname, origin: url.origin, isHttps: url.protocol === "https:" };

    // 상태를 바꾸는 요청은 같은 사이트에서 온 것만 받음(CSRF 완화)
    if (method !== "GET") {
      const origin = request.headers.get("origin");
      if (origin && origin !== ctx.origin) return forbidden("다른 사이트에서 온 요청입니다.");
    }

    try {
      if (path === "/api/register/options" && method === "POST") return await registerOptions(env, ctx, await readJson(request));
      if (path === "/api/register/verify" && method === "POST") return await registerVerify(env, ctx, await readJson(request));
      if (path === "/api/register/cancel" && method === "POST") return await registerCancel(env, await readJson(request));
      if (path === "/api/login/options" && method === "POST") return await loginOptions(env, ctx);
      if (path === "/api/login/verify" && method === "POST") return await loginVerify(env, ctx, await readJson(request));
      if (path === "/api/logout" && method === "POST") return await logout(env, ctx, request);

      // 여기부터는 패스키로 로그인한 세션이 있어야 함
      const auth = await getSessionUser(env, request);
      if (!auth) return unauthorized();

      if (path === "/api/me" && method === "GET") return await me(env, auth);
      if (path === "/api/passkeys/options" && method === "POST") return await addPasskeyOptions(env, ctx, auth);
      if (path === "/api/passkeys/verify" && method === "POST") return await addPasskeyVerify(env, ctx, auth, await readJson(request));
      let m = path.match(/^\/api\/passkeys\/([A-Za-z0-9_-]+)$/);
      if (m && method === "DELETE") return await deletePasskey(env, auth, m[1]);

      if (path === "/api/private" && method === "GET") return await listPrivate(env, auth);
      if (path === "/api/private" && method === "POST") return await createPrivate(env, auth, await readJson(request));
      m = path.match(/^\/api\/private\/([0-9a-f-]{36})$/);
      if (m && method === "DELETE") return await deletePrivate(env, auth, m[1]);

      return notFound();
    } catch (e) {
      return json({ error: "서버 오류: " + e.message }, 500);
    }
  }
};
