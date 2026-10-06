// T08 로컬 검증: 실제 기기 대신 "소프트웨어 인증기"(테스트용 가짜 패스키)를 만들어 서버를 끝까지 두드려 본다.
// 실행: (터미널 1) npx wrangler dev --local   (터미널 2) node test/passkey-check.mjs [http://localhost:8787]
// 세션 토큰은 앞 6글자만 출력하고 나머지는 가린다.

const BASE = process.argv[2] || "http://localhost:8787";
const ORIGIN = new URL(BASE).origin;
const RP_ID = new URL(BASE).hostname;
const subtle = globalThis.crypto.subtle;

let failures = 0;
function check(label, cond) {
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${label}`);
  if (!cond) failures++;
}
function section(t) { console.log(`\n### ${t}`); }
const mask = (t) => (t ? t.slice(0, 6) + "…(가림)" : t);

// ---------- 바이트 도구 ----------
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const fromB64url = (s) => new Uint8Array(Buffer.from(s, "base64url"));
const concat = (...arrs) => { const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let p = 0; for (const a of arrs) { out.set(a, p); p += a.length; } return out; };
const sha256 = async (b) => new Uint8Array(await subtle.digest("SHA-256", b));
const u32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);

// ---------- CBOR 인코더 (인증기가 만드는 형식 흉내) ----------
function cborHead(major, n) {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
  if (n < 65536) return new Uint8Array([(major << 5) | 25, n >> 8, n & 255]);
  return concat(new Uint8Array([(major << 5) | 26]), u32(n));
}
function cbor(v) {
  if (typeof v === "number") return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (typeof v === "string") { const b = new TextEncoder().encode(v); return concat(cborHead(3, b.length), b); }
  if (v instanceof Uint8Array) return concat(cborHead(2, v.length), v);
  const entries = v instanceof Map ? [...v.entries()] : Object.entries(v);
  return concat(cborHead(5, entries.length), ...entries.flatMap(([k, val]) => [cbor(k), cbor(val)]));
}

// ECDSA raw(r||s) → DER (실제 인증기가 보내는 서명 형식)
function rawToDer(raw) {
  const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); if (b[0] & 0x80) b = concat(new Uint8Array([0]), b); return concat(new Uint8Array([2, b.length]), b); };
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

// ---------- 소프트웨어 인증기: 개인키는 이 객체 안에만 있고 절대 서버로 보내지 않는다 ----------
class SoftAuthenticator {
  constructor(label) { this.label = label; this.creds = []; }
  async create(options) {
    const { privateKey, publicKey } = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = await subtle.exportKey("jwk", publicKey);
    const credId = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, fromB64url(jwk.x)], [-3, fromB64url(jwk.y)]]);
    const authData = concat(await sha256(new TextEncoder().encode(options.rp.id)), new Uint8Array([0x45]), u32(0), new Uint8Array(16), new Uint8Array([0, 32]), credId, cbor(cose));
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin: ORIGIN, crossOrigin: false }));
    const cred = { id: b64url(credId), privateKey, publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, userHandle: options.user.id, rpId: options.rp.id, signCount: 0 };
    this.creds.push(cred);
    return { cred, response: { id: cred.id, rawId: cred.id, type: "public-key", response: { clientDataJSON: b64url(clientDataJSON), attestationObject: b64url(cbor({ fmt: "none", attStmt: {}, authData })), transports: ["internal"] } } };
  }
  async get(options, cred, { tamper } = {}) {
    cred.signCount++;
    const authData = concat(await sha256(new TextEncoder().encode(options.rpId)), new Uint8Array([0x05]), u32(cred.signCount));
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin: ORIGIN, crossOrigin: false }));
    const raw = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, cred.privateKey, concat(authData, await sha256(clientDataJSON))));
    if (tamper) raw[10] ^= 0xff; // 일부러 틀린 서명
    return { id: cred.id, rawId: cred.id, type: "public-key", response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(rawToDer(raw)), userHandle: cred.userHandle } };
  }
}

// ---------- HTTP (쿠키 직접 관리) ----------
async function call(method, path, body, cookie) {
  const headers = { origin: ORIGIN };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (cookie) headers.cookie = `session=${cookie}`;
  const res = await fetch(BASE + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const setCookie = res.headers.get("set-cookie") || "";
  const m = setCookie.match(/session=([^;]*)/);
  let data; try { data = await res.json(); } catch { data = null; }
  return { status: res.status, data, session: m ? m[1] : undefined };
}
const show = (label, r) => console.log(`  ${label} → ${r.status} ${JSON.stringify(r.data)}`);

async function registerAccount(auth, username, passkeyName) {
  const opt = await call("POST", "/api/register/options", { username });
  const { cred, response } = await auth.create(opt.data.options);
  const ver = await call("POST", "/api/register/verify", { flow_id: opt.data.flow_id, credential: response, passkey_name: passkeyName });
  return { opt, cred, response, ver, session: ver.session };
}
async function login(auth, cred, opts) {
  const opt = await call("POST", "/api/login/options", {});
  const assertion = await auth.get(opt.data.options, cred, opts);
  const ver = await call("POST", "/api/login/verify", { flow_id: opt.data.flow_id, credential: assertion });
  return { opt, assertion, ver, session: ver.session };
}

// =====================================================================
const run = Date.now().toString(36).slice(-4);
const A = `alice-${run}`, B = `bob-${run}`;
const devA = new SoftAuthenticator("alice 노트북"), devA2 = new SoftAuthenticator("alice 휴대폰"), devB = new SoftAuthenticator("bob 노트북");

section("1. 패스키 등록 (계정 alice)");
const o1 = await call("POST", "/api/register/options", { username: A });
const o2 = await call("POST", "/api/register/options", { username: A });
console.log(`  등록 질문 1회차 challenge: ${o1.data.options.challenge}`);
console.log(`  등록 질문 2회차 challenge: ${o2.data.options.challenge}`);
check("등록 요청마다 질문 값이 다르다 (C20)", o1.data.options.challenge !== o2.data.options.challenge);
await call("POST", "/api/register/cancel", { flow_id: o1.data.flow_id });
await call("POST", "/api/register/cancel", { flow_id: o2.data.flow_id });

const regA = await registerAccount(devA, A, "alice 노트북 크롬");
const regBody = { flow_id: "(생략)", credential: regA.response, passkey_name: "alice 노트북 크롬" };
console.log(`  등록 요청 본문의 키: credential.response = ${JSON.stringify(Object.keys(regA.response.response))}`);
const privJwk = await subtle.exportKey("jwk", regA.cred.privateKey); // 인증기 안의 개인키 (비교용, 출력하지 않음)
const sentText = JSON.stringify(regBody);
console.log(`  등록 요청 본문에 개인키 값(d)이 들어 있나? ${sentText.includes(privJwk.d)}`);
check("등록 요청 본문에 개인키가 없다 (C23)", !sentText.includes(privJwk.d));
console.log(`  인증기 공개키(JWK): ${JSON.stringify(regA.cred.publicJwk)}  ← 서버 DB의 public_key_jwk와 비교`);
show("등록 확인", regA.ver);
console.log(`  발급된 세션: ${mask(regA.session)}`);
check("등록 성공 + 세션 발급 (C21)", regA.ver.status === 201 && !!regA.session);
const reuseReg = await call("POST", "/api/register/verify", { flow_id: regA.opt.data.flow_id, credential: regA.response, passkey_name: "x" });
show("같은 등록 질문으로 다시 등록", reuseReg);
check("이미 쓴 등록 질문은 거절", reuseReg.status === 400);

section("2. 등록 중간에 취소");
const cOpt = await call("POST", "/api/register/options", { username: `cancel-${run}` });
show("취소", await call("POST", "/api/register/cancel", { flow_id: cOpt.data.flow_id }));
const afterCancel = await call("POST", "/api/register/verify", { flow_id: cOpt.data.flow_id, credential: {}, passkey_name: "x" });
show("취소한 질문으로 등록 확인 시도", afterCancel);
const sameNameAgain = await call("POST", "/api/register/options", { username: `cancel-${run}` });
console.log(`  같은 별명으로 다시 등록 시작 → ${sameNameAgain.status} (409가 아니면 계정이 안 만들어졌다는 뜻)`);
check("취소 후 서버에 계정·질문이 남지 않음 (C25)", afterCancel.status === 400 && sameNameAgain.status === 200);
await call("POST", "/api/register/cancel", { flow_id: sameNameAgain.data.flow_id });

section("3. 로그인 없이 비공개 자리 요청");
const page = await (await fetch(BASE + "/")).text();
const noAuth = await call("GET", "/api/private");
show("쿠키 없이 GET /api/private", noAuth);
check("로그인 없으면 401 (C16, C17)", noAuth.status === 401);
show("가짜 세션으로 GET /api/private", await call("GET", "/api/private", undefined, "made-up-token"));

section("4. 비공개 메모 추가 (alice 3개, bob 3개)");
for (const t of ["준비 중인 프로젝트 메모(가상)", "지원하려는 곳 목록(가상)", "이번 주 회고(가상)"]) await call("POST", "/api/private", { title: `[alice] ${t}`, body: "만들어 넣은 테스트 내용" }, regA.session);
const regB = await registerAccount(devB, B, "bob 노트북 엣지");
for (const t of ["bob 비밀 메모 1(가상)", "bob 비밀 메모 2(가상)", "bob 비밀 메모 3(가상)"]) await call("POST", "/api/private", { title: t, body: "만들어 넣은 테스트 내용" }, regB.session);
const listA = await call("GET", "/api/private", undefined, regA.session);
const listB = await call("GET", "/api/private", undefined, regB.session);
console.log(`  alice 목록: ${listA.data.count}개 ${JSON.stringify(listA.data.items.map((i) => i.title))}`);
console.log(`  bob 목록:   ${listB.data.count}개 ${JSON.stringify(listB.data.items.map((i) => i.title))}`);
check("두 계정 각각 서로 다른 비공개 내용 3개 이상 (C14, C36)", listA.data.count >= 3 && listB.data.count >= 3 && !listA.data.items.some((i) => i.title.includes("bob")));
const page2 = await (await fetch(BASE + "/")).text();
check("로그인 안 한 상태로 받은 페이지 소스에 비공개 내용 없음 (C18)", !page2.includes("[alice]") && !page2.includes("bob 비밀"));

section("5. 패스키 로그인");
await call("POST", "/api/logout", {}, regA.session);
const l1 = await login(devA, regA.cred);
const l2 = await login(devA, regA.cred);
console.log(`  로그인 질문 1회차 challenge: ${l1.opt.data.options.challenge}`);
console.log(`  로그인 질문 2회차 challenge: ${l2.opt.data.options.challenge}`);
check("로그인 요청마다 질문 값이 다르다 (C27, C28)", l1.opt.data.options.challenge !== l2.opt.data.options.challenge);
show("[성공] 올바른 서명으로 로그인", l1.ver);
const bad = await login(devA, regA.cred, { tamper: true });
show("[실패] 일부러 틀린 서명으로 로그인", bad.ver);
check("서명 확인 성공은 200, 틀린 서명은 401 (C29, C30)", l1.ver.status === 200 && bad.ver.status === 401);
const replay = await call("POST", "/api/login/verify", { flow_id: l1.opt.data.flow_id, credential: l1.assertion });
show("[재사용] 이미 쓴 질문+서명을 그대로 다시 보냄", replay);
check("이미 쓴 질문 재사용은 거절 (C31)", replay.status === 401);
const sess = l2.session;
show("로그인 세션으로 GET /api/private", { status: (await call("GET", "/api/private", undefined, sess)).status, data: `(세션 ${mask(sess)})` });
show("로그아웃", await call("POST", "/api/logout", {}, sess));
const afterLogout = await call("GET", "/api/private", undefined, sess);
show(`로그아웃 뒤 같은 세션(${mask(sess)})으로 GET /api/private`, afterLogout);
check("로그아웃 뒤 같은 세션 값은 거절 (C33)", afterLogout.status === 401);

section("6. 남의 자료 (alice ↔ bob)");
const sA = (await login(devA, regA.cred)).session;
const sB = (await login(devB, regB.cred)).session;
const bobItemId = listB.data.items[0].id, aliceItemId = listA.data.items[0].id;
const bobBefore = (await call("GET", "/api/private", undefined, sB)).data.count;
show("[alice 세션] DELETE bob의 메모", await call("DELETE", `/api/private/${bobItemId}`, undefined, sA));
show("[alice 세션] DELETE bob의 패스키", await call("DELETE", `/api/passkeys/${regB.cred.id}`, undefined, sA));
const bobAfter = (await call("GET", "/api/private", undefined, sB)).data.count;
console.log(`  bob 메모 개수: 공격 전 ${bobBefore} → 공격 후 ${bobAfter}`);
const aliceBefore = (await call("GET", "/api/private", undefined, sA)).data.count;
show("[bob 세션] DELETE alice의 메모", await call("DELETE", `/api/private/${aliceItemId}`, undefined, sB));
const aliceAfter = (await call("GET", "/api/private", undefined, sA)).data.count;
console.log(`  alice 메모 개수: 공격 전 ${aliceBefore} → 공격 후 ${aliceAfter}`);
check("양방향 모두 거절되고 건수 그대로 (C37, C38, C39)", bobBefore === bobAfter && aliceBefore === aliceAfter);
const q = await call("GET", `/api/private?username=${B}&user_id=${B}`, undefined, sA);
console.log(`  [alice 세션] GET /api/private?username=${B}&user_id=${B} → ${q.status} owner=${q.data.owner}, ${JSON.stringify(q.data.items.map((i) => i.title))}`);
const p = await call("POST", "/api/private", { title: "[alice] 주인 바꾸기 시도", body: "x", user_id: B, username: B, owner: B }, sA);
const bobAfter2 = (await call("GET", "/api/private", undefined, sB)).data;
console.log(`  [alice 세션] POST /api/private 본문에 user_id/username/owner="${B}" → ${p.status}; bob 목록에 들어갔나? ${bobAfter2.items.some((i) => i.title.includes("주인 바꾸기"))}`);
check("주소·본문에 다른 계정을 적어도 내 자료만 (C40)", q.data.owner === A && !q.data.items.some((i) => i.title.includes("bob")) && !bobAfter2.items.some((i) => i.title.includes("주인 바꾸기")));
show("[로그인 안 함] DELETE bob의 메모", await call("DELETE", `/api/private/${bobItemId}`));
const csrf = await fetch(BASE + "/api/private", { method: "POST", headers: { origin: "https://evil.example", cookie: `session=${sA}`, "content-type": "application/json" }, body: JSON.stringify({ title: "csrf" }) });
console.log(`  [다른 사이트 Origin] POST /api/private → ${csrf.status}`);

section("7. 패스키 두 개 → 하나 지우기");
const addOpt = await call("POST", "/api/passkeys/options", {}, sA);
console.log(`  excludeCredentials(이미 등록된 것 제외 목록): ${addOpt.data.options.excludeCredentials.length}개`);
const second = await devA2.create(addOpt.data.options);
show("두 번째 패스키 등록", await call("POST", "/api/passkeys/verify", { flow_id: addOpt.data.flow_id, credential: second.response, passkey_name: "alice 휴대폰" }, sA));
const me2 = await call("GET", "/api/me", undefined, sA);
console.log(`  패스키 목록: ${JSON.stringify(me2.data.passkeys.map((k) => ({ name: k.name, created_at: k.created_at })))}`);
check("한 계정에 패스키 2개, 이름·등록일 보임 (C42, C43)", me2.data.passkeys.length === 2 && me2.data.passkeys.every((k) => k.name && k.created_at));
const sA2 = (await login(devA2, second.cred)).session; // 휴대폰으로 로그인한 세션
show("첫 번째(노트북) 패스키 지우기", await call("DELETE", `/api/passkeys/${regA.cred.id}`, undefined, sA2));
const oldSessionAfterDelete = await call("GET", "/api/private", undefined, sA);
show("지운 패스키로 열었던 기존 세션으로 GET /api/private", oldSessionAfterDelete);
const viaRemaining = await login(devA2, second.cred);
show("[성공] 남은 패스키(휴대폰)로 로그인", viaRemaining.ver);
const viaDeleted = await login(devA, regA.cred);
show("[실패] 지운 패스키(노트북)로 로그인", viaDeleted.ver);
check("남은 하나로 들어가지고, 지운 것으론 못 들어감 (C44, C45)", viaRemaining.ver.status === 200 && viaDeleted.ver.status === 401 && oldSessionAfterDelete.status === 401);
const lastDel = await call("DELETE", `/api/passkeys/${second.cred.id}`, undefined, viaRemaining.session);
show("마지막 남은 패스키 지우기 시도", lastDel);
check("마지막 패스키는 못 지움 (C46)", lastDel.status === 409);

console.log(`\n결과: ${failures === 0 ? "모든 확인 통과" : failures + "개 실패"}  (계정: ${A}, ${B})`);
process.exit(failures ? 1 : 0);
