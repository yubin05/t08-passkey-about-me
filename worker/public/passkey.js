// T08 패스키 화면 — 외부 라이브러리 없이 브라우저 기본 WebAuthn API(navigator.credentials)만 사용
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var statusEl = $("pk-status");

  function setStatus(msg, kind) {
    statusEl.textContent = msg || "";
    statusEl.className = "pk-status" + (kind ? " " + kind : "");
  }

  // ---- base64url <-> ArrayBuffer (서버와 주고받는 형식) ----
  function b64urlToBuf(s) {
    var b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
    var bin = atob(b64), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function api(path, method, body) {
    var res = await fetch(path, {
      method: method || "GET",
      headers: body ? { "content-type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
      credentials: "same-origin"
    });
    var data = null;
    try { data = await res.json(); } catch (e) { data = {}; }
    if (!res.ok) { var err = new Error(data.error || ("요청 실패 (" + res.status + ")")); err.status = res.status; throw err; }
    return data;
  }

  function supported() {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      setStatus("이 브라우저는 패스키를 지원하지 않습니다. 최신 크롬·엣지·사파리에서 열어 주세요.", "error");
      return false;
    }
    return true;
  }

  // 서버가 보낸 등록 옵션 → 기기에 열쇠 한 쌍을 만들어 달라고 요청 → 공개키가 담긴 응답만 서버로 돌려줌
  async function createPasskey(options) {
    var pk = Object.assign({}, options, {
      challenge: b64urlToBuf(options.challenge),
      user: Object.assign({}, options.user, { id: b64urlToBuf(options.user.id) }),
      excludeCredentials: (options.excludeCredentials || []).map(function (c) { return Object.assign({}, c, { id: b64urlToBuf(c.id) }); })
    });
    var cred = await navigator.credentials.create({ publicKey: pk });
    return {
      id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        attestationObject: bufToB64url(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : []
      }
    };
  }

  // 등록 중 취소·실패 처리. 취소면 서버에 보관된 질문도 지워서 아무것도 남지 않게 한다.
  async function handleCreateError(e, flowId) {
    if (flowId) { try { await api("/api/register/cancel", "POST", { flow_id: flowId }); } catch (ignore) {} }
    if (e && e.name === "NotAllowedError") setStatus("패스키 등록을 취소했습니다. 서버에는 아무것도 저장되지 않았습니다.", "error");
    else if (e && e.name === "InvalidStateError") setStatus("이 기기(또는 비밀번호 관리자)에는 이미 이 계정의 패스키가 있습니다. 다른 기기나 브라우저에서 등록해 보세요.", "error");
    else setStatus((e && e.message) || "패스키 등록에 실패했습니다.", "error");
  }

  async function register(ev) {
    ev.preventDefault();
    if (!supported()) return;
    var flowId = null;
    try {
      setStatus("서버에서 등록용 질문을 받는 중…");
      var start = await api("/api/register/options", "POST", { username: $("pk-username").value });
      flowId = start.flow_id;
      setStatus("기기 창에서 패스키를 만들어 주세요…");
      var credential = await createPasskey(start.options);
      await api("/api/register/verify", "POST", { flow_id: flowId, credential: credential, passkey_name: $("pk-reg-name").value });
      setStatus("계정과 패스키를 만들었습니다.", "ok");
      await refresh();
    } catch (e) { await handleCreateError(e, flowId); }
  }

  async function login() {
    if (!supported()) return;
    try {
      setStatus("서버에서 로그인용 질문을 받는 중…");
      var start = await api("/api/login/options", "POST", {});
      var o = start.options;
      var cred = await navigator.credentials.get({ publicKey: Object.assign({}, o, { challenge: b64urlToBuf(o.challenge), allowCredentials: [] }) });
      var credential = {
        id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
        response: {
          clientDataJSON: bufToB64url(cred.response.clientDataJSON),
          authenticatorData: bufToB64url(cred.response.authenticatorData),
          signature: bufToB64url(cred.response.signature),
          userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null
        }
      };
      await api("/api/login/verify", "POST", { flow_id: start.flow_id, credential: credential });
      setStatus("패스키로 들어왔습니다.", "ok");
      await refresh();
    } catch (e) {
      if (e && e.name === "NotAllowedError") setStatus("로그인을 취소했거나 이 사이트용 패스키가 없습니다.", "error");
      else setStatus((e && e.message) || "로그인에 실패했습니다.", "error");
    }
  }

  async function logout() {
    await api("/api/logout", "POST", {});
    setStatus("로그아웃했습니다.", "ok");
    showLocked();
  }

  async function addPasskey(ev) {
    ev.preventDefault();
    if (!supported()) return;
    var flowId = null;
    try {
      var start = await api("/api/passkeys/options", "POST", {});
      flowId = start.flow_id;
      setStatus("기기 창에서 새 패스키를 만들어 주세요…");
      var credential = await createPasskey(start.options);
      await api("/api/passkeys/verify", "POST", { flow_id: flowId, credential: credential, passkey_name: $("pk-add-name").value });
      $("pk-add-name").value = "";
      setStatus("패스키를 하나 더 등록했습니다.", "ok");
      await refresh();
    } catch (e) { await handleCreateError(e, flowId); }
  }

  async function deletePasskey(id, name) {
    if (!confirm("패스키 '" + name + "'을(를) 지울까요? 지운 패스키로는 다시 들어올 수 없습니다.")) return;
    try {
      var r = await api("/api/passkeys/" + encodeURIComponent(id), "DELETE");
      if (r.logged_out) { setStatus("지금 쓰던 패스키를 지워서 로그아웃되었습니다. 남은 패스키로 다시 들어오세요.", "ok"); showLocked(); return; }
      setStatus("패스키를 지웠습니다.", "ok");
      await refresh();
    } catch (e) { setStatus(e.message, "error"); }
  }

  async function addItem(ev) {
    ev.preventDefault();
    try {
      await api("/api/private", "POST", { title: $("pk-item-title").value, body: $("pk-item-body").value });
      $("pk-item-title").value = ""; $("pk-item-body").value = "";
      await refresh();
    } catch (e) { setStatus(e.message, "error"); }
  }
  async function deleteItem(id) {
    try { await api("/api/private/" + id, "DELETE"); await refresh(); } catch (e) { setStatus(e.message, "error"); }
  }

  function fmt(iso) {
    return iso ? new Date(iso).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" }) : "—";
  }
  function li(children) {
    var el = document.createElement("li");
    children.forEach(function (c) { el.appendChild(c); });
    return el;
  }
  function textEl(tag, text, cls) {
    var el = document.createElement(tag); el.textContent = text; if (cls) el.className = cls; return el;
  }
  function button(text, cls, onClick) {
    var b = textEl("button", text, cls); b.type = "button"; b.addEventListener("click", onClick); return b;
  }

  function showLocked() {
    $("pk-locked").hidden = false;
    $("pk-unlocked").hidden = true;
    // 화면에서 숨기는 것만이 아니라, 받아 왔던 비공개 내용 자체를 지운다
    $("pk-items").replaceChildren(); $("pk-keys").replaceChildren(); $("pk-who").textContent = "";
  }

  async function refresh() {
    var meData, priv;
    try {
      meData = await api("/api/me");
      priv = await api("/api/private");
    } catch (e) {
      if (e.status === 401) { showLocked(); return; }
      setStatus(e.message, "error"); return;
    }
    $("pk-locked").hidden = true;
    $("pk-unlocked").hidden = false;
    $("pk-who").textContent = meData.username;

    $("pk-item-count").textContent = priv.count;
    $("pk-items").replaceChildren.apply($("pk-items"), priv.items.map(function (it) {
      var box = document.createElement("div");
      box.appendChild(textEl("strong", it.title));
      if (it.body) box.appendChild(textEl("div", it.body));
      box.appendChild(textEl("div", fmt(it.created_at), "pk-meta"));
      return li([box, button("삭제", "secondary", function () { deleteItem(it.id); })]);
    }));

    $("pk-key-count").textContent = meData.passkeys.length;
    $("pk-keys").replaceChildren.apply($("pk-keys"), meData.passkeys.map(function (k) {
      var box = document.createElement("div");
      box.appendChild(textEl("strong", k.name + (k.id === meData.current_passkey_id ? " (지금 사용 중)" : "")));
      box.appendChild(textEl("div", "등록: " + fmt(k.created_at) + " · 마지막 사용: " + fmt(k.last_used_at), "pk-meta"));
      var del = button("지우기", "danger", function () { deletePasskey(k.id, k.name); });
      if (meData.passkeys.length <= 1) { del.disabled = true; del.title = "마지막 패스키는 지울 수 없습니다"; }
      return li([box, del]);
    }));
  }

  $("pk-register-form").addEventListener("submit", register);
  $("pk-login-btn").addEventListener("click", login);
  $("pk-logout-btn").addEventListener("click", logout);
  $("pk-add-form").addEventListener("submit", addPasskey);
  $("pk-item-form").addEventListener("submit", addItem);
  refresh();
})();
