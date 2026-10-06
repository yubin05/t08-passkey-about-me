-- T08: 비밀번호 없는 패스키 계정 + 비공개 자리

-- 계정: 비밀번호 칸 자체가 없다. webauthn_user_id는 패스키에 같이 묶이는 무작위 사용자 핸들(개인정보 아님)
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  webauthn_user_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

-- 패스키: 서버에는 "공개키"만 저장한다(public_key_jwk). 개인키는 기기 밖으로 나오지 않으므로 저장할 수도 없다.
CREATE TABLE credentials (
  id TEXT PRIMARY KEY,               -- credential ID (base64url)
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,                -- 사람이 알아볼 수 있는 이름
  public_key_jwk TEXT NOT NULL,      -- 공개키 (JWK JSON)
  alg INTEGER NOT NULL,              -- COSE 알고리즘 (-7 = ES256, -257 = RS256)
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX idx_credentials_user ON credentials(user_id);

-- 일회용 질문(challenge): 서버가 만들어 보관하고, 확인할 때 꺼내면서 바로 지운다(재사용 불가)
CREATE TABLE challenges (
  id TEXT PRIMARY KEY,               -- flow_id
  kind TEXT NOT NULL,                -- register | login | add
  challenge TEXT NOT NULL,           -- base64url
  user_id TEXT,                      -- add: 이 질문을 받은 로그인 사용자
  username TEXT,                     -- register: 만들 계정 이름
  webauthn_user_id TEXT,             -- register: 미리 정한 사용자 핸들
  expires_at TEXT NOT NULL
);

-- 로그인 후 사람을 알아보는 방법: 서버 DB에 저장하는 무작위 세션 토큰(HttpOnly 쿠키)
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  credential_id TEXT NOT NULL,       -- 어떤 패스키로 들어왔는지 (그 패스키를 지우면 세션도 같이 끊음)
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- 비공개 자리 항목 (만들어 넣은 내용만)
CREATE TABLE private_items (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_private_items_user ON private_items(user_id);
