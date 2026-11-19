const SESSION_TTL = 7 * 24 * 60 * 60 * 1000; // 7 дней

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function randomHex(bytes = 32) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return [...arr].map(b => b.toString(16).padStart(2, "0")).join("");
}

function parseCookies(req) {
  const cookie = req.headers.get("Cookie") || "";
  return Object.fromEntries(
    cookie.split(";").map(c => c.trim().split("=")).filter(p => p[0])
  );
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = Uint8Array.from(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function sessionCookie(token, maxAgeSeconds) {
  return `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}`;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    try {
      if (url.pathname === "/api/register" && req.method === "POST") {
        return await handleRegister(req, env);
      }
      if (url.pathname === "/api/login" && req.method === "POST") {
        return await handleLogin(req, env);
      }
      if (url.pathname === "/api/logout" && req.method === "POST") {
        return await handleLogout(req, env);
      }
      if (url.pathname === "/api/me" && req.method === "GET") {
        return await handleMe(req, env);
      }
      // Всё остальное — статика из папки public/
      return env.ASSETS.fetch(req);
    } catch (err) {
      return json({ error: "Server error", details: String(err) }, 500);
    }
  },
};

async function handleRegister(req, env) {
  const { email, password } = await req.json();
  const cleanEmail = (email || "").trim().toLowerCase();

  if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return json({ error: "Некорректный email" }, 400);
  }
  if (!password || password.length < 8) {
    return json({ error: "Пароль от 8 символов" }, 400);
  }

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);

  try {
    await env.DB.prepare(
      "INSERT INTO users (email, password_hash, salt, created_at) VALUES (?, ?, ?, ?)"
    ).bind(cleanEmail, hash, salt, Date.now()).run();
  } catch (e) {
    return json({ error: "Этот email уже зарегистрирован" }, 409);
  }

  return json({ ok: true }, 201);
}

async function handleLogin(req, env) {
  const { email, password } = await req.json();
  const cleanEmail = (email || "").trim().toLowerCase();

  const row = await env.DB.prepare("SELECT * FROM users WHERE email = ?")
    .bind(cleanEmail).first();

  if (!row) return json({ error: "Неверный email или пароль" }, 401);

  const hash = await hashPassword(password || "", row.salt);
  if (hash !== row.password_hash) {
    return json({ error: "Неверный email или пароль" }, 401);
  }

  const token = randomHex(32);
  const expires = Date.now() + SESSION_TTL;

  await env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
  ).bind(token, row.id, expires).run();

  return json({ ok: true, user: { id: row.id, email: row.email } }, 200, {
    "Set-Cookie": sessionCookie(token, SESSION_TTL / 1000),
  });
}

async function handleLogout(req, env) {
  const token = parseCookies(req).session;
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  }
  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
}

async function handleMe(req, env) {
  const token = parseCookies(req).session;
  if (!token) return json({ user: null }, 401);

  const session = await env.DB.prepare("SELECT * FROM sessions WHERE token = ?")
    .bind(token).first();

  if (!session || session.expires_at < Date.now()) {
    return json({ user: null }, 401);
  }

  const user = await env.DB.prepare(
    "SELECT id, email, created_at FROM users WHERE id = ?"
  ).bind(session.user_id).first();

  return json({ user });
}
