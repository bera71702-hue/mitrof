const SESSION_TTL = 7 * 24 * 60 * 60 * 1000; // 7 дней
const VERIFY_TTL = 24 * 60 * 60 * 1000;      // 24 часа

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

async function sendVerificationEmail(env, email, token, origin) {
  const verifyUrl = `${origin}/api/verify?token=${token}`;
  const html = `
    <h2>Подтверждение email</h2>
    <p>Привет! Чтобы завершить регистрацию, перейди по ссылке:</p>
    <p><a href="${verifyUrl}">${verifyUrl}</a></p>
    <p>Ссылка действует 24 часа.</p>
  `;

  await env.EMAIL.send({
    to: email,
    from: "noreply@mitrofanov.vedernikof.workers.dev",
    subject: "Подтверждение регистрации",
    html,
  });
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
      if (url.pathname === "/api/verify" && req.method === "GET") {
        return await handleVerify(req, env);
      }
      return env.ASSETS.fetch(req);
    } catch (err) {
      return json({ error: "Server error", details: String(err) }, 500);
    }
  },
};

async function handleRegister(req, env) {
  const { email, password } = await req.json();
  const cleanEmail = (email || "").trim().toLowerCase();
  const origin = new URL(req.url).origin;

  if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return json({ error: "Некорректный email" }, 400);
  }
  if (!password || password.length < 8) {
    return json({ error: "Пароль от 8 символов" }, 400);
  }

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);

  let userId;
  try {
    const result = await env.DB.prepare(
      "INSERT INTO users (email, password_hash, salt, created_at, verified) VALUES (?, ?, ?, ?, 0)"
    ).bind(cleanEmail, hash, salt, Date.now()).run();
    userId = result.meta.last_row_id;
  } catch (e) {
    const msg = String(e && e.message || e);
    if (/UNIQUE constraint failed/i.test(msg)) {
      return json({ error: "Этот email уже зарегистрирован" }, 409);
    }
    return json({ error: "DB error", details: msg }, 500);
  }

  const token = randomHex(32);
  await env.DB.prepare(
    "INSERT INTO email_tokens (token, user_id, expires_at) VALUES (?, ?, ?)"
  ).bind(token, userId, Date.now() + VERIFY_TTL).run();

  try {
    await sendVerificationEmail(env, cleanEmail, token, origin);
  } catch (e) {
    console.error("Email send failed:", e);
    return json({ ok: true, message: "Аккаунт создан, но письмо не отправлено. Запроси повторно позже." }, 201);
  }

  return json({ ok: true, message: "Проверь почту — там ссылка для подтверждения." }, 201);
}

async function handleVerify(req, env) {
  const url = new URL(req.url);
  const token = url.searchParams.get("token");
  if (!token) return json({ error: "Токен не указан" }, 400);

  const row = await env.DB.prepare("SELECT * FROM email_tokens WHERE token = ?")
    .bind(token).first();
  if (!row) return json({ error: "Ссылка недействительна" }, 400);
  if (row.expires_at < Date.now()) {
    return json({ error: "Срок действия ссылки истёк" }, 400);
  }

  await env.DB.prepare("UPDATE users SET verified = 1 WHERE id = ?")
    .bind(row.user_id).run();
  await env.DB.prepare("DELETE FROM email_tokens WHERE token = ?")
    .bind(token).run();

  return Response.redirect(`${url.origin}/?verified=1`, 302);
}

async function handleLogin(req, env) {
  const { email, password } = await req.json();
  const cleanEmail = (email || "").trim().toLowerCase();

  try {
    const row = await env.DB.prepare("SELECT * FROM users WHERE email = ?")
      .bind(cleanEmail).first();

    if (!row) return json({ error: "Неверный email или пароль" }, 401);

    const hash = await hashPassword(password || "", row.salt);
    if (hash !== row.password_hash) {
      return json({ error: "Неверный email или пароль" }, 401);
    }

    if (!row.verified) {
      return json({ error: "Подтверди email, чтобы войти" }, 403);
    }

    const token = randomHex(32);
    const expires = Date.now() + SESSION_TTL;

    await env.DB.prepare(
      "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
    ).bind(token, row.id, expires).run();

    return json({ ok: true, user: { id: row.id, email: row.email } }, 200, {
      "Set-Cookie": sessionCookie(token, SESSION_TTL / 1000),
    });
  } catch (e) {
    return json({ error: "DB error", details: String(e && e.message || e) }, 500);
  }
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
