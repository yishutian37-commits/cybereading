// Google OAuth Worker - ES Modules format
const REDIRECT_URI = 'https://cybereading.online/api/auth/callback/google';

const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登录 - 赛博算命</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
    .login-box{background:rgba(255,255,255,0.1);backdrop-filter:blur(10px);border-radius:20px;padding:60px 50px;text-align:center;border:1px solid rgba(255,255,255,0.2)}
    h1{color:#fff;margin-bottom:30px;font-size:28px}
    .google-btn{display:inline-flex;align-items:center;gap:12px;background:#fff;color:#333;border:none;padding:16px 32px;border-radius:50px;font-size:16px;font-weight:600;cursor:pointer;text-decoration:none;transition:transform .2s,box-shadow .2s}
    .google-btn:hover{transform:translateY(-2px);box-shadow:0 10px 30px rgba(0,0,0,0.3)}
    .google-btn svg{width:20px;height:20px}
    .user-info{background:rgba(255,255,255,0.1);border-radius:20px;padding:40px;text-align:center;color:#fff}
    .user-info img{width:80px;height:80px;border-radius:50%;margin-bottom:20px;border:3px solid rgba(255,255,255,0.3)}
    .user-info h2{margin-bottom:10px}
    .user-info p{color:rgba(255,255,255,0.7);margin-bottom:30px}
    .logout-btn{background:#dc3545;color:#fff;border:none;padding:12px 30px;border-radius:25px;font-size:14px;cursor:pointer;text-decoration:none}
    .logout-btn:hover{background:#c82333}
  </style>
</head>
<body>
  {{CONTENT}}
</body>
</html>`;

function base64Encode(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function base64Decode(str) {
  return decodeURIComponent(escape(atob(str)));
}

function createSession(user, env) {
  const payload = JSON.stringify({ user, exp: Date.now() + 86400000 });
  const encoded = base64Encode(payload);
  const secret = env.SESSION_SECRET;
  const signature = btoa(secret + encoded).replace(/=/g, '');
  return encoded + '.' + signature;
}

function verifySession(token, env) {
  try {
    const [payload, signature] = token.split('.');
    const secret = env.SESSION_SECRET;
    const expectedSig = btoa(secret + payload).replace(/=/g, '');
    if (signature !== expectedSig) return null;
    const data = JSON.parse(base64Decode(payload));
    if (Date.now() > data.exp) return null;
    return data.user;
  } catch { return null; }
}

function getCookie(request, name) {
  const match = request.headers.get('cookie')?.match(new RegExp('(^|;\\s*)' + name + '=([^;]*)'));
  return match ? match[2] : null;
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === '/api/auth/login') {
    const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' +
      'client_id=' + env.GOOGLE_CLIENT_ID +
      '&redirect_uri=' + encodeURIComponent(REDIRECT_URI) +
      '&response_type=code' +
      '&scope=' + encodeURIComponent('openid email profile') +
      '&access_type=offline' +
      '&prompt=consent';
    return Response.redirect(authUrl, 302);
  }

  if (path === '/api/auth/callback/google') {
    const code = url.searchParams.get('code');
    if (!code) return new Response('Missing code: ' + url, { status: 400 });

    try {
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: REDIRECT_URI,
          grant_type: 'authorization_code'
        })
      });

      if (!tokenRes.ok) {
        const errText = await tokenRes.text();
        return new Response('Token exchange failed: ' + errText, { status: 400 });
      }

      const tokens = await tokenRes.json();
      const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: 'Bearer ' + tokens.access_token }
      });
      const user = await userRes.json();

      if (!user.email) {
        return new Response('Failed to get user info: ' + JSON.stringify(user), { status: 400 });
      }

      const session = createSession({ id: user.id, name: user.name, email: user.email, picture: user.picture }, env);

      console.log('Login success:', user.email, 'Session:', session.substring(0, 20) + '...');

      // Return simple HTML page showing login result
      const html = '<!DOCTYPE html><html><head><title>Login Success</title><meta charset="utf-8"><meta http-equiv="refresh" content="2;url=/"></head><body style="font-family:Arial;text-align:center;padding:50px;background:#1a1a2e;color:#fff;"><h1>Login Successful!</h1><p>Welcome, ' + user.name + '</p><p>Redirecting...</p><script>setTimeout(() => window.location.href="/", 2000);</script></body></html>';
      return new Response(html, {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Set-Cookie': 'session=' + session + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Domain=cybereading.online'
        }
      });
    } catch (e) {
      console.error('Callback error:', e);
      return new Response('Callback error: ' + e.message, { status: 500 });
    }
  }

  if (path === '/api/auth/logout') {
    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/',
        'Set-Cookie': 'session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Domain=cybereading.online'
      }
    });
  }

  if (path === '/api/auth/me') {
    const session = getCookie(request, 'session');
    console.log('/api/auth/me called, session:', session ? session.substring(0, 20) + '...' : 'null');
    if (!session) {
      const cookies = request.headers.get('cookie');
      console.log('All cookies:', cookies);
      return new Response(JSON.stringify({ loggedIn: false, reason: 'no session cookie', allCookies: cookies }), { headers: { 'Content-Type': 'application/json' } });
    }
    const user = verifySession(session, env);
    if (!user) {
      console.log('Session verification failed');
      return new Response(JSON.stringify({ loggedIn: false, reason: 'invalid session' }), { headers: { 'Content-Type': 'application/json' } });
    }
    console.log('User logged in:', user.email);
    return new Response(JSON.stringify({ loggedIn: true, user }), { headers: { 'Content-Type': 'application/json' } });
  }

  // Debug endpoint to show raw cookies
  if (path === '/api/auth/debug') {
    const cookies = request.headers.get('cookie');
    return new Response(JSON.stringify({ cookies }), { headers: { 'Content-Type': 'application/json' } });
  }

  if (path === '/login') {
    const session = getCookie(request, 'session');
    const user = session ? verifySession(session, env) : null;
    const content = user
      ? '<div class="user-info"><img src="' + user.picture + '" alt="' + user.name + '"><h2>欢迎，' + user.name + '</h2><p>' + user.email + '</p><a href="/api/auth/logout" class="logout-btn">退出登录</a></div>'
      : '<div class="login-box"><h1>赛博算命</h1><a href="/api/auth/login" class="google-btn"><svg viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>使用 Google 登录</a></div>';
    return new Response(html.replace('{{CONTENT}}', content), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  return new Response('Not Found', { status: 404 });
}

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  }
};
