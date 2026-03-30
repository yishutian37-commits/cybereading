// Google OAuth Worker - ES Modules format with User Profile & History
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

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substring(2);
}

// Get or create user profile in KV
async function getUserProfile(env, userId) {
  const key = 'user:' + userId;
  const data = await env.USER_DATA.get(key);
  if (data) return JSON.parse(data);
  return null;
}

async function saveUserProfile(env, userId, profile) {
  const key = 'user:' + userId;
  await env.USER_DATA.put(key, JSON.stringify(profile));
}

// Get user history from KV
async function getUserHistory(env, userId) {
  const key = 'history:' + userId;
  const data = await env.USER_DATA.get(key);
  if (data) return JSON.parse(data);
  return [];
}

async function saveUserHistory(env, userId, history) {
  const key = 'history:' + userId;
  await env.USER_DATA.put(key, JSON.stringify(history));
}

// Require authentication helper - supports both cookie and Bearer token
async function requireAuth(request, env) {
  // Try cookie first
  let session = getCookie(request, 'session');
  // Try Authorization header (for pages.dev requests)
  if (!session) {
    const authHeader = request.headers.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      session = authHeader.substring(7);
    }
  }
  if (!session) return null;
  return verifySession(session, env);
}

// Clean old history entries (older than 7 days)
function cleanOldHistory(history, daysOld = 7) {
  const cutoff = Date.now() - (daysOld * 24 * 60 * 60 * 1000);
  return history.filter(entry => entry.timestamp > cutoff);
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS headers for pages.dev
  const corsHeaders = {
    'Access-Control-Allow-Origin': 'https://cybereading.pages.dev',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true'
  };

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  // Helper to add CORS to response
  const withCors = (response) => {
    const newHeaders = { ...Object.fromEntries(response.headers.entries()), ...corsHeaders };
    return new Response(response.body, {
      status: response.status,
      headers: newHeaders
    });
  };

  // Helper for JSON responses with CORS
  const jsonResponse = (data, options = {}) => {
    return withCors(new Response(JSON.stringify(data), {
      headers: { 'Content-Type': 'application/json' },
      ...options
    }));
  };

  // === AUTH ROUTES ===
  if (path === '/api/auth/login') {
    // Get redirect URL from query param
    const redirectUrl = url.searchParams.get('redirect') || 'https://cybereading.pages.dev/';
    const state = encodeURIComponent(redirectUrl);

    const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' +
      'client_id=' + env.GOOGLE_CLIENT_ID +
      '&redirect_uri=' + encodeURIComponent(REDIRECT_URI) +
      '&response_type=code' +
      '&scope=' + encodeURIComponent('openid email profile') +
      '&access_type=offline' +
      '&prompt=consent' +
      '&state=' + state;
    return Response.redirect(authUrl, 302);
  }

  if (path === '/api/auth/callback/google') {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state'); // Original redirect URL from login
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
      const googleUser = await userRes.json();

      if (!googleUser.email) {
        return new Response('Failed to get user info', { status: 400 });
      }

      // Check if user exists in KV, if not create new profile
      let userProfile = await getUserProfile(env, googleUser.id);
      if (!userProfile) {
        userProfile = {
          id: googleUser.id,
          name: googleUser.name,
          nickname: googleUser.name,
          email: googleUser.email,
          picture: googleUser.picture,
          created_at: new Date().toISOString(),
          subscription: {
            tier: 'free', // free, basic, premium, lifetime
            expiresAt: null
          },
          usage: {
            freeUses: 0,
            lastReset: Date.now()
          },
          settings: {
            theme: 'dark'
          }
        };
        await saveUserProfile(env, googleUser.id, userProfile);
      } else {
        // Update last login time
        userProfile.last_login = new Date().toISOString();
        await saveUserProfile(env, googleUser.id, userProfile);
      }

      const sessionUser = { id: googleUser.id, name: googleUser.name, email: googleUser.email, picture: googleUser.picture };
      const session = createSession(sessionUser, env);

      // Get target from state (the original redirect URL)
      const targetUrl = state ? decodeURIComponent(state) : 'https://cybereading.pages.dev/';
      // Append token and user as query params
      const finalUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}token=${encodeURIComponent(session)}&user=${encodeURIComponent(JSON.stringify(sessionUser))}`;
      return Response.redirect(finalUrl, 302);
    } catch (e) {
      console.error('Callback error:', e);
      return new Response('Callback error: ' + e.message, { status: 500 });
    }
  }

  if (path === '/api/auth/logout') {
    // Redirect to pages.dev with logout indicator
    return Response.redirect('https://cybereading.pages.dev/?logout=1', 302);
  }

  if (path === '/api/auth/me') {
    const user = await requireAuth(request, env);
    if (!user) return jsonResponse({ loggedIn: false });
    return jsonResponse({ loggedIn: true, user });
  }

  // === CHAT API (GLM Proxy) ===
  if (path === '/api/chat') {
    const user = await requireAuth(request, env);
    if (!user) return jsonResponse({ error: 'Unauthorized', requiresAuth: true }, { status: 401 });

    try {
      const body = await request.json();
      const { messages, type, question } = body;

      if (!messages || !Array.isArray(messages)) {
        return jsonResponse({ error: 'Invalid messages' }, { status: 400 });
      }

      // Get user profile for subscription info
      const profile = await getUserProfile(env, user.id);
      if (!profile) {
        return jsonResponse({ error: 'User profile not found' }, { status: 400 });
      }

      const { subscription, usage } = profile;
      const now = Date.now();

      // Check if free user has remaining uses (only once, no reset)
      let canUse = false;
      let freeUsesRemaining = 0;

      if (subscription.tier === 'free') {
        // 只有一次免费额度，用完就没了（不重置）
        freeUsesRemaining = Math.max(0, 1 - usage.freeUses);
        canUse = freeUsesRemaining > 0;
      } else if (subscription.tier === 'basic' || subscription.tier === 'premium' || subscription.tier === 'lifetime') {
        // Check if subscription expired
        if (subscription.expiresAt && new Date(subscription.expiresAt) < new Date()) {
          subscription.tier = 'free';
          subscription.expiresAt = null;
          profile.subscription = subscription;
          await saveUserProfile(env, user.id, profile);
          canUse = usage.freeUses < 1;
          freeUsesRemaining = Math.max(0, 1 - usage.freeUses);
        } else {
          canUse = true;
          freeUsesRemaining = 999; // Unlimited
        }
      }

      if (!canUse) {
        return jsonResponse({
          error: 'No remaining uses',
          requiresUpgrade: true,
          freeUsesRemaining: 0,
          tier: subscription.tier
        }, { status: 403 });
      }

      // Increment usage
      if (subscription.tier === 'free') {
        usage.freeUses += 1;
        profile.usage = usage;
        await saveUserProfile(env, user.id, profile);
      }

      // Call GLM API
      const glmRes = await fetch('https://open.bigmodel.cn/api/paas/v4/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + env.GLM_API_KEY
        },
        body: JSON.stringify({
          model: 'glm-4-flash',
          messages: messages,
          temperature: 0.7,
          top_p: 0.9
        })
      });

      if (!glmRes.ok) {
        const err = await glmRes.text();
        console.error('GLM API error:', err);
        return jsonResponse({ error: 'AI service error' }, { status: 502 });
      }

      const glmData = await glmRes.json();
      const reply = glmData.choices[0].message.content;

      // Save to history
      const history = await getUserHistory(env, user.id);
      history.unshift({
        id: generateId(),
        type: type || '易经卜卦',
        question: question || '',
        result: reply.substring(0, 200) + (reply.length > 200 ? '...' : ''),
        timestamp: new Date().toISOString()
      });
      // Keep last 100
      if (history.length > 100) history.splice(100);
      await saveUserHistory(env, user.id, history);

      return jsonResponse({
        success: true,
        reply: reply,
        usage: glmData.usage,
        freeUsesRemaining: subscription.tier === 'free' ? Math.max(0, 1 - usage.freeUses) : 999
      });

    } catch (e) {
      console.error('Chat error:', e);
      return jsonResponse({ error: 'Invalid request' }, { status: 400 });
    }
  }

  // === GET USAGE INFO ===
  if (path === '/api/user/usage') {
    const user = await requireAuth(request, env);
    if (!user) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });

    const profile = await getUserProfile(env, user.id);
    if (!profile) return jsonResponse({ error: 'Profile not found' }, { status: 404 });

    const { subscription, usage } = profile;

    let freeUsesRemaining = 0;
    if (subscription.tier === 'free') {
      // 只有一次免费额度，用完就没了（不重置）
      freeUsesRemaining = Math.max(0, 1 - usage.freeUses);
    } else {
      freeUsesRemaining = subscription.tier === 'lifetime' ? 999 : 999;
    }

    return jsonResponse({
      tier: subscription.tier,
      expiresAt: subscription.expiresAt,
      freeUsesRemaining: freeUsesRemaining,
      hasActiveSubscription: subscription.tier !== 'free'
    });
  }

  // === UPDATE SUBSCRIPTION (for future payment integration) ===
  if (path === '/api/user/subscription' && request.method === 'PUT') {
    const user = await requireAuth(request, env);
    if (!user) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });

    try {
      const body = await request.json();
      const profile = await getUserProfile(env, user.id);
      if (!profile) return jsonResponse({ error: 'Profile not found' }, { status: 404 });

      if (body.tier) {
        profile.subscription.tier = body.tier;
        profile.subscription.expiresAt = body.expiresAt || null;
        await saveUserProfile(env, user.id, profile);
      }

      return jsonResponse({ success: true, subscription: profile.subscription });
    } catch (e) {
      return jsonResponse({ error: 'Invalid request' }, { status: 400 });
    }
  }

  // === USER PROFILE ROUTES ===
  if (path === '/api/user/profile') {
    const user = await requireAuth(request, env);
    if (!user) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });

    if (request.method === 'GET') {
      const profile = await getUserProfile(env, user.id);
      return jsonResponse(profile);
    }

    if (request.method === 'PUT') {
      try {
        const body = await request.json();
        const profile = await getUserProfile(env, user.id);
        if (body.nickname) profile.nickname = body.nickname;
        if (body.settings) profile.settings = { ...profile.settings, ...body.settings };
        profile.updated_at = new Date().toISOString();
        await saveUserProfile(env, user.id, profile);
        return jsonResponse(profile);
      } catch (e) {
        return jsonResponse({ error: 'Invalid request body' }, { status: 400 });
      }
    }
  }

  // === USER HISTORY ROUTES ===
  if (path === '/api/user/history') {
    const user = await requireAuth(request, env);
    if (!user) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });

    if (request.method === 'GET') {
      let history = await getUserHistory(env, user.id);
      // Clean old entries on read
      history = cleanOldHistory(history, 7);
      await saveUserHistory(env, user.id, history);
      return jsonResponse(history);
    }

    if (request.method === 'POST') {
      try {
        const body = await request.json();
        const history = await getUserHistory(env, user.id);
        const entry = {
          id: generateId(),
          type: body.type || '未知',
          question: body.question || '',
          result: body.result || '',
          timestamp: new Date().toISOString()
        };
        history.unshift(entry); // Add to beginning
        // Keep only last 100 entries
        const finalHistory = history.length > 100 ? history.slice(0, 100) : history;
        await saveUserHistory(env, user.id, finalHistory);
        return jsonResponse(entry);
      } catch (e) {
        return jsonResponse({ error: 'Invalid request body' }, { status: 400 });
      }
    }
  }

  // DELETE /api/user/history/:id
  if (path.startsWith('/api/user/history/') && request.method === 'DELETE') {
    const user = await requireAuth(request, env);
    if (!user) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });

    const id = path.split('/').pop();
    let history = await getUserHistory(env, user.id);
    const originalLength = history.length;
    history = history.filter(entry => entry.id !== id);
    await saveUserHistory(env, user.id, history);
    return jsonResponse({ deleted: originalLength !== history.length });
  }

  // POST /api/user/history/clear
  if (path === '/api/user/history/clear' && request.method === 'POST') {
    const user = await requireAuth(request, env);
    if (!user) return jsonResponse({ error: 'Unauthorized' }, { status: 401 });

    let history = await getUserHistory(env, user.id);
    const originalLength = history.length;
    history = cleanOldHistory(history, 7);
    await saveUserHistory(env, user.id, history);
    return jsonResponse({ cleared: originalLength - history.length });
  }

  // === DEBUG ROUTES ===
  if (path === '/api/auth/debug') {
    const cookies = request.headers.get('cookie');
    return jsonResponse({ cookies });
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
