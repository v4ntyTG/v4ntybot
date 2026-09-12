import sanitizeHtml from 'sanitize-html';

const MAX_TITLE = 180;
const MAX_HTML = 250000;
const MAX_CAPTION = 500;
const MAX_CONTENT_IMAGES = 30;
const ALLOWED_IMAGE_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif'
]);
const ALLOWED_IMAGE_EXT = new Set([
  '.jpg', '.jpeg', '.png', '.webp', '.gif'
]);

const allowedTags = [
  'b','strong','i','em','u','s','strike','del',
  'mark','small','sub','sup','code','pre','a','br',
  'blockquote','h2','h3','p','ul','ol','li','hr',
  'tg-spoiler','v4nty-image'
];

const cleanedHTML = (html) => sanitizeHtml(String(html || ''), {
  allowedTags,
  allowedAttributes: {
    a: ['href', 'target', 'rel', 'title'],
    code: ['class'],
    pre: ['class'],
    blockquote: ['cite'],
    'v4nty-image': ['data-image-id', 'data-image-token']
  },
  allowedSchemes: ['http', 'https', 'mailto', 'tg'],
  allowProtocolRelative: false,
  disallowedTagsMode: 'discard'
}).trim().slice(0, MAX_HTML);

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...extra
    }
  });
}

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const configured = String(env.FRONTEND_ORIGIN || '*');
  const allowed = configured === '*' || origin === configured ? (configured === '*' ? '*' : origin) : '';
  return allowed ? {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Vary': 'Origin'
  } : { 'Vary': 'Origin' };
}

function withCors(response, request, env) {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(request, env))) headers.set(k, v);
  return new Response(response.body, { status: response.status, headers });
}

function now() {
  return new Date().toISOString();
}

function base64url(bytes) {
  let s = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}

function utf8Bytes(value) {
  return new TextEncoder().encode(value);
}

async function hmacHex(secret, value) {
  const key = await crypto.subtle.importKey(
    'raw',
    utf8Bytes(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, utf8Bytes(value));
  return [...new Uint8Array(signature)].map(x => x.toString(16).padStart(2,'0')).join('');
}

function safeEqual(a, b) {
  const aa = String(a);
  const bb = String(b);
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  return diff === 0;
}

async function createToken(env) {
  const days = Math.max(1, Number(env.TOKEN_TTL_DAYS || 7));
  const expires = Date.now() + days * 86400000;
  const payload = `${env.ADMIN_LOGIN}|${expires}`;
  const signature = await hmacHex(env.SESSION_SECRET, payload);
  return base64url(utf8Bytes(`${payload}|${signature}`));
}

async function validToken(token, env) {
  try {
    const raw = String(token).replaceAll('-','+').replaceAll('_','/');
    const decoded = atob(raw + '='.repeat((4 - (raw.length % 4)) % 4));
    const parts = decoded.split('|');
    if (parts.length !== 3) return false;
    const [login, expiresText, signature] = parts;
    const expires = Number(expiresText);
    if (login !== String(env.ADMIN_LOGIN)) return false;
    if (!Number.isFinite(expires) || Date.now() > expires) return false;
    const expected = await hmacHex(env.SESSION_SECRET, `${login}|${expires}`);
    return safeEqual(signature, expected);
  } catch {
    return false;
  }
}

async function isAdmin(request, env) {
  const header = request.headers.get('Authorization') || '';
  if (!header.startsWith('Bearer ')) return false;
  return validToken(header.slice(7), env);
}

async function requireAdmin(request, env) {
  return isAdmin(request, env);
}

function slugify(title) {
  const map = {
    а:'a',б:'b',в:'v',г:'g',д:'d',е:'e',ё:'e',ж:'zh',з:'z',и:'i',й:'y',к:'k',л:'l',м:'m',
    н:'n',о:'o',п:'p',р:'r',с:'s',т:'t',у:'u',ф:'f',х:'h',ц:'c',ч:'ch',ш:'sh',щ:'shch',ъ:'',
    ы:'y',ь:'',э:'e',ю:'yu',я:'ya'
  };
  let value = [...String(title).toLowerCase()].map(ch => map[ch] ?? ch).join('');
  value = value.normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,70);
  return value || 'post';
}

async function makeSlug(env, title, ignoreId = null) {
  const base = slugify(title);
  let slug = base;
  let n = 2;
  while (true) {
    const row = ignoreId == null
      ? await env.DB.prepare('SELECT id FROM posts WHERE slug = ? LIMIT 1').bind(slug).first()
      : await env.DB.prepare('SELECT id FROM posts WHERE slug = ? AND id != ? LIMIT 1').bind(slug, ignoreId).first();
    if (!row) return slug;
    slug = `${base}-${n++}`;
  }
}

function extFromName(name) {
  const m = String(name || '').toLowerCase().match(/\.[a-z0-9]+$/);
  return m ? m[0] : '';
}

function validImageFile(file) {
  if (!(file instanceof File)) return false;
  const ext = extFromName(file.name);
  return ALLOWED_IMAGE_TYPES.has(file.type) && ALLOWED_IMAGE_EXT.has(ext);
}

function randomId() {
  return crypto.randomUUID().replaceAll('-','');
}

function mediaUrl(request, env, key) {
  const owner = String(env.GITHUB_OWNER || '');
  const repo = String(env.GITHUB_REPO || '');
  const branch = String(env.GITHUB_BRANCH || 'main');
  if (owner && repo) {
    return `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(branch)}/${key.split('/').map(encodeURIComponent).join('/')}`;
  }
  const url = new URL(request.url);
  url.pathname = `/media/${key.split('/').map(encodeURIComponent).join('/')}`;
  url.search = '';
  return url.toString();
}

function githubContentPath(env, key) {
  const root = String(env.GITHUB_MEDIA_DIR || 'media').replace(/^\/+|\/+$/g, '');
  return `${root}/${String(key).replace(/^\/+/, '')}`;
}

function githubApiPath(path) {
  return String(path).split('/').map(encodeURIComponent).join('/');
}

function githubHeaders(env) {
  return {
    'Accept': 'application/vnd.github+json',
    'Authorization': `Bearer ${String(env.GITHUB_TOKEN || '')}`,
    'X-GitHub-Api-Version': '2022-11-28',
    'Content-Type': 'application/json'
  };
}

function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

async function githubRequest(env, method, path, body = null) {
  const owner = String(env.GITHUB_OWNER || '');
  const repo = String(env.GITHUB_REPO || '');
  if (!owner || !repo || !env.GITHUB_TOKEN) {
    throw new Error('Не настроено GitHub-хранилище изображений.');
  }
  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${githubApiPath(path)}`;
  const response = await fetch(url, {
    method,
    headers: githubHeaders(env),
    body: body == null ? undefined : JSON.stringify(body)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`GitHub API ${response.status}: ${data?.message || 'ошибка'}`);
  }
  return data;
}

async function githubPutFile(env, key, file, message) {
  const path = githubContentPath(env, key);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const content = bytesToBase64(bytes);
  await githubRequest(env, 'PUT', path, {
    message,
    content,
    branch: String(env.GITHUB_BRANCH || 'main')
  });
}

async function githubDeleteFile(env, key, message) {
  const path = githubContentPath(env, key);
  const current = await githubRequest(env, 'GET', path);
  if (!current?.sha) return;
  await githubRequest(env, 'DELETE', path, {
    message,
    sha: current.sha,
    branch: String(env.GITHUB_BRANCH || 'main')
  });
}

async function postImageRows(env, postId) {
  const { results } = await env.DB.prepare(
    'SELECT id, object_key, caption, sort_order, created_at FROM post_images WHERE post_id = ? ORDER BY sort_order ASC, id ASC'
  ).bind(postId).all();
  return results || [];
}

function renderContentHtml(html, imageMap) {
  return String(html || '').replace(/<v4nty-image\s+[^>]*data-image-id=["'](\d+)["'][^>]*><\/v4nty-image\s*>/gi, (_m, id) => {
    const image = imageMap.get(Number(id));
    if (!image) return '';
    const caption = image.caption ? `<figcaption>${escapeHtml(image.caption)}</figcaption>` : '';
    return `<figure class="post-inline-image"><img src="${escapeAttr(image.url)}" alt="${escapeAttr(image.caption || 'Изображение')}" loading="lazy">${caption}</figure>`;
  });
}

function escapeHtml(v) {
  return String(v ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
}

function escapeAttr(v) {
  return escapeHtml(v).replaceAll('"','&quot;').replaceAll("'",'&#039;');
}

async function enrichPost(request, env, post) {
  const rows = await postImageRows(env, post.id);
  const images = rows.map(row => ({
    ...row,
    url: mediaUrl(request, env, row.object_key)
  }));
  const map = new Map(images.map(x => [Number(x.id), x]));
  return {
    ...post,
    cover_url: post.cover_key ? mediaUrl(request, env, post.cover_key) : null,
    content_html: renderContentHtml(post.content_html, map),
    content_images: images
  };
}

async function listPosts(request, env) {
  const url = new URL(request.url);
  const q = String(url.searchParams.get('q') || '').trim();
  const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') || 50)));
  const admin = await isAdmin(request, env);
  let rows;
  if (q) {
    const like = `%${q}%`;
    rows = admin
      ? (await env.DB.prepare('SELECT * FROM posts WHERE title LIKE ? OR content_html LIKE ? ORDER BY created_at DESC LIMIT ?').bind(like, like, limit).all()).results
      : (await env.DB.prepare('SELECT * FROM posts WHERE published = 1 AND (title LIKE ? OR content_html LIKE ?) ORDER BY created_at DESC LIMIT ?').bind(like, like, limit).all()).results;
  } else {
    rows = admin
      ? (await env.DB.prepare('SELECT * FROM posts ORDER BY created_at DESC LIMIT ?').bind(limit).all()).results
      : (await env.DB.prepare('SELECT * FROM posts WHERE published = 1 ORDER BY created_at DESC LIMIT ?').bind(limit).all()).results;
  }
  return (rows || []).map(post => ({
    ...post,
    cover_url: post.cover_key ? mediaUrl(request, env, post.cover_key) : null
  }));
}

async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const login = String(body?.login || '');
  const password = String(body?.password || '');
  if (!safeEqual(login, String(env.ADMIN_LOGIN)) || !safeEqual(password, String(env.ADMIN_PASSWORD))) {
    return json({ ok:false, error:'Неверный логин или пароль.' }, 401);
  }
  return json({ ok:true, token: await createToken(env) });
}

async function handleCreatePost(request, env) {
  if (!(await requireAdmin(request, env))) return json({ ok:false, error:'Требуется авторизация.' }, 401);
  const form = await request.formData();
  const title = String(form.get('title') || '').trim().slice(0, MAX_TITLE);
  const rawContent = String(form.get('contentHtml') || '');
  const content = cleanedHTML(rawContent);
  const cover = form.get('coverImage');
  const coverCaption = String(form.get('coverCaption') || '').trim().slice(0, MAX_CAPTION);
  const published = String(form.get('published') || '') === '1' ? 1 : 0;
  const imageMeta = JSON.parse(String(form.get('contentImages') || '[]'));

  if (!title) return json({ ok:false, error:'Укажи заголовок.' }, 400);
  if (!content) return json({ ok:false, error:'Добавь содержимое.' }, 400);
  if (!Array.isArray(imageMeta) || imageMeta.length > MAX_CONTENT_IMAGES) return json({ ok:false, error:`Можно добавить максимум ${MAX_CONTENT_IMAGES} изображений внутри поста.`}, 400);
  if (cover && cover.size && !validImageFile(cover)) return json({ok:false,error:'Недопустимый формат обложки.'},400);

  const slug = await makeSlug(env, title);
  const timestamp = now();
  const insert = await env.DB.prepare('INSERT INTO posts (slug,title,content_html,cover_key,cover_caption,published,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)')
    .bind(slug, title, content, null, coverCaption, published, timestamp, timestamp).run();
  const postId = Number(insert.meta.last_row_id);

  let coverKey = null;
  const uploadedKeys = [];
  try {
    if (cover instanceof File && cover.size) {
      coverKey = `covers/${postId}-${randomId()}${extFromName(cover.name)}`;
      await githubPutFile(env, coverKey, cover, `Add cover for post ${postId}`);
      uploadedKeys.push(coverKey);
      await env.DB.prepare('UPDATE posts SET cover_key = ? WHERE id = ?').bind(coverKey, postId).run();
    }

    const tokenToId = new Map();
    let sort = 0;
    for (const item of imageMeta) {
      const token = String(item.token || '');
      const caption = String(item.caption || '').trim().slice(0, MAX_CAPTION);
      const file = form.get(`contentImage_${token}`);
      if (!token || !(file instanceof File) || !file.size || !validImageFile(file)) continue;
      const key = `posts/${postId}/${randomId()}${extFromName(file.name)}`;
      await githubPutFile(env, key, file, `Add inline image for post ${postId}`);
      uploadedKeys.push(key);
      const row = await env.DB.prepare('INSERT INTO post_images (post_id,object_key,caption,sort_order,created_at) VALUES (?,?,?,?,?)')
        .bind(postId, key, caption, sort++, timestamp).run();
      tokenToId.set(token, Number(row.meta.last_row_id));
    }

    let finalHtml = content;
    finalHtml = finalHtml.replace(/<v4nty-image\s+[^>]*data-image-token=["']([^"']+)["'][^>]*><\/v4nty-image\s*>/gi, (m, token) => {
      const id = tokenToId.get(String(token));
      return id ? `<v4nty-image data-image-id="${id}"></v4nty-image>` : '';
    });
    await env.DB.prepare('UPDATE posts SET content_html = ? WHERE id = ?').bind(finalHtml, postId).run();
  } catch (error) {
    for (const key of uploadedKeys) { try { await githubDeleteFile(env, key, `Rollback media for post ${postId}`); } catch {} }
    await env.DB.prepare('DELETE FROM posts WHERE id = ?').bind(postId).run();
    console.error(error);
    return json({ok:false,error:'Не удалось сохранить пост.'},500);
  }

  const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ?').bind(postId).first();
  return json({ok:true,post: await enrichPost(request, env, post)},201);
}

async function handleUpdatePost(request, env, id) {
  if (!(await requireAdmin(request, env))) return json({ ok:false, error:'Требуется авторизация.' }, 401);
  const postId = Number(id);
  if (!Number.isInteger(postId) || postId < 1) return json({ok:false,error:'Некорректный ID.'},400);
  const old = await env.DB.prepare('SELECT * FROM posts WHERE id = ? LIMIT 1').bind(postId).first();
  if (!old) return json({ok:false,error:'Пост не найден.'},404);

  const form = await request.formData();
  const title = String(form.get('title') || '').trim().slice(0, MAX_TITLE);
  const content = cleanedHTML(String(form.get('contentHtml') || ''));
  const cover = form.get('coverImage');
  const removeCover = String(form.get('removeCover') || '') === '1';
  const coverCaption = String(form.get('coverCaption') || '').trim().slice(0, MAX_CAPTION);
  const published = String(form.get('published') || '') === '1' ? 1 : 0;
  const imageMeta = JSON.parse(String(form.get('contentImages') || '[]'));
  const referencedExisting = new Set((imageMeta || []).filter(x => x && Number.isInteger(Number(x.id))).map(x => Number(x.id)));

  if (!title || !content) return json({ok:false,error:'Заголовок и содержимое обязательны.'},400);
  if (!Array.isArray(imageMeta) || imageMeta.length > MAX_CONTENT_IMAGES) return json({ok:false,error:`Можно добавить максимум ${MAX_CONTENT_IMAGES} изображений внутри поста.`},400);
  if (cover && cover.size && !validImageFile(cover)) return json({ok:false,error:'Недопустимый формат обложки.'},400);

  const oldImages = await postImageRows(env, postId);
  const allowedExisting = new Set(oldImages.map(x => Number(x.id)));
  for (const idValue of referencedExisting) if (!allowedExisting.has(idValue)) return json({ok:false,error:'Некорректное изображение поста.'},400);

  const timestamp = now();
  let coverKey = old.cover_key || null;
  const uploadedKeys = [];
  try {
    if (cover instanceof File && cover.size) {
      coverKey = `covers/${postId}-${randomId()}${extFromName(cover.name)}`;
      await githubPutFile(env, coverKey, cover, `Replace cover for post ${postId}`);
      uploadedKeys.push(coverKey);
      if (old.cover_key) await githubDeleteFile(env, old.cover_key, `Replace cover for post ${postId}`);
    } else if (removeCover) {
      if (old.cover_key) await githubDeleteFile(env, old.cover_key, `Replace cover for post ${postId}`);
      coverKey = null;
    }

    const tokenToId = new Map();
    let sort = 0;
    for (const item of imageMeta) {
      const caption = String(item.caption || '').trim().slice(0, MAX_CAPTION);
      if (Number.isInteger(Number(item.id))) {
        const iid = Number(item.id);
        tokenToId.set(`existing:${iid}`, iid);
        await env.DB.prepare('UPDATE post_images SET caption = ?, sort_order = ? WHERE id = ? AND post_id = ?')
          .bind(caption, sort++, iid, postId).run();
        continue;
      }
      const token = String(item.token || '');
      const file = form.get(`contentImage_${token}`);
      if (!token || !(file instanceof File) || !file.size || !validImageFile(file)) continue;
      const key = `posts/${postId}/${randomId()}${extFromName(file.name)}`;
      await githubPutFile(env, key, file, `Add inline image for post ${postId}`);
      uploadedKeys.push(key);
      const row = await env.DB.prepare('INSERT INTO post_images (post_id,object_key,caption,sort_order,created_at) VALUES (?,?,?,?,?)')
        .bind(postId,key,caption,sort++,timestamp).run();
      tokenToId.set(token, Number(row.meta.last_row_id));
    }

    const keepExisting = new Set([...referencedExisting]);
    const rowsNow = await postImageRows(env, postId);
    for (const row of rowsNow) {
      if (!keepExisting.has(Number(row.id)) && !tokenToIdHasDbId(tokenToId, Number(row.id))) {
        try { await githubDeleteFile(env, row.object_key, `Delete inline image from post ${postId}`); } catch (error) { console.error(error); }
        await env.DB.prepare('DELETE FROM post_images WHERE id = ? AND post_id = ?').bind(row.id,postId).run();
      }
    }

    let finalHtml = content.replace(/<v4nty-image\s+[^>]*data-image-token=["']([^"']+)["'][^>]*><\/v4nty-image\s*>/gi, (_m, token) => {
      const iid = tokenToId.get(String(token));
      return iid ? `<v4nty-image data-image-id="${iid}"></v4nty-image>` : '';
    });

    await env.DB.prepare('UPDATE posts SET title=?, content_html=?, cover_key=?, cover_caption=?, published=?, updated_at=? WHERE id=?')
      .bind(title,finalHtml,coverKey,coverCaption,published,timestamp,postId).run();
  } catch (error) {
    for (const key of uploadedKeys) { try { await githubDeleteFile(env, key, `Rollback media for post ${postId}`); } catch {} }
    console.error(error);
    return json({ok:false,error:'Не удалось изменить пост.'},500);
  }

  const updated = await env.DB.prepare('SELECT * FROM posts WHERE id = ?').bind(postId).first();
  return json({ok:true,post:await enrichPost(request,env,updated)});
}

function tokenToIdHasDbId(map, id) {
  for (const value of map.values()) if (Number(value) === id) return true;
  return false;
}

async function handleDeletePost(request, env, id) {
  if (!(await requireAdmin(request, env))) return json({ ok:false, error:'Требуется авторизация.' }, 401);
  const postId = Number(id);
  const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ? LIMIT 1').bind(postId).first();
  if (!post) return json({ok:false,error:'Пост не найден.'},404);
  const images = await postImageRows(env,postId);
  const keys = images.map(x=>x.object_key);
  if (post.cover_key) keys.push(post.cover_key);
  for (const key of keys) { try { await githubDeleteFile(env, key, `Delete media for post ${postId}`); } catch (error) { console.error(error); } }
  await env.DB.prepare('DELETE FROM posts WHERE id = ?').bind(postId).run();
  return json({ok:true});
}

async function handlePreview(request, env) {
  if (!(await requireAdmin(request, env))) return json({ ok:false, error:'Требуется авторизация.' }, 401);
  const body = await request.json().catch(()=>({}));
  return json({ok:true,html:cleanedHTML(body.html || '')});
}

async function handleMedia(request, env, key) {
  const url = mediaUrl(request, env, key);
  return Response.redirect(url, 302);
}

async function route(request, env) {
  const url = new URL(request.url);
  const method = request.method;
  if (method === 'OPTIONS') return new Response(null,{status:204});

  if (url.pathname.startsWith('/media/')) {
    return handleMedia(request,env,decodeURIComponent(url.pathname.slice('/media/'.length)));
  }
  if (url.pathname === '/api/site' && method === 'GET') {
    return json({ok:true,isAdmin:await isAdmin(request,env),site:{name:'V4nty | Бот',links:{channel:'https://t.me/v4nty_bot_channel',chat:'https://t.me/v4nty_bot_chat',owner:'https://t.me/v4nty',support:'https://t.me/v4nty_spamblock_bot',bot:'https://t.me/v4nty_bot'}}});
  }
  if (url.pathname === '/api/login' && method === 'POST') return handleLogin(request,env);
  if (url.pathname === '/api/logout' && method === 'POST') {
    if (!(await requireAdmin(request,env))) return json({ok:false,error:'Требуется авторизация.'},401);
    return json({ok:true});
  }
  if (url.pathname === '/api/posts' && method === 'GET') return json({ok:true,posts:await listPosts(request,env)});
  if (url.pathname === '/api/preview' && method === 'POST') return handlePreview(request,env);
  const postMatch = url.pathname.match(/^\/api\/posts\/([^/]+)$/);
  if (postMatch && method === 'GET') {
    const slug = decodeURIComponent(postMatch[1]);
    const post = await env.DB.prepare('SELECT * FROM posts WHERE slug = ? LIMIT 1').bind(slug).first();
    if (!post || (!post.published && !(await isAdmin(request,env)))) return json({ok:false,error:'Пост не найден.'},404);
    return json({ok:true,post:await enrichPost(request,env,post)});
  }
  if (url.pathname === '/api/admin/posts' && method === 'POST') return handleCreatePost(request,env);
  const adminPost = url.pathname.match(/^\/api\/admin\/posts\/(\d+)$/);
  if (adminPost && method === 'PUT') return handleUpdatePost(request,env,adminPost[1]);
  if (adminPost && method === 'DELETE') return handleDeletePost(request,env,adminPost[1]);
  return json({ok:false,error:'Маршрут не найден.'},404);
}

export default {
  async fetch(request, env) {
    if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET || !env.ADMIN_LOGIN) {
      return json({ok:false,error:'Не настроены секреты ADMIN_LOGIN, ADMIN_PASSWORD и SESSION_SECRET.'},500);
    }
    if (!env.GITHUB_TOKEN || !env.GITHUB_OWNER || !env.GITHUB_REPO) {
      return json({ok:false,error:'Не настроено GitHub-хранилище изображений: нужен GITHUB_TOKEN, GITHUB_OWNER и GITHUB_REPO.'},500);
    }
    try {
      return withCors(await route(request,env),request,env);
    } catch (error) {
      console.error(error);
      return withCors(json({ok:false,error:'Внутренняя ошибка сервера.'},500),request,env);
    }
  }
};
