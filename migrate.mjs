import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const dbPath = process.env.OLD_DB || path.resolve('./data/v4nty.sqlite');
const out = process.env.OUT_SQL || path.resolve('./migration.sql');

if (!fs.existsSync(dbPath)) {
  throw new Error(`Не найден старый SQLite: ${dbPath}`);
}

const db = new DatabaseSync(dbPath);
const posts = db.prepare('SELECT * FROM posts ORDER BY id ASC').all();

const autoSqlString = (value) => {
  if (value === null || value === undefined) return 'NULL';
  return `'${String(value).replaceAll("'", "''")}'`;
};

const lines = [
  'PRAGMA foreign_keys = ON;',
  ''
];

for (const post of posts) {
  lines.push(`INSERT INTO posts (id,slug,title,content_html,cover_key,cover_caption,published,created_at,updated_at) VALUES (${Number(post.id)},${autoSqlString(post.slug)},${autoSqlString(post.title)},${autoSqlString(post.content_html)},${post.image_filename ? autoSqlString(`covers/${path.basename(post.image_filename)}`) : 'NULL'},${autoSqlString(post.image_caption || '')},${Number(post.published) ? 1 : 0},${autoSqlString(post.created_at)},${autoSqlString(post.updated_at)});`);
}

lines.push(`\n-- Imported ${posts.length} posts from ${dbPath}`);
fs.writeFileSync(out, lines.join('\n'), 'utf8');
console.log(`Создан ${out}`);
console.log(`Постов: ${posts.length}`);
console.log('Важно: старые фотографии нужно отдельно загрузить в R2 с ключами covers/<имя-файла>.');
