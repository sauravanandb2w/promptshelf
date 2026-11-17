# PromptShelf

Prompt directory: Node + Express + SQLite. Frontend in `public/index.html`.

## Run locally
```
npm install
ADMIN_EMAIL=you@example.com ANTHROPIC_API_KEY=sk-ant-... npm start
```
Open http://localhost:3000. Register with `ADMIN_EMAIL` to become admin.

## Deploy on Render
1. Push this folder to a GitHub repo.
2. Render > New > Blueprint > pick the repo (uses `render.yaml`; the 1 GB disk keeps SQLite across deploys, needs a paid instance).
3. Set `ADMIN_EMAIL` and `ANTHROPIC_API_KEY` in the dashboard.

Railway: new project from repo, add a volume at `/data`, set `DB_PATH=/data/promptshelf.db`, `JWT_SECRET`, `ADMIN_EMAIL`, `ANTHROPIC_API_KEY`.

## API
| Method | Path | Auth |
|---|---|---|
| POST | /api/auth/register, /api/auth/login | - |
| GET | /api/auth/me | user |
| GET | /api/categories, /api/tags | - |
| GET | /api/prompts?q&category&tag&sort=new\|popular\|copied&page&limit | - |
| GET | /api/prompts/:id | - |
| POST | /api/prompts/:id/copy | - |
| POST | /api/prompts | user (pending until approved; admin auto-approved) |
| PUT/DELETE | /api/prompts/:id | owner or admin |
| POST | /api/prompts/:id/like, /api/prompts/:id/save | user (toggle) |
| GET | /api/me/saved, /api/me/prompts | user |
| GET | /api/admin/pending | admin |
| POST | /api/admin/prompts/:id/approve\|reject | admin |
| POST | /api/admin/import | admin (Prompt Bench JSON) |
| POST | /api/ai/improve `{prompt}` | user (20/hour) |
