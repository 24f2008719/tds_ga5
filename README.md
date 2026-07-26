# GA-5 Solutions

Your own implementation, built from scratch and tested (`test_main.py`, 10/10 passing).

## What's here

- `main.py` — FastAPI app with `/charge` (Q2 proration) and `/q3/check` (Q3 guardrail hook)
- `test_main.py` — test suite; run with `pytest test_main.py -v`
- `maze_solver.py` — standalone BFS solver for the offline maze question (not hosted, run locally: `python3 maze_solver.py your-maze.json`)
- `render.yaml` — Render deployment config
- `requirements.txt`

## Deploying to Render

1. Push this folder to your own GitHub repo.
2. In Render: **New → Web Service**, connect your repo. Render should auto-detect `render.yaml`.
   - If it doesn't, set manually: **Build Command** `pip install -r requirements.txt`, **Start Command** `uvicorn main:app --host 0.0.0.0 --port $PORT`.
3. **Before submitting for grading**, go to your assignment page, copy your specific Q3 parameters, and set them as environment variables in Render's dashboard (Settings → Environment):
   - `Q3_HOME_DIR`
   - `Q3_CWD`
   - `Q3_SECRET_REL`
   - `Q3_WRITE_DIR`
   - `Q3_ALLOWED_DOMAINS` (comma-separated)
4. Redeploy after changing env vars (Render does this automatically on save, or trigger manually).
5. Sanity check: `GET /q3/check` returns the policy currently loaded, so you can confirm it matches your assignment page before submitting.

## Endpoints to submit

- Proration: `https://<your-app>.onrender.com/charge`
- Guardrail: `https://<your-app>.onrender.com/q3/check`

## Note on Render's free tier

Free Render web services spin down after inactivity and take ~30-50s to wake on the next request. The assignment says the grader times out slow requests. If your first grading request might hit a cold start, either:
- ping the service yourself a minute before submitting, or
- use a paid/always-on instance, or
- switch to a host without cold starts for this submission.
