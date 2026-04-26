import os
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from src.env import CyberEnvironment
from src.models import Action

app = FastAPI()
envs: dict[str, CyberEnvironment] = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

SITE_DIR = os.path.join(os.path.dirname(__file__), "..", "site")
SITE_DIR = os.path.abspath(SITE_DIR)
if os.path.isdir(SITE_DIR):
    app.mount("/site", StaticFiles(directory=SITE_DIR), name="site")

class ResetRequest(BaseModel):
    task_name: str = Field(
        default="phishing_triage",
        description="One of: phishing_triage, policy_drift, incident_containment",
    )

def _session_id(
    request: Request,
    response: Response,
    x_session_id: str | None = Header(default=None, alias="X-Session-ID"),
) -> str:
    session_id = x_session_id or request.cookies.get("cyber_sentinel_session") or uuid4().hex
    response.set_cookie(
        key="cyber_sentinel_session",
        value=session_id,
        httponly=True,
        samesite="lax",
    )
    return session_id

def _get_env(session_id: str) -> CyberEnvironment:
    if session_id not in envs:
        env = CyberEnvironment()
        env.reset()
        envs[session_id] = env
    return envs[session_id]

@app.get("/")
def read_root():
    # Serve the UI if it exists; otherwise return API status.
    index_path = os.path.join(SITE_DIR, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return {"status": "Cyber-Sentinel Environment is live!"}

@app.get("/ui")
def ui():
    index_path = os.path.join(SITE_DIR, "index.html")
    return FileResponse(index_path)

@app.get("/download")
def download_submission():
    zip_path = os.path.join(SITE_DIR, "cyber-sentinel-env-submission.zip")
    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename="cyber-sentinel-env-submission.zip",
    )

@app.post("/reset")
def reset(
    request: Request,
    response: Response,
    body: ResetRequest | None = None,
    x_session_id: str | None = Header(default=None, alias="X-Session-ID"),
):
    session_id = _session_id(request, response, x_session_id)
    task_name = (body.task_name if body is not None else "phishing_triage") or "phishing_triage"
    envs[session_id] = CyberEnvironment(task_name=task_name)
    obs = envs[session_id].reset()
    return {"session_id": session_id, "observation": obs, "output": obs.output, "error": obs.error}

@app.post("/step")
def step(
    action: Action,
    request: Request,
    response: Response,
    x_session_id: str | None = Header(default=None, alias="X-Session-ID"),
):
    session_id = _session_id(request, response, x_session_id)
    env = _get_env(session_id)
    obs, reward, done, info = env.step(action)
    info["session_id"] = session_id
    return {
        "observation": obs,
        "reward": reward,
        "done": done,
        "info": info
    }

@app.post("/state")
def state_post(
    request: Request,
    response: Response,
    x_session_id: str | None = Header(default=None, alias="X-Session-ID"),
):
    session_id = _session_id(request, response, x_session_id)
    state = _get_env(session_id).state()
    state["session_id"] = session_id
    return state

@app.get("/state")
def state_get(
    request: Request,
    response: Response,
    x_session_id: str | None = Header(default=None, alias="X-Session-ID"),
):
    session_id = _session_id(request, response, x_session_id)
    state = _get_env(session_id).state()
    state["session_id"] = session_id
    return state

def main():
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860)

if __name__ == "__main__":
    main()
