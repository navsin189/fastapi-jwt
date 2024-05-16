import json
import aiofiles
from fastapi import FastAPI, Request, Response, status, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Dict

CRED_FILE = 'users.json'

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/")
async def dashboard(request: Request):
    return {'msg': 'Welcome to Dashboard'}

@app.get("/login")
async def login(request: Request, response: Response):
    response.status_code = status.HTTP_405_METHOD_NOT_ALLOWED
    return {'msg': 'Method Not Allowed', 'status_code': 405}

async def get_credentials() -> Dict[str, Dict[str, str]]:
    async with aiofiles.open(CRED_FILE, 'r') as cred:
        return json.loads(await cred.read())

async def save_credentials(credentials: Dict[str, Dict[str, str]]):
    async with aiofiles.open(CRED_FILE, 'w') as cred:
        await cred.write(json.dumps(credentials))

@app.post("/api/login")
async def api_login(request: Request, response: Response):
    content_type = request.headers.get('Content-Type')
    
    if content_type == 'application/json':
        body = await request.json()
    elif content_type == 'application/x-www-form-urlencoded':
        form = await request.form()
        body = dict(form)
    else:
        response.status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        return {'msg': 'Unsupported Content-Type', 'status_code': 415}
    
    user_email = body.get('email')
    user_password = body.get('password')
    
    if not user_email:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'msg': 'Please Enter Email', 'status_code': 400}
    
    credentials = await get_credentials()
    
    if user_email not in credentials:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {'msg': 'Please register First!!!', 'status_code': 401}
    
    if user_password != credentials[user_email]['password']:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {'msg': 'Incorrect Password', 'status_code': 403}
    
    return {'msg': 'Successfully logged In'}

@app.post("/api/signup")
async def api_signup(request: Request, response: Response):
    content_type = request.headers.get('Content-Type')
    
    if content_type == 'application/json':
        body = await request.json()
    elif content_type == 'application/x-www-form-urlencoded':
        form = await request.form()
        body = dict(form)
    else:
        response.status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        return {'msg': 'Unsupported Content-Type', 'status_code': 415}
    
    user_email = body.get('email')
    user_name = body.get('name')
    user_password = body.get('password')
    
    if not all([user_email, user_name, user_password]):
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'msg': 'Please Provide Email, Username, Password', 'status_code': 400}
    
    credentials = await get_credentials()
    
    if user_email in credentials:
        response.status_code = status.HTTP_409_CONFLICT
        return {'msg': 'User already exists', 'status_code': 409}
    
    credentials[user_email] = {
        'name': user_name,
        'password': user_password,
        'token': ''
    }
    
    await save_credentials(credentials)
    
    return {'msg': 'Successfully Registered'}

# @app.post("/login", response_class=HTMLResponse)
# async def post_login(email: str = Form(...), password: str = Form(...)):
#     body = {"email": email, "password": password}
#     return {'msg': 'Successfully logged In'}
