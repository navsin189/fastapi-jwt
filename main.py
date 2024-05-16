from fastapi import FastAPI, Depends, HTTPException, status, Form, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
import aiofiles
import json

# JWT configuration
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

CRED_FILE = 'users.json'

app = FastAPI()

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None

class User(BaseModel):
    username: str
    email: str

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_credentials():
    async with aiofiles.open(CRED_FILE, 'r') as cred:
        return json.loads(await cred.read())

async def save_credentials(credentials):
    async with aiofiles.open(CRED_FILE, 'w') as cred:
        await cred.write(json.dumps(credentials))

async def authenticate_user(email: str, password: str):
    credentials = await get_credentials()
    if email not in credentials:
        return False
    user_dict = credentials[email]
    user = UserInDB(**user_dict)
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    credentials = await get_credentials()
    if token_data.email not in credentials:
        raise credentials_exception
    user_dict = credentials[token_data.email]
    user = UserInDB(**user_dict)
    return user

@app.post("/token", response_model=Token)
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    content_type = request.headers.get('Content-Type')
    if content_type == "application/json":
        body = await request.json()
        email = body.get("email")
        password = body.get("password")
    else:
        email = form_data.username
        password = form_data.password

    user = await authenticate_user(email, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/signup", status_code=status.HTTP_201_CREATED)
async def api_signup(request: Request):
    content_type = request.headers.get('Content-Type')
    if content_type == "application/json":
        body = await request.json()
        email = body.get("email")
        name = body.get("name")
        password = body.get("password")
    else:
        form = await request.form()
        email = form.get("email")
        name = form.get("name")
        password = form.get("password")

    if not email or not name or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email, name, and password are required",
        )

    credentials = await get_credentials()
    if email in credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    hashed_password = get_password_hash(password)
    credentials[email] = {
        "username": name,
        "email": email,
        "hashed_password": hashed_password,
    }
    await save_credentials(credentials)
    return {"msg": "Successfully Registered"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user
