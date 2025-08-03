import os, json
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError, ExpiredSignatureError
from passlib.context import CryptContext

router = APIRouter()

JWT_SECRET = os.getenv("JWT_SECRET", "conformscan-backend-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

USERS_DB_PATH = "users.json"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def _read_users() -> Dict[str, Dict]:
    if not os.path.isfile(USERS_DB_PATH):
        return {}
    try:
        with open(USERS_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _write_users(data: Dict[str, Dict]) -> None:
    with open(USERS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def get_user(email: str) -> Optional[Dict]:
    return _read_users().get(email)

def create_user(email: str, password: str, role: str = "admin") -> None:
    db = _read_users()
    if email in db:
        return
    db[email] = {
        "email": email,
        "password_hash": pwd_context.hash(password),
        "role": role,
        "is_active": True,
        "stripe_status": "inactive"
    }
    _write_users(db)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

@router.post("/token")
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form.username)
    if not user or not verify_password(form.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Identifiants invalides")
    token = create_access_token({"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Token invalide")
        user = get_user(email)
        if not user or not user.get("is_active"):
            raise HTTPException(status_code=401, detail="Utilisateur inactif")
        return user
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide")

@router.get("/me")
def me(user: Dict = Depends(get_current_user)):
    return {"email": user["email"], "role": user["role"], "is_active": user["is_active"]}

def initialize_admin_user():
    if not get_user("admin@conformscan.ch"):
        create_user("admin@conformscan.ch", "admin123", role="admin")
        print("✅ Admin créé : admin@conformscan.ch / admin123")
    else:
        print("ℹ️ Admin déjà existant : admin@conformscan.ch")
