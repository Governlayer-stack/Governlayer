from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from src.models.database import get_db, User
from src.models.schemas import UserRegister, UserLogin
from src.security.auth import hash_password, verify_password, create_token

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = User(email=user.email, password_hash=hash_password(user.password), company=user.company)
    db.add(new_user)
    db.commit()
    token = create_token(user.email)
    return {"message": f"Welcome to GovernLayer {user.company}", "token": token, "email": user.email}


@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": create_token(user.email), "email": user.email}
