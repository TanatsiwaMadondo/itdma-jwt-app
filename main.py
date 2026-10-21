from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models, schemas
from auth.jwt_auth import (
    hash_password, verify_password,
    create_access_token, get_current_user
)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Student Auth API — JWT", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
def root():
    with open("templates/index.html") as f:
        return f.read()


@app.post("/auth/register", response_model=schemas.StudentOut, status_code=201)
def register(student: schemas.StudentCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Student).filter(models.Student.email == student.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = hash_password(student.password)
    db_student = models.Student(
        full_name=student.full_name,
        email=student.email,
        hashed_password=hashed
    )
    db.add(db_student)
    db.commit()
    db.refresh(db_student)
    return db_student


@app.post("/auth/login", response_model=schemas.TokenResponse)
def login(credentials: schemas.LoginRequest, db: Session = Depends(get_db)):
    student = db.query(models.Student).filter(models.Student.email == credentials.email).first()
    if not student or not verify_password(credentials.password, student.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": str(student.id), "email": student.email})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/students/me", response_model=schemas.StudentOut)
def get_me(current_user: models.Student = Depends(get_current_user)):
    return current_user


@app.get("/students", response_model=list[schemas.StudentOut])
def list_students(
    db: Session = Depends(get_db),
    current_user: models.Student = Depends(get_current_user)
):
    return db.query(models.Student).all()


@app.delete("/students/{student_id}", status_code=204)
def delete_student(
    student_id: int,
    db: Session = Depends(get_db),
    current_user: models.Student = Depends(get_current_user)
):
    student = db.query(models.Student).filter(models.Student.id == student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    db.delete(student)
    db.commit()
