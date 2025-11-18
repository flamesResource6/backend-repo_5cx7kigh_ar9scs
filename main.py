import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from bson import ObjectId
import jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents
from schemas import User as UserSchema, VendorKYC as VendorKYCSchema, Apartment as ApartmentSchema, Review as ReviewSchema, Favorite as FavoriteSchema, Message as MessageSchema, MessageThread as MessageThreadSchema, BookingInterest as BookingSchema, Payment as PaymentSchema

# Config
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_scheme = HTTPBearer()

app = FastAPI(title="Igloo API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AuthUser(BaseModel):
    id: str
    role: str
    email: EmailStr
    full_name: str


def get_current_user(token: HTTPAuthorizationCredentials = Depends(auth_scheme)) -> AuthUser:
    try:
        payload = jwt.decode(token.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        return AuthUser(id=payload.get("sub"), role=payload.get("role"), email=payload.get("email"), full_name=payload.get("name"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_role(required: List[str]):
    def checker(user: AuthUser = Depends(get_current_user)):
        if user.role not in required:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker

# Auth Models
class RegisterRequest(BaseModel):
    role: str
    full_name: str
    email: EmailStr
    password: str
    phone: Optional[str] = None
    school: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class SimpleOK(BaseModel):
    ok: bool

# Utilities

def find_one(collection: str, query: dict):
    doc = db[collection].find_one(query)
    if not doc:
        return None
    doc["id"] = str(doc.pop("_id"))
    return doc


def list_with_id(cursor):
    items = []
    for d in cursor:
        d["id"] = str(d.pop("_id"))
        items.append(d)
    return items

# Routes
@app.get("/")
def root():
    return {"name": "Igloo API", "status": "ok"}

@app.get("/schema")
def schema_defs():
    # hint for flames viewer
    from schemas import User, VendorKYC, Apartment, Review, Favorite, Message, MessageThread, BookingInterest, Payment
    return {
        "collections": [
            "user","vendorkyc","apartment","review","favorite","message","messagethread","bookinginterest","payment"
        ]
    }

# Auth
@app.post("/auth/register", response_model=TokenResponse)
def register(data: RegisterRequest):
    if db["user"].find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = pwd_context.hash(data.password)
    user = UserSchema(
        role=data.role, full_name=data.full_name, email=data.email, password_hash=hashed,
        phone=data.phone, school=data.school, is_verified=False
    )
    user_id = db["user"].insert_one(user.model_dump()).inserted_id
    token = create_access_token({"sub": str(user_id), "role": user.role, "email": user.email, "name": user.full_name})
    return TokenResponse(access_token=token)

@app.post("/auth/login", response_model=TokenResponse)
def login(data: LoginRequest):
    user = db["user"].find_one({"email": data.email})
    if not user or not pwd_context.verify(data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user["_id"]), "role": user["role"], "email": user["email"], "name": user.get("full_name","Igloo User")})
    return TokenResponse(access_token=token)

@app.get("/auth/me")
def me(user: AuthUser = Depends(get_current_user)):
    me_doc = find_one("user", {"_id": ObjectId(user.id)})
    return me_doc

# Vendor KYC
@app.post("/vendor/kyc", response_model=SimpleOK)
def submit_kyc(payload: VendorKYCSchema, user: AuthUser = Depends(require_role(["vendor"]))):
    payload_dict = payload.model_dump()
    payload_dict.update({"user_id": user.id, "status": "pending"})
    db["vendorkyc"].insert_one(payload_dict)
    return SimpleOK(ok=True)

@app.get("/vendor/kyc")
def get_my_kyc(user: AuthUser = Depends(require_role(["vendor"]))):
    return list_with_id(db["vendorkyc"].find({"user_id": user.id}))

# Apartments
class ApartmentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    school: str
    location: str
    price_monthly: float
    type: str
    distance_km: float
    amenities: List[str] = []
    photos: List[str] = []
    video_url: Optional[str] = None

@app.post("/apartments", response_model=dict)
def create_apartment(data: ApartmentCreate, user: AuthUser = Depends(require_role(["vendor"]))):
    apt = ApartmentSchema(
        vendor_id=user.id,
        title=data.title,
        description=data.description,
        school=data.school,
        location=data.location,
        price_monthly=data.price_monthly,
        type=data.type,
        distance_km=data.distance_km,
        amenities=data.amenities,
        photos=data.photos,
        video_url=data.video_url,
        is_available=True,
    )
    inserted = db["apartment"].insert_one(apt.model_dump())
    return {"id": str(inserted.inserted_id)}

@app.get("/apartments")
def list_apartments(school: Optional[str] = None, q: Optional[str] = None, min_price: Optional[float] = None, max_price: Optional[float] = None, amenities: Optional[str] = None):
    query = {}
    if school:
        query["school"] = school
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"location": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
        ]
    price_range = {}
    if min_price is not None:
        price_range["$gte"] = min_price
    if max_price is not None:
        price_range["$lte"] = max_price
    if price_range:
        query["price_monthly"] = price_range
    if amenities:
        query["amenities"] = {"$all": amenities.split(",")}
    return list_with_id(db["apartment"].find(query).sort("created_at", -1))

@app.get("/apartments/{apt_id}")
def get_apartment(apt_id: str):
    doc = db["apartment"].find_one({"_id": ObjectId(apt_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    doc["id"] = str(doc.pop("_id"))
    return doc

@app.post("/apartments/{apt_id}/reviews", response_model=SimpleOK)
def add_review(apt_id: str, payload: ReviewSchema, user: AuthUser = Depends(require_role(["user","vendor"]))):
    if payload.apartment_id != apt_id:
        raise HTTPException(status_code=400, detail="Mismatched apartment id")
    entry = payload.model_dump()
    entry.update({"user_id": user.id})
    db["review"].insert_one(entry)
    # Update rating aggregate
    stats = list(db["review"].aggregate([
        {"$match": {"apartment_id": apt_id}},
        {"$group": {"_id": "$apartment_id", "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}}
    ]))
    if stats:
        s = stats[0]
        db["apartment"].update_one({"_id": ObjectId(apt_id)}, {"$set": {"rating_avg": s["avg"], "rating_count": s["count"]}})
    return SimpleOK(ok=True)

# Favorites
@app.post("/favorites/{apt_id}", response_model=SimpleOK)
def save_favorite(apt_id: str, user: AuthUser = Depends(require_role(["user","vendor"]))):
    if not db["favorite"].find_one({"apartment_id": apt_id, "user_id": user.id}):
        db["favorite"].insert_one({"apartment_id": apt_id, "user_id": user.id})
    return SimpleOK(ok=True)

@app.get("/favorites")
def my_favorites(user: AuthUser = Depends(require_role(["user","vendor"]))):
    favs = list_with_id(db["favorite"].find({"user_id": user.id}))
    apt_ids = [ObjectId(f["apartment_id"]) for f in favs]
    apartments = list_with_id(db["apartment"].find({"_id": {"$in": apt_ids}})) if apt_ids else []
    return apartments

# Messaging
@app.post("/threads", response_model=dict)
def create_thread(vendor_id: str, user: AuthUser = Depends(require_role(["user"]))):
    existing = db["messagethread"].find_one({"student_id": user.id, "vendor_id": vendor_id})
    if existing:
        return {"id": str(existing["_id"]) }
    thread = MessageThreadSchema(student_id=user.id, vendor_id=vendor_id)
    inserted = db["messagethread"].insert_one(thread.model_dump())
    return {"id": str(inserted.inserted_id)}

class SendMessage(BaseModel):
    thread_id: str
    body: str

@app.post("/messages", response_model=SimpleOK)
def send_message(payload: SendMessage, user: AuthUser = Depends(require_role(["user","vendor"]))):
    thread = db["messagethread"].find_one({"_id": ObjectId(payload.thread_id)})
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")
    # authorization
    if user.role == "user" and thread["student_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not participant")
    if user.role == "vendor" and thread["vendor_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not participant")
    msg = MessageSchema(thread_id=payload.thread_id, from_user_id=user.id, to_user_id=(thread["vendor_id"] if user.role=="user" else thread["student_id"]), body=payload.body)
    db["message"].insert_one(msg.model_dump())
    db["messagethread"].update_one({"_id": ObjectId(payload.thread_id)}, {"$set": {"last_message": payload.body, "last_time": datetime.now(timezone.utc)}})
    return SimpleOK(ok=True)

@app.get("/threads")
def my_threads(user: AuthUser = Depends(require_role(["user","vendor"]))):
    filt = {"student_id": user.id} if user.role == "user" else {"vendor_id": user.id}
    return list_with_id(db["messagethread"].find(filt).sort("last_time", -1))

@app.get("/messages/{thread_id}")
def thread_messages(thread_id: str, user: AuthUser = Depends(require_role(["user","vendor"]))):
    thread = db["messagethread"].find_one({"_id": ObjectId(thread_id)})
    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")
    if user.role == "user" and thread["student_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not participant")
    if user.role == "vendor" and thread["vendor_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not participant")
    return list_with_id(db["message"].find({"thread_id": thread_id}).sort("created_at", 1))

# Booking Interests
class BookingCreate(BaseModel):
    apartment_id: str
    message: Optional[str] = None

@app.post("/bookings", response_model=SimpleOK)
def create_booking(payload: BookingCreate, user: AuthUser = Depends(require_role(["user"]))):
    apt = db["apartment"].find_one({"_id": ObjectId(payload.apartment_id)})
    if not apt:
        raise HTTPException(status_code=404, detail="Apartment not found")
    entry = BookingSchema(apartment_id=payload.apartment_id, user_id=user.id, vendor_id=str(apt["vendor_id"]) if isinstance(apt["vendor_id"], ObjectId) else apt["vendor_id"], message=payload.message)
    db["bookinginterest"].insert_one(entry.model_dump())
    return SimpleOK(ok=True)

@app.get("/bookings")

def my_bookings(user: AuthUser = Depends(require_role(["user","vendor"]))):
    filt = {"user_id": user.id} if user.role == "user" else {"vendor_id": user.id}
    return list_with_id(db["bookinginterest"].find(filt).sort("created_at", -1))

# Admin
class AdminAction(BaseModel):
    id: str
    approve: bool
    notes: Optional[str] = None

@app.get("/admin/overview")
def admin_overview(user: AuthUser = Depends(require_role(["admin"]))):
    return {
        "users": db["user"].count_documents({}),
        "vendors": db["user"].count_documents({"role": "vendor"}),
        "apartments": db["apartment"].count_documents({}),
        "active_listings": db["apartment"].count_documents({"is_available": True}),
        "bookings": db["bookinginterest"].count_documents({}),
        "pending_kyc": db["vendorkyc"].count_documents({"status": "pending"}),
    }

@app.get("/admin/kyc")
def admin_list_kyc(user: AuthUser = Depends(require_role(["admin"]))):
    return list_with_id(db["vendorkyc"].find({"status": "pending"}))

@app.post("/admin/kyc/decision", response_model=SimpleOK)
def admin_kyc_decision(payload: AdminAction, user: AuthUser = Depends(require_role(["admin"]))):
    status = "approved" if payload.approve else "rejected"
    db["vendorkyc"].update_one({"_id": ObjectId(payload.id)}, {"$set": {"status": status, "notes": payload.notes}})
    return SimpleOK(ok=True)

@app.get("/admin/listings")
def admin_listings(user: AuthUser = Depends(require_role(["admin"]))):
    return list_with_id(db["apartment"].find({}))

class ListingDecision(BaseModel):
    id: str
    is_available: bool

@app.post("/admin/listings/availability", response_model=SimpleOK)
def admin_toggle_listing(payload: ListingDecision, user: AuthUser = Depends(require_role(["admin"]))):
    db["apartment"].update_one({"_id": ObjectId(payload.id)}, {"$set": {"is_available": payload.is_available}})
    return SimpleOK(ok=True)

# Health/Test
@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
