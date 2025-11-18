from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

# Igloo Schemas (each class name lowercased becomes collection name)

class User(BaseModel):
    role: str = Field(..., description="user|vendor|admin")
    full_name: str
    email: EmailStr
    password_hash: str
    phone: Optional[str] = None
    school: Optional[str] = None
    avatar_url: Optional[str] = None
    is_verified: bool = False

class VendorKYC(BaseModel):
    user_id: str
    business_name: Optional[str] = None
    gov_id_type: Optional[str] = None
    gov_id_number: Optional[str] = None
    cac_number: Optional[str] = None
    address: Optional[str] = None
    status: str = Field("pending", description="pending|approved|rejected")
    notes: Optional[str] = None

class Apartment(BaseModel):
    vendor_id: str
    title: str
    description: Optional[str] = None
    school: str
    location: str
    price_monthly: float
    type: str = Field(..., description="self-contained|shared|studio|1-bed|2-bed")
    distance_km: float
    amenities: List[str] = []
    photos: List[str] = []
    video_url: Optional[str] = None
    is_available: bool = True
    rating_avg: float = 0.0
    rating_count: int = 0

class Review(BaseModel):
    apartment_id: str
    user_id: str
    rating: int = Field(..., ge=1, le=5)
    comment: Optional[str] = None

class Favorite(BaseModel):
    user_id: str
    apartment_id: str

class Message(BaseModel):
    thread_id: str
    from_user_id: str
    to_user_id: str
    body: str

class MessageThread(BaseModel):
    student_id: str
    vendor_id: str
    last_message: Optional[str] = None
    last_time: Optional[datetime] = None

class BookingInterest(BaseModel):
    apartment_id: str
    user_id: str
    vendor_id: str
    message: Optional[str] = None
    status: str = Field("pending", description="pending|accepted|declined")

class Payment(BaseModel):
    user_id: str
    vendor_id: str
    apartment_id: str
    amount: float
    status: str = Field("pending", description="pending|paid|failed|refunded")

