from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, Depends, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import base64
import io
from openai import OpenAI
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import jwt
from passlib.context import CryptContext

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'neuroscan_db')]

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# Security
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production-2024')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# LLM Configuration
LLM_API_KEY = os.environ.get('EMERGENT_LLM_KEY', '')

# Auth Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    full_name: str
    phone: Optional[str] = None
    age: Optional[int] = None
    gender: Optional[str] = None
    address: Optional[str] = None
    medical_history: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None
    age: Optional[int] = None
    gender: Optional[str] = None
    address: Optional[str] = None
    medical_history: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

# Appointment Models
class AppointmentCreate(BaseModel):
    doctor_id: str
    appointment_date: str
    appointment_time: str
    reason: str

class Appointment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    doctor_id: str
    doctor_name: str
    doctor_specialization: str
    appointment_date: str
    appointment_time: str
    reason: str
    status: str = "Pending"  # Pending, Confirmed, Cancelled
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Other Models
class ScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    scan_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    image_data: str
    analysis_result: str
    tumor_detected: bool
    severity: Optional[str] = None
    recommended_doctor: Optional[str] = None
    doctor_specialization: Optional[str] = None

class ScanCreate(BaseModel):
    user_id: str
    image_data: str

class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    user_id: str
    message: str
    response: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ChatRequest(BaseModel):
    user_id: str
    session_id: str
    message: str

class Doctor(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    specialization: str
    experience: str
    location: str
    contact: str
    rating: float

# Auth Helper Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# Auth Routes
@api_router.post("/auth/register", response_model=Token)
async def register(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email,
        full_name=user_data.full_name
    )
    
    user_doc = user.model_dump()
    user_doc['created_at'] = user_doc['created_at'].isoformat()
    user_doc['password_hash'] = get_password_hash(user_data.password)
    
    await db.users.insert_one(user_doc)
    
    # Create token
    access_token = create_access_token(data={"sub": user.id})
    
    return Token(access_token=access_token, token_type="bearer", user=user)

@api_router.post("/auth/login", response_model=Token)
async def login(login_data: UserLogin):
    user = await db.users.find_one({"email": login_data.email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not verify_password(login_data.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Remove password_hash from response
    user.pop('password_hash', None)
    user_obj = User(**user)
    access_token = create_access_token(data={"sub": user_obj.id})
    
    return Token(access_token=access_token, token_type="bearer", user=user_obj)

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@api_router.put("/profile", response_model=User)
async def update_profile(profile_data: UserProfileUpdate, current_user: User = Depends(get_current_user)):
    update_data = {k: v for k, v in profile_data.model_dump().items() if v is not None}
    
    if update_data:
        await db.users.update_one(
            {"id": current_user.id},
            {"$set": update_data}
        )
    
    # Fetch updated user
    updated_user = await db.users.find_one({"id": current_user.id}, {"_id": 0, "password_hash": 0})
    return User(**updated_user)

# Appointment Routes
@api_router.post("/appointments", response_model=Appointment)
async def create_appointment(appointment_data: AppointmentCreate, current_user: User = Depends(get_current_user)):
    # Get doctor info
    doctor = await db.doctors.find_one({"id": appointment_data.doctor_id}, {"_id": 0})
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    appointment = Appointment(
        user_id=current_user.id,
        doctor_id=appointment_data.doctor_id,
        doctor_name=doctor['name'],
        doctor_specialization=doctor['specialization'],
        appointment_date=appointment_data.appointment_date,
        appointment_time=appointment_data.appointment_time,
        reason=appointment_data.reason
    )
    
    doc = appointment.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.appointments.insert_one(doc)
    
    return appointment

@api_router.get("/appointments", response_model=List[Appointment])
async def get_user_appointments(current_user: User = Depends(get_current_user)):
    appointments = await db.appointments.find(
        {"user_id": current_user.id},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    for apt in appointments:
        if isinstance(apt['created_at'], str):
            apt['created_at'] = datetime.fromisoformat(apt['created_at'])
    
    return appointments

@api_router.delete("/appointments/{appointment_id}")
async def cancel_appointment(appointment_id: str, current_user: User = Depends(get_current_user)):
    result = await db.appointments.update_one(
        {"id": appointment_id, "user_id": current_user.id},
        {"$set": {"status": "Cancelled"}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    return {"message": "Appointment cancelled successfully"}

# AI Analysis Function

# REAL MRI ANALYSIS USING OPENAI GPT-4o VISION
async def analyze_mri_image(image_base64: str):
    """
    Uses OpenAI GPT-4o to analyze an MRI brain image.
    Returns tumor presence, severity, specialist, and explanation.
    """
    try:
        # Build chat completion request with embedded image (data URI)
        response = client_ai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a medical MRI analyst specialized in detecting brain tumors. "
                        "Analyze the image and follow EXACTLY this format:\n"
                        "TUMOR_DETECTED: YES/NO\n"
                        "SEVERITY: Low/Medium/High\n"
                        "SPECIALIST: Neurologist/Neurosurgeon/Oncologist\n"
                        "ANALYSIS: short explanation"
                    )
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Analyze this MRI scan:"},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/png;base64,{image_base64}"}
                        }
                    ]
                }
            ],
            temperature=0.0,
            max_tokens=1000
        )

        # Extract response text
        result = ""
        if hasattr(response, "choices") and len(response.choices) > 0:
            try:
                result = response.choices[0].message["content"]
            except Exception:
                result = str(response.choices[0])
        else:
            result = str(response)

        # Normalize for parsing
        up = result.upper()
        tumor_detected = False
        if "TUMOR_DETECTED:" in up:
            try:
                val = up.split("TUMOR_DETECTED:")[1].split("\n")[0].strip()
                tumor_detected = val.startswith("Y")
            except Exception:
                tumor_detected = "YES" in up

        # severity
        severity = "Unknown"
        if "SEVERITY:" in up:
            s = up.split("SEVERITY:")[1].split("\n")[0].strip()
            if "HIGH" in s:
                severity = "High"
            elif "MEDIUM" in s:
                severity = "Medium"
            elif "LOW" in s:
                severity = "Low"

        specialist = "Neurologist"
        if "SPECIALIST:" in up:
            try:
                specialist = result.split("SPECIALIST:")[1].split("\n")[0].strip()
            except Exception:
                pass

        return {
            "tumor_detected": tumor_detected,
            "severity": severity,
            "specialist": specialist,
            "analysis": result
        }

    except Exception as e:
        logging.error(f"AI analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"AI Analysis failed: {str(e)}")

# Routes
@api_router.get("/")
async def root():
    return {"message": "NeuroScan AI API"}

@api_router.post("/scan", response_model=ScanResult)
async def create_scan(scan: ScanCreate, current_user: User = Depends(get_current_user)):
    try:
        # Analyze the MRI image
        analysis = await analyze_mri_image(scan.image_data)
        
        # Get recommended doctor based on specialization
        recommended_doctor = None
        doctor_specialization = analysis['specialist']
        
        doctors = await db.doctors.find_one({"specialization": doctor_specialization})
        if doctors:
            recommended_doctor = doctors.get('name')
        
        # Create scan result
        scan_result = ScanResult(
            user_id=current_user.id,
            image_data=scan.image_data,
            analysis_result=analysis['analysis'],
            tumor_detected=analysis['tumor_detected'],
            severity=analysis['severity'],
            recommended_doctor=recommended_doctor,
            doctor_specialization=doctor_specialization
        )
        
        # Save to database
        doc = scan_result.model_dump()
        doc['scan_date'] = doc['scan_date'].isoformat()
        await db.scans.insert_one(doc)
        
        return scan_result
    except Exception as e:
        logging.error(f"Error creating scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/scans/{user_id}", response_model=List[ScanResult])
async def get_user_scans(user_id: str, current_user: User = Depends(get_current_user)):
    if user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    scans = await db.scans.find({"user_id": user_id}, {"_id": 0}).sort("scan_date", -1).to_list(100)
    
    for scan in scans:
        if isinstance(scan['scan_date'], str):
            scan['scan_date'] = datetime.fromisoformat(scan['scan_date'])
    
    return scans

@api_router.post("/chat", response_model=ChatMessage)
async def chat_assistant(chat_req: ChatRequest, current_user: User = Depends(get_current_user)):
    try:
        chat = LlmChat(
            api_key=LLM_API_KEY,
            session_id=chat_req.session_id,
            system_message="You are NeuroScan AI assistant. Help users understand their brain health, MRI results, and provide medical information. Always remind users to consult healthcare professionals for medical advice."
        ).with_model("openai", "gpt-4o-mini")
        
        user_message = UserMessage(text=chat_req.message)
        response = await chat.send_message(user_message)
        
        chat_message = ChatMessage(
            session_id=chat_req.session_id,
            user_id=current_user.id,
            message=chat_req.message,
            response=response
        )
        
        # Save to database
        doc = chat_message.model_dump()
        doc['timestamp'] = doc['timestamp'].isoformat()
        await db.chats.insert_one(doc)
        
        return chat_message
    except Exception as e:
        logging.error(f"Error in chat: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/chat-history/{user_id}/{session_id}")
async def get_chat_history(user_id: str, session_id: str, current_user: User = Depends(get_current_user)):
    if user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    chats = await db.chats.find(
        {"user_id": user_id, "session_id": session_id},
        {"_id": 0}
    ).sort("timestamp", 1).to_list(1000)
    
    for chat in chats:
        if isinstance(chat['timestamp'], str):
            chat['timestamp'] = datetime.fromisoformat(chat['timestamp'])
    
    return chats

@api_router.get("/doctors", response_model=List[Doctor])
async def get_doctors(current_user: User = Depends(get_current_user)):
    doctors = await db.doctors.find({}, {"_id": 0}).to_list(100)
    return doctors

@api_router.post("/doctors", response_model=Doctor)
async def create_doctor(doctor: Doctor):
    doc = doctor.model_dump()
    await db.doctors.insert_one(doc)
    return doctor

@api_router.get("/report/{scan_id}")
async def generate_report(scan_id: str, current_user: User = Depends(get_current_user)):
    try:
        # Get scan data
        scan = await db.scans.find_one({"id": scan_id, "user_id": current_user.id}, {"_id": 0})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Create PDF
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=30,
            alignment=1
        )
        story.append(Paragraph("NeuroScan AI - Medical Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Patient Info
        data = [
            ['Report ID:', scan_id],
            ['Scan Date:', scan.get('scan_date', 'N/A')],
            ['Patient ID:', scan.get('user_id', 'N/A')],
        ]
        
        t = Table(data, colWidths=[2*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e0e7ff')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3*inch))
        
        # Results
        story.append(Paragraph("<b>Analysis Results</b>", styles['Heading2']))
        story.append(Spacer(1, 0.1*inch))
        
        result_data = [
            ['Tumor Detected:', 'Yes' if scan.get('tumor_detected') else 'No'],
            ['Severity:', scan.get('severity', 'N/A')],
            ['Recommended Specialist:', scan.get('doctor_specialization', 'N/A')],
        ]
        
        t2 = Table(result_data, colWidths=[2*inch, 4*inch])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#fee2e2')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(t2)
        story.append(Spacer(1, 0.3*inch))
        
        # Detailed Analysis
        story.append(Paragraph("<b>Detailed Analysis</b>", styles['Heading2']))
        story.append(Spacer(1, 0.1*inch))
        analysis_text = scan.get('analysis_result', 'No analysis available')
        story.append(Paragraph(analysis_text.replace('\n', '<br/>'), styles['BodyText']))
        
        doc.build(story)
        buffer.seek(0)
        
        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=neuroscan_report_{scan_id}.pdf"}
        )
    except Exception as e:
        logging.error(f"Error generating report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()