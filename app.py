import re
import os
import io
import json
import logging
import traceback
from google.cloud.firestore_v1 import FieldFilter
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from pypdf import PdfReader
from google.cloud import storage
from sentence_transformers import SentenceTransformer
from google.cloud import aiplatform
from vertexai.generative_models import GenerativeModel
import firebase_admin
from firebase_admin import credentials, auth, firestore
import requests
from functools import wraps
from flask_mail import Mail, Message
import random
import time
from dotenv import load_dotenv
from datetime import datetime, timedelta
from chat import chat_bp
from chatbot import chatbot_bp
from google.cloud.firestore_v1 import SERVER_TIMESTAMP
from firebase_admin import auth as fb_auth
from google.cloud import firestore
from firebase_admin.auth import UserNotFoundError  # Added for correct exception handling
from google.auth import default

# Import enhanced Vertex AI RAG services
ENHANCED_RAG_AVAILABLE = False
enhanced_chat_service = None
enhanced_quiz_service = None


try:
    from vertex_ai_rag import EnhancedChatService, EnhancedQuizService
    ENHANCED_RAG_AVAILABLE = True
    print("✅ Enhanced RAG services imported successfully")
except ImportError as e:
    print(f"⚠️ Enhanced RAG not available: {e}")
    print("💡 To enable enhanced features, install: pip install google-cloud-aiplatform vertexai sentence-transformers")
except Exception as e:
    print(f"⚠️ Error importing enhanced RAG: {e}")
    print("💡 The application will run with original features only")

load_dotenv()

# ===== Initialize Flask App =====
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default-secret')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.register_blueprint(chat_bp)
app.register_blueprint(chatbot_bp)

# ===== Configure Logging =====
app_logger = logging.getLogger(__name__)
app_logger.setLevel(logging.INFO)
if not app_logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app_logger.addHandler(handler)

# ===== Google Cloud Configuration =====
project_id = os.getenv('PROJECT_ID', 'guru-ai-project-id')
location = os.getenv('LOCATION', 'us-central1')

try:
    aiplatform.init(project=project_id, location=location)
    app.logger.info(f"Vertex AI Platform initialized for project {project_id} in {location}.")
except Exception as e:
    app.logger.error(f"Failed to initialize Vertex AI Platform: {str(e)}", exc_info=True)

# ===== Initialize Enhanced RAG Services =====
if ENHANCED_RAG_AVAILABLE:
    try:
        enhanced_chat_service = EnhancedChatService(project_id, location)
        enhanced_quiz_service = EnhancedQuizService(project_id, location)
        app.logger.info("Enhanced RAG services initialized successfully")
    except Exception as e:
        app.logger.error(f"Failed to initialize enhanced RAG services: {str(e)}")
        enhanced_chat_service = None
        enhanced_quiz_service = None

# ===== Firebase Initialization =====
def initialize_firebase():
    if not firebase_admin._apps:
        try:
            cred_path = os.getenv("FIREBASE_CREDENTIALS_PATH")or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
            if not cred_path or not os.path.exists(cred_path):
                app.logger.warning("Service account key file not found")
                cred = None 
            else:
                app.logger.info(f"Using Firebase credentials from path: {cred_path}")
                cred = credentials.Certificate(cred_path)
            
            firebase_admin.initialize_app(cred, {
                'projectId': os.getenv("PROJECT_ID")
            })
            app.logger.info("Firebase initialized successfully")
            return firestore.Client()
        except Exception as e:
            app.logger.error(f"Firebase initialization error: {str(e)}", exc_info=True)
            raise
    creds, proj = default()
    app.logger.info(f"✅ Active service account: {creds.service_account_email}")
    return firestore.Client()


try:
    db = initialize_firebase()
except Exception as e:
    db = None
    app.logger.error(f"WARNING: Firebase initialization failed - {str(e)}")

# ===== Load Sentence Transformer Model =====
try:
    embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
    app.logger.info("Embedding model loaded successfully")
except Exception as e:
    embedding_model = None
    app.logger.error(f"Failed to load embedding model: {str(e)}", exc_info=True)

# ===== Email Configuration =====
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER')
)
mail = Mail(app)

# ===== Recaptcha Configuration =====
RECAPTCHA_ENABLED = os.getenv("RECAPTCHA_ENABLED", "false").lower() == "true"

# ===== Helper Functions =====

def validate_pdf_path(path):
    """
    More flexible path validation for your bucket structure.
    Expected format: gs://guru-ai-bucket/NCERT/Class X/Subject/chapter (X).pdf
    or variations.
    """
    if not path.startswith('gs://guru-ai-bucket/'):
        app.logger.warning(f"Invalid path prefix: {path}")
        return False
    
    parts = path.split('/')
    if len(parts) < 7: # Minimum parts for a valid path
        app.logger.warning(f"Path has too few segments ({len(parts)}): {path}")
        return False
        
    if parts[3].lower() != 'ncert':
        app.logger.warning(f"Expected 'NCERT' at parts[3], got '{parts[3]}' from {path}")
        return False

    class_part = parts[4].lower() 
    if not re.match(r'class[ _]?(6|7|8|9|10|11|12)$', class_part):
        app.logger.warning(f"Invalid class format in path: '{class_part}' from {path}")
        return False
        
    chapter_file = parts[-1].lower()
    valid_patterns = [
        r'chapter[ _]?\(?\d+\)?\.pdf$',
        r'chapter[ _]\d+[ _].+\.pdf$'
    ]
    
    is_valid_file = any(re.match(p, chapter_file) for p in valid_patterns)
    if not is_valid_file:
        app.logger.warning(f"Invalid chapter file format: '{chapter_file}' from {path}")
    return is_valid_file

def get_pdf_from_storage(bucket_name, file_path):
    """
    Retrieve PDF content from Google Cloud Storage.
    This function expects the exact GCS file_path (blob name).
    Path variations should be handled *before* calling this function.
    """
    try:
        app.logger.info(f"Attempting to load PDF from GCS: gs://{bucket_name}/{file_path}")
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(file_path)
        
        if not blob.exists():
            app.logger.error(f"File not found in GCS: gs://{bucket_name}/{file_path}")
            raise FileNotFoundError(f"File not found at gs://{bucket_name}/{file_path}")
            
        pdf_bytes = blob.download_as_bytes()
        app.logger.info(f"Successfully downloaded {len(pdf_bytes)} bytes from GCS for '{file_path}'.")
        return pdf_bytes
    except Exception as e:
        app.logger.error(f"Error loading PDF from GCS for '{file_path}': {str(e)}", exc_info=True)
        raise

def split_pdf_into_chunks(pdf_bytes, metadata=None, chunk_size=1000):
    """
    Split PDF into manageable chunks, associating each with provided metadata.
    Uses io.BytesIO to present bytes as a file-like object to pypdf.
    """
    if metadata is None:
        metadata = {} # Ensure metadata is always a dict
    
    try:
        app.logger.info(f"Starting PDF splitting into chunks. Bytes received: {len(pdf_bytes)}. Metadata: {metadata}")
        pdf_stream = io.BytesIO(pdf_bytes)
        
        reader = PdfReader(pdf_stream)
        
        chunks_with_metadata = []
        
        for i, page in enumerate(reader.pages):
            try:
                text = page.extract_text()
                if text:
                    words = text.split()
                    for j in range(0, len(words), chunk_size):
                        chunk_text = ' '.join(words[j:j+chunk_size])
                        # Store each chunk as a dictionary with text and its metadata
                        chunks_with_metadata.append({
                            "text": chunk_text,
                            "metadata": {**metadata, "page": i + 1} # Add page number to metadata
                        })
                else:
                    app.logger.warning(f"No text extracted from page {i+1}.")
            except Exception as page_e:
                app.logger.error(f"Error extracting text from page {i+1}: {str(page_e)}", exc_info=True)
                
        app.logger.info(f"Finished PDF splitting. Total chunks with metadata: {len(chunks_with_metadata)}")
        return chunks_with_metadata
    except Exception as e:
        app.logger.error(f"Error splitting PDF: {str(e)}", exc_info=True)
        raise

def get_chunks_filename(bucket_name, file_path):
    """
    Generate consistent filename for storing chunks in /tmp/.
    Cloud Run's ephemeral storage is /tmp/.
    """
    safe_path = file_path.replace('/', '_').replace('.', '_').replace(' ', '_').replace('(', '').replace(')', '')
    temp_dir = f"/tmp/chunks_cache"
    os.makedirs(temp_dir, exist_ok=True)
    return os.path.join(temp_dir, f"{bucket_name}_{safe_path}.json")

def store_chunks(bucket_name, file_path, chunks):
    """Store chunks (with metadata) in local filesystem (/tmp/) with proper error handling"""
    chunks_filename = get_chunks_filename(bucket_name, file_path)
    try:
        with open(chunks_filename, 'w', encoding='utf-8') as f:
            json.dump(chunks, f, ensure_ascii=False)
        app.logger.info(f"Successfully stored chunks (with metadata) to temporary file: {chunks_filename}")
    except Exception as e:
        app.logger.error(f"Error storing chunks to {chunks_filename}: {str(e)}", exc_info=True)
        raise

def load_chunks(bucket_name, file_path):
    """Load chunks (with metadata) from local filesystem (/tmp/) with proper error handling"""
    chunks_filename = get_chunks_filename(bucket_name, file_path)
    try:
        app.logger.info(f"Attempting to load chunks (with metadata) from temporary file: {chunks_filename}")
        if os.path.exists(chunks_filename):
            with open(chunks_filename, 'r', encoding='utf-8') as f:
                loaded_chunks = json.load(f)
            app.logger.info(f"Successfully loaded {len(loaded_chunks)} chunks from cache.")
            return loaded_chunks
        app.logger.info(f"Chunks file not found in cache: {chunks_filename}")
        return None
    except Exception as e:
        app.logger.error(f"Error loading chunks from {chunks_filename}: {str(e)}", exc_info=True)
        return None

def retrieve_relevant_chunks(chunks_with_metadata, query, filters=None, top_k=3):
    """
    Retrieve most relevant chunks using semantic search, applying metadata filters first.
    chunks_with_metadata: List of dictionaries, each with 'text' and 'metadata' keys.
    filters: Dictionary of metadata to filter by, e.g., {'class': 'Class 10', 'subject': 'Science'}
    """
    if not chunks_with_metadata or not query:
        app.logger.warning("No chunks or query provided for retrieval.")
        return []
            
    if embedding_model is None:
        app.logger.error("Embedding model not loaded. Cannot retrieve relevant chunks.")
        return []

    # 1. Apply metadata filters
    filtered_chunks = []
    if filters:
        app.logger.info(f"Applying metadata filters: {filters}")
        for chunk_item in chunks_with_metadata:
            match = True
            for key, value in filters.items():
                if key not in chunk_item['metadata'] or chunk_item['metadata'][key].lower() != value.lower():
                    match = False
                    break
            if match:
                filtered_chunks.append(chunk_item)
        app.logger.info(f"Filtered down to {len(filtered_chunks)} chunks after metadata filtering.")
    else:
        filtered_chunks = chunks_with_metadata # No filters, use all chunks

    if not filtered_chunks:
        app.logger.info("No chunks found after applying metadata filters.")
        return []

    # 2. Perform semantic search on filtered chunks
    try:
        query_embedding = embedding_model.encode([query])[0]
        
        # Extract just the text for embedding
        texts_to_embed = [item['text'] for item in filtered_chunks]
        chunk_embeddings = embedding_model.encode(texts_to_embed) 
        
        scored_chunks = []
        for i, chunk_embedding in enumerate(chunk_embeddings):
            score = (query_embedding * chunk_embedding).sum() 
            scored_chunks.append((score, filtered_chunks[i])) # Keep the original chunk item (with metadata)
            
        scored_chunks.sort(reverse=True, key=lambda x: x[0])
        
        # Return only the 'text' content of the top_k relevant chunks
        # You might want to return the full chunk_item if you need metadata later
        relevant_texts = [item['text'] for score, item in scored_chunks[:top_k]]
        app.logger.info(f"Retrieved {len(relevant_texts)} relevant chunks after semantic search.")
        return relevant_texts
    except Exception as e:
        app.logger.error(f"Error retrieving chunks: {str(e)}", exc_info=True)
        return []

def generate_answer(context, query, model_name="gemini-2.0-flash-001"):
    """Generate answer using Gemini model with proper error handling"""
    try:
        if not context or not query:
            app.logger.warning("No context or query provided for answer generation.")
            return "I couldn't find enough context to answer that question."
            
        model = GenerativeModel(model_name)
        prompt = (
            f"You are an expert educational assistant. Provide detailed, structured answers to student questions.\n\n"
            f"Context:\n{context}\n\n"
            f"Question: {query}\n\n"
            f"Format your answer with:\n"
            f"- **Bold** for key terms\n"
            f"- *Italics* for emphasis\n"
            f"- Lists for multiple items\n"
            f"- Tables for comparative data\n"
            f"- Headings for sections\n"
            f"- Clear explanations with examples where needed\n\n"
            f"Answer in detail, covering all relevant aspects from the context. "
            f"If the question can't be answered from the context, say so explicitly.\n\n"
            f"Answer:"
        )
        
        response = model.generate_content(prompt)
        app.logger.info("Successfully generated answer from Gemini.")
        return response.text.strip()
    except Exception as e:
        app.logger.error(f"Error generating answer: {str(e)}", exc_info=True)
        return "I encountered an error while generating an answer. Please try again."

# ===== Authentication Decorator =====
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            app.logger.warning("Authentication required, user not in session.")
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return wrapper

# ===== Routes =====
@app.route('/')
@app.route('/index.html')
def index():
    # if 'user' in session:
    #     return redirect(url_for('dashboard'))
    # return redirect(url_for('login_page'))
    return render_template('index.html')

@app.route('/chatbot.html')
def chatbot():
    return render_template('chatbot.html') 

@app.route('/dashboard.html')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/login.html')
def login_page():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    firebase_config = {
        "apiKey": os.getenv("FIREBASE_API_KEY"),
        "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
        "projectId": os.getenv("FIREBASE_PROJECT_ID"),
        "appId": os.getenv("FIREBASE_APP_ID")
    }
    recaptcha_enabled = RECAPTCHA_ENABLED
    return render_template("login.html", firebase_config=json.dumps(firebase_config), recaptcha_enabled=recaptcha_enabled)

@app.route('/register.html')
def register_page():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/chat.html')
@login_required
def chat_page():
    return render_template('chat.html')

@app.route('/quiz.html')
@login_required
def quiz_page():
    return render_template('quiz.html')

@app.route('/otp_verification.html')
def otp_verification_page():
    if 'registration_data' not in session:
        return redirect(url_for('register_page'))
    return render_template('otp_verification.html')

@app.route('/forgot-password.html')
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/api/user')
@login_required
def get_user():
    try:
        if db is None:
            return jsonify({'error': 'Database not initialized'}), 500
        user_email = session.get('user')
        app.logger.info(f"API /user called - Session user: {user_email}")
        app.logger.info(f"Full session data: {dict(session)}")
        
        if not user_email:
            app.logger.warning("No user email in session")
            return jsonify({'error': 'User not authenticated'}), 401
        
        # Try to get user from Firebase Auth first (for regular users)
        try:
            user = auth.get_user_by_email(user_email)
            user_ref = db.collection('users').document(user.uid)
            user_data = user_ref.get().to_dict()
            
            if not user_data:
                app.logger.warning(f"User data not found for UID: {user.uid}")
                return jsonify({'error': 'User data not found'}), 404
            
            # Handle timestamp fields
            for ts_field in ['createdAt', 'lastLogin']:
                if ts_field in user_data and hasattr(user_data[ts_field], 'isoformat'):
                    user_data[ts_field] = user_data[ts_field].isoformat()

            return jsonify({
                'user': {
                    'uid': user.uid,
                    'email': user.email,
                    'name': user.display_name,
                    'board': user_data.get('board', ''),
                    'class': user_data.get('class', ''),
                    'stream': user_data.get('stream', 'NA'),
                    'scores': user_data.get('scores', {}),
                    'createdAt': user_data.get('createdAt'),
                    'lastLogin': user_data.get('lastLogin')
                }
            })
            
        except UserNotFoundError:
            # User not found in Firebase Auth - try to get from Firestore directly (for OTP users)
            app.logger.info(f"User not found in Firebase Auth, trying Firestore for email: {user_email}")
            
            # Check if this is a phone-based identifier
            if user_email.startswith('phone_'):
                # Extract phone number from the identifier
                phone_number = user_email.replace('phone_', '').replace('@guruai.local', '')
                app.logger.info(f"Phone-based identifier detected, looking up by phone: {phone_number}")
                
                # Search for user by phone number in Firestore
                user_query = db.collection('users').where('phoneNumber', '==', phone_number).limit(1).get()
            else:
                # Search for user by email in Firestore
                user_query = db.collection('users').where('email', '==', user_email).limit(1).get()
            
            if not user_query:
                app.logger.warning(f"User not found in Firestore for identifier: {user_email}")
                return jsonify({'error': 'User data not found'}), 404
            
            user_doc = user_query[0]
            user_data = user_doc.to_dict() or {}
            
            # Handle timestamp fields
            for ts_field in ['createdAt', 'lastLogin']:
                if ts_field in user_data and hasattr(user_data[ts_field], 'isoformat'):
                    user_data[ts_field] = user_data[ts_field].isoformat()

            return jsonify({
                'user': {
                    'uid': user_doc.id,
                    'email': user_data.get('email', ''),
                    'name': user_data.get('name', ''),
                    'board': user_data.get('board', ''),
                    'class': user_data.get('class', ''),
                    'stream': user_data.get('stream', 'NA'),
                    'scores': user_data.get('scores', {}),
                    'createdAt': user_data.get('createdAt'),
                    'lastLogin': user_data.get('lastLogin')
                }
            })
            
    except Exception as e:
        app.logger.error(f"Error getting user data: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500


# Add these new routes to your existing app.py
def get_db():
    global db
    if db is None:
        try:
            db = initialize_firebase()  # will raise if it still can't init
        except Exception as e:
            app.logger.error(f"Firestore unavailable: {e}")
            return None
    return db

@app.route('/api/check-username', methods=['POST'])
def check_username():
    db_client = get_db()
    if db_client is None:
        return jsonify({'status': 'error',
                        'message': 'Database connection failed'}), 500
    try:
        data = request.get_json()
        username = data.get('username', '').strip().lower()
        
        if not username:
            return jsonify({'status': 'error', 'message': 'Username is required'}), 400
        
        # Validate username format
        if not re.match(r'^[a-z0-9_]{3,20}$', username):
            return jsonify({
                'status': 'error',
                'message': 'Username must be 3-20 characters (letters, numbers, underscores)'
            }), 400
        
        # Check if username exists
        query = db_client.collection('users').where(filter=FieldFilter('username', '==', username)).limit(1).get()
        
        if not query:
            return jsonify({'status': 'success', 'available': True})
        
        # Generate suggestions if username is taken
        suggestions = []
        base_username = username
        suffix = 1
        
        while len(suggestions) < 3 and suffix < 100:  # Limit to 100 attempts
            new_username = f"{base_username}{suffix}"
            check_query = db_client.collection('users').where(filter=FieldFilter('username', '==', new_username)).limit(1).get()
            if not check_query:
                suggestions.append(new_username)
            suffix += 1
        
        return jsonify({
            'status': 'success',
            'available': False,
            'suggestions': suggestions
        })
        
    except Exception as e:
        app.logger.error(f"Username check error: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/api/check-mobile', methods=['POST'])
def check_mobile():
    db_client = get_db()
    if db_client is None:
        return jsonify({'status': 'error',
                        'message': 'Database connection failed'}), 500
    try:
        data = request.get_json()
        mobile = data.get('mobile', '').strip()
        
        if not mobile:
            return jsonify({'status': 'error', 'message': 'Mobile number is required'}), 400
        
        # Validate mobile number format
        if not mobile.isdigit() or len(mobile) != 10:
            return jsonify({
                'status': 'error',
                'message': 'Mobile number must be 10 digits'
            }), 400
        
        # Check if mobile number exists
        query = db_client.collection('users').where(filter=FieldFilter('phoneNumber', '==', mobile)).limit(1).get()
        
        if not query:
            return jsonify({'status': 'success', 'available': True})
        
        return jsonify({
            'status': 'success',
            'available': False,
            'message': 'Mobile number already registered'
        })
        
    except Exception as e:
        app.logger.error(f"Mobile check error: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/api/register', methods=['POST'])
def register():
    try:
        if db is None:
            return jsonify({'status': 'error', 'message': 'Database not initialized'}), 500
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400

        required_fields = ['name', 'username', 'email', 'mobile', 'password', 'board', 'class']
        if not all(field in data for field in required_fields):
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

        # Validate username
        username = data['username'].strip().lower()
        if not re.match(r'^[a-z0-9_]{3,20}$', username):
            return jsonify({
                'status': 'error',
                'message': 'Username must be 3-20 characters (letters, numbers, underscores)',
                'field': 'username'
            }), 400

        username_query = db.collection('users').where(filter=FieldFilter('username', '==', username)).limit(1).get()
        if username_query:
            suggestions = []
            base_username = username
            suffix = 1
            while len(suggestions) < 3 and suffix < 100:
                new_username = f"{base_username}{suffix}"
                check_query = db.collection('users').where(filter=FieldFilter('username', '==', new_username)).limit(1).get()
                if not check_query:
                    suggestions.append(new_username)
                suffix += 1
            return jsonify({
                'status': 'error',
                'message': 'Username already taken',
                'field': 'username',
                'suggestions': suggestions
            }), 400

        email = data['email'].strip()
        password = data['password'].strip()
        name = data['name'].strip()
        mobile = data['mobile'].strip()
        board = data['board'].strip()
        class_ = data['class'].strip()
        stream = data.get('stream', 'NA').strip()

        if '@' not in email or '.' not in email.split('@')[1]:
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
        if len(password) < 6:
            return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400
        if not mobile.isdigit() or len(mobile) != 10:
            return jsonify({'status': 'error', 'message': 'Invalid mobile number'}), 400

        # Check if mobile number already exists
        mobile_query = db.collection('users').where(filter=FieldFilter('phoneNumber', '==', mobile)).limit(1).get()
        if mobile_query:
            return jsonify({
                'status': 'error',
                'message': 'Mobile number already registered',
                'field': 'mobile'
            }), 400

        # Generate OTP
        otp = random.randint(100000, 999999)
        otp_expiry = time.time() + 300  # 5 minutes expiry

        session['registration_data'] = {
            'username': username,
            'email': email,
            'password': password,
            'name': name,
            'mobile': mobile,
            'board': board,
            'class': class_,
            'stream': stream,
            'otp': otp,
            'otp_expiry': otp_expiry
        }

        # Send OTP via email
        try:
            msg = Message('Your OTP for Email Verification', recipients=[email])
            msg.body = f"Your OTP is {otp}. It will expire in 5 minutes."
            mail.send(msg)
            app.logger.info(f"OTP email sent to {email}")
        except Exception as e:
            app.logger.error(f"Failed to send OTP email to {email}: {str(e)}", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Failed to send OTP email'}), 500

        return jsonify({'status': 'success', 'message': 'OTP sent to email'})

    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500




@app.route('/api/login', methods=['POST'])
def login():
    try:
        if db is None:
            return jsonify({'status': 'error', 'message': 'Database not initialized'}), 500
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
        identifier = data.get('identifier', '').strip()
        password = data.get('password', '').strip()

        if not identifier or not password:
            return jsonify({'status': 'error', 'message': 'Email/username and password are required'}), 400

        # First try to find user by email or username
        user_email = None
        if '@' in identifier:  # Assume it's an email
            user_email = identifier
        else:  # Assume it's a username
            users = db.collection('users').where('username', '==', identifier).limit(1).stream() if db else []
            for user in users:
                user_email = auth.get_user(user.id).email
                break

        if not user_email:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        FIREBASE_API_KEY = os.getenv('FIREBASE_API_KEY')
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        payload = {
            "email": user_email,
            "password": password,
            "returnSecureToken": True
        }
        
        response = requests.post(url, json=payload)
        result = response.json()

        if 'idToken' in result:
            session.permanent = True
            session['user'] = user_email
            app.logger.info(f"User {user_email} logged in successfully.")
            return jsonify({'status': 'success'})
        else:
            error_msg = result.get('error', {}).get('message', 'Login failed')
            app.logger.warning(f"Login failed for {user_email}: {error_msg}")
            return jsonify({
                'status': 'error',
                'message': error_msg,
                'code': result.get('error', {}).get('code', '')
            }), 401
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/login-otp', methods=['POST'])
def login_otp():
    try:
        if db is None:
            return jsonify({'status': 'error', 'message': 'Database not initialized'}), 500
        # 1. Extract & verify the ID-token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({'status': 'error', 'message': 'Missing ID token'}), 401

        id_token = auth_header.split(" ", 1)[1]
        decoded  = fb_auth.verify_id_token(id_token)          # throws if invalid / expired

        uid        = decoded["uid"]
        phone_full = decoded.get("phone_number", "")          # e.g. "+919876543210"
        phone_national = phone_full.replace("+91", "", 1)

        # 2. Optional safety check: does the token's phone match the body?
        body = request.get_json(force=True) or {}
        if body.get("mobile") and body["mobile"] != phone_national:
            return jsonify({'status': 'error', 'message': 'Token / payload mismatch'}), 400

        # 3. Look for the user in Firestore by phone number
        user_query = db.collection("users").where("phoneNumber", "==", phone_national).limit(1).get()
        
        if not user_query:
            # User doesn't exist - return error message
            return jsonify({
                'status': 'error',
                'message': 'Mobile number not found. Please register first.',
                'code': 'USER_NOT_FOUND'
            }), 404
        
        # User exists - load their details
        user_doc = user_query[0]
        user_doc_ref = user_doc.reference
        user_data = user_doc.to_dict() or {}
        
        # Update lastLogin
        user_doc_ref.update({"lastLogin": firestore.SERVER_TIMESTAMP})
        app.logger.info(f"Found existing user by phone: {phone_national}, UID: {user_doc.id}")

        # Get user email from Firebase Auth or use stored email
        try:
            user = fb_auth.get_user(uid)
            user_email = user.email if hasattr(user, 'email') and user.email else user_data.get('email', '')
            app.logger.info(f"Firebase Auth user email: {user_email}")
        except:
            # If Firebase Auth user doesn't exist, use email from Firestore
            user_email = user_data.get('email', '')
            app.logger.info(f"Using Firestore email: {user_email}")

        # If no email is available, create a unique identifier using phone number
        if not user_email:
            app.logger.info(f"No email found, creating phone-based identifier for: {phone_national}")
            user_email = f"phone_{phone_national}@guruai.local"
            app.logger.info(f"Created phone-based email: {user_email}")

        # 4. Create Flask session
        session.permanent = True
        session["user"] = user_email
        
        # Debug logging
        app.logger.info(f"Session created for OTP user: {user_email}")
        app.logger.info(f"Session data: {dict(session)}")
        app.logger.info(f"User data being returned: {user_data}")

        return jsonify({
            'status': 'success',
            'user_data': user_data
        })

    except fb_auth.InvalidIdTokenError:
        return jsonify({'status': 'error', 'message': 'Invalid or expired ID token'}), 401
    except Exception as e:
        app.logger.error(f"login_otp error: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    try:
        if db is None:
            return jsonify({'status': 'error', 'message': 'Database not initialized'}), 500
        data = request.get_json()
        if not data or not data.get('otp'):
            return jsonify({'status': 'error', 'message': 'OTP is required'}), 400

        reg_data = session.get('registration_data')
        if not reg_data:
            app.logger.warning("Registration data not found in session for OTP verification.")
            return jsonify({'status': 'error', 'message': 'Session expired. Please register again.'}), 400

        if time.time() > reg_data['otp_expiry']:
            session.pop('registration_data', None)
            app.logger.warning("OTP expired during verification.")
            return jsonify({'status': 'error', 'message': 'OTP expired. Please register again.'}), 400

        if int(data['otp']) != reg_data['otp']:
            app.logger.warning(f"Invalid OTP entered for {reg_data['email']}. Expected: {reg_data['otp']}, Received: {data['otp']}")
            return jsonify({'status': 'error', 'message': 'Invalid OTP'}), 400

        try:
            user = auth.create_user(
                email=reg_data['email'],
                password=reg_data['password'],
                display_name=reg_data['name'], # Name is used here for Auth display name
                email_verified=True
            )
            app.logger.info(f"Firebase user created: {user.uid}")

            user_ref = db.collection('users').document(user.uid)
            user_ref.set({
                'name': reg_data['name'],          # Add this line
                'email': reg_data['email'],        # Good to store email in Firestore too for easy queries
                'phoneNumber': reg_data.get('mobile', ''), # Add this line, use .get() for safety
                'board': reg_data['board'],
                'class': reg_data['class'],
                'stream': reg_data['stream'],
                'createdAt': firestore.SERVER_TIMESTAMP,
                'lastLogin': firestore.SERVER_TIMESTAMP,
                'scores': {}  # Initialize scores dictionary
            })
            app.logger.info(f"User data stored in Firestore for {user.uid}.")

            session['user'] = user.email
            session['user_name'] = user.display_name
            session.pop('registration_data', None)
            app.logger.info(f"User {user.email} successfully registered and logged in.")

            return jsonify({'status': 'success'})
        except auth.EmailAlreadyExistsError:
            app.logger.warning(f"Registration attempt with existing email: {reg_data['email']}")
            return jsonify({'status': 'error', 'message': 'Email already registered'}), 400
        except Exception as e:
            error_msg = str(e)
            app.logger.error(f"Error during verification for {reg_data['email']}: {error_msg}", exc_info=True)
            if "PERMISSION_DENIED" in error_msg:
                return jsonify({
                    'status': 'error',
                    'message': 'Server configuration error. Please contact support.',
                    'code': 'PERMISSION_DENIED'
                }), 403
            return jsonify({'status': 'error', 'message': error_msg}), 500
    except Exception as e:
        app.logger.error(f"OTP verification error: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        user_email = session.get('user', 'unknown')
        session.clear()
        app.logger.info(f"User {user_email} logged out.")
        return jsonify({'status': 'success'})
    except Exception as e:
        app.logger.error(f"Logout error: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/getout-subjects')
def getout_subjects():
    
    try:
        def sanitize_input(value):
            if value in [None, '', 'null', 'undefined']:
                return None
            return value

        class_level = sanitize_input(request.args.get('class'))
        stream = sanitize_input(request.args.get('stream')) or 'NA'

        session_user = session.get('user')
        if session_user and db is not None:
            try:
                # Try to get user from Firebase Auth first (for regular users)
                try:
                    user = auth.get_user_by_email(session_user)
                    user_ref = db.collection('users').document(user.uid)
                    user_data = user_ref.get().to_dict()
                    class_level = class_level or user_data.get('class', '')
                    stream = stream or user_data.get('stream', 'NA')
                except UserNotFoundError:
                    # User not found in Firebase Auth - try to get from Firestore directly (for OTP users)
                    app.logger.info(f"User not found in Firebase Auth, trying Firestore for identifier: {session_user}")
                    
                    # Check if this is a phone-based identifier
                    if session_user.startswith('phone_'):
                        # Extract phone number from the identifier
                        phone_number = session_user.replace('phone_', '').replace('@guruai.local', '')
                        app.logger.info(f"Phone-based identifier detected, looking up by phone: {phone_number}")
                        
                        # Search for user by phone number in Firestore
                        user_query = db.collection('users').where('phoneNumber', '==', phone_number).limit(1).get()
                    else:
                        # Search for user by email in Firestore
                        user_query = db.collection('users').where('email', '==', session_user).limit(1).get()
                    
                    if user_query:
                        user_doc = user_query[0]
                        user_data = user_doc.to_dict() or {}
                        class_level = class_level or user_data.get('class', '')
                        stream = stream or user_data.get('stream', 'NA')
                        app.logger.info(f"Found user data for OTP user: class={class_level}, stream={stream}")
                    else:
                        app.logger.warning(f"User not found in Firestore for identifier: {session_user}")
            except Exception as e:
                app.logger.warning(f"Could not fetch user info for {session_user}: {e}")

        if not class_level:
            return jsonify({'error': 'Class information missing'}), 400

        try:
            class_level = int(class_level)
        except ValueError:
            return jsonify({'error': 'Invalid class format'}), 400

        # Subject logic
        core_subjects = ['English']
        subjects = []

        if class_level <= 7:
            subjects = core_subjects + ['Maths', 'Science', 'Social']
        elif class_level == 8:
            subjects = core_subjects + ['Maths', 'Science', 'History','Civics','Geography']
        elif class_level in [9, 10]:
            subjects = core_subjects + ['Maths', 'Science', 'History','Civics','Geography','Economics']
        else:
            if stream == 'Science':
                if class_level == 11:
                    subjects = core_subjects + ['Physics-Part1', 'Physics-Part2', 'Chemistry-Part1', 'Chemistry-Part2', 'Maths', 'Biology']
                elif class_level == 12:
                    subjects = core_subjects + ['Physics', 'Chemistry', 'Maths', 'Biology']
            elif stream == 'Commerce':
                if class_level == 11:
                    subjects = core_subjects + ['Financial accounting-Part1', 'Financial accounting-Part2', 'Business Studies', 'Economics', 'Maths']
                elif class_level == 12:
                    subjects = core_subjects + ['Accountancy-Part1', 'Accountancy-Part2', 'Business Studies', 'Economics-Part1', 'Economics-Part2', 'Maths', 'Political Science']
            # Add fallback/defaults if needed

        return jsonify(subjects)

    except Exception as e:
        app.logger.error(f"Error getting subjects: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch subjects', 'details': str(e)}), 500

@app.route('/api/get-subjects')
@login_required
def get_subjects():
    
    try:
        def sanitize_input(value):
            if value in [None, '', 'null', 'undefined']:
                return None
            return value

        class_level = sanitize_input(request.args.get('class'))
        stream = sanitize_input(request.args.get('stream')) or 'NA'
        # If user is logged in, optionally override with their saved class/stream
        session_user = session.get('user')
        if session_user and db is not None:
            try:
                # Try to get user from Firebase Auth first (for regular users)
                try:
                    user = auth.get_user_by_email(session_user)
                    user_ref = db.collection('users').document(user.uid)
                    user_data = user_ref.get().to_dict()
                    class_level = class_level or user_data.get('class', '')
                    stream = stream or user_data.get('stream', 'NA')
                except UserNotFoundError:
                    # User not found in Firebase Auth - try to get from Firestore directly (for OTP users)
                    app.logger.info(f"User not found in Firebase Auth, trying Firestore for email: {session_user}")
                    user_query = db.collection('users').where('email', '==', session_user).limit(1).get()
                    if user_query:
                        user_doc = user_query[0]
                        user_data = user_doc.to_dict() or {}
                        class_level = class_level or user_data.get('class', '')
                        stream = stream or user_data.get('stream', 'NA')
            except Exception as e:
                app.logger.warning(f"Could not fetch user info for {session_user}: {e}")

        if not class_level:
            return jsonify({'error': 'Class information missing'}), 400

        try:
            class_level = int(class_level)
        except ValueError:
            return jsonify({'error': 'Invalid class format'}), 400

        # Subject logic
        core_subjects = ['English']
        subjects = []

        if class_level <= 7:
            subjects = core_subjects + ['Maths', 'Science', 'Social']
        elif class_level == 8:
            subjects = core_subjects + ['Maths', 'Science', 'History','Civics','Geography']
        elif class_level in [9, 10]:
            subjects = core_subjects + ['Maths', 'Science', 'History','Civics','Geography','Economics']
        else:
            if stream == 'Science':
                if class_level == 11:
                    subjects = core_subjects + ['Physics-Part1', 'Physics-Part2', 'Chemistry-Part1', 'Chemistry-Part2', 'Maths', 'Biology']
                elif class_level == 12:
                    subjects = core_subjects + ['Physics', 'Chemistry', 'Maths', 'Biology']
            elif stream == 'Commerce':
                if class_level == 11:
                    subjects = core_subjects + ['Financial accounting-Part1', 'Financial accounting-Part2', 'Business Studies', 'Economics', 'Maths']
                elif class_level == 12:
                    subjects = core_subjects + ['Accountancy-Part1', 'Accountancy-Part2', 'Business Studies', 'Economics-Part1', 'Economics-Part2', 'Maths', 'Political Science']
            # Add fallback/defaults if needed

        return jsonify(subjects)

    except Exception as e:
        app.logger.error(f"Error getting subjects: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch subjects', 'details': str(e)}), 500

@app.route('/api/getout-chapters')
def getout_chapters():
    try:
        board = request.args.get('board', 'NCERT')
        class_level = request.args.get('class')
        subject = request.args.get('subject')
        literature_type = request.args.get('literature', '').lower()  # for English

        if not all([board, class_level, subject]):
            return jsonify({'error': 'Missing required parameters'}), 400

        # Load data from the master chapter mapping
        from app import SUBJECT_CHAPTER_DATA  # Ensure this import works or move data to separate module

        board_data = SUBJECT_CHAPTER_DATA.get(board)
        if not board_data:
            return jsonify({'error': f'Board {board} not found'}), 404

        class_key = f"Class {class_level}"
        class_data = board_data.get(class_key)
        if not class_data:
            return jsonify({'error': f'Class {class_key} not found'}), 404

        subject_data = class_data.get(subject)
        if not subject_data:
            return jsonify({'error': f'Subject {subject} not found for {class_key}'}), 404

        # Special case: English literature/supplementary
        if isinstance(subject_data, dict) and subject and isinstance(subject, str) and subject.lower() == "english":
            if not literature_type or literature_type not in subject_data:
                return jsonify({'error': f'Missing or invalid literature type'}), 400
            chapters = subject_data[literature_type]
        else:
            chapters = subject_data

        return jsonify(chapters)

    except Exception as e:
        app.logger.error(f"Error getting chapters: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

# app.py
# ... (imports and app setup) ...

# Define subject-specific chapter IDs (e.g., "Chapter 1", "Chapter 2")
# This data structure should mirror how your frontend's classSubjectChapterNames uses keys.
SUBJECT_CHAPTER_DATA = {
    "NCERT": {
        "Class 6": {
            "Maths": [
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5", 
                "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9", "Chapter 10"
            ],
            "Science": [
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9", "Chapter 10",
                "Chapter 11", "Chapter 12"
            ],
            "English": [ "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5"],
            "Social":["Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9", "Chapter 10",
                "Chapter 11", "Chapter 12","Chapter 13",
                "Chapter 14"  
           ]
        },
         "Class 7": {
            "Maths": [
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5", 
                "Chapter 6", "Chapter 7", "Chapter 8"
            ],
            "Science": [
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9", "Chapter 10",
                "Chapter 11", "Chapter 12"
            ],
            "English": [ "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5"],
             "Social":["Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9", "Chapter 10",
                "Chapter 11", "Chapter 12"    
           ]
        },
        "Class 8": { # Assuming Class 8 now exists here
            "Maths": [
                "Chapter 1",
                "Chapter 2",
                "Chapter 3",
                "Chapter 4",
                "Chapter 5",
                "Chapter 6",
                "Chapter 7",
                "Chapter 8",
                "Chapter 9",
                "Chapter 10",
                "Chapter 11",
                "Chapter 12",
                "Chapter 13",
                "Chapter 14",
                "Chapter 15",
                "Chapter 16"
            ],
            "Science":[
                "Chapter 1",
                "Chapter 2",
                "Chapter 3",
                "Chapter 4",
                "Chapter 5",
                "Chapter 6",
                "Chapter 7",
                "Chapter 8",
                "Chapter 9",
                "Chapter 10",
                "Chapter 11",
                "Chapter 12"

            ],
            "English":{
                "literature": [
                    "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                    "Chapter 6", "Chapter 7", "Chapter 8"
                ],
                "supplementary": [
                    "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                    "Chapter 6", "Chapter 7", "Chapter 8"
                ]

            },
            "History":[
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                "Chapter 6", "Chapter 7", "Chapter 8"
            ],
            "Geography":[
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5"
            ],
            "Civics":["Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                "Chapter 6", "Chapter 7", "Chapter 8"
            ]     # ... other Class 8 subjects
        },
        "Class 9": {
            "Maths": [
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5", 
                "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9", "Chapter 10", 
                "Chapter 11", "Chapter 12"
            ],
            "Science": [
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9", "Chapter 10",
                "Chapter 11", "Chapter 12"
            ],
            "English": { # English might need a nested structure for literature types
                "literature": [
                    "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                    "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9"
                ],
                "supplementary": [
                    "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                    "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9"
                ]
            },
            "History":[
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5"
            ],
             "Geography":[
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5","Chapter 6"
            ],
            "Civics":["Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
            ] ,
            "Economics":[
                 "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4"
            ]
        },
        "Class 10": {
            "Maths": [
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5", 
                "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9", "Chapter 10", 
                "Chapter 11", "Chapter 12","Chapter 13",
                "Chapter 14"
            ],
            "Science": [
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9", "Chapter 10",
                "Chapter 11", "Chapter 12", "Chapter 13"
            ],
            "English": { # English might need a nested structure for literature types
                "literature": [
                    "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                    "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9"
                ],
                "supplementary": [
                    "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5",
                    "Chapter 6", "Chapter 7", "Chapter 8", "Chapter 9"
                ]
            },
            "History":[
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5"
            ],
             "Geography":[
                "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5","Chapter 6","Chapter 6", "Chapter 7"
            ],
            "Civics":["Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4", "Chapter 5"
            ] ,
            "Economics":[
                 "Chapter 1", "Chapter 2", "Chapter 3", "Chapter 4","Chapter 5"
            ]
        },
        "Class 11":{
    "English":[
       
      "Chapter 1",
      "Chapter 2",
      "Chapter 3",
      "Chapter 4",
      "Chapter 5",
      "Chapter 6",
      "Chapter 7",
      "Chapter 8"
    ],
        "Biology": [
  "Chapter 1","Chapter 2","Chapter 3","Chapter 4","Chapter 5","Chapter 6","Chapter 7","Chapter 8","Chapter 9","Chapter 10","Chapter 11","Chapter 12",
  "Chapter 13","Chapter 14","Chapter 15","Chapter 16","Chapter 17","Chapter 18","Chapter 19"
        ],
"Chemistry-Part1": ["Chapter 1","Chapter 2","Chapter 3","Chapter 4","Chapter 5","Chapter 6"
],
"Chemistry-Part2": [
  "Chapter 1","Chapter 2","Chapter 3"
],
"Maths": [
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
    "Chapter 6",
    "Chapter 7",
    "Chapter 8",
    "Chapter 9",
    "Chapter 10",
    "Chapter 11",
    "Chapter 12",
    "Chapter 13",
    "Chapter 14"
],
"Physics-Part1": [
  "Chapter 1",
  "Chapter 2",
  "Chapter 3",
  "Chapter 4",
  "Chapter 5",
  "Chapter 6",
  "Chapter 7"
],
"Physics-Part2": [
  "Chapter 1",
  "Chapter 2",
  "Chapter 3",
  "Chapter 4",
  "Chapter 5",
  "Chapter 6",
  "Chapter 7"
]
,
  
        "Business Studies": [
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
    "Chapter 6",
    "Chapter 7",
    "Chapter 8",
    "Chapter 9",
    "Chapter 10",
    "Chapter 11"
        ],
  "Financial accounting-Part1": [
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
    "Chapter 6",
    "Chapter 7"
  ],
  "Financial accounting-Part2 ": [
    "Chapter 8",
    "Chapter 9"
  ]
    }
,
"Class 12":{
    "English":{
        "literature":[
        "Chapter 1",
      "Chapter 2",
      "Chapter 3",
      "Chapter 4",
      "Chapter 5",
      "Chapter 6",
      "Chapter 7",
      "Chapter 8"
        ],
        "supplementary":[
     "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
    "Chapter 6"
        ]
    },
  "Biology": [
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
    "Chapter 6",
    "Chapter 7",
    "Chapter 8",
    "Chapter 9",
    "Chapter 10",
    "Chapter 11",
    "Chapter 12",
    "Chapter 13"
  ],
  "Chemistry": [
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
     "Chapter 6",
    "Chapter 7",
    "Chapter 8",
    "Chapter 9",
    "Chapter 10"
  ],
  "Physics": [
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
    "Chapter 6",
    "Chapter 7",
    "Chapter 8",
    "Chapter 9",
    "Chapter 10",
    "Chapter 11",
    "Chapter 12",
    "Chapter 13",
    "Chapter 14"
  ],
  "Maths": [
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
    "Chapter 6",
    "Chapter 7",
    "Chapter 8",
    "Chapter 9",
    "Chapter 10",
    "Chapter 11",
    "Chapter 12",
    "Chapter 13"
  ],
    "Accountancy-Part1": [
  "Chapter 1",
  "Chapter 2",
  "Chapter 3",
  "Chapter 4"
    ],
"Accountancy-Part2": [
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
    "Chapter 6"
],
  "Business Studies": [
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
    "Chapter 6",
    "Chapter 7",
    "Chapter 8",
    "Chapter 9",
    "Chapter 10",
    "Chapter 11"
  ],
  "Economics-Part2": {
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5"
  },
  "Economics-Part1":[
    "Chapter 1",
    "Chapter 2",
    "Chapter 3",
    "Chapter 4",
    "Chapter 5",
    "Chapter 6"

  ]

}}}

        # ... other classes and boards
    



@app.route('/api/get-chapters')
@login_required
def get_chapters():
    try:
        subject = request.args.get('subject')
        board = request.args.get('board')
        class_level = request.args.get('class') # This will be like "10" (number string)
        literature_type = request.args.get('type') # For English subject

        if not all([subject, board, class_level]):
            app.logger.warning("Missing parameters for get_chapters.")
            return jsonify({'error': 'Subject, board, and class parameters are required'}), 400
        
        # Convert class_level back to "Class X" format if your data structure uses it
        # Or adjust SUBJECT_CHAPTER_DATA to use "10" instead of "Class 10"
        # For consistency with frontend's classSubjectChapterNames, let's use "Class X"
        formatted_class_level = f"Class {class_level}" 

        chapters = []
        if literature_type: # Specific handling for English literature
            board_dict = SUBJECT_CHAPTER_DATA.get(board or '', {})
            class_dict = board_dict.get(formatted_class_level or '', {}) if isinstance(board_dict, dict) else {}
            subject_dict = class_dict.get(subject or '', {}) if isinstance(class_dict, dict) else {}
            chapters = subject_dict.get(literature_type, []) if isinstance(subject_dict, dict) else []
        else: # General subjects
            board_dict = SUBJECT_CHAPTER_DATA.get(board or '', {})
            class_dict = board_dict.get(formatted_class_level or '', {}) if isinstance(board_dict, dict) else {}
            chapters = class_dict.get(subject or '', []) if isinstance(class_dict, dict) else []

        if not chapters:
            app.logger.warning(f"No chapters found for subject: {subject}, board: {board}, class: {formatted_class_level}, type: {literature_type}")
            return jsonify({'error': f"No chapters found for the selected criteria"}), 404

        app.logger.info(f"Returning {len(chapters)} chapters for subject: {subject}")
        
        return jsonify(chapters) # Returns a list like ["Chapter 1", "Chapter 2", "Chapter 3"]
    except Exception as e:
        app.logger.error(f"Error getting chapters: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

CHAPTER_MAPPING_FILE = 'chapter_mapping_quiz.json'

def load_chapter_mapping():
    """Loads the chapter mapping from the JSON file."""
    if not os.path.exists(CHAPTER_MAPPING_FILE):
        # Log an error if the file is not found
        logging.error(f"Error: {CHAPTER_MAPPING_FILE} not found. Please ensure it's in the same directory as app.py")
        return {}
    try:
        with open(CHAPTER_MAPPING_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {CHAPTER_MAPPING_FILE}: {e}")
        return {}
    except Exception as e:
        logging.error(f"An unexpected error occurred loading {CHAPTER_MAPPING_FILE}: {e}")
        return {}

# Load mapping once on startup
chapter_mapping = load_chapter_mapping()

@app.route('/api/get-chapters-quiz', methods=['GET'])
def get_chapters_quiz():
    board = request.args.get('board')
    class_level = request.args.get('class')
    subject = request.args.get('subject')
    literature_type = request.args.get('literatureType')  # Updated to match frontend param

    if not all([board, class_level, subject]):
        return jsonify({'error': 'Missing board, class, or subject parameters'}), 400

    if class_level and not class_level.startswith("Class "):
        class_level = f"Class {class_level}"

    try:
        board_data = chapter_mapping.get(board, {}) if board else {}
        class_data = board_data.get(class_level, {}) if class_level else {}
        subject_data = class_data.get(subject) if subject else None

        # Special case: English requires literatureType
        if subject and subject.lower() == 'english':
            if not literature_type:
                return jsonify({'error': 'Literature type required for English'}), 400

            subject_data = subject_data.get(literature_type.lower(), {}) if subject_data else {}
            if not subject_data:
                return jsonify([])

        elif not subject_data:
            return jsonify([])

        formatted_chapters = []
        for chapter_key, chapter_name in subject_data.items():
            match = re.search(r'\d+', chapter_key)
            chapter_number = match.group(0) if match else '0'
            formatted_chapters.append({
                "name": chapter_name,
                "value": chapter_key
            })

        def chapter_sort_key(x):
            match = re.search(r'\d+', x['value'])
            return int(match.group(0)) if match else 0
        formatted_chapters.sort(key=chapter_sort_key)

        return jsonify(formatted_chapters)

    except Exception as e:
        app.logger.error(f"Error fetching chapters: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/save-score', methods=['POST'])
@login_required
def save_score():
    try:
        if db is None:
            return jsonify({'error': 'Database not initialized'}), 500
        data = request.get_json()
        subject = data.get('subject')
        score = data.get('score')

        if not subject or score is None:
            return jsonify({'error': 'Missing subject or score'}), 400

        try:
            score = int(score)
            if score < 0 or score > 100:
                return jsonify({'error': 'Score must be between 0 and 100'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid score format'}), 400

        user = auth.get_user_by_email(session.get('user'))
        user_ref = db.collection('users').document(user.uid)

        history_entry = {
            'score': score,
            'timestamp': datetime.utcnow().isoformat()  # Store as readable timestamp
        }

        user_ref.update({
            f'scores.{subject}': score,
            f'scoreHistory.{subject}': firestore.ArrayUnion([history_entry])
        })

        return jsonify({'status': 'success'})

    except Exception as e:
        app.logger.error(f"Error saving score: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/submit-path', methods=['POST'])
# @login_required
def submit_path():
    try:
        data = request.get_json()
        path = data.get("path")
        app.logger.info(f"Received submit-path request for path: {path}")

        if not path:
            app.logger.warning("Missing path in submit-path request.")
            return jsonify({"error": "Missing path"}), 400

        if not validate_pdf_path(path):
            app.logger.error(f"Path validation failed for: {path}")
            return jsonify({"error": "Invalid path format"}), 400

        bucket_name = path.split('/')[2]
        app.logger.info(f"Extracted bucket_name: {bucket_name}")

        path_segments = path.split('/')
        # Extract metadata from the path
        # Expected: gs:// / rag-project-storagebucket / NCERT / Class X / Subject / chapter (X).pdf
        # Index:    0    1   2                  3        4         5         6
        extracted_metadata = {
            "board": path_segments[3],
            "class": path_segments[4],
            "subject": path_segments[5],
            "chapter_filename": path_segments[6] # Keep original filename for variations
        }
        app.logger.info(f"Extracted metadata from path: {extracted_metadata}")

        gcs_folder_prefix = "/".join(path_segments[3:-1]) + "/" 
        original_filename = path_segments[-1] 
        app.logger.info(f"Extracted GCS folder prefix: {gcs_folder_prefix}")
        app.logger.info(f"Extracted original filename: {original_filename}")

        # Define filename variations to try in GCS
        filename_variations_to_try = [
            original_filename,
            original_filename.replace(" (", "_").replace(").pdf", ".pdf"),
            original_filename.replace("(", "").replace(")", ""),
            original_filename.lower(),
            original_filename.lower().replace(" (", "_").replace(").pdf", ".pdf"),
            original_filename.lower().replace("(", "").replace(")", ""),
            original_filename.replace("_", " "), 
            original_filename.lower().replace("_", " "), 
        ]
        filename_variations_to_try = list(dict.fromkeys(filename_variations_to_try))
        app.logger.info(f"Generated filename variations: {filename_variations_to_try}")

        pdf_content = None
        actual_file_path_in_gcs = None 

        for filename_var in filename_variations_to_try:
            current_gcs_file_path_original_folders = f"{gcs_folder_prefix}{filename_var}"
            normalized_gcs_folder_prefix = gcs_folder_prefix.replace("Class ", "Class_").replace(" ", "_")
            current_gcs_file_path_normalized_folders = f"{normalized_gcs_folder_prefix}{filename_var}"
            
            paths_to_attempt_this_iteration = list(dict.fromkeys([
                current_gcs_file_path_original_folders,
                current_gcs_file_path_normalized_folders
            ]))

            for attempt_path in paths_to_attempt_this_iteration:
                try:
                    app.logger.info(f"Attempting to load PDF from GCS using full path: {attempt_path}")
                    pdf_content = get_pdf_from_storage(bucket_name, attempt_path)
                    actual_file_path_in_gcs = attempt_path 
                    app.logger.info(f"SUCCESS: Loaded PDF using path: {actual_file_path_in_gcs}")
                    break 
                except FileNotFoundError:
                    app.logger.info(f"File not found for path: {attempt_path}. Trying next variation.")
                    continue 
                except Exception as e:
                    app.logger.error(f"Unexpected error trying GCS path variation {attempt_path}: {e}", exc_info=True)
                    continue
            if pdf_content: 
                break

        if not pdf_content or not actual_file_path_in_gcs:
            app.logger.error(f"FAILURE: PDF not found after trying all variations for requested path: {path}")
            return jsonify({"error": "PDF not found (tried multiple path variations)"}), 404

        # Use the *actual_file_path_in_gcs* for caching to ensure consistency
        # The cache key should be based on the actual GCS path used.
        chunks_cache_key = actual_file_path_in_gcs 
        chunks_from_cache = load_chunks(bucket_name, chunks_cache_key)

        if chunks_from_cache is None:
            app.logger.info("Chunks not found in cache. Processing PDF...")
            try:
                # Pass extracted metadata to split_pdf_into_chunks
                chunks = split_pdf_into_chunks(pdf_content, metadata=extracted_metadata)
                store_chunks(bucket_name, chunks_cache_key, chunks)
                app.logger.info(f"Successfully processed and stored {len(chunks)} chunks for {actual_file_path_in_gcs}.")
                return jsonify({
                    "status": "success", 
                    "message": "Let's start learning the Chapter", 
                    "chunks": len(chunks)
                })
            except Exception as e:
                app.logger.error(f"Error processing PDF after GCS download: {str(e)}", exc_info=True)
                return jsonify({"error": f"Failed to process PDF: {str(e)}"}), 500
        else:
            app.logger.info(f"Using cached PDF chunks for {actual_file_path_in_gcs}. Count: {len(chunks_from_cache)}")
            return jsonify({
                "status": "success", 
                "message": "Using cached PDF chunks", 
                "chunks": len(chunks_from_cache)
            })

    except Exception as e:
        app.logger.error(f"Error in submit_path route: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/ask', methods=['POST'])
# @login_required
def ask():
    try:
        data = request.get_json()
        path = data.get("path")
        question = data.get("question")
        app.logger.info(f"Received ask request for path: {path}, question: {question[:50]}...")

        if not path or not question:
            app.logger.warning("Missing path or question in ask request.")
            return jsonify({"error": "Missing path or question"}), 400

        if not validate_pdf_path(path):
            return jsonify({"error": "Invalid path format"}), 400

        bucket_name = path.split('/')[2]
        # Extract metadata from the path for filtering
        path_segments = path.split('/')
        filters = {
            "board": path_segments[3],
            "class": path_segments[4],
            "subject": path_segments[5],
            # "chapter_filename": path_segments[6] # Can add chapter if needed for more granular filtering
        }
        app.logger.info(f"Extracted filters for 'ask' route: {filters}")

        # The cache key should be based on the actual GCS path used during submit_path
        # For simplicity, we'll use the original requested path as the key here.
        # In a more robust system, you might store the actual_file_path_in_gcs in the session
        # or a database after submit_path to retrieve it consistently.
        chunks_cache_key = "/".join(path.split('/')[3:]) 
        
        chunks_with_metadata = load_chunks(bucket_name, chunks_cache_key)

        if chunks_with_metadata is None:
            app.logger.info("Chunks not found in cache for 'ask' route. Re-processing PDF...")
            try:
                # Re-attempt finding PDF with variations if not in cache
                gcs_folder_prefix = "/".join(path_segments[3:-1]) + "/" 
                original_filename = path_segments[-1]

                filename_variations_to_try = [
                    original_filename,
                    original_filename.replace(" (", "_").replace(").pdf", ".pdf"),
                    original_filename.replace("(", "").replace(")", ""),
                    original_filename.lower(),
                    original_filename.lower().replace(" (", "_").replace(").pdf", ".pdf"),
                    original_filename.lower().replace("(", "").replace(")", ""),
                ]
                
                pdf_content = None
                actual_file_path_in_gcs_for_ask = None

                for filename_var in filename_variations_to_try:
                    current_gcs_file_path = f"{gcs_folder_prefix}{filename_var}"
                    current_gcs_file_path_normalized_space = current_gcs_file_path.replace("Class ", "Class_").replace(" ", "_")
                    
                    paths_to_attempt = list(dict.fromkeys([current_gcs_file_path, current_gcs_file_path_normalized_space]))

                    for attempt_path in paths_to_attempt:
                        try:
                            app.logger.info(f"Attempting to load PDF for 'ask' from GCS using path variation: {attempt_path}")
                            pdf_content = get_pdf_from_storage(bucket_name, attempt_path)
                            actual_file_path_in_gcs_for_ask = attempt_path
                            app.logger.info(f"Successfully loaded PDF for 'ask' using path: {actual_file_path_in_gcs_for_ask}")
                            break
                        except FileNotFoundError:
                            continue
                        except Exception as e:
                            app.logger.error(f"Unexpected error trying GCS path variation for 'ask' {attempt_path}: {e}", exc_info=True)
                            continue
                    if pdf_content:
                        break

                if not pdf_content:
                    app.logger.error(f"PDF not found for 'ask' after trying all variations for path: {path}")
                    return jsonify({"error": "PDF content not found for this path."}), 404

                # Pass extracted metadata to split_pdf_into_chunks
                chunks_with_metadata = split_pdf_into_chunks(pdf_content, metadata=filters) # Use filters as initial metadata
                store_chunks(bucket_name, chunks_cache_key, chunks_with_metadata) 
                app.logger.info(f"Successfully re-processed and stored {len(chunks_with_metadata)} chunks for 'ask' route.")
            except Exception as e:
                app.logger.error(f"Failed to re-process PDF for 'ask' route: {str(e)}", exc_info=True)
                return jsonify({"error": f"Failed to load content for asking: {str(e)}"}), 500

        # Pass filters to retrieve_relevant_chunks
        relevant_chunks_text = retrieve_relevant_chunks(chunks_with_metadata, question, filters=filters)
        if not relevant_chunks_text:
            app.logger.info("No relevant chunks found for question after filtering.")
            return jsonify({"answer": "I couldn't find relevant information to answer your question."})

        context = " ".join(chunk.replace("\n", " ") for chunk in relevant_chunks_text).strip()
        answer = generate_answer(context, question)
        app.logger.info("Answer generated successfully.")

        return jsonify({"answer": answer})
    except Exception as e:
        app.logger.error(f"Error answering question: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# Route to generate a quiz based on subject, chapter, and difficulty level
@app.route('/generate-quiz', methods=['POST'])
@login_required
def generate_quiz():
    try:
        if db is None:
            return jsonify({'error': 'Database not initialized'}), 500
        # Parse incoming data
        data = request.get_json()
        subject = data.get("subject")
        chapter = data.get("chapter")
        difficulty = data.get("difficulty", "medium")
        literature_type = data.get("literatureType", "").strip().lower()
        print(subject, chapter, difficulty, literature_type)
        app.logger.info(f"Received data: {data}")
        app.logger.info(f"Received generate-quiz request: Subject={subject}, Chapter={chapter}, Difficulty={difficulty}, LiteratureType={literature_type}")

        if not subject or not chapter:
            return jsonify({"error": "Missing subject or chapter"}), 400

        # Fetch user context from Firestore
        user = auth.get_user_by_email(session.get('user'))
        user_ref = db.collection('users').document(user.uid)
        user_data = user_ref.get().to_dict()

        board = user_data.get('board', '').strip()
        class_level = user_data.get('class', '').strip()

        if not board or not class_level:
            return jsonify({"error": "User profile missing board or class"}), 400

        # Extract chapter number (e.g., from "Chapter 3" get "3")
        chapter_number_match = re.search(r'\d+', chapter)
        chapter_number = chapter_number_match.group() if chapter_number_match else '1'

        # Adjust subject path if English with literature/supplementary
        subject_path = subject
        if subject.lower() == 'english' and literature_type != '':
            subject_path = f"{subject}/{literature_type}"
            print("literature type added",subject_path)

        app.logger.info(f"Using subject_path: {subject_path}")

        # Construct base path to look for PDF file
        base_path_segments = [board, f"Class {class_level}", subject_path]
        gcs_folder_prefix = "/".join(base_path_segments) + "/"

        # Try multiple filename variants to account for inconsistencies
        filename_variations = [
            f"Chapter_{chapter_number}.pdf",
            f"Chapter ({chapter_number}).pdf",
            f"Chapter {chapter_number}.pdf",
            f"chapter ({chapter_number}).pdf",
            f"chapter_{chapter_number}.pdf",
            f"chapter {chapter_number}.pdf",
        ]

        pdf_content = None
        actual_file_path_in_gcs = None

        # Attempt to locate the correct PDF file in GCS
        for f_name_var in filename_variations:
            current_gcs_file_path = f"{gcs_folder_prefix}{f_name_var}"
            current_gcs_file_path_normalized_space = current_gcs_file_path.replace("Class ", "Class_").replace(" ", "_")

            paths_to_attempt = list(dict.fromkeys([current_gcs_file_path, current_gcs_file_path_normalized_space]))

            for attempt_path in paths_to_attempt:
                try:
                    app.logger.info(f"Trying quiz PDF path variation: {attempt_path}")
                    pdf_content = get_pdf_from_storage("guru-ai-bucket", attempt_path)
                    actual_file_path_in_gcs = attempt_path
                    break
                except FileNotFoundError:
                    continue
                except Exception as e:
                    app.logger.warning(f"Error trying quiz path variation {attempt_path}: {e}")
                    continue
            if pdf_content:
                break

        # If no file was found after all attempts
        if not pdf_content or not actual_file_path_in_gcs:
            return jsonify({"error": "PDF not found for quiz generation (tried multiple path variations)"}), 404

        # Metadata for caching and context filtering
        quiz_metadata = {
            "board": board,
            "class": f"Class {class_level}",
            "subject": subject,
            "chapter_filename": actual_file_path_in_gcs.split('/')[-1]
        }

        chunks_cache_key = actual_file_path_in_gcs
        chunks_with_metadata = load_chunks("guru-ai-bucket", chunks_cache_key)

        # If not cached, split PDF and cache chunks
        if chunks_with_metadata is None:
            app.logger.info("Chunks not found. Processing PDF...")
            chunks_with_metadata = split_pdf_into_chunks(pdf_content, metadata=quiz_metadata)
            store_chunks("guru-ai-bucket", chunks_cache_key, chunks_with_metadata)
            app.logger.info(f"Stored {len(chunks_with_metadata)} chunks.")
        else:
            app.logger.info(f"Loaded cached chunks: {len(chunks_with_metadata)}")

        # Filter chunks by metadata
        quiz_filters = {
            "board": board,
            "class": f"Class {class_level}",
            "subject": subject
        }

        # Use semantic search to find most relevant chunks for question generation
        context_chunks_text = retrieve_relevant_chunks(
            chunks_with_metadata,
            "generate quiz question",
            filters=quiz_filters,
            top_k=20
        )
        context = " ".join(chunk.replace("\n", " ") for chunk in context_chunks_text)

        if not context:
            return jsonify({"error": "No relevant context found to generate a quiz."}), 500

        # Gemini prompt to generate quiz questions
        model = GenerativeModel("gemini-2.0-flash-001")
        prompt = (
            f"Generate 10 multiple choice questions based on the following educational content. "
            f"Difficulty level: {difficulty}. "
            f"Each question should be clear and complete. For each question, provide:\n"
            f"- A complete question text\n"
            f"- 4 possible options (labeled a, b, c, d)\n"
            f"- The correct answer (0-3 corresponding to options)\n"
            f"- A complete and detailed explanation\n"
            f"- The topic from the content\n"
            f"Format the response as a JSON array with these fields: question, options, correctAnswer, explanation, topic.\n"
            f"Content:\n{context}\n\nQuestions:"
        )

        app.logger.info("Sending prompt to Gemini model...")
        response = model.generate_content(prompt)
        app.logger.info("Received response from Gemini.")

        # Clean and parse the JSON response from Gemini
        try:
            json_text = response.text.strip()
            if json_text.startswith("```json"):
                json_text = json_text[len("```json"):].strip()
            if json_text.endswith("```"):
                json_text = json_text[:-len("```")].strip()

            if '][' in json_text:
                json_text = "[" + json_text.replace('][', ',') + "]"

            cleaned_json_text = re.sub(r',\s*([\]}])', r'\1', json_text)
            questions = json.loads(cleaned_json_text)

        except json.JSONDecodeError as json_err:
            app.logger.error(f"Invalid JSON format: {json_err}")
            return jsonify({"error": "Failed to generate quiz due to AI formatting error."}), 500

        # Validate each question object
        validated_questions = []
        for q in questions:
            if all(k in q for k in ['question', 'options', 'correctAnswer', 'explanation', 'topic']) \
               and isinstance(q['options'], list) and len(q['options']) == 4 \
               and isinstance(q['correctAnswer'], int) and 0 <= q['correctAnswer'] <= 3:
                validated_questions.append(q)
            if len(validated_questions) >= 10:
                break

        # Ensure we have at least one valid question
        if not validated_questions:
            return jsonify({"error": "No valid questions generated"}), 500

        # Return the generated quiz questions
        return jsonify({
            "questions": validated_questions,
            "subject": subject,
            "chapter": chapter,
            "generatedAt": datetime.now().isoformat()
        })

    except Exception as e:
        app.logger.error(f"Error generating quiz: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/forgot-password', methods=['POST'])
def api_forgot_password():
    try:
        email = request.get_json().get('email')
        if not email:
            app.logger.warning("Email missing for forgot password request.")
            return jsonify({'error': "Email is required"}), 400
            
        try:
            user = auth.get_user_by_email(email)
            app.logger.info(f"Found user for forgot password: {email}")
        except UserNotFoundError:
            app.logger.warning(f"Forgot password attempt for non-existent email: {email}")
            return jsonify({'error': "Email not found"}), 404

        try:
            link = auth.generate_password_reset_link(email)
            msg = Message('Reset Your Password', recipients=[email])
            msg.body = f"Click the link to reset your password:\n\n{link}\n\nIf you didn't request this, ignore this email."
            mail.send(msg)
            app.logger.info(f"Password reset email sent to {email}.")
            return jsonify({"message": "Password reset email sent"})
        except Exception as e:
            app.logger.error(f"Error sending password reset email to {email}: {str(e)}", exc_info=True)
            return jsonify({"error": "Failed to send password reset email"}), 500
    except Exception as e:
        app.logger.error(f"Forgot password error: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/get-user-by-phone')
def get_user_by_phone():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({'error': 'Authentication required'}), 401
    id_token = auth_header.split(" ", 1)[1]
    try:
        decoded = fb_auth.verify_id_token(id_token)
    except Exception:
        return jsonify({'error': 'Invalid or expired token'}), 401
    phone = request.args.get('phone')
    if not phone:
        return jsonify({'error': 'Phone number required'}), 400
    try:
        if db is None:
            return jsonify({'error': 'Database not initialized'}), 500
        user_query = db.collection('users').where('phoneNumber', '==', phone).limit(1).get()
        if not user_query:
            return jsonify({'error': 'User not found'}), 404
        user_doc = user_query[0]
        user_data = user_doc.to_dict()
        if not user_data:
            return jsonify({'error': 'User data not found'}), 404
        user_data['uid'] = user_doc.id
        return jsonify({'user': user_data})
    except Exception as e:
        app.logger.error(f"Error fetching user by phone: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug-session')
def debug_session():
    """Debug endpoint to check session status"""
    try:
        session_data = dict(session)
        user_email = session.get('user')
        
        debug_info = {
            'session_exists': 'user' in session,
            'user_email': user_email,
            'full_session': session_data,
            'session_permanent': session.permanent if hasattr(session, 'permanent') else 'N/A'
        }
        
        if user_email and db:
            # Try to find user in database
            try:
                # Check if this is a phone-based identifier
                if user_email.startswith('phone_'):
                    phone_number = user_email.replace('phone_', '').replace('@guruai.local', '')
                    debug_info['identifier_type'] = 'phone_based'
                    debug_info['phone_number'] = phone_number
                    
                    # Try Firestore by phone number
                    user_query = db.collection('users').where('phoneNumber', '==', phone_number).limit(1).get()
                    if user_query:
                        user_doc = user_query[0]
                        user_data = user_doc.to_dict() or {}
                        debug_info['firestore_user'] = {
                            'doc_id': user_doc.id,
                            'email': user_data.get('email'),
                            'name': user_data.get('name'),
                            'class': user_data.get('class'),
                            'stream': user_data.get('stream'),
                            'phoneNumber': user_data.get('phoneNumber')
                        }
                    else:
                        debug_info['firestore_user'] = 'Not found in Firestore'
                else:
                    debug_info['identifier_type'] = 'email_based'
                    # Try Firebase Auth first
                    try:
                        user = auth.get_user_by_email(user_email)
                        debug_info['firebase_auth_user'] = {
                            'uid': user.uid,
                            'email': user.email,
                            'display_name': user.display_name
                        }
                    except UserNotFoundError:
                        debug_info['firebase_auth_user'] = 'Not found in Firebase Auth'
                    
                    # Try Firestore
                    user_query = db.collection('users').where('email', '==', user_email).limit(1).get()
                    if user_query:
                        user_doc = user_query[0]
                        user_data = user_doc.to_dict() or {}
                        debug_info['firestore_user'] = {
                            'doc_id': user_doc.id,
                            'email': user_data.get('email'),
                            'name': user_data.get('name'),
                            'class': user_data.get('class'),
                            'stream': user_data.get('stream')
                        }
                    else:
                        debug_info['firestore_user'] = 'Not found in Firestore'
            except Exception as e:
                debug_info['database_error'] = str(e)
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===== Enhanced Vertex AI RAG Routes =====

@app.route('/api/enhanced/submit-path', methods=['POST'])
@login_required
def enhanced_submit_path():
    """
    Enhanced submit path using Vertex AI RAG
    """
    try:
        if enhanced_chat_service is None:
            return jsonify({"error": "Enhanced RAG service not available"}), 503
            
        data = request.get_json()
        gcs_path = data.get("path")
        
        if not gcs_path:
            return jsonify({"error": "Missing GCS path"}), 400
            
        if not gcs_path.startswith("gs://"):
            return jsonify({"error": "Invalid GCS path format"}), 400
            
        # Extract bucket and file path
        bucket_name = gcs_path.split('/')[2]
        file_path = '/'.join(gcs_path.split('/')[3:])
        
        # Extract metadata from path
        path_segments = gcs_path.split('/')
        metadata = {
            "board": path_segments[3] if len(path_segments) > 3 else "NCERT",
            "class": path_segments[4] if len(path_segments) > 4 else "",
            "subject": path_segments[5] if len(path_segments) > 5 else "",
            "chapter": path_segments[-1] if len(path_segments) > 5 else ""
        }
        
        # Process document using enhanced service
        cache_key = enhanced_chat_service.process_document(bucket_name, file_path, metadata)
        
        return jsonify({
            "status": "success",
            "message": "Document processed successfully using enhanced RAG",
            "cache_key": cache_key,
            "metadata": metadata
        })
        
    except Exception as e:
        app.logger.error(f"Error in enhanced submit path: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/enhanced/ask', methods=['POST'])
@login_required
def enhanced_ask():
    """
    Enhanced ask question using Vertex AI RAG
    """
    try:
        if enhanced_chat_service is None:
            return jsonify({"error": "Enhanced RAG service not available"}), 503
            
        data = request.get_json()
        cache_key = data.get("cache_key")
        question = data.get("question")
        top_k = data.get("top_k", 5)
        
        if not cache_key or not question:
            return jsonify({"error": "Missing cache_key or question"}), 400
            
        # Ask question using enhanced service
        result = enhanced_chat_service.ask_question(cache_key, question, top_k)
        
        if "error" in result:
            return jsonify(result), 400
            
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Error in enhanced ask: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/enhanced/generate-quiz', methods=['POST'])
@login_required
def enhanced_generate_quiz():
    """
    Enhanced quiz generation using Vertex AI RAG
    """
    try:
        if enhanced_quiz_service is None:
            return jsonify({"error": "Enhanced RAG service not available"}), 503
            
        data = request.get_json()
        subject = data.get("subject")
        chapter = data.get("chapter")
        difficulty = data.get("difficulty", "medium")
        num_questions = data.get("num_questions", 10)
        literature_type = data.get("literatureType", "").strip().lower()
        
        if not subject or not chapter:
            return jsonify({"error": "Missing subject or chapter"}), 400
            
        # Get user context
        user = auth.get_user_by_email(session.get('user'))
        user_ref = db.collection('users').document(user.uid)
        user_data = user_ref.get().to_dict()
        
        board = user_data.get('board', '').strip()
        class_level = user_data.get('class', '').strip()
        
        if not board or not class_level:
            return jsonify({"error": "User profile missing board or class"}), 400
            
        # Extract chapter number
        chapter_number_match = re.search(r'\d+', chapter)
        chapter_number = chapter_number_match.group() if chapter_number_match else '1'
        
        # Adjust subject path if English with literature/supplementary
        subject_path = subject
        if subject.lower() == 'english' and literature_type != '':
            subject_path = f"{subject}/{literature_type}"
            
        # Construct file path
        base_path_segments = [board, f"Class {class_level}", subject_path]
        gcs_folder_prefix = "/".join(base_path_segments) + "/"
        
        # Try multiple filename variants
        filename_variations = [
            f"Chapter_{chapter_number}.pdf",
            f"Chapter ({chapter_number}).pdf",
            f"Chapter {chapter_number}.pdf",
            f"chapter ({chapter_number}).pdf",
            f"chapter_{chapter_number}.pdf",
            f"chapter {chapter_number}.pdf",
        ]
        
        pdf_content = None
        actual_file_path_in_gcs = None
        
        # Find the correct PDF file
        for f_name_var in filename_variations:
            current_gcs_file_path = f"{gcs_folder_prefix}{f_name_var}"
            current_gcs_file_path_normalized_space = current_gcs_file_path.replace("Class ", "Class_").replace(" ", "_")
            
            paths_to_attempt = list(dict.fromkeys([current_gcs_file_path, current_gcs_file_path_normalized_space]))
            
            for attempt_path in paths_to_attempt:
                try:
                    pdf_content = get_pdf_from_storage("guru-ai-bucket", attempt_path)
                    actual_file_path_in_gcs = attempt_path
                    break
                except FileNotFoundError:
                    continue
                except Exception as e:
                    app.logger.warning(f"Error trying quiz path variation {attempt_path}: {e}")
                    continue
            if pdf_content:
                break
                
        if not pdf_content or not actual_file_path_in_gcs:
            return jsonify({"error": "PDF not found for quiz generation"}), 404
            
        # Metadata for quiz generation
        quiz_metadata = {
            "board": board,
            "class": f"Class {class_level}",
            "subject": subject,
            "chapter_filename": actual_file_path_in_gcs.split('/')[-1]
        }
        
        # Generate quiz using enhanced service
        bucket_name = "guru-ai-bucket"
        result = enhanced_quiz_service.generate_quiz(
            bucket_name, 
            actual_file_path_in_gcs, 
            quiz_metadata, 
            difficulty, 
            num_questions
        )
        
        if "error" in result:
            return jsonify(result), 400
            
        # Add additional metadata
        result["subject"] = subject
        result["chapter"] = chapter
        
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Error in enhanced quiz generation: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/enhanced/status')
def enhanced_status():
    """
    Check status of enhanced RAG services
    """
    return jsonify({
        "enhanced_rag_available": ENHANCED_RAG_AVAILABLE,
        "enhanced_chat_service": enhanced_chat_service is not None,
        "enhanced_quiz_service": enhanced_quiz_service is not None,
        "project_id": project_id,
        "location": location
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

