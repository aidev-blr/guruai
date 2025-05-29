import re
import os
import io
import json
import logging
import traceback

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
app.logger = app_logger


# ===== Google Cloud Configuration =====
project_id = os.getenv('PROJECT_ID', 'my-rag-project-id')
location = os.getenv('LOCATION', 'us-central1')

try:
    aiplatform.init(project=project_id, location=location)
    app.logger.info(f"Vertex AI Platform initialized for project {project_id} in {location}.")
except Exception as e:
    app.logger.error(f"Failed to initialize Vertex AI Platform: {str(e)}", exc_info=True)

# ===== Firebase Initialization =====
def initialize_firebase():
    if not firebase_admin._apps:
        try:
            cred_path = os.getenv("FIREBASE_CREDENTIALS_PATH")
            if not cred_path or not os.path.exists(cred_path):
                app.logger.warning("FIREBASE_CREDENTIALS_PATH not found or file does not exist. Attempting to use default credentials for Firebase.")
                cred = None 
            else:
                app.logger.info(f"Using Firebase credentials from path: {cred_path}")
                cred = credentials.Certificate(cred_path)
            
            firebase_admin.initialize_app(cred, {
                'projectId': os.getenv("PROJECT_ID")
            })
            app.logger.info("Firebase initialized successfully")
            return firestore.client()
        except Exception as e:
            app.logger.error(f"Firebase initialization error: {str(e)}", exc_info=True)
            raise
    return firestore.client()


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

# ===== Helper Functions =====

def validate_pdf_path(path):
    """
    More flexible path validation for your bucket structure.
    Expected format: gs://rag-project-storagebucket/NCERT/Class X/Subject/chapter (X).pdf
    or variations.
    """
    if not path.startswith('gs://rag-project-storagebucket/'):
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
        r'chapter[ _]\d+[ _].+\.pdf$',
        r'unit[ _]?\d+\.pdf$'
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
    return render_template('login.html')

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
        user_email = session.get('user')
        if not user_email:
            return jsonify({'error': 'User not authenticated'}), 401
            
        user = auth.get_user_by_email(user_email)
        user_ref = db.collection('users').document(user.uid)
        user_data = user_ref.get().to_dict()
        
        if not user_data:
            app.logger.warning(f"User data not found for UID: {user.uid}")
            return jsonify({'error': 'User data not found'}), 404
        
        return jsonify({
            'user': {
                'email': user.email,
                'name': user.display_name,
                'board': user_data.get('board', ''),
                'class': user_data.get('class', ''),
                'stream': user_data.get('stream', 'NA')
            }
        })
    except Exception as e:
        app.logger.error(f"Error getting user data: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        
        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Email and password are required'}), 400

        FIREBASE_API_KEY = os.getenv('FIREBASE_API_KEY')
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        
        response = requests.post(url, json=payload)
        result = response.json()

        if 'idToken' in result:
            session.permanent = True
            session['user'] = email
            app.logger.info(f"User {email} logged in successfully.")
            return jsonify({'status': 'success'})
        else:
            error_msg = result.get('error', {}).get('message', 'Login failed')
            app.logger.warning(f"Login failed for {email}: {error_msg}")
            return jsonify({
                'status': 'error',
                'message': error_msg,
                'code': result.get('error', {}).get('code', '')
            }), 401
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    try:
        reg_data = session.get('registration_data')
        if not reg_data:
            app.logger.warning("No registration data found in session for OTP resend.")
            return jsonify({'status': 'error', 'message': 'Session expired. Please register again.'}), 400

        # Generate new OTP
        new_otp = random.randint(100000, 999999)
        new_otp_expiry = time.time() + 300  # 5 minutes expiry

        # Update session with new OTP
        session['registration_data']['otp'] = new_otp
        session['registration_data']['otp_expiry'] = new_otp_expiry
        session.modified = True

        app.logger.info(f"Generated new OTP for {reg_data['email']}. OTP: {new_otp}")

        try:
            msg = Message('Your New OTP for Email Verification', recipients=[reg_data['email']])
            msg.body = f"Your new OTP is {new_otp}. It will expire in 5 minutes."
            mail.send(msg)
            app.logger.info(f"New OTP email sent to {reg_data['email']}.")
            return jsonify({'status': 'success', 'message': 'New OTP sent. Please check your email.'})
        except Exception as e:
            app.logger.error(f"Error sending new OTP email to {reg_data['email']}: {str(e)}", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Failed to send new OTP. Please try again.'}), 500
    except Exception as e:
        app.logger.error(f"Error in resend_otp route: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
        

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        name = data.get('name', '').strip()
        board = data.get('board', '').strip()
        class_ = data.get('class', '').strip()
        stream = data.get('stream', 'NA').strip()

        if not all([email, password, name, board, class_]):
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

        if '@' not in email or '.' not in email.split('@')[1]:
            return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400

        if len(password) < 6:
            return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400

        otp = random.randint(100000, 999999)
        otp_expiry = time.time() + 300  # 5 minutes expiry

        session['registration_data'] = {
            'email': email,
            'password': password,
            'name': name,
            'board': board,
            'class': class_,
            'stream': stream,
            'otp': otp,
            'otp_expiry': otp_expiry
        }
        app.logger.info(f"Generated OTP for {email}. OTP: {otp}")

        try:
            msg = Message('Your OTP for Email Verification', recipients=[email])
            msg.body = f"Your OTP is {otp}. It will expire in 5 minutes."
            mail.send(msg)
            app.logger.info(f"OTP email sent to {email}.")
            return jsonify({'status': 'success', 'message': 'OTP sent. Please verify your email.'})
        except Exception as e:
            session.pop('registration_data', None)
            app.logger.error(f"Error sending OTP email to {email}: {str(e)}", exc_info=True)
            return jsonify({'status': 'error', 'message': 'Failed to send OTP. Please try again.'}), 500
    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    try:
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
                display_name=reg_data['name'],
                email_verified=True
            )
            app.logger.info(f"Firebase user created: {user.uid}")

            user_ref = db.collection('users').document(user.uid)
            user_ref.set({
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
        # If user is logged in, optionally override with their saved class/stream
        session_user = session.get('user')
        if session_user:
            try:
                user = auth.get_user_by_email(session_user)
                user_ref = db.collection('users').document(user.uid)
                user_data = user_ref.get().to_dict()
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
        if session_user:
            try:
                user = auth.get_user_by_email(session_user)
                user_ref = db.collection('users').document(user.uid)
                user_data = user_ref.get().to_dict()
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


@app.route('/api/get-chapters')
# @login_required
def get_chapters():
    try:
        subject = request.args.get('subject')
        if not subject:
            app.logger.warning("Subject parameter missing for get_chapters.")
            return jsonify({'error': 'Subject parameter is required'}), 400
        
        chapters = [
                    "Chapter 1",
                    "Chapter 2",
                    "Chapter 3",
                    "Chapter 4",
                    "Chapter 5",
                    "Chapter 6",
                    "Chapter 7",
                    "Chapter 8"
        ]
        app.logger.info(f"Returning fixed chapters for subject: {subject}")
        
        return jsonify(chapters)
    except Exception as e:
        app.logger.error(f"Error getting chapters: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/save-score', methods=['POST'])
@login_required
def save_score():
    try:
        data = request.get_json()
        subject = data.get('subject')
        score = data.get('score')
        
        if not subject or score is None: 
            app.logger.warning("Missing subject or score for save_score.")
            return jsonify({'error': 'Missing subject or score'}), 400
            
        try:
            score = int(score)
            if score < 0 or score > 100:
                app.logger.warning(f"Invalid score value: {score}")
                return jsonify({'error': 'Score must be between 0 and 100'}), 400
        except ValueError:
            app.logger.warning(f"Invalid score format: {score}")
            return jsonify({'error': 'Invalid score format'}), 400
            
        user = auth.get_user_by_email(session.get('user'))
        user_ref = db.collection('users').document(user.uid)
        
        user_ref.update({
            f'scores.{subject}': score,
            f'scoreHistory.{subject}': firestore.ArrayUnion([{
                'score': score,
                'timestamp': firestore.SERVER_TIMESTAMP
            }])
        })
        app.logger.info(f"Score {score} saved for {user.email}, subject {subject}.")
        
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

@app.route('/generate-quiz', methods=['POST'])
@login_required
def generate_quiz():
    try:
        data = request.get_json()
        subject = data.get("subject")
        chapter = data.get("chapter")
        difficulty = data.get("difficulty", "medium")
        app.logger.info(f"Received generate-quiz request: Subject={subject}, Chapter={chapter}, Difficulty={difficulty}")

        if not subject or not chapter:
            app.logger.warning("Missing subject or chapter for quiz generation.")
            return jsonify({"error": "Missing subject or chapter"}), 400

        user = auth.get_user_by_email(session.get('user'))
        user_ref = db.collection('users').document(user.uid)
        user_data = user_ref.get().to_dict()
        
        board = "NCERT" 
        class_level = user_data.get('class', '8')  

        # Extract chapter number and construct full GCS path
        chapter_number_match = re.search(r'\d+', chapter)
        chapter_number = chapter_number_match.group() if chapter_number_match else '1'
        
        # Define base path segments for GCS
        base_path_segments = [board, f"Class {class_level}", subject]
        gcs_folder_prefix = "/".join(base_path_segments) + "/"

        # Define filename variations for quiz generation
        filename_variations = [
            f"Chapter_{chapter_number}.pdf",
            f"Chapter ({chapter_number}).pdf",
            f"Chapter {chapter_number}.pdf",
            f"chapter ({chapter_number}).pdf", 
            f"chapter_{chapter_number}.pdf",
            f"chapter {chapter_number}.pdf",
            f"Unit ({chapter_number}).pdf", 
            f"Unit_{chapter_number}.pdf",
            f"Unit {chapter_number}.pdf",
            f"unit ({chapter_number}).pdf",
            f"unit_{chapter_number}.pdf",
            f"unit {chapter_number}.pdf",
        ]
        
        pdf_content = None
        actual_file_path_in_gcs = None

        for f_name_var in filename_variations:
            current_gcs_file_path = f"{gcs_folder_prefix}{f_name_var}"
            current_gcs_file_path_normalized_space = current_gcs_file_path.replace("Class ", "Class_").replace(" ", "_")
            
            paths_to_attempt = list(dict.fromkeys([current_gcs_file_path, current_gcs_file_path_normalized_space]))

            for attempt_path in paths_to_attempt:
                try:
                    app.logger.info(f"Trying quiz PDF path variation: {attempt_path}")
                    pdf_content = get_pdf_from_storage("rag-project-storagebucket", attempt_path)
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
            app.logger.error(f"PDF not found for quiz generation after trying all variations for: {subject} {chapter}")
            return jsonify({"error": "PDF not found for quiz generation (tried multiple path variations)"}), 404

        # Extract metadata for quiz context
        quiz_metadata = {
            "board": board,
            "class": f"Class {class_level}", # Ensure consistent format
            "subject": subject,
            "chapter_filename": actual_file_path_in_gcs.split('/')[-1] # Use the actual filename
        }
        app.logger.info(f"Extracted metadata for quiz generation: {quiz_metadata}")

        # Process PDF and retrieve/store chunks
        chunks_cache_key = actual_file_path_in_gcs
        chunks_with_metadata = load_chunks("rag-project-storagebucket", chunks_cache_key)
        if chunks_with_metadata is None:
            app.logger.info("Chunks not found for quiz. Processing PDF...")
            chunks_with_metadata = split_pdf_into_chunks(pdf_content, metadata=quiz_metadata)
            store_chunks("rag-project-storagebucket", chunks_cache_key, chunks_with_metadata)
            app.logger.info(f"Processed and stored {len(chunks_with_metadata)} chunks for quiz generation.")
        else:
            app.logger.info(f"Using cached chunks for quiz. Count: {len(chunks_with_metadata)}")

        # Pass filters to retrieve_relevant_chunks for quiz generation context
        # Here, we want content relevant to the *entire chapter* for quiz generation
        # So, the filters should be broad enough to cover the whole chapter.
        # We can use board, class, subject, and potentially the chapter number.
        quiz_filters = {
            "board": board,
            "class": f"Class {class_level}",
            "subject": subject,
            # "chapter_filename": actual_file_path_in_gcs.split('/')[-1] # Can be too specific, depends on quiz scope
        }

        context_chunks_text = retrieve_relevant_chunks(chunks_with_metadata, "generate quiz question", filters=quiz_filters, top_k=20) # Get more chunks for quiz context
        context = " ".join(chunk.replace("\n", " ") for chunk in context_chunks_text)
        if not context:
            app.logger.warning("No context available for quiz generation after filtering.")
            return jsonify({"error": "No relevant context found to generate a quiz."}), 500

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

        app.logger.info("Sending prompt to Gemini model for quiz generation...")
        response = model.generate_content(prompt)
        app.logger.info("Received response from Gemini model for quiz.")

        try:
            json_text = response.text.strip()
            if json_text.startswith("```json"):
                json_text = json_text[len("```json"):].strip()
            if json_text.endswith("```"):
                json_text = json_text[:-len("```")].strip()
            
            if '][' in json_text: 
                 json_text = "[" + json_text.replace('][', ',') + "]"

            questions = json.loads(json_text)
            app.logger.info(f"Successfully parsed {len(questions)} questions from Gemini response.")

        except json.JSONDecodeError as json_err:
            app.logger.error(f"Invalid JSON format from model for quiz: {response.text}. Error: {json_err}", exc_info=True)
            return jsonify({"error": "Failed to generate quiz due to an unexpected format from the AI model."}), 500
        except Exception as e:
            app.logger.error(f"Error processing Gemini quiz response: {e}", exc_info=True)
            return jsonify({"error": "An error occurred while processing the generated quiz."}), 500

        validated_questions = []
        for q in questions:
            if all(k in q for k in ['question', 'options', 'correctAnswer', 'explanation', 'topic']) \
               and isinstance(q['options'], list) and len(q['options']) == 4 \
               and isinstance(q['correctAnswer'], int) and 0 <= q['correctAnswer'] <= 3:
                validated_questions.append(q)
            if len(validated_questions) >= 10: 
                break

        if not validated_questions:
            app.logger.warning("No valid questions generated after parsing and validation.")
            return jsonify({"error": "No valid questions generated"}), 500

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
        except firebase_admin.auth.UserNotFoundError:
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

