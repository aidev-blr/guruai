import os
import io
import json
import traceback
from flask import Blueprint, request, jsonify, render_template, session
from PyPDF2 import PdfReader
from google.cloud import storage
import numpy as np
from sentence_transformers import SentenceTransformer
from vertexai.generative_models import GenerativeModel
import firebase_admin
from firebase_admin import credentials
from functools import wraps
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create Blueprint with corrected prefix
chatbot_bp = Blueprint('chatbot', __name__, url_prefix='/api/chatbot', template_folder='templates')

# Initialize Firebase
if not firebase_admin._apps:
    try:
        cred = credentials.Certificate(os.getenv('FIREBASE_CREDENTIALS_PATH'))
        firebase_admin.initialize_app(cred)
    except Exception as e:
        print(f"Firebase initialization error: {e}")

# Load embedding model
embedding_model = SentenceTransformer('all-MiniLM-L6-v2')

@chatbot_bp.route('/chatbot.html')
def chat_page():
    return render_template('chatbot.html')

@chatbot_bp.route('/submit-path', methods=['POST'])
def submit_path():
    try:
        data = request.get_json()
        gcs_path = data.get("path")
        print(f"[DEBUG] Received GCS path: {gcs_path}")

        if not gcs_path:
            return jsonify({"status": "error", "message": "Missing GCS path"}), 400

        if not gcs_path.startswith("gs://") or len(gcs_path.split('/')) < 4:
            return jsonify({"status": "error", "message": "Invalid GCS path format"}), 400

        chunks_path = get_chunks_path(gcs_path)

        if os.path.exists(chunks_path):
            return jsonify({
                "status": "success",
                "message": "Using cached chunks",
                "chunks_path": os.path.abspath(chunks_path)
            })

        bucket_name = gcs_path.split('/')[2]
        file_path = '/'.join(gcs_path.split('/')[3:])

        pdf_bytes = load_pdf_from_gcs(bucket_name, file_path)
        chunks = split_pdf_into_chunks(pdf_bytes)
        store_chunks_locally(chunks_path, chunks)

        return jsonify({
            "status": "success",
            "message": "PDF processed and chunks saved",
            "chunks_path": os.path.abspath(chunks_path),
            "chunk_count": len(chunks)
        })

    except FileNotFoundError as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "suggestion": "Please verify the PDF exists in GCS"
        }), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": str(e),
            "suggestion": "Unexpected error. Check logs or GCS permissions."
        }), 500

@chatbot_bp.route('/ask', methods=['POST'])
def ask():
    try:
        data = request.get_json()
        gcs_path = data.get("path")
        question = data.get("question")

        if not gcs_path or not question:
            return jsonify({"error": "Missing path or question"}), 400

        print(f"Received request - GCS Path: {gcs_path}, Question: {question}")

        chunks_path = get_chunks_path(gcs_path)
        if not os.path.exists(chunks_path):
            print(f"Chunks path does not exist: {chunks_path}")
            return jsonify({
                "error": "Chunks not found",
                "solution": "Submit the PDF path first using /api/chatbot/submit-path"
            }), 404

        with open(chunks_path, 'r') as f:
            chunks = json.load(f)

        print(f"Loaded {len(chunks)} chunks from: {chunks_path}")

        relevant_chunks = retrieve_relevant_chunks_with_scores(chunks, question)
        print(f"Found {len(relevant_chunks)} relevant chunks for the question.")

        debug_info = [{
            "text": chunk[:200] + "..." if len(chunk) > 200 else chunk,
            "score": float(score)
        } for chunk, score in relevant_chunks]

        context = " ".join(chunk.replace("\n", " ") for chunk, _ in relevant_chunks).strip()
        if not context:
            return jsonify({
                "error": "No relevant context found",
                "debug": {
                    "question": question,
                    "top_chunks": debug_info
                }
            }), 404

        answer = generate_answer(context, question)

        return jsonify({
            "answer": answer,
            "debug": {
                "question": question,
                "context_used": context[:500] + "..." if len(context) > 500 else context,
                "top_chunks": debug_info
            }
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ---------------- UTILITY FUNCTIONS ----------------

def get_chunks_path(gcs_path):
    parts = gcs_path.split('/')
    bucket = parts[2]
    path = '/'.join(parts[3:])
    return f"{bucket}_{path.replace('/', '_').replace(' ', '')}_chunks.json"

@chatbot_bp.route('/chapter-mapping', methods=['GET'])
def serve_chapter_mapping():
    try:
        with open('chapter_mapping_quiz.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def load_pdf_from_gcs(bucket_name, file_path):
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)

    path_variants = [
        file_path,
        file_path + ".pdf",
        file_path.replace(" ", "_"),
        file_path.replace("Chapter ", "Chapter_"),
        file_path.replace("Class ", "Class_"),
        file_path.lower(),
        file_path.upper()
    ]

    for variant in path_variants:
        blob = bucket.blob(variant)
        if blob.exists():
            return blob.download_as_bytes()

    raise FileNotFoundError(f"PDF not found in GCS. Tried: {path_variants}")

def split_pdf_into_chunks(pdf_bytes):
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return [page.extract_text() for page in reader.pages if page.extract_text()]

def store_chunks_locally(chunks_path, chunks):
    with open(chunks_path, 'w') as f:
        json.dump(chunks, f)

def retrieve_relevant_chunks_with_scores(chunks, query, top_k=3):
    query_embedding = embedding_model.encode([query])[0]
    scored = []
    for chunk in chunks:
        chunk_embedding = embedding_model.encode([chunk])[0]
        score = np.dot(query_embedding, chunk_embedding)
        scored.append((chunk, score))
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:top_k]

def generate_answer(context, query, model_name="gemini-2.0-flash-001"):
    try:
        if not context or not query:
            return "I couldn't find enough context to answer that question."

        model = GenerativeModel(model_name)
        prompt = (
            f"You are an expert educational assistant. Provide detailed, structured answers to student questions.\n\n"
            f"Context:\n{context}\n\n"
            f"Question: {query}\n\n"
            f"Format your answer with:\n"
            f"- Bold for key terms\n"
            f"- Italics for emphasis\n"
            f"- Lists for multiple items\n"
            f"- Tables for comparative data\n"
            f"- Headings for sections\n"
            f"- Clear explanations with examples where needed\n\n"
            f"Answer:"
        )
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        import traceback
        traceback.print_exc()  # 🔥 Add this
        return f"An error occurred while generating the answer: {str(e)}"

# ---------------- FLASK APP FOR TESTING ----------------
if __name__ == '__main__':
    from flask import Flask
    app = Flask(__name__)
    app.secret_key = os.getenv('SECRET_KEY')
    app.register_blueprint(chatbot_bp)
    app.run(debug=True, port=5002)
