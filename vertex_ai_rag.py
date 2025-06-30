import os
import io
import json
import logging
import numpy as np
from typing import List, Dict, Optional, Tuple
from google.cloud import aiplatform
from google.cloud import storage
from vertexai.generative_models import GenerativeModel
from sentence_transformers import SentenceTransformer
from pypdf import PdfReader
import firebase_admin
from firebase_admin import firestore
from datetime import datetime
import re

# Configure logging
logger = logging.getLogger(__name__)

class VertexAIRAG:
    """
    Enhanced RAG implementation using Vertex AI for embeddings and text generation
    """
    
    def __init__(self, project_id: str, location: str = "us-central1"):
        self.project_id = project_id
        self.location = location
        self.storage_client = storage.Client()
        
        # Initialize Vertex AI
        try:
            aiplatform.init(project=project_id, location=location)
            logger.info(f"Vertex AI initialized for project {project_id} in {location}")
        except Exception as e:
            logger.error(f"Failed to initialize Vertex AI: {str(e)}")
            raise
        
        # Initialize models
        self._init_models()
        
    def _init_models(self):
        """Initialize Vertex AI models"""
        try:
            # Text generation model
            self.text_model = GenerativeModel("gemini-2.0-flash-001")
            logger.info("Gemini text model initialized")
            
            # Use sentence-transformers as primary embedding model (more reliable)
            try:
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
                logger.info("Sentence-transformers embedding model initialized")
            except Exception as e:
                logger.error(f"Failed to initialize sentence-transformers: {e}")
                self.embedding_model = None
                
        except Exception as e:
            logger.error(f"Failed to initialize models: {str(e)}")
            raise
    
    def get_embeddings(self, texts: List[str]) -> np.ndarray:
        """
        Get embeddings using sentence-transformers model
        """
        try:
            if self.embedding_model is None:
                raise Exception("Embedding model not initialized")
            
            embeddings = self.embedding_model.encode(texts)
            return embeddings
        except Exception as e:
            logger.error(f"Error getting embeddings: {str(e)}")
            raise Exception(f"Failed to generate embeddings: {str(e)}")
    
    def process_pdf(self, bucket_name: str, file_path: str, metadata: Dict = None) -> List[Dict]:
        """
        Process PDF from GCS and return chunks with embeddings
        """
        try:
            # Download PDF from GCS
            bucket = self.storage_client.bucket(bucket_name)
            blob = bucket.blob(file_path)
            
            if not blob.exists():
                raise FileNotFoundError(f"PDF not found: gs://{bucket_name}/{file_path}")
            
            pdf_bytes = blob.download_as_bytes()
            logger.info(f"Downloaded PDF: {len(pdf_bytes)} bytes")
            
            # Split into chunks
            chunks = self._split_pdf_into_chunks(pdf_bytes, metadata)
            logger.info(f"Created {len(chunks)} chunks")
            
            # Generate embeddings for chunks
            texts = [chunk['text'] for chunk in chunks]
            embeddings = self.get_embeddings(texts)
            
            # Add embeddings to chunks
            for i, chunk in enumerate(chunks):
                chunk['embedding'] = embeddings[i].tolist()
            
            return chunks
            
        except Exception as e:
            logger.error(f"Error processing PDF: {str(e)}")
            raise
    
    def _split_pdf_into_chunks(self, pdf_bytes: bytes, metadata: Dict = None, chunk_size: int = 1000) -> List[Dict]:
        """Split PDF into chunks with metadata"""
        if metadata is None:
            metadata = {}
        
        chunks = []
        pdf_stream = io.BytesIO(pdf_bytes)
        reader = PdfReader(pdf_stream)
        
        for i, page in enumerate(reader.pages):
            try:
                text = page.extract_text()
                if text:
                    words = text.split()
                    for j in range(0, len(words), chunk_size):
                        chunk_text = ' '.join(words[j:j+chunk_size])
                        chunk = {
                            "text": chunk_text,
                            "metadata": {**metadata, "page": i + 1},
                            "chunk_id": f"page_{i+1}_chunk_{j//chunk_size + 1}"
                        }
                        chunks.append(chunk)
            except Exception as e:
                logger.warning(f"Error extracting text from page {i+1}: {e}")
        
        return chunks
    
    def semantic_search(self, query: str, chunks: List[Dict], top_k: int = 5) -> List[Tuple[Dict, float]]:
        """
        Perform semantic search using embeddings
        """
        try:
            # Get query embedding
            query_embedding = self.get_embeddings([query])[0]
            
            # Calculate similarities
            scored_chunks = []
            for chunk in chunks:
                if 'embedding' in chunk:
                    chunk_embedding = np.array(chunk['embedding'])
                    similarity = np.dot(query_embedding, chunk_embedding) / (
                        np.linalg.norm(query_embedding) * np.linalg.norm(chunk_embedding)
                    )
                    scored_chunks.append((chunk, float(similarity)))
            
            # Sort by similarity and return top_k
            scored_chunks.sort(key=lambda x: x[1], reverse=True)
            return scored_chunks[:top_k]
            
        except Exception as e:
            logger.error(f"Error in semantic search: {str(e)}")
            return []
    
    def generate_answer(self, context: str, question: str, model_name: str = "gemini-2.0-flash-001") -> str:
        """
        Generate answer using Vertex AI Gemini model
        """
        try:
            model = GenerativeModel(model_name)
            
            prompt = f"""
            You are an expert educational assistant. Provide detailed, structured answers to student questions.
            
            Context from educational materials:
            {context}
            
            Student Question: {question}
            
            Instructions:
            - Provide a comprehensive answer based on the context provided
            - Use **bold** for key terms and concepts
            - Use *italics* for emphasis
            - Include examples where appropriate
            - Structure your answer clearly with headings if needed
            - If the question cannot be answered from the context, say so explicitly
            - Keep the tone educational and encouraging
            
            Answer:
            """
            
            response = model.generate_content(prompt)
            return response.text.strip()
            
        except Exception as e:
            logger.error(f"Error generating answer: {str(e)}")
            return "I encountered an error while generating an answer. Please try again."
    
    def generate_quiz_questions(self, context: str, difficulty: str = "medium", num_questions: int = 10) -> List[Dict]:
        """
        Generate quiz questions using Vertex AI
        """
        try:
            model = GenerativeModel("gemini-2.0-flash-001")
            
            prompt = f"""
            Generate {num_questions} multiple choice questions based on the following educational content.
            
            Difficulty level: {difficulty}
            
            Content:
            {context}
            
            Requirements:
            - Each question should be clear and complete
            - Provide 4 options (labeled a, b, c, d)
            - Include the correct answer (0-3 corresponding to options a-d)
            - Provide a detailed explanation for the correct answer
            - Include the topic/subject area
            - Questions should test understanding, not just memorization
            - Vary question types (concept understanding, application, analysis)
            
            Format the response as a JSON array with these fields:
            - question: The question text
            - options: Array of 4 options
            - correctAnswer: Integer (0-3)
            - explanation: Detailed explanation
            - topic: Topic/subject area
            - difficulty: Estimated difficulty level
            
            JSON Response:
            """
            
            response = model.generate_content(prompt)
            
            # Clean and parse JSON response
            json_text = response.text.strip()
            if json_text.startswith("```json"):
                json_text = json_text[len("```json"):].strip()
            if json_text.endswith("```"):
                json_text = json_text[:-len("```")].strip()
            
            # Handle potential JSON formatting issues
            json_text = re.sub(r',\s*([\]}])', r'\1', json_text)
            
            questions = json.loads(json_text)
            
            # Validate questions
            validated_questions = []
            for q in questions:
                if (all(k in q for k in ['question', 'options', 'correctAnswer', 'explanation', 'topic']) and
                    isinstance(q['options'], list) and len(q['options']) == 4 and
                    isinstance(q['correctAnswer'], int) and 0 <= q['correctAnswer'] <= 3):
                    validated_questions.append(q)
                if len(validated_questions) >= num_questions:
                    break
            
            return validated_questions
            
        except Exception as e:
            logger.error(f"Error generating quiz questions: {str(e)}")
            return []
    
    def store_chunks_in_firestore(self, chunks: List[Dict], collection_name: str = "document_chunks") -> bool:
        """
        Store chunks with embeddings in Firestore for persistent storage
        """
        try:
            db = firestore.client()
            collection_ref = db.collection(collection_name)
            
            # Batch write for efficiency
            batch = db.batch()
            
            for i, chunk in enumerate(chunks):
                doc_ref = collection_ref.document(f"chunk_{i}_{datetime.now().timestamp()}")
                # Convert numpy arrays to lists for Firestore storage
                chunk_data = {
                    'text': chunk['text'],
                    'metadata': chunk['metadata'],
                    'chunk_id': chunk['chunk_id'],
                    'embedding': chunk['embedding'],
                    'created_at': datetime.now()
                }
                batch.set(doc_ref, chunk_data)
            
            batch.commit()
            logger.info(f"Stored {len(chunks)} chunks in Firestore")
            return True
            
        except Exception as e:
            logger.error(f"Error storing chunks in Firestore: {str(e)}")
            return False
    
    def load_chunks_from_firestore(self, filters: Dict = None, collection_name: str = "document_chunks") -> List[Dict]:
        """
        Load chunks from Firestore with optional filtering
        """
        try:
            db = firestore.client()
            collection_ref = db.collection(collection_name)
            
            # Apply filters if provided
            if filters:
                query = collection_ref
                for key, value in filters.items():
                    query = query.where(f"metadata.{key}", "==", value)
                docs = query.stream()
            else:
                docs = collection_ref.stream()
            
            chunks = []
            for doc in docs:
                chunk_data = doc.to_dict()
                chunks.append(chunk_data)
            
            logger.info(f"Loaded {len(chunks)} chunks from Firestore")
            return chunks
            
        except Exception as e:
            logger.error(f"Error loading chunks from Firestore: {str(e)}")
            return []

class EnhancedChatService:
    """
    Enhanced chat service using Vertex AI RAG
    """
    
    def __init__(self, project_id: str, location: str = "us-central1"):
        self.rag = VertexAIRAG(project_id, location)
        self.chunk_cache = {}  # In-memory cache for chunks
    
    def process_document(self, bucket_name: str, file_path: str, metadata: Dict = None) -> str:
        """
        Process a document and return a cache key
        """
        cache_key = f"{bucket_name}_{file_path}"
        
        if cache_key not in self.chunk_cache:
            chunks = self.rag.process_pdf(bucket_name, file_path, metadata)
            self.chunk_cache[cache_key] = chunks
            
            # Optionally store in Firestore for persistence
            try:
                self.rag.store_chunks_in_firestore(chunks)
            except Exception as e:
                logger.warning(f"Failed to store chunks in Firestore: {e}")
        
        return cache_key
    
    def ask_question(self, cache_key: str, question: str, top_k: int = 5) -> Dict:
        """
        Ask a question and get an answer using RAG
        """
        try:
            if cache_key not in self.chunk_cache:
                return {"error": "Document not processed. Please process the document first."}
            
            chunks = self.chunk_cache[cache_key]
            
            # Perform semantic search
            relevant_chunks = self.rag.semantic_search(question, chunks, top_k)
            
            if not relevant_chunks:
                return {"answer": "I couldn't find relevant information to answer your question."}
            
            # Prepare context
            context = " ".join([chunk[0]['text'] for chunk in relevant_chunks])
            
            # Generate answer
            answer = self.rag.generate_answer(context, question)
            
            # Prepare debug information
            debug_info = {
                "question": question,
                "context_used": context[:500] + "..." if len(context) > 500 else context,
                "relevant_chunks": [
                    {
                        "text": chunk[0]['text'][:200] + "..." if len(chunk[0]['text']) > 200 else chunk[0]['text'],
                        "similarity_score": chunk[1],
                        "metadata": chunk[0]['metadata']
                    }
                    for chunk in relevant_chunks
                ]
            }
            
            return {
                "answer": answer,
                "debug": debug_info
            }
            
        except Exception as e:
            logger.error(f"Error in ask_question: {str(e)}")
            return {"error": str(e)}

class EnhancedQuizService:
    """
    Enhanced quiz service using Vertex AI RAG
    """
    
    def __init__(self, project_id: str, location: str = "us-central1"):
        self.rag = VertexAIRAG(project_id, location)
        self.chunk_cache = {}
    
    def generate_quiz(self, bucket_name: str, file_path: str, metadata: Dict, 
                     difficulty: str = "medium", num_questions: int = 10) -> Dict:
        """
        Generate a quiz using RAG
        """
        try:
            cache_key = f"{bucket_name}_{file_path}"
            
            if cache_key not in self.chunk_cache:
                chunks = self.rag.process_pdf(bucket_name, file_path, metadata)
                self.chunk_cache[cache_key] = chunks
                try:
                    self.rag.store_chunks_in_firestore(chunks)
                except Exception as e:
                    logger.warning(f"Failed to store chunks in Firestore: {e}")
            
            chunks = self.chunk_cache[cache_key]
            
            # Get relevant context for quiz generation
            quiz_context_chunks = self.rag.semantic_search("generate quiz questions", chunks, top_k=10)
            
            if not quiz_context_chunks:
                return {"error": "No relevant content found for quiz generation."}
            
            # Prepare context
            context = " ".join([chunk[0]['text'] for chunk in quiz_context_chunks])
            
            # Generate quiz questions
            questions = self.rag.generate_quiz_questions(context, difficulty, num_questions)
            
            if not questions:
                return {"error": "Failed to generate quiz questions."}
            
            return {
                "questions": questions,
                "metadata": metadata,
                "difficulty": difficulty,
                "generated_at": datetime.now().isoformat(),
                "total_questions": len(questions)
            }
            
        except Exception as e:
            logger.error(f"Error generating quiz: {str(e)}")
            return {"error": str(e)} 