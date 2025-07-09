# Enhanced Vertex AI RAG System for Guru AI

This document describes the enhanced chat and quiz features that have been converted to use Vertex AI and RAG (Retrieval-Augmented Generation) with your existing files.

## 🚀 Overview

The enhanced system provides:
- **Improved Chat Functionality**: Better semantic search and context-aware responses
- **Enhanced Quiz Generation**: More intelligent question generation with better context understanding
- **Persistent Storage**: Chunks and embeddings stored in Firestore for better performance
- **Fallback Support**: Graceful degradation if enhanced features are unavailable

## 📁 File Structure

```
Phase 12/
├── app.py                    # Main application file (enhanced with RAG)
├── vertex_ai_rag.py         # Enhanced RAG implementation
├── test_enhanced_rag.py     # Test script for verification
├── chat.py                  # Original chat implementation
├── chatbot.py               # Original chatbot implementation
├── requirements.txt         # Dependencies
└── README_ENHANCED_RAG.md   # This file
```

## 🔧 Key Components

### 1. VertexAIRAG Class
- **Purpose**: Core RAG implementation using Vertex AI
- **Features**:
  - PDF processing and chunking
  - Semantic search using embeddings
  - Answer generation with Vertex AI Gemini
  - Quiz question generation
  - Firestore integration for persistent storage

### 2. EnhancedChatService
- **Purpose**: High-level chat service using RAG
- **Features**:
  - Document processing and caching
  - Question answering with context retrieval
  - Debug information for transparency

### 3. EnhancedQuizService
- **Purpose**: High-level quiz generation service
- **Features**:
  - Intelligent quiz question generation
  - Difficulty level support
  - Context-aware question creation

## 🛠️ Installation & Setup

### 1. Environment Variables
Ensure your `.env` file contains:
```bash
PROJECT_ID=your-gcp-project-id
LOCATION=us-central1
FIREBASE_CREDENTIALS_PATH=path/to/service-account.json
GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json
```

### 2. Dependencies
The enhanced system uses these additional packages:
```bash
pip install google-cloud-aiplatform vertexai sentence-transformers
```

### 3. Testing
Run the test script to verify everything works:
```bash
python test_enhanced_rag.py
```

## 🚀 Usage

### Running the Application
```bash
python app.py
```

### API Endpoints

#### Enhanced Chat Endpoints

1. **Submit Document Path**
   ```http
   POST /api/enhanced/submit-path
   Content-Type: application/json
   
   {
     "path": "gs://guru-ai-bucket/NCERT/Class 10/Science/Chapter 1.pdf"
   }
   ```

2. **Ask Question**
   ```http
   POST /api/enhanced/ask
   Content-Type: application/json
   
   {
     "cache_key": "guru-ai-bucket_NCERT_Class 10_Science_Chapter 1.pdf",
     "question": "What is photosynthesis?",
     "top_k": 5
   }
   ```

#### Enhanced Quiz Endpoints

3. **Generate Quiz**
   ```http
   POST /api/enhanced/generate-quiz
   Content-Type: application/json
   
   {
     "subject": "Science",
     "chapter": "Chapter 1",
     "difficulty": "medium",
     "num_questions": 10,
     "literatureType": ""
   }
   ```

4. **Check Status**
   ```http
   GET /api/enhanced/status
   ```

## 🔄 Migration from Original System

### Backward Compatibility
- **Original endpoints still work**: `/ask`, `/generate-quiz`, etc.
- **Enhanced endpoints are additive**: `/api/enhanced/*`
- **Graceful fallback**: If enhanced system fails, original system continues to work

### Key Differences

| Feature | Original System | Enhanced System |
|---------|----------------|-----------------|
| Embeddings | Sentence Transformers | Sentence Transformers + Vertex AI |
| Text Generation | Vertex AI Gemini | Vertex AI Gemini (enhanced prompts) |
| Storage | Local JSON files | Firestore + local cache |
| Context Retrieval | Basic similarity | Advanced semantic search |
| Error Handling | Basic | Comprehensive with fallbacks |

## 📊 Performance Improvements

### 1. Better Context Retrieval
- **Enhanced semantic search** with improved similarity scoring
- **Metadata filtering** for more relevant results
- **Chunk optimization** with better text segmentation

### 2. Improved Answer Quality
- **Structured prompts** for more consistent responses
- **Context-aware generation** with better understanding
- **Educational focus** with subject-specific formatting

### 3. Persistent Storage
- **Firestore integration** for chunk and embedding storage
- **Reduced reprocessing** of documents
- **Better scalability** for multiple users

## 🛡️ Error Handling & Fallbacks

### 1. Graceful Degradation
- If enhanced RAG fails, system falls back to original implementation
- Clear error messages and status reporting
- Automatic retry mechanisms

### 2. Service Health Checks
- `/api/enhanced/status` endpoint for monitoring
- Detailed logging for debugging
- Performance metrics tracking

## 🔍 Debugging & Monitoring

### 1. Logging
The system provides comprehensive logging:
```python
# Check if enhanced services are available
if enhanced_chat_service is not None:
    # Use enhanced system
else:
    # Fall back to original system
```

### 2. Debug Information
Enhanced responses include debug information:
```json
{
  "answer": "Generated answer...",
  "debug": {
    "question": "Original question",
    "context_used": "Context used for generation",
    "relevant_chunks": [
      {
        "text": "Chunk text...",
        "similarity_score": 0.85,
        "metadata": {...}
      }
    ]
  }
}
```

## 🚀 Future Enhancements

### Planned Features
1. **Vector Database Integration**: Pinecone or Weaviate for better scalability
2. **Multi-modal Support**: Image and diagram understanding
3. **Real-time Learning**: User feedback integration
4. **Advanced Analytics**: Usage patterns and performance metrics

### Performance Optimizations
1. **Batch Processing**: Parallel document processing
2. **Caching Layers**: Redis for frequently accessed data
3. **CDN Integration**: Faster content delivery

## 📝 Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   pip install google-cloud-aiplatform vertexai sentence-transformers
   ```

2. **Authentication Issues**
   - Verify service account credentials
   - Check PROJECT_ID and LOCATION in .env

3. **Memory Issues**
   - Reduce chunk size in vertex_ai_rag.py
   - Implement chunk streaming for large documents

4. **Performance Issues**
   - Enable Firestore caching
   - Use batch operations for multiple documents

### Support
For issues or questions:
1. Check the logs in `app.logger`
2. Run `python test_enhanced_rag.py` for diagnostics
3. Verify environment variables and credentials

## 🎉 Conclusion

The enhanced Vertex AI RAG system provides significant improvements in:
- **Answer quality** through better context understanding
- **Performance** with persistent storage and caching
- **Scalability** with cloud-native architecture
- **Reliability** with comprehensive error handling

The system maintains full backward compatibility while adding powerful new capabilities for your educational AI platform. 