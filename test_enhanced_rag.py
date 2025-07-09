#!/usr/bin/env python3
"""
Test script for enhanced Vertex AI RAG system
"""

import os
import sys
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_vertex_ai_rag():
    """Test the Vertex AI RAG system"""
    try:
        # Import the enhanced RAG module
        from vertex_ai_rag import VertexAIRAG, EnhancedChatService, EnhancedQuizService
        
        print("✅ Successfully imported Vertex AI RAG modules")
        
        # Get project configuration
        project_id = os.getenv('PROJECT_ID', 'guru-ai-project-id')
        location = os.getenv('LOCATION', 'us-central1')
        
        print(f"📋 Project ID: {project_id}")
        print(f"📍 Location: {location}")
        
        # Test Vertex AI RAG initialization
        try:
            rag = VertexAIRAG(project_id, location)
            print("✅ Vertex AI RAG initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize Vertex AI RAG: {e}")
            return False
        
        # Test Enhanced Chat Service
        try:
            chat_service = EnhancedChatService(project_id, location)
            print("✅ Enhanced Chat Service initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize Enhanced Chat Service: {e}")
            return False
        
        # Test Enhanced Quiz Service
        try:
            quiz_service = EnhancedQuizService(project_id, location)
            print("✅ Enhanced Quiz Service initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize Enhanced Quiz Service: {e}")
            return False
        
        # Test embedding generation
        try:
            test_texts = ["This is a test sentence.", "Another test sentence for embedding."]
            embeddings = rag.get_embeddings(test_texts)
            print(f"✅ Generated embeddings: {embeddings.shape}")
        except Exception as e:
            print(f"❌ Failed to generate embeddings: {e}")
            return False
        
        print("\n🎉 All tests passed! Enhanced Vertex AI RAG system is working correctly.")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure all required packages are installed:")
        print("pip install google-cloud-aiplatform vertexai sentence-transformers")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_app_integration():
    """Test app.py integration"""
    try:
        # Import app modules
        from app import enhanced_chat_service, enhanced_quiz_service, ENHANCED_RAG_AVAILABLE
        
        print("\n🔧 Testing app.py integration...")
        
        if ENHANCED_RAG_AVAILABLE:
            print("✅ Enhanced RAG is available in app.py")
        else:
            print("❌ Enhanced RAG is not available in app.py")
            return False
        
        if enhanced_chat_service is not None:
            print("✅ Enhanced Chat Service is initialized in app.py")
        else:
            print("❌ Enhanced Chat Service is not initialized in app.py")
            return False
        
        if enhanced_quiz_service is not None:
            print("✅ Enhanced Quiz Service is initialized in app.py")
        else:
            print("❌ Enhanced Quiz Service is not initialized in app.py")
            return False
        
        print("🎉 App.py integration test passed!")
        return True
        
    except Exception as e:
        print(f"❌ App integration test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 Testing Enhanced Vertex AI RAG System")
    print("=" * 50)
    
    # Test 1: Vertex AI RAG functionality
    rag_test_passed = test_vertex_ai_rag()
    
    # Test 2: App integration
    app_test_passed = test_app_integration()
    
    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    print(f"   Vertex AI RAG: {'✅ PASSED' if rag_test_passed else '❌ FAILED'}")
    print(f"   App Integration: {'✅ PASSED' if app_test_passed else '❌ FAILED'}")
    
    if rag_test_passed and app_test_passed:
        print("\n🎉 All tests passed! Your enhanced system is ready to use.")
        print("\n📝 Usage:")
        print("   - Run: python app.py")
        print("   - Enhanced chat: POST /api/enhanced/submit-path")
        print("   - Enhanced ask: POST /api/enhanced/ask")
        print("   - Enhanced quiz: POST /api/enhanced/generate-quiz")
        print("   - Status check: GET /api/enhanced/status")
        return 0
    else:
        print("\n❌ Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 