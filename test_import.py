#!/usr/bin/env python3
"""
Simple test to check if vertex_ai_rag can be imported
"""

import sys
import os

def test_import():
    """Test if vertex_ai_rag can be imported"""
    try:
        print("Testing import of vertex_ai_rag...")
        from vertex_ai_rag import EnhancedChatService, EnhancedQuizService
        print("✅ Successfully imported EnhancedChatService and EnhancedQuizService")
        
        # Test if classes can be instantiated
        print("Testing class instantiation...")
        project_id = "test-project"
        location = "us-central1"
        
        chat_service = EnhancedChatService(project_id, location)
        print("✅ EnhancedChatService instantiated successfully")
        
        quiz_service = EnhancedQuizService(project_id, location)
        print("✅ EnhancedQuizService instantiated successfully")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("This might be due to missing dependencies.")
        return False
    except Exception as e:
        print(f"❌ Other error: {e}")
        return False

if __name__ == "__main__":
    success = test_import()
    if success:
        print("\n🎉 Import test passed!")
    else:
        print("\n❌ Import test failed!")
        print("\nTo fix this, make sure you have installed the required packages:")
        print("pip install google-cloud-aiplatform vertexai sentence-transformers") 