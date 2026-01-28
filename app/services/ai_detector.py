"""AI/ML component detection service for AI Act compliance."""
import re
from typing import List, Dict, Set, Optional
from app.core.logger import logger


class AIDetector:
    """Detects AI/ML frameworks, model files, and AI-related code patterns."""
    
    # AI/ML Framework packages (Python)
    PYTHON_FRAMEWORKS = {
        "tensorflow", "torch", "pytorch", "keras", "sklearn", "scikit-learn",
        "xgboost", "lightgbm", "catboost", "transformers", "huggingface",
        "openai", "langchain", "llama-index", "anthropic", "cohere",
        "jax", "flax", "optuna", "ray", "mlflow", "wandb"
    }
    
    # AI/ML Framework packages (JavaScript/TypeScript)
    JS_FRAMEWORKS = {
        "tensorflow", "tensorflow.js", "@tensorflow/tfjs", "brain.js", "ml5",
        "synaptic", "convnetjs", "neataptic", "neurojs"
    }
    
    # AI/ML Framework packages (Java)
    JAVA_FRAMEWORKS = {
        "deeplearning4j", "dl4j", "weka", "smile", "rapidminer"
    }
    
    # Model file extensions
    MODEL_EXTENSIONS = {
        ".h5", ".hdf5", ".pkl", ".pickle", ".pb", ".onnx", ".tflite",
        ".pt", ".pth", ".ckpt", ".safetensors", ".gguf", ".ggml",
        ".joblib", ".model", ".weights", ".bin"
    }
    
    # Training-related file patterns
    TRAINING_PATTERNS = {
        "train.py", "training.py", "train_*.py", "*_train.py",
        "train.ipynb", "training.ipynb", "*_train.ipynb",
        "fit.py", "fit_*.py", "*_fit.py"
    }
    
    # Inference-related patterns
    INFERENCE_PATTERNS = {
        "predict.py", "inference.py", "predict_*.py", "*_predict.py",
        "infer.py", "classify.py", "generate.py", "forward.py"
    }
    
    # AI-related import patterns
    IMPORT_PATTERNS = {
        r'import\s+(tensorflow|torch|keras|sklearn|transformers)',
        r'from\s+(tensorflow|torch|keras|sklearn|transformers)',
        r'require\(["\'](tensorflow|@tensorflow/tfjs|brain\.js|ml5)',
    }
    
    def __init__(self):
        """Initialize AI detector."""
        self.compiled_import_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.IMPORT_PATTERNS
        ]
    
    def detect_ai_frameworks(self, dependencies: List[Dict[str, str]]) -> List[str]:
        """
        Detect AI/ML frameworks from dependency list.
        
        Args:
            dependencies: List of dependency dicts with 'name' and 'type' keys
        
        Returns:
            List of detected framework names
        """
        frameworks: Set[str] = []
        
        for dep in dependencies:
            dep_name = dep.get("name", "").lower()
            dep_type = dep.get("type", "").lower()
            
            # Check Python frameworks
            if dep_type in ("python", "poetry"):
                for framework in self.PYTHON_FRAMEWORKS:
                    if framework in dep_name:
                        frameworks.add(framework)
            
            # Check JavaScript frameworks
            elif dep_type == "node":
                for framework in self.JS_FRAMEWORKS:
                    if framework in dep_name:
                        frameworks.add(framework)
            
            # Check Java frameworks
            elif dep_type == "java":
                for framework in self.JAVA_FRAMEWORKS:
                    if framework in dep_name:
                        frameworks.add(framework)
        
        result = sorted(list(frameworks))
        if result:
            logger.debug("Detected AI frameworks: %s", ", ".join(result))
        
        return result
    
    def detect_model_files(self, file_paths: List[str]) -> List[str]:
        """
        Detect model files in repository.
        
        Args:
            file_paths: List of file paths
        
        Returns:
            List of detected model file paths
        """
        model_files: List[str] = []
        
        for file_path in file_paths:
            file_lower = file_path.lower()
            
            # Check file extension
            if any(file_lower.endswith(ext) for ext in self.MODEL_EXTENSIONS):
                model_files.append(file_path)
            # Check for model-related directory patterns
            elif any(pattern in file_lower for pattern in ["/models/", "/model/", "/checkpoints/", "/weights/"]):
                if any(file_lower.endswith(ext) for ext in self.MODEL_EXTENSIONS):
                    model_files.append(file_path)
        
        if model_files:
            logger.debug("Detected %d model files", len(model_files))
        
        return model_files
    
    def detect_ai_imports(self, file_path: str, content: str) -> List[str]:
        """
        Detect AI/ML framework imports in code.
        
        Args:
            file_path: Path to the file
            content: File content
        
        Returns:
            List of detected framework names from imports
        """
        frameworks: Set[str] = []
        
        if not content:
            return []
        
        for pattern in self.compiled_import_patterns:
            matches = pattern.finditer(content)
            for match in matches:
                # Extract framework name from import
                import_text = match.group(0).lower()
                
                # Check Python frameworks
                for framework in self.PYTHON_FRAMEWORKS:
                    if framework in import_text:
                        frameworks.add(framework)
                
                # Check JS frameworks
                for framework in self.JS_FRAMEWORKS:
                    if framework in import_text:
                        frameworks.add(framework)
        
        result = sorted(list(frameworks))
        if result:
            logger.debug("Detected AI imports in %s: %s", file_path, ", ".join(result))
        
        return result
    
    def detect_training_code(self, file_paths: List[str]) -> List[str]:
        """
        Detect training-related files.
        
        Args:
            file_paths: List of file paths
        
        Returns:
            List of training file paths
        """
        training_files: List[str] = []
        
        for file_path in file_paths:
            file_lower = file_path.lower()
            file_name = file_path.split("/")[-1].lower()
            
            # Check against training patterns
            for pattern in self.TRAINING_PATTERNS:
                if pattern.replace("*", "") in file_name or pattern.replace("*", "") in file_lower:
                    training_files.append(file_path)
                    break
        
        if training_files:
            logger.debug("Detected %d training files", len(training_files))
        
        return training_files
    
    def detect_inference_code(self, file_paths: List[str]) -> List[str]:
        """
        Detect inference-related files.
        
        Args:
            file_paths: List of file paths
        
        Returns:
            List of inference file paths
        """
        inference_files: List[str] = []
        
        for file_path in file_paths:
            file_lower = file_path.lower()
            file_name = file_path.split("/")[-1].lower()
            
            # Check against inference patterns
            for pattern in self.INFERENCE_PATTERNS:
                if pattern.replace("*", "") in file_name or pattern.replace("*", "") in file_lower:
                    inference_files.append(file_path)
                    break
        
        if inference_files:
            logger.debug("Detected %d inference files", len(inference_files))
        
        return inference_files
    
    def detect_ai_components(
        self,
        file_paths: List[str],
        dependencies: List[Dict[str, str]],
        file_contents: Optional[Dict[str, str]] = None
    ) -> Dict[str, any]:
        """
        Comprehensive AI component detection.
        
        Args:
            file_paths: List of all file paths in repository
            dependencies: List of dependencies
            file_contents: Optional dict mapping file_path -> content for import detection
        
        Returns:
            Dictionary with detection results:
            {
                "frameworks": List[str],
                "model_files": List[str],
                "training_files": List[str],
                "inference_files": List[str],
                "has_ai": bool,
                "confidence": float
            }
        """
        # Detect frameworks from dependencies
        frameworks_from_deps = self.detect_ai_frameworks(dependencies)
        
        # Detect frameworks from imports
        frameworks_from_imports: Set[str] = set()
        if file_contents:
            for file_path, content in file_contents.items():
                imports = self.detect_ai_imports(file_path, content)
                frameworks_from_imports.update(imports)
        
        # Combine all frameworks
        all_frameworks = sorted(list(set(frameworks_from_deps) | frameworks_from_imports))
        
        # Detect model files
        model_files = self.detect_model_files(file_paths)
        
        # Detect training code
        training_files = self.detect_training_code(file_paths)
        
        # Detect inference code
        inference_files = self.detect_inference_code(file_paths)
        
        # Determine if AI is present
        has_ai = (
            len(all_frameworks) > 0 or
            len(model_files) > 0 or
            len(training_files) > 0 or
            len(inference_files) > 0
        )
        
        # Calculate confidence
        confidence = 0.0
        if len(all_frameworks) > 0:
            confidence += 0.4
        if len(model_files) > 0:
            confidence += 0.3
        if len(training_files) > 0:
            confidence += 0.2
        if len(inference_files) > 0:
            confidence += 0.1
        confidence = min(1.0, confidence)
        
        result = {
            "frameworks": all_frameworks,
            "model_files": model_files,
            "training_files": training_files,
            "inference_files": inference_files,
            "has_ai": has_ai,
            "confidence": confidence
        }
        
        if has_ai:
            logger.info(
                "AI components detected: frameworks=%d, models=%d, training=%d, inference=%d",
                len(all_frameworks), len(model_files), len(training_files), len(inference_files)
            )
        
        return result
