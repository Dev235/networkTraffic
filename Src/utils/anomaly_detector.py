# src/utils/anomaly_detector.py

import joblib
import pandas as pd
import os
import numpy as np
# from sklearn.ensemble import RandomForestClassifier # Not needed here, only for type hinting if desired

class AnomalyDetector:
    """
    Handles anomaly detection logic using a pre-trained machine learning model.
    """
    def __init__(self, model_dir):
        self.model = None
        self.scaler = None
        self.model_dir = model_dir
        self._load_model_and_scaler()

    def _load_model_and_scaler(self):
        """Loads the pre-trained RF model and RobustScaler."""
        try:
            model_path = os.path.join(self.model_dir, 'supervised', 'random_forest_model.joblib')
            scaler_path = os.path.join(self.model_dir, 'scalars', 'robust_scalar_supervised.joblib')
            
            print(f"Loading model from: {model_path}")
            print(f"Loading scaler from: {scaler_path}")

            with open(model_path, 'rb') as f:
                self.model = joblib.load(f)
            
            with open(scaler_path, 'rb') as f:
                self.scaler = joblib.load(f)
            
            print("Model and Scaler loaded successfully.")
        except FileNotFoundError as e:
            print(f"Error loading model or scaler: {e}. Please ensure model_trainer.py has been run and paths are correct.")
            self.model = None
            self.scaler = None
        except Exception as e:
            print(f"An unexpected error occurred during model/scaler loading: {e}")
            self.model = None
            self.scaler = None

    def detect_anomaly(self, flow_features_df: pd.DataFrame):
        """
        Predicts if a set of flow features represents an anomaly using the loaded model.

        Args:
            flow_features_df (pd.DataFrame): DataFrame of flow features,
                                             structured like the training data.

        Returns:
            pd.Series: A Series of predictions (e.g., 'Normal Traffic' or 'Attack_Type').
            pd.Series: A Series of anomaly probabilities/scores.
            pd.Series: A boolean Series indicating if a flow is anomalous.
        """
        if self.model is None or self.scaler is None:
            print("Anomaly detector is not initialized (model/scaler missing). Cannot detect.")
            return pd.Series(), pd.Series(), pd.Series()

        if flow_features_df.empty:
            return pd.Series(), pd.Series(), pd.Series()

        try:
            # --- DEBUGGING: Print features received by detector ---
            print("AnomalyDetector: Features received for detection:")
            print(flow_features_df.columns.tolist())
            print(f"Shape of received features: {flow_features_df.shape}\n")
            # --- END DEBUGGING ---

            # Scale the features. This outputs a NumPy array.
            scaled_features = pd.DataFrame(
                self.scaler.transform(flow_features_df),
                columns=flow_features_df.columns
            )

            
            # Predict labels
            predictions = self.model.predict(scaled_features)
            
            # Get probabilities for each class
            probabilities = self.model.predict_proba(scaled_features)
            
            # Ensure model.classes_ is a numpy array for consistent indexing
            class_labels = np.array(self.model.classes_)
            
            # --- DEBUGGING: Print model classes and probabilities shape ---
            print(f"Model classes: {class_labels}")
            print(f"Probabilities shape: {probabilities.shape}\n")
            # --- END DEBUGGING ---

            anomaly_scores = pd.Series(np.zeros(len(predictions)), index=flow_features_df.index)
            
            # --- MODIFIED: More robust way to get attack class indices ---
            attack_class_indices = [i for i, label in enumerate(class_labels) if label != 'Normal Traffic']
            
            if len(attack_class_indices) > 0:
                # Select probabilities corresponding to attack classes using integer indices
                # Ensure probabilities is a pure numpy array just before slicing, although it should be already
                probabilities_np = np.asarray(probabilities) 
                attack_probabilities = probabilities_np[:, attack_class_indices]
                
                # The anomaly score is the maximum probability among these attack classes
                anomaly_scores = pd.Series(np.max(attack_probabilities, axis=1), index=flow_features_df.index)
            else:
                anomaly_scores = pd.Series(np.zeros(len(predictions)), index=flow_features_df.index)

            # Convert numerical predictions back to class names
            predicted_labels = pd.Series([class_labels[int(pred_idx)] if isinstance(pred_idx, (int, np.integer)) else pred_idx for pred_idx in predictions],index=flow_features_df.index)

            
            # A flow is anomalous if its predicted label is NOT 'Normal Traffic'
            is_anomaly = (predicted_labels != 'Normal Traffic')
            
            return predicted_labels, anomaly_scores, is_anomaly


        except Exception as e:
            print(f"Error during anomaly detection: {e}")
            # You can add more detailed debugging here if needed, e.g., print types and shapes
            # print(f"Debug: type(probabilities)={type(probabilities)}, probabilities.shape={probabilities.shape if hasattr(probabilities, 'shape') else 'N/A'}")
            # print(f"Debug: type(class_labels)={type(class_labels)}, class_labels.shape={class_labels.shape if hasattr(class_labels, 'shape') else 'N/A'}")
            # print(f"Debug: attack_class_indices={attack_class_indices}, type(attack_class_indices)={type(attack_class_indices)}")
            return pd.Series(), pd.Series(), pd.Series()