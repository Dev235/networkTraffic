# src/utils/anomaly_detector.py

import joblib
import pandas as pd
import os
import numpy as np

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
        """
        if self.model is None or self.scaler is None:
            print("Anomaly detector is not initialized (model/scaler missing). Cannot detect.")
            return pd.Series(), pd.Series() # Return empty series

        if flow_features_df.empty:
            return pd.Series(), pd.Series()

        # Scale the features
        try:
            scaled_features = self.scaler.transform(flow_features_df)
            
            # Predict using the model
            predictions = self.model.predict(scaled_features)
            
            # For Random Forest, you can get probabilities of each class
            probabilities = self.model.predict_proba(scaled_features)
            
            # Assuming 'Normal Traffic' is one of the classes, and others are anomalies
            # We need to map numerical predictions back to original labels if the model outputs numbers
            # Get class names from the model if available
            class_names = self.model.classes_ # e.g., ['Normal Traffic', 'DoS', 'DDoS', ...]
            
            # Convert numerical predictions back to class names
            predicted_labels = pd.Series([class_names[pred_idx] for pred_idx in predictions], index=flow_features_df.index)
            
            # Determine if it's an anomaly: if it's not 'Normal Traffic'
            is_anomaly = (predicted_labels != 'Normal Traffic')
            
            # For anomaly score, we might use the probability of 'Normal Traffic' being low,
            # or simply mark as 'anomaly' (1) if it's not normal.
            # A simple anomaly score could be 1 for anomaly, 0 for normal.
            # Or, for multi-class, we could sum probabilities of attack classes.
            anomaly_scores = pd.Series(np.max(probabilities[:, self.model.classes_ != 'Normal Traffic'], axis=1) if 'Normal Traffic' in self.model.classes_ else np.max(probabilities, axis=1), index=flow_features_df.index)
            
            return predicted_labels, anomaly_scores, is_anomaly

        except Exception as e:
            print(f"Error during anomaly detection: {e}")
            return pd.Series(), pd.Series(), pd.Series() # Return empty series