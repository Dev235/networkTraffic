# src/utils/model_trainer.py

import pandas as pd
import numpy as np
import joblib
import os
import re
import time
import psutil
import threading
from memory_profiler import memory_usage

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling import SMOTE

# Import helper functions from utils.py
from utils import apply_rf, get_feature_types

# --- Configuration ---
# Path to your preprocessed CICIDS2017 dataset
DATASET_PATH = os.path.join(os.path.dirname(__file__), '../../cicids2017_cleaned.csv') # Adjust path as needed
MODELS_DIR = os.path.join(os.path.dirname(__file__), '../ml_models') # Directory to save models and scalars
SUPERVISED_MODELS_DIR = os.path.join(MODELS_DIR, 'supervised')
SCALARS_DIR = os.path.join(MODELS_DIR, 'scalars')

# Ensure directories exist
os.makedirs(SUPERVISED_MODELS_DIR, exist_ok=True)
os.makedirs(SCALARS_DIR, exist_ok=True)

# --- Random Forest Hyperparameters from supervised notebook ---
# These were identified as the best performing ones in the notebook
BEST_RF_PARAMS = {
    'n_estimators': 200,
    'min_samples_split': 5,
    'min_samples_leaf': 2,
    'max_features': 'sqrt',
    'max_depth': None
}

RANDOM_STATE = 42
N_JOBS = -1 # Use all available cores

def train_and_save_model():
    """
    Loads data, preprocesses, trains the Random Forest model,
    and saves the model and scaler.
    """
    print(f"Loading dataset from: {DATASET_PATH}")
    try:
        clean_df = pd.read_csv(DATASET_PATH)
    except FileNotFoundError:
        print(f"Error: Dataset not found at {DATASET_PATH}. Please ensure the path is correct.")
        return

    # --- Data Preparation ---
    print("Preparing training and test sets...")
    X = clean_df.drop('Attack Type', axis=1)
    y = clean_df['Attack Type']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=RANDOM_STATE, stratify=y)
    
    # --- ADDED FOR DEBUGGING: Print the exact column names used for training ---
    print("\n--- Features used for model training (X_train.columns.tolist()): ---")
    print(X_train.columns.tolist())
    print("-------------------------------------------------------------------\n")
    # --- END DEBUGGING CODE ---

    # Clean up original df to save memory
    del X, y, clean_df

    # --- Feature Scaling ---
    print("Applying Robust Scaling...")
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    # Note: X_test_scaled is not directly used for training, but we keep the scaler fit on X_train
    # to transform it later for evaluation or live inference.
    # X_test_scaled = scaler.transform(X_test) # No need to transform X_test here for training

    # Save the fitted scaler
    scaler_path = os.path.join(SCALARS_DIR, 'robust_scalar_supervised.joblib')
    joblib.dump(scaler, scaler_path)
    print(f"RobustScaler saved to: {scaler_path}")

    # --- Resampling Techniques ---
    print("Applying RandomUnderSampler for 'Normal Traffic'...")
    # Convert X_train_scaled back to DataFrame to preserve feature names for SMOTE
    X_train_scaled_df = pd.DataFrame(X_train_scaled, columns=X_train.columns)
    
    X_train_resampled, y_train_resampled = RandomUnderSampler(
        sampling_strategy={'Normal Traffic': 500000}, random_state=RANDOM_STATE
    ).fit_resample(X_train_scaled_df, y_train) # Use X_train_scaled_df here

    print("Applying SMOTE for minority classes...")
    X_train_resampled_final, y_train_resampled_final = SMOTE(
        sampling_strategy={
            'Bots': 2000,
            'Web Attacks': 2000,
            'Brute Force': 7000,
            'Port Scanning': 70000,
            'DDoS': 90000,
            'DoS': 200000
        },
        random_state=RANDOM_STATE
    ).fit_resample(X_train_resampled, y_train_resampled) # Apply SMOTE

    print("Resampling complete. Final training set distribution:")
    print(y_train_resampled_final.value_counts())

    # --- Random Forest Training ---
    print("Training Random Forest model...")
    cv_scores_rf, measurement_rf, rf_model = apply_rf(
        X_train_resampled_final, y_train_resampled_final,
        best_params=BEST_RF_PARAMS, random_state=RANDOM_STATE, n_jobs=N_JOBS
    )

    if rf_model:
        model_path = os.path.join(SUPERVISED_MODELS_DIR, 'random_forest_model.joblib')
        joblib.dump(rf_model, model_path)
        print(f"Random Forest model saved to: {model_path}")
        print("\nRandom Forest Training Metrics:")
        print(f"Cross validation average score: {np.mean(cv_scores_rf):.4f}")
        print(f"Training Time (s): {measurement_rf['Training Time (s)']:.2f}")
        print(f"Peak Memory Usage (MB): {measurement_rf['Memory Usage (MB)']:.2f}")
        print(f"Average CPU Usage (%): {measurement_rf['Average CPU Usage (%)']:.2f}")
    else:
        print("Random Forest model training failed.")

    print("Model training script finished.")

if __name__ == "__main__":
    train_and_save_model()