# src/utils/utils.py

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.model_selection import train_test_split # Added for analyze_feature_importance_rf

# --- NEW IMPORTS ADDED HERE ---
import threading # Added for threading.Event
import psutil    # Added for psutil.cpu_percent
from memory_profiler import memory_usage # Added for memory_usage
import time # Added for time.time() if not already there implicitly via psutil.cpu_percent's interval

def get_feature_types(df, target_col='Attack Type'):
    """
    Identify numeric and categorical features, if present, in the dataset.

    Parameters:
    -----------\n
    df : pandas.DataFrame
        Input DataFrame containing the dataset
    target_col : str, optional (default='Attack Type')
        Name of the target column to exclude from features

    Returns:
    --------
    tuple : (list, list)
        Two lists containing:
        - numeric_features: List of column names with numerical data
        - categorical_features: List of column names with categorical data

    Notes:
    ------
    - Numerical features are identified as columns containing numeric data types
    - Categorical features are identified as columns containing object data types
    - The target column is excluded from both feature lists if present
    """

    numeric_features = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_features = df.select_dtypes(include=['object']).columns.tolist()

    # Remove target column if present
    if target_col in numeric_features:
        numeric_features.remove(target_col)
    if target_col in categorical_features:
        categorical_features.remove(target_col)

    return numeric_features, categorical_features

def correlation_analysis(df, numeric_features, threshold=0.85):
    """
    Analyze correlations between numerical features.

    Parameters:
    -----------\n
    df : pandas.DataFrame
        Input DataFrame containing the dataset
    numeric_features : list
        List of column names containing numerical features to analyze
    threshold : float
        Threshold for determining highly correlated features (default='0.85')

    Returns:
    --------
    list of tuples
        List of highly correlated feature pairs and their correlation values
        Each tuple contains (feature1, feature2, correlation_value)

    Notes:
    ------
    - Generates a correlation matrix heatmap
    - Identifies feature pairs with absolute correlation > 0.85
    - Only returns upper triangle of correlation matrix to avoid duplicates
    - The heatmap uses a diverging color scheme centered at 0
    """

    # Calculate correlation matrix
    corr_matrix = df[numeric_features].corr()

    # Plot correlation heatmap
    plt.figure(figsize=(20, 20))
    sns.heatmap(corr_matrix, annot=False, cmap='coolwarm', center=0, linewidth = 0.5)
    plt.title('Feature Correlation Heatmap')
    plt.xticks(rotation=90)
    plt.yticks(rotation=0)
    plt.show()

    # Identify highly correlated features
    threshold = threshold
    high_corr = np.where(np.abs(corr_matrix) > threshold)
    high_corr = [(corr_matrix.index[x], corr_matrix.columns[y], corr_matrix.iloc[x, y])
                 for x, y in zip(*high_corr) if x != y and x < y]

    return high_corr

def analyze_variance_homogeneity(df, numeric_features, target_col='Attack Type'):
    """
    Analyze the homogeneity of variances using Levene's test.

    Parameters:
    -----------\n
    df : pandas.DataFrame
        Input DataFrame containing the dataset.
    numeric_features : list
        List of column names containing numerical features to analyze.
    target_col : str, optional (default='Attack Type')
        Name of the target column

    Returns:
    --------
    dict
        Dictionary containing the results of Levene's test for each feature.
    """
    
    results_levene = {}
    
    for feature in numeric_features:
        # Group data by y and filter out groups with zero values
        groups = [group[feature].dropna().values for name, group in df.groupby(target_col) 
                  if not group[feature].dropna().empty]
        
        # Filter out groups that contain only zero values or have zero variance
        groups = [group for group in groups if len(group) > 0 and np.any(group != 0) and np.var(group) > 0]
        
        # Check if there are at least two groups with valid data
        if len(groups) < 2:
            print(f"Not enough valid groups to perform Levene's test for feature: {feature}")
            continue  # Skip this feature if not enough valid groups

        # Perform Levene's Test
        stat_levene, p_value_levene = stats.levene(*groups)
        results_levene[feature] = {'Statistic': stat_levene, 'p-value': p_value_levene}

    return results_levene

def analyze_feature_importance_rf(df, numeric_features, target_col='Attack Type'):
    """
    Analyze feature importance using a Random Forest classifier.

    Parameters:
    -----------\n
    df : pandas.DataFrame
        Input DataFrame containing the dataset
    numeric_features : list
        List of column names containing numerical features to analyze
    target_col : str
        Column name of the target variable

    Returns:
    --------
    pandas.DataFrame
        DataFrame containing feature importances sorted by importance in descending order
    cm
        Confusion Matrix for further analysis
    rf_labels
        Labels for plotting the confusion matrix
    cv_scores
        Cross-validation scores for future reference

    Notes:
    ------
    - Uses a Random Forest classifier to assess feature importance.
    - Generates bar plot of feature importances for visual comparison.
    """

    # Hyperparameter settings
    hyperparameters = {
        'n_estimators': 150,    # Number of trees
        'max_depth': 30,        # Limit tree depth
        'random_state': 42,     # For reproducibility
        'n_jobs': -1            # Use all available cores
    }

    # Prepare the data
    X = df[numeric_features]
    y = df[target_col]

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=hyperparameters['random_state'], stratify=y)

    # Create the Random Forest model with specified hyperparameters
    rf = RandomForestClassifier(**hyperparameters)

    # Fit the model on the training set
    rf.fit(X_train, y_train)

    # Cross-validation on the training set
    cv_scores = cross_val_score(rf, X_train, y_train, cv=5, n_jobs=-1)
    print(f'Cross-Validation Score: {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}')
    
    # Predict on test set
    y_pred = rf.predict(X_test)

    # Feature importances
    importances = rf.feature_importances_
    feature_importance_df = pd.DataFrame({'Feature': numeric_features, 'Importance': importances})
    feature_importance_df = feature_importance_df.sort_values('Importance', ascending=False)

    # Confusion matrix
    rf_labels = rf.classes_
    cm = confusion_matrix(y_test, y_pred)

    # Calculate test scores
    report = classification_report(y_test, y_pred, target_names=rf_labels)
    print("\nClassification Report:\n")
    print(report, end='\n\n')

    # Plot feature importances
    plt.figure(figsize=(18, 12))
    plt.bar(feature_importance_df['Feature'], feature_importance_df['Importance'], color='skyblue')
    plt.ylabel('Importance')
    plt.xlabel('Features')
    plt.title('Feature Importance from Random Forest')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

    return feature_importance_df, cm, rf_labels, cv_scores

def apply_rf(X_train, y_train, best_params=None, random_state=42, n_jobs=-1, cv=5):
    """
    Apply Random Forest with resource measurements, including memory, training time, and CPU usage.

    Parameters:
        X_train: Training features.
        y_train: Training labels.
        best_params: Dictionary of best parameters for Random Forest.
        random_state: Random state for reproducibility.
        n_jobs: Number of jobs for parallel processing.
        cv: Number of cross-validation folds.

    Returns:
        cv_scores_rf: Cross-validation scores.
        measurement_rf: Dictionary of memory, training time, and CPU usage.
        rf_model: Trained Random Forest model.
    """
    
    measurement_rf = {}

    # Default to empty dictionary if best_params is not provided
    best_params = best_params or {}

    rf_model = RandomForestClassifier(**best_params, random_state=random_state, n_jobs=n_jobs)
    
    # Function to monitor CPU usage during training
    cpu_usage = []
    stop_flag = threading.Event()

    def monitor_cpu():
        while not stop_flag.is_set():
            cpu_usage.append(psutil.cpu_percent(interval=0.1))

    # Function to train the model
    def train_model():
        rf_model.fit(X_train, y_train)

    try:
        # Start CPU monitoring in a separate thread
        cpu_thread = threading.Thread(target=monitor_cpu)
        cpu_thread.start()

        # Measure memory usage and training time
        start_time = time.time()
        # memory_usage expects a (function, args=(), kwds={}) tuple
        train_memory_rf = max(memory_usage((train_model,)))  # Measure peak memory usage
        training_time = time.time() - start_time

        # Stop CPU monitoring
        stop_flag.set()
        cpu_thread.join()

        # Add measurements
        measurement_rf['Memory Usage (MB)'] = train_memory_rf
        measurement_rf['Training Time (s)'] = training_time
        measurement_rf['Peak CPU Usage (%)'] = max(cpu_usage) if cpu_usage else 0
        measurement_rf['Average CPU Usage (%)'] = sum(cpu_usage) / len(cpu_usage) if cpu_usage else 0

        # Perform cross-validation
        cv_scores_rf = cross_val_score(rf_model, X_train, y_train, cv=cv, n_jobs=n_jobs)

        return cv_scores_rf, measurement_rf, rf_model

    except Exception as e:
        print(f"Error during Random Forest training: {e}")
        return None, None, None

# You can add apply_xgboost and apply_knn here if needed for completeness,
# but for this specific request, Random Forest is the chosen model.
# I'll just include a placeholder for them.

def apply_xgboost(X_train, y_train, best_params=None, random_state=42, n_jobs=-1, cv=5):
    """Placeholder for XGBoost training function."""
    print("XGBoost training function (placeholder)")
    return None, None, None

def apply_knn(X_train, y_train, best_params=None, n_jobs=-1, cv=5):
    """Placeholder for KNN training function."""
    print("KNN training function (placeholder)")
    return None, None, None