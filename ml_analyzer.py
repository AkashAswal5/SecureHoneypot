import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Dropout, LSTM
import joblib
import os
import logging
import time
import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HoneypotMLAnalyzer:
    """Machine learning analyzer for honeypot attack data."""
    
    def __init__(self, model_dir='models'):
        """Initialize the ML analyzer.
        
        Args:
            model_dir (str): Directory to store trained models
        """
        self.model_dir = model_dir
        self.anomaly_model = None
        self.classification_model = None
        self.prediction_model = None
        self.encoders = {}
        self.scaler = None
        
        # Create model directory if it doesn't exist
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
    
    def preprocess_data(self, logs_data):
        """Preprocess logs data for machine learning.
        
        Args:
            logs_data (list): List of dictionaries containing attack logs
            
        Returns:
            pd.DataFrame: Preprocessed dataframe
        """
        # Convert to DataFrame
        df = pd.DataFrame(logs_data)
        
        # Convert timestamp to datetime and extract features
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['day'] = df['timestamp'].dt.day
        df['month'] = df['timestamp'].dt.month
        
        # Handle categorical data
        categorical_columns = ['service', 'attack_type', 'source_ip']
        
        for col in categorical_columns:
            if col in df.columns:
                if col not in self.encoders:
                    self.encoders[col] = LabelEncoder()
                    df[f'{col}_encoded'] = self.encoders[col].fit_transform(df[col])
                else:
                    # Handle new categories that weren't in the training data
                    known_categories = set(self.encoders[col].classes_)
                    new_categories = set(df[col].unique()) - known_categories
                    
                    if new_categories:
                        # Retrain the encoder with new categories
                        self.encoders[col] = LabelEncoder()
                        df[f'{col}_encoded'] = self.encoders[col].fit_transform(df[col])
                    else:
                        df[f'{col}_encoded'] = self.encoders[col].transform(df[col])
        
        # Convert port to numeric, if not already
        if 'port' in df.columns and not pd.api.types.is_numeric_dtype(df['port']):
            df['port'] = pd.to_numeric(df['port'], errors='coerce')
            df['port'].fillna(-1, inplace=True)
        
        # If IP address is in the data, convert to numerical features
        if 'source_ip' in df.columns:
            # Extract features from IP (e.g., first octet, etc.)
            try:
                df['ip_first_octet'] = df['source_ip'].apply(lambda x: int(x.split('.')[0]) if isinstance(x, str) and '.' in x else -1)
            except:
                df['ip_first_octet'] = -1
        
        return df
    
    def train_anomaly_detector(self, logs_data):
        """Train an anomaly detection model on the logs data.
        
        Args:
            logs_data (list): List of dictionaries containing attack logs
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info("Training anomaly detection model...")
            
            # Preprocess data
            df = self.preprocess_data(logs_data)
            
            # Select features for anomaly detection
            feature_cols = [col for col in df.columns if col.endswith('_encoded') or 
                           col in ['port', 'hour', 'day_of_week', 'ip_first_octet']]
            
            # Scale the features
            self.scaler = StandardScaler()
            X = self.scaler.fit_transform(df[feature_cols])
            
            # Train Isolation Forest model
            self.anomaly_model = IsolationForest(
                n_estimators=100, 
                contamination=0.1,  # Assuming 10% of traffic might be anomalous
                random_state=42
            )
            self.anomaly_model.fit(X)
            
            # Save the model
            joblib.dump(self.anomaly_model, os.path.join(self.model_dir, 'anomaly_model.pkl'))
            joblib.dump(self.scaler, os.path.join(self.model_dir, 'scaler.pkl'))
            joblib.dump(self.encoders, os.path.join(self.model_dir, 'encoders.pkl'))
            
            logger.info("Anomaly detection model trained successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error training anomaly detection model: {e}")
            return False
    
    def detect_anomalies(self, logs_data):
        """Detect anomalies in the logs data.
        
        Args:
            logs_data (list): List of dictionaries containing attack logs
            
        Returns:
            list: Indices of anomalous logs
        """
        try:
            # Load model if not already loaded
            if self.anomaly_model is None:
                model_path = os.path.join(self.model_dir, 'anomaly_model.pkl')
                scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
                encoders_path = os.path.join(self.model_dir, 'encoders.pkl')
                
                if os.path.exists(model_path) and os.path.exists(scaler_path) and os.path.exists(encoders_path):
                    self.anomaly_model = joblib.load(model_path)
                    self.scaler = joblib.load(scaler_path)
                    self.encoders = joblib.load(encoders_path)
                else:
                    logger.warning("No anomaly detection model found. Training a new one...")
                    self.train_anomaly_detector(logs_data)
            
            # Preprocess data
            df = self.preprocess_data(logs_data)
            
            # Select features for anomaly detection
            feature_cols = [col for col in df.columns if col.endswith('_encoded') or 
                           col in ['port', 'hour', 'day_of_week', 'ip_first_octet']]
            
            # Scale the features
            X = self.scaler.transform(df[feature_cols])
            
            # Predict anomalies
            # -1 for anomalies, 1 for normal data points
            predictions = self.anomaly_model.predict(X)
            
            # Get indices of anomalies
            anomaly_indices = np.where(predictions == -1)[0]
            
            return anomaly_indices.tolist()
        
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return []
    
    def train_attack_classifier(self, logs_data):
        """Train a classification model to predict attack types.
        
        Args:
            logs_data (list): List of dictionaries containing attack logs
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info("Training attack classification model...")
            
            # Preprocess data
            df = self.preprocess_data(logs_data)
            
            # Select features and target for classification
            feature_cols = [col for col in df.columns if col.endswith('_encoded') or 
                           col in ['port', 'hour', 'day_of_week', 'day', 'month', 'ip_first_octet']]
            
            # Make sure we have the attack_type column
            if 'attack_type_encoded' not in df.columns or 'attack_type' not in df.columns:
                logger.error("Attack type column missing from data")
                return False
            
            # Split into features and target
            X = df[feature_cols]
            y = df['attack_type_encoded']
            
            # Split into train and test sets
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Train Random Forest classifier
            self.classification_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            self.classification_model.fit(X_train, y_train)
            
            # Evaluate the model
            accuracy = self.classification_model.score(X_test, y_test)
            logger.info(f"Classification model accuracy: {accuracy:.4f}")
            
            # Save the model
            joblib.dump(self.classification_model, os.path.join(self.model_dir, 'classification_model.pkl'))
            
            logger.info("Attack classification model trained successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error training attack classification model: {e}")
            return False
    
    def predict_attack_type(self, log_entry):
        """Predict the attack type for a log entry.
        
        Args:
            log_entry (dict): A single log entry
            
        Returns:
            str: Predicted attack type
        """
        try:
            # Load model if not already loaded
            if self.classification_model is None:
                model_path = os.path.join(self.model_dir, 'classification_model.pkl')
                encoders_path = os.path.join(self.model_dir, 'encoders.pkl')
                
                if os.path.exists(model_path) and os.path.exists(encoders_path):
                    self.classification_model = joblib.load(model_path)
                    self.encoders = joblib.load(encoders_path)
                else:
                    logger.warning("No classification model found")
                    return "Unknown"
            
            # Preprocess the single log entry
            df = self.preprocess_data([log_entry])
            
            # Select features for classification
            feature_cols = [col for col in df.columns if col.endswith('_encoded') or 
                           col in ['port', 'hour', 'day_of_week', 'day', 'month', 'ip_first_octet']]
            
            # Make prediction
            prediction = self.classification_model.predict(df[feature_cols])
            
            # Convert prediction back to attack type string
            attack_type = self.encoders['attack_type'].inverse_transform(prediction)[0]
            
            return attack_type
        
        except Exception as e:
            logger.error(f"Error predicting attack type: {e}")
            return "Unknown"
    
    def train_time_series_model(self, logs_data, target_service=None, lookback=24):
        """Train a time series model to predict attack trends.
        
        Args:
            logs_data (list): List of dictionaries containing attack logs
            target_service (str, optional): Specific service to predict attacks for
            lookback (int): Number of hours to look back for prediction
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Training time series prediction model for {'all services' if target_service is None else target_service}...")
            
            # Preprocess data
            df = self.preprocess_data(logs_data)
            
            # Create time series data
            # Resample to hourly count of attacks
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.set_index('timestamp')
            
            if target_service:
                # Filter for specific service
                df = df[df['service'] == target_service]
            
            # Count attacks per hour
            hourly_attacks = df.resample('H').size()
            
            # Fill missing hours with zero attacks
            date_range = pd.date_range(start=hourly_attacks.index.min(), end=hourly_attacks.index.max(), freq='H')
            hourly_attacks = hourly_attacks.reindex(date_range, fill_value=0)
            
            # Create sequences for LSTM
            sequences = []
            for i in range(len(hourly_attacks) - lookback):
                sequences.append(hourly_attacks.iloc[i:i+lookback+1].values)
            
            # Convert to numpy array and reshape for LSTM
            sequences = np.array(sequences)
            X = sequences[:, :-1]  # All but the last value
            y = sequences[:, -1]   # Only the last value
            
            # Reshape for LSTM [samples, time steps, features]
            X = X.reshape(X.shape[0], X.shape[1], 1)
            
            # Split into train and test sets
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Build LSTM model
            self.prediction_model = Sequential([
                LSTM(50, activation='relu', input_shape=(lookback, 1), return_sequences=True),
                Dropout(0.2),
                LSTM(50, activation='relu'),
                Dropout(0.2),
                Dense(1)
            ])
            
            self.prediction_model.compile(optimizer='adam', loss='mse')
            
            # Train the model
            self.prediction_model.fit(
                X_train, y_train,
                epochs=50,
                batch_size=32,
                validation_data=(X_test, y_test),
                verbose=1
            )
            
            # Save the model
            model_filename = f"time_series_model{'_' + target_service if target_service else ''}.h5"
            self.prediction_model.save(os.path.join(self.model_dir, model_filename))
            
            # Save the last sequence for future predictions
            joblib.dump(hourly_attacks[-lookback:].values, 
                       os.path.join(self.model_dir, f"last_sequence{'_' + target_service if target_service else ''}.pkl"))
            
            logger.info("Time series prediction model trained successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error training time series model: {e}")
            return False
    
    def predict_attack_trends(self, hours_ahead=24, target_service=None, lookback=24):
        """Predict attack trends for the next X hours.
        
        Args:
            hours_ahead (int): Number of hours to predict ahead
            target_service (str, optional): Specific service to predict attacks for
            lookback (int): Number of hours to look back for prediction
            
        Returns:
            list: Predicted number of attacks for each hour
        """
        try:
            # Load model if not already loaded
            model_filename = f"time_series_model{'_' + target_service if target_service else ''}.h5"
            sequence_filename = f"last_sequence{'_' + target_service if target_service else ''}.pkl"
            
            model_path = os.path.join(self.model_dir, model_filename)
            sequence_path = os.path.join(self.model_dir, sequence_filename)
            
            if not os.path.exists(model_path) or not os.path.exists(sequence_path):
                logger.warning("No prediction model or sequence data found")
                return []
            
            if self.prediction_model is None or (target_service and not self.prediction_model.name.endswith(target_service)):
                self.prediction_model = load_model(model_path)
            
            # Load the last sequence
            last_sequence = joblib.load(sequence_path)
            
            # Make predictions iteratively
            curr_sequence = last_sequence.reshape(1, lookback, 1)
            predictions = []
            
            for _ in range(hours_ahead):
                # Predict the next hour
                next_pred = self.prediction_model.predict(curr_sequence)[0][0]
                predictions.append(max(0, next_pred))  # Ensure non-negative prediction
                
                # Update sequence
                curr_sequence = np.append(curr_sequence[:, 1:, :], [[[next_pred]]], axis=1)
            
            return predictions
        
        except Exception as e:
            logger.error(f"Error predicting attack trends: {e}")
            return []
    
    def generate_attack_pattern_report(self, logs_data):
        """Generate a report on attack patterns.
        
        Args:
            logs_data (list): List of dictionaries containing attack logs
            
        Returns:
            dict: Report containing attack pattern insights
        """
        try:
            logger.info("Generating attack pattern report...")
            
            # Preprocess data
            df = self.preprocess_data(logs_data)
            
            # Basic statistics
            total_attacks = len(df)
            unique_ips = df['source_ip'].nunique()
            unique_attack_types = df['attack_type'].nunique()
            
            # Top attack types
            attack_type_counts = df['attack_type'].value_counts().to_dict()
            
            # Top attacking IPs
            top_attacker_ips = df['source_ip'].value_counts().head(10).to_dict()
            
            # Attacks by hour of day
            attacks_by_hour = df['hour'].value_counts().sort_index().to_dict()
            
            # Attacks by day of week
            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            attacks_by_day = df['day_of_week'].value_counts().sort_index().to_dict()
            attacks_by_day = {day_names[k]: v for k, v in attacks_by_day.items()}
            
            # Attack type by service
            attack_by_service = df.groupby(['service', 'attack_type']).size().reset_index()
            attack_by_service.columns = ['service', 'attack_type', 'count']
            attack_by_service_dict = {}
            
            for service in attack_by_service['service'].unique():
                service_data = attack_by_service[attack_by_service['service'] == service]
                attack_by_service_dict[service] = dict(zip(service_data['attack_type'], service_data['count']))
            
            # Detect anomalies
            anomaly_indices = self.detect_anomalies(logs_data)
            anomalies = []
            
            if anomaly_indices:
                anomaly_df = df.iloc[anomaly_indices]
                for _, row in anomaly_df.iterrows():
                    anomalies.append({
                        'timestamp': row['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                        'source_ip': row['source_ip'],
                        'service': row['service'],
                        'attack_type': row['attack_type'],
                        'reason': 'Unusual attack pattern detected by ML model'
                    })
            
            # Compile the report
            report = {
                'total_attacks': total_attacks,
                'unique_ips': unique_ips,
                'unique_attack_types': unique_attack_types,
                'top_attack_types': attack_type_counts,
                'top_attacker_ips': top_attacker_ips,
                'attacks_by_hour': attacks_by_hour,
                'attacks_by_day': attacks_by_day,
                'attack_by_service': attack_by_service_dict,
                'anomalies': anomalies,
                'generated_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            return report
        
        except Exception as e:
            logger.error(f"Error generating attack pattern report: {e}")
            return {'error': str(e)}
    
    def generate_visualizations(self, logs_data, output_dir='static/images'):
        """Generate visualizations for attack data.
        
        Args:
            logs_data (list): List of dictionaries containing attack logs
            output_dir (str): Directory to save visualization images
            
        Returns:
            dict: Paths to generated visualization images
        """
        try:
            logger.info("Generating visualizations...")
            
            # Create output directory if it doesn't exist
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Preprocess data
            df = self.preprocess_data(logs_data)
            
            # Set plot style
            plt.style.use('dark_background')
            sns.set_style("darkgrid")
            
            # Visualization 1: Attack types distribution
            plt.figure(figsize=(12, 8))
            attack_counts = df['attack_type'].value_counts().head(10)
            sns.barplot(x=attack_counts.values, y=attack_counts.index)
            plt.title('Top 10 Attack Types', fontsize=16)
            plt.xlabel('Number of Attacks', fontsize=12)
            plt.tight_layout()
            attack_types_path = os.path.join(output_dir, 'attack_types.png')
            plt.savefig(attack_types_path)
            plt.close()
            
            # Visualization 2: Attacks by hour
            plt.figure(figsize=(12, 6))
            hourly_attacks = df.groupby(df['timestamp'].dt.hour).size()
            sns.lineplot(x=hourly_attacks.index, y=hourly_attacks.values)
            plt.title('Attacks by Hour of Day', fontsize=16)
            plt.xlabel('Hour of Day', fontsize=12)
            plt.ylabel('Number of Attacks', fontsize=12)
            plt.xticks(range(0, 24))
            plt.tight_layout()
            hourly_path = os.path.join(output_dir, 'hourly_attacks.png')
            plt.savefig(hourly_path)
            plt.close()
            
            # Visualization 3: Attacks by service
            plt.figure(figsize=(12, 8))
            service_counts = df['service'].value_counts()
            sns.barplot(x=service_counts.values, y=service_counts.index)
            plt.title('Attacks by Service', fontsize=16)
            plt.xlabel('Number of Attacks', fontsize=12)
            plt.tight_layout()
            service_path = os.path.join(output_dir, 'service_attacks.png')
            plt.savefig(service_path)
            plt.close()
            
            # Visualization 4: Attack type by service heatmap
            plt.figure(figsize=(14, 10))
            attack_service_counts = pd.crosstab(df['attack_type'], df['service'])
            sns.heatmap(attack_service_counts, cmap='viridis', annot=False)
            plt.title('Attack Types by Service', fontsize=16)
            plt.tight_layout()
            heatmap_path = os.path.join(output_dir, 'attack_service_heatmap.png')
            plt.savefig(heatmap_path)
            plt.close()
            
            # Visualization 5: Time series of attacks
            plt.figure(figsize=(14, 6))
            df['date'] = df['timestamp'].dt.date
            daily_attacks = df.groupby('date').size()
            sns.lineplot(x=daily_attacks.index, y=daily_attacks.values)
            plt.title('Daily Attack Trend', fontsize=16)
            plt.xlabel('Date', fontsize=12)
            plt.ylabel('Number of Attacks', fontsize=12)
            plt.xticks(rotation=45)
            plt.tight_layout()
            trend_path = os.path.join(output_dir, 'attack_trend.png')
            plt.savefig(trend_path)
            plt.close()
            
            # Return paths to the generated visualizations
            visualization_paths = {
                'attack_types': attack_types_path,
                'hourly_attacks': hourly_path,
                'service_attacks': service_path,
                'attack_service_heatmap': heatmap_path,
                'attack_trend': trend_path
            }
            
            return visualization_paths
        
        except Exception as e:
            logger.error(f"Error generating visualizations: {e}")
            return {'error': str(e)}