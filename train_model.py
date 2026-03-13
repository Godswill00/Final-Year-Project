import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Load dataset
data = pd.read_csv("data/cicids2017_cleaned.csv")

# Separate features and target
X = data.drop("Attack Type", axis=1)
y = data["Attack Type"]

# Split dataset into training and testing parts
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Training data shape:", X_train.shape)
print("Testing data shape:", X_test.shape)

# Create model
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)

# Train model
print("Training model...")
model.fit(X_train, y_train)

# Predict
print("Making predictions...")
y_pred = model.predict(X_test)

# Evaluate
print("\nAccuracy:")
print(accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "model/intrusion_model.pkl")
print("\nModel saved successfully in model/intrusion_model.pkl")