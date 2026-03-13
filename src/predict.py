import pandas as pd
import joblib

# Load trained model
model = joblib.load("model/intrusion_model.pkl")

# Example: load some network traffic to test
data = pd.read_csv("data/cicids2017_cleaned.csv")

# Take one sample
sample = data.drop("Attack Type", axis=1).iloc[0:1]

# Predict
prediction = model.predict(sample)

print("Predicted attack type:", prediction[0])