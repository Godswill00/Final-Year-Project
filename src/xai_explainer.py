import shap
import joblib
import pandas as pd

MODEL_PATH = "model/intrusion_model.pkl"

model = joblib.load(MODEL_PATH)

explainer = shap.TreeExplainer(model)

def explain_prediction(feature_df):

    shap_values = explainer.shap_values(feature_df)

    explanation = []

    feature_names = feature_df.columns

    for i, value in enumerate(shap_values[0]):
        explanation.append((feature_names[i], value))

    explanation.sort(key=lambda x: abs(x[1]), reverse=True)

    return explanation[:5]