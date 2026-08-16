import streamlit as st
import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import joblib

# 1. Load the model from memory cache
@st.cache_resource
def load_model():
    return joblib.load("phishing_pipeline.joblib")

pipeline = load_model()

# List of feature names in the exact order they are extracted
FEATURE_NAMES = [
    "URL Length", "Hostname Length", "Path Length",
    "Dot Count (.)", "Hyphen Count (-)", "At Count (@)", 
    "Question Count (?)", "Equal Count (=)", "Underscore Count (_)", 
    "Slash Count (/", "Percent Count (%)", "Ampersand Count (&)", 
    "Plus Count (+)", "Exclamation Count (!)", "Dollar Count ($)",
    "URL Digits", "URL Letters", "Hostname Digits", 
    "Contains IP Pattern", "Hostname Dot Count", "Contains mailto",
    "Keyword: login", "Keyword: verify", "Keyword: bank", 
    "Keyword: secure", "Keyword: update", "Keyword: signin", 
    "Keyword: account", "Keyword: free", "Keyword: bonus", 
    "Keyword: paypal", "Keyword: amazon", "Keyword: ebay"
]

def extract_features(url: str) -> list:
    features = []
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc if parsed_url.netloc else ""
    path = parsed_url.path

    # Structural Lengths
    features.append(len(url))
    features.append(len(hostname))
    features.append(len(path))

    # Character count
    s = ['.', '-', '@', '?', '=', '_', '/', '%', '&', '+', '!', '$']
    for i in s:
        features.append(url.count(i))

    # Content analysis
    features.append(sum(c.isdigit() for c in url))
    features.append(sum(c.isalpha() for c in url))
    features.append(sum(c.isdigit() for c in hostname))

    # FIXED REGEX: Re-inserted missing '[01]' boundaries to prevent silent engine failure
    ip_pattern = re.compile(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])')

    features.append(1 if ip_pattern.search(url) else 0)
    features.append(hostname.count('.'))
    features.append(1 if "mailto" in url else 0)

    # Keyword Indicators
    keywords = ['login', 'verify', 'bank', 'secure', 'update', 'signin', 'account', 'free', 'bonus', 'paypal', 'amazon', 'ebay']
    url_lower = url.lower()
    for keyword in keywords:
        features.append(1 if keyword in url_lower else 0)
        
    return features

# --- Streamlit UI Interface Configuration ---
st.set_page_config(page_title="Phishing Detector", page_icon="🔒", layout="centered")
st.title("🔒 Phishing URL Detector")
st.write("An intelligent ensemble machine learning application to flag malicious hyperlinks.")

url_input = st.text_input("Enter the URL to analyze:", placeholder="https://example.com")

if st.button("Predict Status", type="primary"):
    if url_input.strip():
        target_url = url_input.strip()
        
        # 1. Extract features (always outputs exactly 33 numeric variables)
        features = extract_features(target_url)
        features_array = np.array(features).reshape(1, -1)
        
        try:
            # 2. Run Inference
            prediction = pipeline.predict(features_array)
            
            if hasattr(pipeline, "predict_proba"):
                probabilities = pipeline.get_params # Placeholder check logic
                probabilities = pipeline.predict_proba(features_array)[0]
                phishing_prob = probabilities[1] * 100
                safe_prob = probabilities[0] * 100
            else:
                phishing_prob = 100.0 if prediction[0] == 1 else 0.0
                safe_prob = 100.0 if prediction[0] == 0 else 0.0

            st.write("---")
            
            # 3. Render visual prediction results
            if prediction[0] == 1:
                st.error("⚠️ **Warning: High Risk Link Detected!**")
                st.metric(label="Phishing Probability", value=f"{phishing_prob:.2f}%")
            else:
                st.success("✅ **Safe: Low Risk Link Detected**")
                st.metric(label="Legitimate Probability", value=f"{safe_prob:.2f}%")
                
            # 4. Feature Importance Visualization Section
            st.write("---")
            st.subheader("📊 Global Model Feature Importance")
            st.write("The chart below illustrates which structural elements have the highest predictive weight across the entire model.")

            # Attempt to extract feature importances from different pipeline structures
            importances = None
            
            # If it's a raw estimator
            if hasattr(pipeline, "feature_importances_"):
                importances = pipeline.feature_importances_
            # If it's a Scikit-Learn Pipeline object with a final estimator step named 'model' or 'classifier'
            elif hasattr(pipeline, "named_steps"):
                final_step = list(pipeline.named_steps.values())[-1]
                if hasattr(final_step, "feature_importances_"):
                    importances = final_step.feature_importances_

            if importances is not None:
                # Build and sort the importance DataFrame
                importance_df = pd.DataFrame({
                    "Feature": FEATURE_NAMES[:len(importances)], # Safeguard bounds
                    "Importance": importances
                }).sort_values(by="Importance", ascending=True)

                # Render horizontal bar chart (Top 15 most important features for layout neatness)
                top_features = importance_df.tail(15)
                
                st.bar_chart(
                    top_features, 
                    x="Importance", 
                    y="Feature", 
                    horizontal=True,
                    use_container_width=True
                )
            else:
                st.info("ℹ️ Feature importance data could not be extracted automatically. Ensure your pipeline's final estimator supports `feature_importances_` (e.g., Random Forest or Gradient Boosting).")
                
        except Exception as e:
            st.error(f"Error executing machine learning pipeline: {e}")
            
    else:
        st.warning("Please type or paste a complete URL address inside the text field.")
