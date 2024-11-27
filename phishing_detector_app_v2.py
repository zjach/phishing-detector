import streamlit as st
import joblib
import pandas as pd
import re

# Load the trained model
model = joblib.load('phishing_detector_v2.pkl')  # Make sure this file exists in your project directory


# Define feature extraction function
def extract_features_from_url(url):
    """
    Extract features required for the phishing detection model.
    """
    features = {
        'having_IPhaving_IP_Address': 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0,
        'URLURL_Length': len(url),
        'Shortining_Service': 1 if 'bit.ly' in url or 'tinyurl' in url else 0,
        'having_At_Symbol': 1 if '@' in url else 0,
        'double_slash_redirecting': 1 if url.count('//') > 1 else 0,
        'Prefix_Suffix': 1 if '-' in url.split('//')[-1] else 0,
        'having_Sub_Domain': 1 if url.count('.') > 2 else 0,
        'SSLfinal_State': 2 if url.startswith('https://') else 0,
        'Domain_registeration_length': 12,  # Default value; replace with dynamic logic if available
        'Favicon': 1,  # Default value
        'port': 0,  # Default value; adjust if parsing for specific ports
        'HTTPS_token': 1 if 'https-' in url.lower() else 0,
        'Request_URL': 1,  # Default value
        'URL_of_Anchor': 0,  # Default value
        'Links_in_tags': 0,  # Default value
        'SFH': 1,  # Default value
        'Submitting_to_email': 1 if 'mailto:' in url else 0,
        'Abnormal_URL': 0,  # Default value
        'Redirect': 1 if url.count('//') > 2 else 0,
        'on_mouseover': 0,  # Default value
        'RightClick': 0,  # Default value
        'popUpWidnow': 0,  # Default value
        'Iframe': 0,  # Default value
        'age_of_domain': 6,  # Default value in months; replace with dynamic logic
        'DNSRecord': 1,  # Default value; replace with DNS lookup logic if required
        'web_traffic': 1,  # Default value; replace with dynamic traffic analysis
        'Page_Rank': 1,  # Default value
        'Google_Index': 1,  # Default value
        'Links_pointing_to_page': 0,  # Default value
        'Statistical_report': 0,  # Default value
    }
    return pd.DataFrame([features])


# Streamlit app
st.title("Phishing URL Detection")
st.write("""
This app predicts whether a URL is **phishing** or **legitimate** using a trained machine learning model.
Enter a URL below to check.
""")

# URL input from user
url = st.text_input("Enter a URL to test:")

# Prediction logic
if st.button("Predict"):
    if url:
        try:
            # Extract features from the input URL
            features = extract_features_from_url(url)
            st.write("Extracted Features (debugging):", features)  # Optional debugging output

            # Make prediction
            prediction = model.predict(features)[0]
            phishing_probability = model.predict_proba(features)[0][1]  # Get the probability of being phishing

            # Display result
            if prediction == 1:
                st.error(f"Warning: This URL is likely a Phishing URL! (Probability: {phishing_probability:.2f})")
                classification = "Phishing"
            else:
                st.success(f"This URL appears to be Legitimate. (Probability: {phishing_probability:.2f})")
                classification = "Legitimate"

            # Log predictions to a CSV file
            log_data = {
                "URL": url,
                "Phishing Probability": phishing_probability,
                "Classification": classification
            }
            log_df = pd.DataFrame([log_data])

            # Append to CSV
            log_df.to_csv('prediction_logs.csv', mode='a', header=False, index=False)

            st.write("Prediction logged successfully!")

        except Exception as e:
            st.error(f"Error processing URL: {e}")
    else:
        st.warning("Please enter a URL to test.")
