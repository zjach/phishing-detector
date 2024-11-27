import streamlit as st
import joblib
import pandas as pd
import requests
import re

# Load the trained model
model = joblib.load('phishing_detector_v2.pkl')  # Ensure this file exists

# Google Safe Browsing API Key (replace with your API key)
GOOGLE_API_KEY = "AIzaSyBjH1COOcM0iZQM_WKpt8xwO41atpbL648"  # Replace with your actual API key
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


# Define feature extraction function
def extract_features_from_url(url):
    features = {
        'having_IPhaving_IP_Address': 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0,
        'URLURL_Length': len(url),
        'Shortining_Service': 1 if 'bit.ly' in url or 'tinyurl' in url else 0,
        'having_At_Symbol': 1 if '@' in url else 0,
        'double_slash_redirecting': 1 if url.count('//') > 1 else 0,
        'Prefix_Suffix': 1 if '-' in url.split('//')[-1] else 0,
        'having_Sub_Domain': 1 if url.count('.') > 2 else 0,
        'SSLfinal_State': 2 if url.startswith('https://') else 0,
        'Domain_registeration_length': 12,
        'Favicon': 1,
        'port': 0,
        'HTTPS_token': 1 if 'https-' in url.lower() else 0,
        'Request_URL': 1,
        'URL_of_Anchor': 0,
        'Links_in_tags': 0,
        'SFH': 1,
        'Submitting_to_email': 1 if 'mailto:' in url else 0,
        'Abnormal_URL': 0,
        'Redirect': 1 if url.count('//') > 2 else 0,
        'on_mouseover': 0,
        'RightClick': 0,
        'popUpWidnow': 0,
        'Iframe': 0,
        'age_of_domain': 6,
        'DNSRecord': 1,
        'web_traffic': 1,
        'Page_Rank': 1,
        'Google_Index': 1,
        'Links_pointing_to_page': 0,
        'Statistical_report': 0,
    }
    return pd.DataFrame([features])


# Function to check URL with Google Safe Browsing API
def check_google_safe_browsing(url):
    payload = {
        "client": {
            "clientId": "streamlit-app",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": GOOGLE_API_KEY},
            json=payload,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("matches"):
                return True  # URL flagged as a threat
        return False
    except Exception as e:
        st.error(f"Google Safe Browsing API error: {e}")
        return False


# Streamlit app
st.title("Phishing URL Detection with Database Check")
st.write("""
This app predicts whether a URL is **phishing** or **legitimate** and cross-checks it with the Google Safe Browsing database.
Enter a URL below to check.
""")

# URL input from user
url = st.text_input("Enter a URL to test:")

# Prediction logic
if st.button("Predict"):
    if url:
        try:
            # Check URL with Google Safe Browsing
            is_flagged = check_google_safe_browsing(url)
            google_result = "Flagged as Phishing (Google)" if is_flagged else "Not Flagged (Google)"

            # Extract features and make a model prediction
            features = extract_features_from_url(url)
            prediction = model.predict(features)[0]
            ml_result = "Phishing (ML Model)" if prediction == 1 else "Legitimate (ML Model)"

            # Display both results
            st.subheader("Google Safe Browsing Result")
            if is_flagged:
                st.error(google_result)
            else:
                st.success(google_result)

            st.subheader("Machine Learning Model Result")
            if prediction == 1:
                st.warning(ml_result)
            else:
                st.success(ml_result)

        except Exception as e:
            st.error(f"Error processing URL: {e}")
    else:
        st.warning("Please enter a URL to test.")
