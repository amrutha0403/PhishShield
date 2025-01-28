import hashlib
import joblib
import requests
import os
from flask import Flask, render_template, request, make_response, redirect
from flask_caching import Cache
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
csrf = CSRFProtect(app)

# Configure Flask-Caching to use on-disk caching
cache_dir = os.path.join(app.root_path, '.cache')
cache = Cache(app, config={'CACHE_TYPE': 'filesystem', 'CACHE_DIR': cache_dir})

# Loading the trained models
try:
    text_model = joblib.load("models/text_model.joblib")
    feature_model = joblib.load("models/feature_model.joblib")
except FileNotFoundError as e:
    raise RuntimeError(f"Model file missing: {e}")

# Configure reCAPTCHA keys
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")


@app.route('/verify_recaptcha', methods=['GET', 'POST'])
@csrf.exempt
def verify_recaptcha():
    if request.method == 'POST':
        token = request.form.get('g-recaptcha-response')
        if not token:
            return render_template('verification.html', error='Please complete the reCAPTCHA.')
        
        # Verify reCAPTCHA token with Google
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': RECAPTCHA_SECRET_KEY,
                'response': token
            }
        )

        if response.ok:
            result = response.json()
            if 'success' in result and result.get('success'):
                # reCAPTCHA verification successful, set a cookie to indicate verification
                resp = make_response(redirect('/'))
                resp.set_cookie('recaptcha_verified', 'true')
                return resp
            else:
                return render_template('verification.html', error='reCAPTCHA verification failed.')
        else:
            return render_template('verification.html', error='Failed to verify reCAPTCHA. Please try again later.')

    return render_template('verification.html', RECAPTCHA_SITE_KEY=RECAPTCHA_SITE_KEY)


@app.route('/', methods=['GET','POST'])
@csrf.exempt
def detect_phishing():
    if request.cookies.get('recaptcha_verified') == 'true':
        if request.method == 'POST':
            url = request.form["url"]  # Getting URL from the form data
            
            # Use a hashed key for caching to ensure unique and safe keys
            cache_key = hashlib.sha256(url.encode()).hexdigest()
            
            cached_result = cache.get(cache_key)
            if cached_result:
                return cached_result

            # Make predictions
            feature_pred = feature_model.predict([url])[0]
            text_pred = text_model.predict([url])[0]

            try:
                # Get probabilities if supported
                feature_confidence = feature_model.predict_proba([url])
                text_confidence = text_model.predict_proba([url])
            except AttributeError:
                feature_confidence = [[1 - feature_pred, feature_pred]]
                text_confidence = [[1 - text_pred, text_pred]]

            # Extract phishing and legitimate confidence scores
            confidence_phishing_feature = feature_confidence[0][0]
            confidence_legitimate_feature = feature_confidence[0][1]
            confidence_phishing_text = text_confidence[0][0]
            confidence_legitimate_text = text_confidence[0][1]

            # Weighted decision
            weight_feature = 0.6
            weight_text = 0.4
            combined_confidence_phishing = (weight_feature * confidence_phishing_feature) + (weight_text * confidence_phishing_text)
            combined_confidence_legitimate = (weight_feature * confidence_legitimate_feature) + (weight_text * confidence_legitimate_text)

            final_pred = -1 if combined_confidence_phishing > combined_confidence_legitimate else 1
            result = "Phishing" if final_pred == -1 else "Legitimate"

            # Cache result and render
            rendered = render_template('index.html', url=url, result=result)
            cache.set(cache_key, rendered, timeout=3600)  # Cache for 1 hour
            return rendered
        else:
            return render_template('index.html')
    else:
        return redirect('/verify_recaptcha')


if __name__ == '__main__':
    app.run(debug=True)
