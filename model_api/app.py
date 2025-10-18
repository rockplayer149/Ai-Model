from flask import Flask, request, jsonify
from flask_cors import CORS
from llama_cpp import Llama

# --- CONFIGURE THIS ---
# Ensure this is the exact filename of your local .gguf model.
MODEL_PATH = "deepseek-coder-6.7b-instruct.Q4_K_M.gguf"
# -------------------------

app = Flask(__name__)
CORS(app)

print(f"Loading GGUF model from: {MODEL_PATH}")
llm = Llama(model_path=MODEL_PATH, n_ctx=2048, n_gpu_layers=0, verbose=False)
print("✅ GGUF Model loaded successfully!")


def classify_email_text(text_to_analyze):
    """
    Analyzes email text using a prompt tailored to the model's training data.
    """
    # --- MODIFICATION START: The prompt now uses the model's actual labels ---
    messages = [
        {
            "role": "system",
            "content": "You are an expert cybersecurity analyst. Classify the user's email content as either 'legitimate_email' or 'phishing_email'. Respond with only the label.",
        },
        {"role": "user", "content": text_to_analyze},
    ]
    # --- MODIFICATION END ---

    try:
        completion = llm.create_chat_completion(messages=messages, max_tokens=10)
        model_output = completion['choices'][0]['message']['content'].lower().strip()
        
        # --- MODIFICATION START: Translate the model's output to our application's labels ---
        if "phishing_email" in model_output:
            return "spam"  # Translate to 'spam'
        if "legitimate_email" in model_output:
            return "ham"   # Translate to 'ham'
        
        print(f"Warning: Model returned an unexpected label: '{model_output}'")
        return "unknown"
        # --- MODIFICATION END ---

    except (KeyError, IndexError, Exception) as e:
        print(f"Error during model inference: {e}")
        return "unknown"

@app.route("/predict", methods=["POST"])
def predict():
    if not request.json or 'text' not in request.json:
        return jsonify({"error": "Missing 'text' field in request"}), 400
    
    text = request.json['text']
    if not text:
        return jsonify({"verdict": "ham", "confidence": 1.0}), 200

    try:
        verdict = classify_email_text(text)
        return jsonify({"verdict": verdict, "confidence": 0.95})
    except Exception as e:
        print(f"An error occurred during prediction: {e}")
        return jsonify({"error": "Failed to get a prediction from the model."}), 500

if __name__ == "__main__":
    print("Starting Flask server for GGUF model...")
    app.run(host="0.0.0.0", port=5001)

