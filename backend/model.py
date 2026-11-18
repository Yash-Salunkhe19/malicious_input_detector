import pickle

# Load model and vectorizer
with open("backend/trained_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("backend/vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)


def predict_text(text):
    vector = vectorizer.transform([text])
    prediction = model.predict(vector)[0]
    return "Malicious" if prediction == 1 else "Normal"