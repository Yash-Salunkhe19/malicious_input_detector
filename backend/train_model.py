import pandas as pd
import re
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report, accuracy_score


# ==========================================
# STEP 1: LOAD DATASET
# ==========================================

df = pd.read_csv("dataset.csv")

# Make sure columns are Query and Label
df.columns = ["Query", "Label"]


# ==========================================
# STEP 2: CLEAN DATA
# ==========================================

df.dropna(inplace=True)
df.drop_duplicates(inplace=True)


def clean_text(text):

    text = str(text).lower()

    # Keep letters, numbers and spaces
    text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)

    # Remove extra spaces
    text = re.sub(r"\s+", " ", text).strip()

    return text


df["Query"] = df["Query"].apply(clean_text)


# ==========================================
# STEP 3: CHECK DATASET
# ==========================================

print("\nDataset distribution:")
print(df["Label"].value_counts())

print("\nDataset:")
print(df.head())


# ==========================================
# STEP 4: SPLIT DATA
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    df["Query"],
    df["Label"],
    test_size=0.2,
    random_state=42,
    stratify=df["Label"]
)


# ==========================================
# STEP 5: TF-IDF
# ==========================================

vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    min_df=1,
    sublinear_tf=True
)

X_train_vectorized = vectorizer.fit_transform(X_train)

X_test_vectorized = vectorizer.transform(X_test)


# ==========================================
# STEP 6: TRAIN MODEL
# ==========================================

model = MultinomialNB()

model.fit(
    X_train_vectorized,
    y_train
)


# ==========================================
# STEP 7: TEST MODEL
# ==========================================

predictions = model.predict(
    X_test_vectorized
)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\n==============================")
print("MODEL RESULTS")
print("==============================")

print(
    "Accuracy:",
    round(accuracy * 100, 2),
    "%"
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions
    )
)


# ==========================================
# STEP 8: TEST NORMAL INPUTS
# ==========================================

test_inputs = [

    "hello world",

    "normal user login request",

    "my name is yash",

    "please check my account",

    "welcome to our website",

    "this is a normal API request"

]


test_cleaned = [
    clean_text(x)
    for x in test_inputs
]


test_vectors = vectorizer.transform(
    test_cleaned
)


test_predictions = model.predict(
    test_vectors
)


print("\n==============================")
print("NORMAL INPUT TEST")
print("==============================")


for text, prediction in zip(
    test_inputs,
    test_predictions
):

    print(
        f"{text} -> {prediction}"
    )


# ==========================================
# STEP 9: SAVE MODEL
# ==========================================

with open(
    "backend/trained_model.pkl",
    "wb"
) as f:

    pickle.dump(
        model,
        f
    )


with open(
    "backend/vectorizer.pkl",
    "wb"
) as f:

    pickle.dump(
        vectorizer,
        f
    )


print("\n================================")
print("MODEL SAVED SUCCESSFULLY")
print("================================")

print(
    "backend/trained_model.pkl"
)

print(
    "backend/vectorizer.pkl"
)

print(df["Label"].value_counts())