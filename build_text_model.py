import pandas as pd
from sklearn import metrics
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.feature_extraction.text import CountVectorizer
from preprocessing.preprocess_url import URLPreprocessor
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn import metrics
import joblib
import warnings
from imblearn.under_sampling import RandomUnderSampler
warnings.filterwarnings('ignore')

# Load the dataset
def load_data(file_path):
    df = pd.read_csv(file_path)
    X = df['url']
    y = df['status']
    return X, y

# Split the dataset into training and testing sets
def split_data(X, y, test_size=0.2, random_state=42):
    return train_test_split(X, y, test_size=test_size, random_state=random_state)

# Define parameter grids for GridSearchCV
param_grids = {
    "Logistic Regression": {'solver': ['liblinear'], 'penalty': ['l1', 'l2'], 'C': [0.01, 0.1, 1.0, 10, 20]},
    "Multinomial Naive Bayes": {'alpha': [0.1, 1.0, 10]}
}

# Function to train and evaluate a model
def train_evaluate_model(name, pipeline, X_train, X_test, y_train, y_test):
    pipeline.fit(X_train, y_train)
    best_classifier = pipeline.named_steps['classifier'].best_estimator_
    print(f"GridSearchCV results for {name}:")
    print("Best parameters found:")
    print(best_classifier.get_params())
    y_train_pred = pipeline.predict(X_train)
    y_test_pred = pipeline.predict(X_test)
    acc_train = metrics.accuracy_score(y_train, y_train_pred)
    acc_test = metrics.accuracy_score(y_test, y_test_pred)
    f1_train = metrics.f1_score(y_train, y_train_pred)
    f1_test = metrics.f1_score(y_test, y_test_pred)
    recall_train = metrics.recall_score(y_train, y_train_pred)
    recall_test = metrics.recall_score(y_test, y_test_pred)
    precision_train = metrics.precision_score(y_train, y_train_pred)
    precision_test = metrics.precision_score(y_test, y_test_pred)
    return acc_train, acc_test, f1_train, f1_test, recall_train, recall_test, precision_train, precision_test


def store_results(ML_Model, accuracy_train, accuracy_test, f1_score_train, f1_score_test, recall_train, recall_test, precision_train, precision_test):
    results = {"ML Model": ML_Model, "Accuracy (Train)": accuracy_train, "Accuracy (Test)": accuracy_test, "F1 Score (Train)": f1_score_train, "F1 Score (Test)": f1_score_test, "Recall (Train)": recall_train, "Recall (Test)": recall_test, "Precision (Train)": precision_train, "Precision (Test)": precision_test}
    return results

def main():
    # Load data
    X, y = load_data('datafiles/dataset_for_text_model.csv')

    # Split data
    X_train, X_test, y_train, y_test = split_data(X, y)

    # Define pipeline for each classifier
    classifiers = {
        "Logistic Regression": Pipeline([
            ('preprocessor', URLPreprocessor()),
            ('vectorizer', CountVectorizer(tokenizer=None, stop_words=None, lowercase=False, ngram_range=(1, 2))),
            ('classifier', GridSearchCV(LogisticRegression(), param_grids["Logistic Regression"], cv=5, scoring='f1'))
        ]),
        "Multinomial Naive Bayes": Pipeline([
            ('preprocessor', URLPreprocessor()),
            ('vectorizer', CountVectorizer(tokenizer=None, stop_words=None, lowercase=False, ngram_range=(1, 2))),
            ('classifier', GridSearchCV(MultinomialNB(), param_grids["Multinomial Naive Bayes"], cv=5, n_jobs=-1, scoring='f1'))
        ])
    }

    best_model = None
    best_f1_score = 0
    best_model_name = ""

    # Train and evaluate models
    results = []
    for name, model in classifiers.items():
        acc_train, acc_test, f1_train, f1_test, recall_train, recall_test, precision_train, precision_test = train_evaluate_model(name, model, X_train, X_test, y_train, y_test)
        if f1_test > best_f1_score:
            best_f1_score = f1_test
            best_model = model
            best_model_name = name
        results.append(store_results(name, acc_train, acc_test, f1_train, f1_test, recall_train, recall_test, precision_train, precision_test))

        # Generate classification report
        y_test_pred = model.predict(X_test)
        print(f"Classification Report for {name}:")
        print(metrics.classification_report(y_test, y_test_pred, target_names=('Phishing', 'Legitimate')))


    # Save the best model
    if best_model is not None:
        joblib.dump(best_model, 'models/text_model.joblib')
        print(f"Best performing model saved as 'text_model.joblib'. Classifier: {best_model_name}, with f1-Score: {best_f1_score}")

    # Display results
    results_df = pd.DataFrame(results)
    sorted_results = results_df.sort_values(by=['Accuracy (Test)', 'F1 Score (Test)'], ascending=False).reset_index(drop=True)
    print(sorted_results)


if __name__ == "__main__":
    main()
