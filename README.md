#  Phishing URL Classifier

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)][https://phishing-classifier-qmtthgqsrfy52vf2hqfece.streamlit.app/]
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An end-to-end Machine Learning web application that analyzes URLs in real time to detect phishing threats and malicious links using ensemble classification models.

[**Click Here to Open Live Streamlit App** ][https://phishing-classifier-qmtthgqsrfy52vf2hqfece.streamlit.app/]

---

##  Project Overview

Phishing attacks often rely on subtle structural manipulations in URLs (e.g., brand spoofing, ip-based hosts, excessive subdomains, or suspicious keywords). This app extracts key security features directly from an input URL and evaluates the risk score using a trained machine learning pipeline.

---

##  Key Features

* **Real-time Feature Extraction:** Automatically parses structural signals such as IP address patterns, special character counts (`@`, `?`, `=`, `-`), domain depth, and high-risk keywords (`login`, `verify`, `bank`, `secure`).
* **Ensemble Classification:** Combines **XGBoost**, **Random Forest**, and **K-Nearest Neighbors (KNN)** to predict phishing probability.
* **Interactive UI:** Built with Streamlit for quick, intuitive risk assessments and visual metric outputs.

---

##  Repository Structure

```text
├── app2.py                              # Active Streamlit web application script
├── main_model_with_xgb_rf_knn.joblib    # Pre-trained model pipeline weights
├── requirements.txt                     # Project dependencies
├── src/                                 # Feature extraction pipeline logic
├── static/                              # Static UI assets
└── README.md                            # Project documentation
