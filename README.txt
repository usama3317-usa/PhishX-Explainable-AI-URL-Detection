======================================================================
       PHISHX: EXPLAINABLE AI-DRIVEN REAL-TIME URL DETECTION
======================================================================

OVERVIEW
--------
Welcome to PhishX! This is an advanced, AI-powered cybersecurity 
tool designed to detect zero-day phishing links in real-time. 
Instead of relying on outdated static blacklists, PhishX uses a 
powerful Machine Learning engine combined with Explainable AI (XAI) 
to analyze the structural behavior of a URL and explain why it is 
dangerous.

THE PROBLEM WE SOLVED
---------------------
Modern cybercriminals use dynamic URLs and hide behind anti-bot 
protections like Cloudflare to trick traditional security systems. 
Furthermore, while most AI security tools act as a "Black-Box" 
(giving a warning without an explanation), security analysts need 
to know the reasoning behind a blocked link. 

PhishX solves this by providing a highly accurate machine learning 
model that explains its own decisions mathematically using SHAP.
Read our complete research and methodology: [https://drive.google.com/file/d/1S7AebcLwZbw0k5zgRc335a9sP3DcUJWR/view?usp=sharing]  (PhishX_Research_Report.pdf)
KEY FEATURES
------------
* Advanced ML Engine: A highly tuned Gradient Boosting classifier 
  trained on the modern PhiUSIIL dataset, achieving 98.7% accuracy. 
  The severe dataset imbalance was mathematically resolved using SMOTE.
* Explainable AI (SHAP Insights): Generates human-readable "Waterfall" 
  metrics for every URL, showing exactly which features increased or 
  decreased the phishing risk score.
* Real-Time Feature Extraction: Instantly scrapes and calculates 47 
  distinct structural and lexical features from any live URL.
* Anti-Evasion (WAF) Detection: Built-in logic to detect if a malicious 
  server is hiding behind Cloudflare or Captcha walls to trick the AI.
* Custom Interactive GUI Sandbox: A sleek, dark-themed local UI built 
  with Tkinter that allows users to test URLs and view risk scores.
* Enterprise Whitelisting: Automatically bypasses AI scanning for 
  trusted global domains to save computing resources.

TECHNOLOGY STACK
----------------
* Programming Language: Python 3.x
* Libraries & Frameworks: Scikit-Learn, Imbalanced-Learn (SMOTE), 
  Pandas, NumPy, Requests, urllib3, Joblib
* Explainable AI: SHAP (SHapley Additive exPlanations)
* Frontend GUI: Tkinter (Python Standard GUI)

HOW IT WORKS (THE PIPELINE)
---------------------------
1. Input: The user pastes a target URL into the PhishX Sandbox.
2. Ping & Whitelist Check: The system checks if the domain is globally 
   trusted. If not, it pings the server to ensure it is live.
3. Extraction: A custom Python script visits the URL and extracts 47 
   specific numerical features.
4. AI Inference: The extracted data is scaled and fed into our pre-trained 
   machine learning model.
5. Verdict & Explanation: The system returns a risk percentage and 
   triggers SHAP to print a detailed report.

INSTALLATION & SETUP
--------------------
1. Clone the Repository:
   https://github.com/usama3317-usa/PhishX-Explainable-AI-URL-Detection.git
   cd PhishX-Explainable-AI-URL-Detection

2. Install Dependencies:
   pip install scikit-learn shap pandas numpy requests joblib imbalanced-learn

3. Ensure Model Files are Present:
   Check that 'phishing_model.pkl' (the trained AI) and 'scaler.pkl' 
   (the data scaler) are in the same directory as your main script.

4. Run the Application:
   python gui_agent.py 

PROJECT CREATORS
----------------
This project was built as part of our Software Engineering, Data 
Science  & AI research at the University of South Asia, Lahore.

* Usama Rasheed (B-28739)
* Muhammed Subhan (B-28668)

Supervised by: Miss Rameesha Malik & Sir Taib Ali

5.Referene paper 
https://www.irasspublisher.com/assets/articles/1765195522.pdf

6.Dataset link 
https://drive.google.com/file/d/1FJ-7rdIVnmqnnyvf4hFcAAJZnjkdbr3E/view?usp=sharing
======================================================================
