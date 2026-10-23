# Zero Trust Assurance Console — Compatibility Fallback

This version preserves the formal Streamlit interface and uses a transparent rule-based behavioural scoring heuristic instead of scikit-learn, because Windows Application Control blocked a compiled scikit-learn component on the original setup.

## Run

```powershell
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open the local URL printed by Streamlit, usually http://localhost:8501.

## Important limitation

This is a rule-based demonstration, not an Isolation Forest model and not an IoT-23 evaluation. It does not capture live network traffic or enforce access controls. The scoring rules are illustrative and must not be reported as validated model performance. The original research approach can be restored once scikit-learn is usable in an approved environment.
