import streamlit as st

st.title("About CyberCyte")

st.write("""
CyberCyte is a student-built **autonomous cyber defense project**.  
It integrates data collection, anomaly detection, explainable AI, 
and real-time dashboards to simulate home defense against cyber threats.
""")

st.subheader("Team")
st.markdown("""
- Data Collector Engineer  - Ashley Saunders
- Detector & Model Engineer - Theodora Ikeri
- API & Backend Developer - Zion Auguste
- Dashboard Developer - AuJanai Horton
- Agent & osquery Integrator - Bryson Faust
- Deployment & Lab Engineer - Mikala Mitchell
""")

st.info("Built for educational purposes, not for production deployment.")
