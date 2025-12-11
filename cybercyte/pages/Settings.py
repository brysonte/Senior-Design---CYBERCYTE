import streamlit as st

st.title("⚙️ System Settings")

st.subheader("General")
st.text_input("System Name", "CyberCyte")

st.subheader("Detection Thresholds")
st.slider("Anomaly Sensitivity", min_value=1, max_value=10, value=5)

st.subheader("Integrations")
st.text_input("API Key", type="password")

st.success("Settings can be expanded later to match backend configs.")
