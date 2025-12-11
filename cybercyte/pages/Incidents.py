import streamlit as st
import pandas as pd

st.title("🚨 Incident Logs 🚨 ")

@st.cache_data
def load_data():
    return pd.read_csv("security_events.csv", parse_dates=["timestamp"])

df = load_data()

# Filters
event_type = st.selectbox("Filter by Event Type", options=["All"] + df["event_type"].unique().tolist())
if event_type != "All":
    df = df[df["event_type"] == event_type]

# Show table
st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True)
