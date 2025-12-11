import streamlit as st

st.set_page_config(page_title="CyberCyte - Home", layout="wide")

# Logo + Title
st.image("images/cybercyte_logo.png", width=750)
st.title("🛡️ CyberCyte: Autonomous Home Defense System")

# Intro section
st.subheader("Welcome to CyberCyte")
st.write("""
CyberCyte is an autonomous home defense and monitoring system designed to detect, 
analyze, and visualize security threats in real time.  
Navigate through the pages on the sidebar to explore live dashboards, 
incident reports, and system configurations.
""")

# Features overview
st.subheader("Key Features")
st.markdown("""
- 📊 **Real-time Dashboard** – Monitor live security events and trends  
- 🚨 **Incident Tracking** – Review detailed logs of security alerts  
- ⚙️ **System Settings** – Configure detection thresholds and integrations  
- 👥 **About** – Learn more about the team behind CyberCyte  
""")

# Call to action
st.success("Use the sidebar to navigate through the system.")
