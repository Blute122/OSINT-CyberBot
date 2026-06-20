import streamlit as st
import pandas as pd
import json
import plotly.express as px

# Configure the page
st.set_page_config(page_title="Threat Intelligence Dashboard", layout="wide")
st.title("🛡️ Automated Threat Intelligence & Vulnerability Dashboard")
st.markdown("Aggregating live cybersecurity threats, zero-days, and CVEs directly from RSS feeds using LLM extraction and NVD API enrichment.")

# Load the JSON database
@st.cache_data(ttl=300) # Refreshes every 5 minutes
def load_data():
    try:
        with open("database.json", "r") as f:
            data = json.load(f)
        return pd.DataFrame(data)
    except Exception as e:
        return pd.DataFrame()

df = load_data()

if df.empty:
    st.warning("No threat data found yet. The database is empty.")
else:
    # Clean the data
    df['date'] = pd.to_datetime(df['date'])
    
    # Dynamically extract the severity based on the color indicators we engineered
    def get_severity(text):
        if "🔴" in text: return "Critical"
        if "🟠" in text: return "High"
        if "🟡" in text: return "Medium"
        if "🟢" in text: return "Low"
        return "Unknown"
        
    df['Severity'] = df['content'].apply(get_severity)

    # Top Level Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Threats Tracked", len(df))
    col2.metric("Critical/High Vulnerabilities", len(df[df['Severity'].isin(['Critical', 'High'])]))
    col3.metric("Latest Intelligence", df['date'].max().strftime("%Y-%m-%d %H:%M"))

    kev_count = df['url'].apply(lambda u: False).sum()  # placeholder, see note below
    if 'kev' in df.columns:
        kev_count = df['kev'].fillna(False).sum()
        st.metric("🚨 Actively Exploited (KEV)", int(kev_count))

    st.divider()

    # Data Visualization: Pie Chart
    col_chart, col_data = st.columns([1, 2])
    
    with col_chart:
        st.subheader("Severity Distribution")
        # Map colors exactly to our threat levels
        color_map = {'Critical':'#ff4b4b', 'High':'#ff9f36', 'Medium':'#ffe234', 'Low':'#33ff57', 'Unknown':'#808080'}
        fig = px.pie(df, names='Severity', color='Severity', color_discrete_map=color_map, hole=0.4)
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    # Interactive Search and Database
    with col_data:
        st.subheader("Live Threat Feed")
        search = st.text_input("🔍 Search threats (e.g., Linux, Microsoft, CVE-2026...)")
        
        if search:
            # Filter the dataframe based on the search query
            filtered_df = df[df['content'].str.contains(search, case=False, na=False)]
        else:
            filtered_df = df
            
        kev_only = st.checkbox("Show only CISA KEV (actively exploited)")
        if kev_only and 'kev' in df.columns:
            filtered_df = filtered_df[filtered_df['kev'] == True]
            
        # Display the data cleanly
        st.dataframe(
            filtered_df[['date', 'Severity', 'content', 'url']], 
            use_container_width=True,
            hide_index=True,
            height=400
        )
