import streamlit as st
import re
import pandas as pd
import gzip
import io
from datetime import datetime

st.set_page_config(page_title="Infor LN Performance Dashboard", layout="wide")

st.title("⚡ Infor LN Deep Performance Analyzer")
st.markdown("Cloud-hosted standalone trace analysis. Streaming lines via low-memory chunk structures.")

# --- CACHED PARSING FUNCTION (Low-Memory Stream Optimization) ---
@st.cache_data(show_spinner=False)
def parse_trace_powershell_logic(file_bytes, file_name, min_duration_ms):
    stack = []  
    slow_calls = []
    line_count = 0
    
    # Exact mirror of your PowerShell Regex targets
    entry_pattern = re.compile(r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*?-->>\s+\(depth\s+\d+\):\s+(.*?)\((.*?)\)\s+\(in object\s+(.*?)\)')
    exit_pattern = re.compile(r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*?<<--\s+\(depth\s+\d+\):\s+(.*)')
    table_pattern = re.compile(r'"([^"]+)"')

    # Stream line by line using an memory-optimized wrapper stream
    if file_name.endswith('.gz'):
        f = gzip.open(file_bytes, mode='rt', encoding='utf-8', errors='ignore')
    else:
        # Crucial Fix: Wraps binary data object safely into an on-demand generator text reader line by line
        f = io.TextIOWrapper(file_bytes, encoding='utf-8', errors='ignore')

    try:
        for line in f:
            line_count += 1
            clean_line = line.strip()

            # 1. Match Entry Block (-->>)
            entry_match = entry_pattern.search(clean_line)
            if entry_match:
                time_part, func_name, params, obj_name = entry_match.groups()
                
                table_name = "N/A"
                table_match = table_pattern.search(params)
                if table_match and table_match.group(1).strip():
                    table_name = table_match.group(1).strip()
                elif "whinh" in params or "ttadv" in params:
                    words = re.findall(r'[a-z]{5}\d{3}', params)
                    if words: table_name = words[0]
                
                try:
                    start_time = datetime.strptime(time_part, "%H:%M:%S.%f")
                    stack.append({
                        "Name": func_name.strip(),
                        "Table": table_name,
                        "Start": start_time,
                        "Object": obj_name.strip(),
                        "StartTimeStr": time_part
                    })
                except ValueError:
                    pass
                continue

            # 2. Match Exit Block (<<--)
            exit_match = exit_pattern.search(clean_line)
            if exit_match:
                if stack:  
                    time_part = exit_match.group(1)
                    pop_info = stack.pop()
                    
                    try:
                        end_time = datetime.strptime(time_part, "%H:%M:%S.%f")
                        duration_ms = (end_time - pop_info["Start"]).total_seconds() * 1000
                        
                        if duration_ms < 0:
                            duration_ms += 86400000  # Midnight safety wrap
                        
                        if duration_ms > min_duration_ms:
                            slow_calls.append({
                                "Line": line_count,
                                "FunctionName": pop_info["Name"],
                                "TableName": pop_info["Table"],
                                "Duration_MS": round(duration_ms, 2),
                                "ExecutingObject": pop_info["Object"]
                            })
                    except ValueError:
                        pass
    finally:
        # Always safeguard resources by closing streams when calculations exit
        if not file_name.endswith('.gz'):
            f.detach()

    return pd.DataFrame(slow_calls), line_count

# --- INITIALIZE SESSION TRACKING STATE NODES ---
if 'processed' not in st.session_state:
    st.session_state.processed = False
if 'df_results' not in st.session_state:
    st.session_state.df_results = None
if 'total_scanned' not in st.session_state:
    st.session_state.total_scanned = 0

def reset_app_state():
    st.cache_data.clear()  
    st.session_state.processed = False
    st.session_state.df_results = None
    st.session_state.total_scanned = 0

# UI configurations
uploaded_file = st.file_uploader("📁 Upload Infor LN Trace File (.txt, .log, .gz)", type=["txt", "log", "gz"])

col_scan, col_clear, _ = st.columns([1, 1, 4])

with col_clear:
    if st.button("🗑️ Reset and Clear Data", type="secondary", use_container_width=True, on_click=reset_app_state):
        st.rerun()

if uploaded_file is not None:
    threshold = st.slider("🎯 Filter out fast calls slower than (ms):", min_value=0, max_value=500, value=10)
    
    with col_scan:
        if st.button("🚀 Analyze Log Trace", type="primary", use_container_width=True) or st.session_state.processed:
            
            if not st.session_state.processed:
                with st.spinner("Streaming trace contents into background container blocks..."):
                    df_res, scanned = parse_trace_powershell_logic(uploaded_file, uploaded_file.name, threshold)
                    st.session_state.df_results = df_res
                    st.session_state.total_scanned = scanned
                    st.session_state.processed = True
            
            df_results = st.session_state.df_results
            total_scanned = st.session_state.total_scanned

            if total_scanned == 0:
                st.error("No compatible lines parsed. Check formatting.")
            else:
                st.subheader("📋 Performance Profile Summary")
                k1, k2 = st.columns(2)
                k1.metric("Total Lines Scanned", f"{total_scanned:,}")
                k2.metric(f"Slow Calls Captured (>{threshold}ms)", f"{len(df_results):,}")
                
                st.markdown("---")
                
                if not df_results.empty:
                    tab1, tab2 = st.tabs(["🔍 Interactive Data Browser Grid", "📊 Aggregated Table Analysis Summary"])
                    
                    with tab1:
                        st.subheader("Raw Performance Trace Stream")
                        st.dataframe(df_results[["FunctionName", "TableName", "Duration_MS", "ExecutingObject"]].head(10000), use_container_width=True)
                        
                    with tab2:
                        st.subheader("Loop & Frequency Bottleneck Matrix")
                        agg_df = df_results.groupby(["FunctionName", "TableName"]).agg(
                            Executions=("Duration_MS", "count"),
                            Total_Duration_MS=("Duration_MS", "sum")
                        ).reset_index().sort_values(by="Total_Duration_MS", ascending=False)
                        
                        st.dataframe(agg_df, use_container_width=True)
                else:
                    st.success("Analysis complete. No slow operations detected past your filter conditions.")
else:
    reset_app_state()
