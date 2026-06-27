import streamlit as st
import re
import pandas as pd
import gzip
from datetime import datetime

st.set_page_config(page_title="Infor LN Performance Dashboard", layout="wide")

st.title("⚡ Infor LN Deep Performance Analyzer")
st.markdown("Cloud-hosted standalone trace analysis tracking your custom script logic boundaries.")

# --- PARSING ENGINE MATCHING YOUR POWERSHELL SCHEMA ---
def parse_trace_powershell_logic(uploaded_file, min_duration_ms):
    stack = []  
    slow_calls = []
    line_count = 0
    
    # Exact mirror of your PowerShell Regex targets
    entry_pattern = re.compile(r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*?-->>\s+\(depth\s+\d+\):\s+(.*?)\((.*?)\)\s+\(in object\s+(.*?)\)')
    exit_pattern = re.compile(r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*?<<--\s+\(depth\s+\d+\):\s+(.*)')
    table_pattern = re.compile(r'"([^"]+)"')

    # Detect if file object is compressed Gzip or raw text
    is_gzip = uploaded_file.name.endswith('.gz')
    f = gzip.open(uploaded_file, mode='rt', encoding='utf-8', errors='ignore') if is_gzip else uploaded_file

    progress_text = st.empty()

    # Stream line by line safely from memory buffers
    for line in f:
        line_count += 1
        if line_count % 2000000 == 0:
            progress_text.text(f"⏳ Scanned {line_count / 10000000:.2f} Crore lines...")

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
                        duration_ms += 86400000  # Midnight wrap safety
                    
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

    progress_text.empty()
    return pd.DataFrame(slow_calls), line_count

# --- CLOUD-SAFE UI LOGIC INTERFACE ---
uploaded_file = st.file_uploader("📁 Upload Infor LN Trace File (.txt, .log, .gz)", type=["txt", "log", "gz"])

if uploaded_file is not None:
    threshold = st.slider("🎯 Filter out fast calls slower than (ms):", min_value=0, max_value=500, value=10)
    
    with st.spinner("Processing text streams through background cloud node containers..."):
        df_results, total_scanned = parse_trace_powershell_logic(uploaded_file, threshold)
        
    if total_scanned == 0:
        st.error("No compatible lines parsed. Check formatting.")
    else:
        st.subheader("📋 Performance Profile Summary")
        k1, k2 = st.columns(2)
        k1.metric("Total Lines Scanned", f"{total_scanned / 10000000:.2f} Crore")
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
