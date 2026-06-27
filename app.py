import streamlit as st
import re
import pandas as pd
import gzip
from datetime import datetime
import tkinter as tk
from tkinter import filedialog

st.set_page_config(page_title="Infor LN Performance Dashboard", layout="wide")

st.title("⚡ Infor LN Deep Performance Analyzer")
st.markdown("Displays your standalone trace analysis in the browser exactly matching your CSV report layout.")

# --- NATIVE FILE PICKER HELPER ---
def select_file_locally():
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    file_path = filedialog.askopenfilename(
        title="Select Infor LN Trace File",
        filetypes=[("Trace Files", "*.txt *.log *.gz"), ("All Files", "*.*")]
    )
    root.destroy()
    return file_path

# --- PARSING ENGINE MATCHING YOUR POWERSHELL SCHEMA ---
def parse_trace_powershell_logic(file_path, min_duration_ms):
    stack = []  
    slow_calls = []
    line_count = 0
    
    # Robust patterns configured to bypass formatting whitespace variances
    entry_pattern = re.compile(r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*?-->>\s+\(depth\s+\d+\):\s+(.*?)\((.*?)\)\s+\(in object\s+(.*?)\)')
    exit_pattern = re.compile(r'\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*?<<--\s+\(depth\s+\d+\):\s+(.*)')
    table_pattern = re.compile(r'"([^"]+)"')

    is_gzip = file_path.endswith('.gz')
    f = gzip.open(file_path, mode='rt', encoding='utf-8', errors='ignore') if is_gzip else open(file_path, mode='r', encoding='utf-8', errors='ignore')

    progress_text = st.empty()

    with f:
        for line in f:
            line_count += 1
            if line_count % 2000000 == 0:
                progress_text.text(f"⏳ Scanned {line_count / 10000000:.2f} Crore lines...")

            # Clean carriage returns/newlines upfront to safeguard greedy regex matches
            clean_line = line.strip()

            # 1. Match Entry Block (-->>)
            entry_match = entry_pattern.search(clean_line)
            if entry_match:
                time_part, func_name, params, obj_name = entry_match.groups()
                
                # Extract Table Name logic
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
                        
                        # Replicates your custom delay threshold filter condition
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

# --- INITIALIZE SESSION STATES ---
if 'file_path' not in st.session_state:
    st.session_state.file_path = None

# --- UI CONTROLS BAR LAYOUT ---
col_btn1, col_btn2, col_txt = st.columns([1.2, 1, 4])

with col_btn1:
    if st.button("📁 Select Log File", use_container_width=True):
        st.session_state.file_path = select_file_locally()

with col_btn2:
    # Clears active state and force-reboots the user workspace interface
    if st.button("🗑️ Clear File", type="secondary", use_container_width=True):
        st.session_state.file_path = None
        st.rerun()

with col_txt:
    if st.session_state.file_path:
        st.success(f"Active File: {st.session_state.file_path}")
    else:
        st.info("Select your trace file to execute the pipeline.")

st.markdown("---")

if st.session_state.file_path:
    threshold = st.slider("🎯 Filter out fast calls slower than (ms):", min_value=0, max_value=500, value=10)
    
    with st.spinner("Processing large text stream patterns line-by-line..."):
        df_results, total_scanned = parse_trace_powershell_logic(st.session_state.file_path, threshold)
        
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
                # Displays exact layout match columns matching your schema format rules
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