import streamlit as st
import json
import os
import zipfile
from io import BytesIO
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import subprocess
import re

from parser.log_parser import LogParser
from detector.attack_detector import AttackDetector
from generator.replay_generator import ReplayGenerator
from database.db_manager import DatabaseManager
from batch.batch_processor import BatchProcessor

st.set_page_config(
    page_title="Smart Web Attack Replay Generator",
    page_icon="🔐",
    layout="wide"
)

if 'db_manager' not in st.session_state:
    try:
        st.session_state['db_manager'] = DatabaseManager()
    except Exception:
        st.session_state['db_manager'] = None

db = st.session_state['db_manager']
db_available = db is not None and db.db_available if db else False

st.title("🔐 Smart Web Application Attack Replay Generator")
st.markdown("**Advanced log analysis, attack detection, pattern learning, and automated replay testing**")

st.markdown("---")

with st.sidebar:
    st.header("📋 About")
    st.markdown("""
    **Advanced Features:**
    - Pattern Learning & Unknown Attack Tracking
    - Batch Log Processing
    - Timeline Visualization
    - Custom Pattern Management
    - Automated Replay Execution
    
    **Supported Attack Types:**
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Directory Traversal
    - Command Injection
    - File Inclusion (LFI/RFI)
    """)
    
    if not db_available:
        st.warning("⚠️ Database not available. Advanced features (pattern learning, timeline, custom patterns) are disabled.")
    
    st.markdown("---")
    
    enable_learning = st.checkbox(
        "🧠 Enable Pattern Learning", 
        value=False,
        disabled=not db_available,
        help="Track unknown attacks with suspicious status codes (requires database)"
    )
    
    st.session_state['enable_learning'] = enable_learning and db_available
    
    if st.button("📄 Load Sample Log"):
        st.session_state['use_sample'] = True
        st.rerun()
    
    if st.button("🔄 Reset Analysis"):
        for key in list(st.session_state.keys()):
            if key not in ['db_manager', 'enable_learning']:
                del st.session_state[key]
        st.rerun()

tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9 = st.tabs([
    "📤 Upload & Analyze", 
    "📊 Attack Dashboard", 
    "💾 Generate Scripts", 
    "📈 Statistics",
    "🔁 Batch Processing",
    "📉 Timeline View",
    "🧠 Unknown Attacks",
    "⚙️ Custom Patterns",
    "🚀 Automated Replay"
])

with tab1:
    st.header("Step 1: Upload Log File")
    
    log_content = None
    
    if 'use_sample' in st.session_state and st.session_state['use_sample']:
        st.info("📂 Using sample.log for demonstration")
        try:
            with open('sample.log', 'r') as f:
                log_content = f.read()
            st.session_state['use_sample'] = False
        except Exception as e:
            st.error(f"Error loading sample log: {e}")
    else:
        uploaded_file = st.file_uploader(
            "Choose a log file (Apache/Nginx format)",
            type=['log', 'txt'],
            help="Upload your web server access log file"
        )
        
        if uploaded_file is not None:
            log_content = uploaded_file.read().decode('utf-8')
            st.session_state['current_filename'] = uploaded_file.name
    
    if log_content:
        st.success(f"✅ Log file loaded: {len(log_content.split(chr(10)))} lines")
        
        with st.expander("👁️ Preview Log Content (first 10 lines)"):
            preview_lines = log_content.split('\n')[:10]
            st.code('\n'.join(preview_lines), language='log')
        
        if st.button("🔍 Analyze Log File", type="primary"):
            with st.spinner("Parsing log file..."):
                parser = LogParser()
                parsed_logs = parser.parse_log_file(log_content)
                st.session_state['parsed_logs'] = parsed_logs
                st.session_state['total_lines'] = len(log_content.split('\n'))
            
            with st.spinner("Detecting attacks..."):
                detector = AttackDetector(
                    db_manager=db if db_available else None, 
                    enable_learning=st.session_state.get('enable_learning', False) and db_available
                )
                analysis = detector.analyze_logs(parsed_logs)
                st.session_state['analysis'] = analysis
                
                if st.session_state.get('enable_learning', False) and db_available:
                    st.info(f"🧠 Tracked {analysis.get('unknown_tracked', 0)} unknown suspicious requests")
            
            if db_available:
                try:
                    filename = st.session_state.get('current_filename', 'uploaded_log.txt')
                    db.save_analysis(
                        filename=filename,
                        total_lines=st.session_state['total_lines'],
                        total_attacks=analysis['total_attacks'],
                        unique_ips=analysis['unique_ips'],
                        attack_breakdown=analysis['attack_type_counts'],
                        attacks_data=analysis['attacks']
                    )
                except Exception as e:
                    st.warning(f"⚠️ Could not save to database: {str(e)}")
            
            st.success(f"✅ Analysis complete! Found {analysis['total_attacks']} potential attacks")
            st.rerun()

with tab2:
    st.header("📊 Attack Detection Dashboard")
    
    if 'analysis' in st.session_state:
        analysis = st.session_state['analysis']
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Attacks Detected", analysis['total_attacks'])
        with col2:
            st.metric("Unique IP Addresses", analysis['unique_ips'])
        with col3:
            st.metric("Total Log Lines", st.session_state.get('total_lines', 0))
        
        st.markdown("---")
        
        if analysis['total_attacks'] > 0:
            attack_filter = st.multiselect(
                "Filter by Attack Type",
                options=list(analysis['attack_type_counts'].keys()),
                default=list(analysis['attack_type_counts'].keys())
            )
            
            filtered_attacks = [
                attack for attack in analysis['attacks']
                if attack['attack_type'] in attack_filter
            ]
            
            st.subheader(f"🎯 Detected Attacks ({len(filtered_attacks)})")
            
            for idx, attack in enumerate(filtered_attacks, 1):
                with st.expander(
                    f"Attack #{idx}: {attack['attack_type']} - IP: {attack['ip']} - Line {attack['line_number']}"
                ):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Attack Details:**")
                        st.write(f"**Type:** {attack['attack_type']}")
                        st.write(f"**IP Address:** {attack['ip']}")
                        st.write(f"**Timestamp:** {attack['timestamp']}")
                        st.write(f"**Method:** {attack['method']}")
                        st.write(f"**Status Code:** {attack['status']}")
                    
                    with col2:
                        st.markdown("**Payload Information:**")
                        st.write(f"**Pattern Matched:** `{attack['matched_pattern']}`")
                        st.code(attack['matched_payload'], language='text')
                    
                    st.markdown("**Full URL:**")
                    st.code(attack['full_url'], language='text')
                    
                    st.markdown("**User Agent:**")
                    st.text(attack['user_agent'])
        else:
            st.info("No attacks detected in the log file.")
    else:
        st.info("👆 Upload and analyze a log file first to see the dashboard.")

with tab3:
    st.header("💾 Generate Replay Scripts")
    
    if 'analysis' in st.session_state and st.session_state['analysis']['total_attacks'] > 0:
        analysis = st.session_state['analysis']
        
        st.markdown(f"""
        Generate executable replay scripts for **{analysis['total_attacks']} detected attacks**.
        
        **What you'll get:**
        - Python scripts using `requests` library
        - cURL commands for manual testing
        - JSON summary report
        """)
        
        if st.button("🚀 Generate All Replay Scripts", type="primary"):
            with st.spinner("Generating replay scripts..."):
                generator = ReplayGenerator()
                generator.clean_output_directory()
                
                generated_files = generator.save_replay_scripts(analysis['attacks'])
                report_file = generator.generate_summary_report(analysis, generated_files)
                
                st.session_state['generated_files'] = generated_files
                st.session_state['report_file'] = report_file
            
            st.success("✅ Replay scripts generated successfully!")
            st.rerun()
        
        if 'generated_files' in st.session_state:
            st.markdown("---")
            st.subheader("📦 Download Generated Files")
            
            generated = st.session_state['generated_files']
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Python Scripts", len(generated['python_scripts']))
            with col2:
                st.metric("cURL Scripts", len(generated['curl_commands']))
            with col3:
                st.metric("JSON Report", 1)
            
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for file_path in generated['python_scripts']:
                    if os.path.exists(file_path):
                        zip_file.write(file_path, os.path.basename(file_path))
                
                for file_path in generated['curl_commands']:
                    if os.path.exists(file_path):
                        zip_file.write(file_path, os.path.basename(file_path))
                
                if 'report_file' in st.session_state and os.path.exists(st.session_state['report_file']):
                    zip_file.write(st.session_state['report_file'], os.path.basename(st.session_state['report_file']))
            
            zip_buffer.seek(0)
            
            st.download_button(
                label="📥 Download All Scripts (ZIP)",
                data=zip_buffer,
                file_name="attack_replay_scripts.zip",
                mime="application/zip",
                type="primary"
            )
            
            st.markdown("---")
            st.subheader("👁️ Preview Generated Scripts")
            
            if generated['python_scripts']:
                sample_script = generated['python_scripts'][0]
                if os.path.exists(sample_script):
                    with open(sample_script, 'r') as f:
                        script_content = f.read()
                    
                    with st.expander(f"Preview: {os.path.basename(sample_script)}"):
                        st.code(script_content, language='python')
            
            if 'report_file' in st.session_state and os.path.exists(st.session_state['report_file']):
                with open(st.session_state['report_file'], 'r') as f:
                    report_data = json.load(f)
                
                with st.expander("Preview: attack_summary.json"):
                    st.json(report_data)
    else:
        st.info("👆 Analyze a log file first to generate replay scripts.")

with tab4:
    st.header("📈 Attack Statistics")
    
    if 'analysis' in st.session_state and st.session_state['analysis']['total_attacks'] > 0:
        analysis = st.session_state['analysis']
        
        st.subheader("Attack Type Distribution")
        
        attack_counts = analysis['attack_type_counts']
        df_attacks = pd.DataFrame(
            list(attack_counts.items()),
            columns=['Attack Type', 'Count']
        ).sort_values('Count', ascending=False)
        
        fig = px.bar(df_attacks, x='Attack Type', y='Count', 
                     title="Attack Types Distribution",
                     color='Count', color_continuous_scale='Reds')
        st.plotly_chart(fig, use_container_width=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Attack Type Breakdown")
            st.dataframe(df_attacks, use_container_width=True)
        
        with col2:
            st.subheader("🌐 Top Attacking IPs")
            ip_attack_counts = {
                ip: len(attacks) for ip, attacks in analysis['ip_attacks'].items()
            }
            df_ips = pd.DataFrame(
                list(ip_attack_counts.items()),
                columns=['IP Address', 'Attack Count']
            ).sort_values('Attack Count', ascending=False).head(10)
            
            st.dataframe(df_ips, use_container_width=True)
        
        st.markdown("---")
        st.subheader("📋 Export Analysis Report")
        
        if st.button("📄 Generate JSON Report"):
            report = {
                "total_attacks": analysis['total_attacks'],
                "unique_ips": analysis['unique_ips'],
                "attack_type_counts": analysis['attack_type_counts'],
                "ip_attacks": {k: list(set(v)) for k, v in analysis['ip_attacks'].items()},
                "attacks": analysis['attacks']
            }
            
            st.download_button(
                label="💾 Download JSON Report",
                data=json.dumps(report, indent=2),
                file_name="attack_analysis_report.json",
                mime="application/json"
            )
    else:
        st.info("👆 Analyze a log file first to see statistics.")

with tab5:
    st.header("🔁 Batch Log Processing")
    st.markdown("Upload and analyze multiple log files simultaneously")
    
    uploaded_files = st.file_uploader(
        "Choose multiple log files",
        type=['log', 'txt'],
        accept_multiple_files=True,
        help="Upload multiple Apache/Nginx log files for batch processing"
    )
    
    if uploaded_files:
        st.success(f"✅ {len(uploaded_files)} files uploaded")
        
        if st.button("🚀 Process All Files", type="primary"):
            files_data = []
            for file in uploaded_files:
                content = file.read().decode('utf-8')
                files_data.append((file.name, content))
            
            with st.spinner(f"Processing {len(files_data)} files..."):
                processor = BatchProcessor(db_manager=db if db_available else None)
                results = processor.process_multiple_files(
                    files_data, 
                    enable_learning=st.session_state.get('enable_learning', False) and db_available
                )
                st.session_state['batch_results'] = results
                
                summary = processor.get_batch_summary(results)
                st.session_state['batch_summary'] = summary
            
            st.success("✅ Batch processing complete!")
            if not db_available:
                st.info("ℹ️ Batch results are not persisted (database unavailable)")
            st.rerun()
    
    if 'batch_summary' in st.session_state:
        summary = st.session_state['batch_summary']
        
        st.subheader("📊 Batch Processing Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Files", summary['total_files'])
        with col2:
            st.metric("Successful", summary['successful'], 
                     delta=f"{summary['failed']} failed" if summary['failed'] > 0 else None,
                     delta_color="inverse")
        with col3:
            st.metric("Total Attacks", summary['total_attacks'])
        with col4:
            st.metric("Unique IPs", summary['unique_ips'])
        
        st.markdown("---")
        
        if summary['attack_type_counts']:
            st.subheader("Attack Distribution Across All Files")
            df_batch_attacks = pd.DataFrame(
                list(summary['attack_type_counts'].items()),
                columns=['Attack Type', 'Total Count']
            ).sort_values('Total Count', ascending=False)
            
            fig = px.pie(df_batch_attacks, values='Total Count', names='Attack Type',
                        title="Combined Attack Type Distribution")
            st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        st.subheader("📋 Individual File Results")
        
        results = st.session_state.get('batch_results', [])
        for result in results:
            if result['success']:
                with st.expander(f"✅ {result['filename']} - {result['analysis']['total_attacks']} attacks"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Total Lines", result['total_lines'])
                        st.metric("Parsed Lines", result['parsed_lines'])
                    with col2:
                        st.metric("Attacks Found", result['analysis']['total_attacks'])
                        st.metric("Unique IPs", result['analysis']['unique_ips'])
                    
                    if result['analysis']['attack_type_counts']:
                        st.write("**Attack Breakdown:**")
                        st.json(result['analysis']['attack_type_counts'])
            else:
                with st.expander(f"❌ {result['filename']} - Failed"):
                    st.error(f"Error: {result['error']}")

with tab6:
    st.header("📉 Attack Timeline Visualization")
    st.markdown("Visualize attack patterns over time")
    
    if not db_available:
        st.warning("⚠️ Timeline visualization requires database. Database is currently unavailable.")
        st.info("The timeline feature tracks attack patterns across multiple analysis sessions. Once the database is configured, you'll see historical trends here.")
    else:
        try:
            timeline_data = db.get_timeline_data(days=30)
            
            if timeline_data:
                df_timeline = pd.DataFrame(timeline_data)
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=df_timeline['date'],
                    y=df_timeline['attacks'],
                    mode='lines+markers',
                    name='Total Attacks',
                    line=dict(color='red', width=2),
                    marker=dict(size=8)
                ))
                
                fig.update_layout(
                    title='Attacks Over Time (Last 30 Days)',
                    xaxis_title='Date',
                    yaxis_title='Number of Attacks',
                    hovermode='x unified'
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                fig2 = go.Figure()
                fig2.add_trace(go.Scatter(
                    x=df_timeline['date'],
                    y=df_timeline['unique_ips'],
                    mode='lines+markers',
                    name='Unique IPs',
                    line=dict(color='blue', width=2),
                    marker=dict(size=8)
                ))
                
                fig2.update_layout(
                    title='Unique Attacking IPs Over Time',
                    xaxis_title='Date',
                    yaxis_title='Number of Unique IPs',
                    hovermode='x unified'
                )
                
                st.plotly_chart(fig2, use_container_width=True)
                
                st.subheader("📊 Analysis History")
                history = db.get_analysis_history(limit=20)
                
                if history:
                    df_history = pd.DataFrame(history)
                    df_history['analyzed_at'] = pd.to_datetime(df_history['analyzed_at'])
                    df_history = df_history.sort_values('analyzed_at', ascending=False)
                    
                    st.dataframe(
                        df_history[['filename', 'total_attacks', 'unique_ips', 'total_lines', 'analyzed_at']],
                        use_container_width=True
                    )
            else:
                st.info("No historical data available yet. Analyze some log files to see timeline visualization.")
        except Exception as e:
            st.warning(f"Unable to load timeline data: {str(e)}")

with tab7:
    st.header("🧠 Unknown Attack Pattern Learning")
    st.markdown("Track suspicious requests that don't match known attack patterns")
    
    if not db_available:
        st.warning("⚠️ Pattern learning requires database. Database is currently unavailable.")
        st.info("Enable pattern learning to automatically track suspicious requests with non-success status codes. These can help you discover new attack patterns.")
    else:
        try:
            unknown_attacks = db.get_unknown_attacks(limit=100)
            
            if unknown_attacks:
                st.success(f"📊 Tracking {len(unknown_attacks)} unknown suspicious patterns")
                
                df_unknown = pd.DataFrame(unknown_attacks)
                df_unknown = df_unknown.sort_values('frequency', ascending=False)
                
                st.subheader("🔝 Most Frequent Unknown Patterns")
                
                top_unknown = df_unknown.head(10)
                for idx, row in top_unknown.iterrows():
                    with st.expander(f"Pattern #{idx+1} - Frequency: {row['frequency']} - IP: {row['ip']}"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**IP Address:** {row['ip']}")
                            st.write(f"**Method:** {row['method']}")
                            st.write(f"**Frequency:** {row['frequency']}")
                            st.write(f"**Last Seen:** {row['detected_at']}")
                        
                        with col2:
                            st.write("**URL:**")
                            st.code(row['url'], language='text')
                            st.write("**User Agent:**")
                            st.text(row['user_agent'])
                        
                        if st.button(f"📝 Create Custom Pattern", key=f"create_pattern_{row['id']}"):
                            st.session_state['pattern_from_unknown'] = row
                            st.session_state['active_tab'] = 7
                            st.rerun()
                
                st.markdown("---")
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("🗑️ Clear All Unknown Attacks"):
                        db.clear_unknown_attacks()
                        st.success("✅ Unknown attacks cleared!")
                        st.rerun()
                
                with col2:
                    csv_data = df_unknown.to_csv(index=False)
                    st.download_button(
                        label="📥 Download as CSV",
                        data=csv_data,
                        file_name="unknown_attacks.csv",
                        mime="text/csv"
                    )
            else:
                st.info("No unknown attacks tracked yet. Enable 'Pattern Learning' in the sidebar and analyze logs with suspicious status codes.")
        except Exception as e:
            st.error(f"Error loading unknown attacks: {e}")

with tab8:
    st.header("⚙️ Custom Attack Pattern Management")
    st.markdown("Define and manage your own attack detection patterns")
    
    if not db_available:
        st.warning("⚠️ Custom pattern management requires database. Database is currently unavailable.")
        st.info("Custom patterns allow you to define your own regex-based attack detection rules that work alongside the built-in patterns.")
    else:
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.subheader("➕ Add New Pattern")
            
            with st.form("new_pattern_form"):
                attack_type = st.text_input("Attack Type", placeholder="e.g., Custom Injection")
                
                pattern_regex = st.text_area(
                    "Regex Pattern",
                    placeholder="e.g., (malicious_pattern)",
                    help="Enter a valid Python regex pattern"
                )
                
                description = st.text_area("Description (Optional)")
                
                if st.form_submit_button("✅ Add Pattern"):
                    if attack_type and pattern_regex:
                        try:
                            re.compile(pattern_regex)
                            pattern_id = db.add_custom_pattern(attack_type, pattern_regex, description)
                            st.success(f"✅ Pattern added successfully! (ID: {pattern_id})")
                            st.rerun()
                        except re.error:
                            st.error("❌ Invalid regex pattern. Please check your syntax.")
                    else:
                        st.warning("Please fill in attack type and pattern")
        
        with col2:
            st.subheader("📋 Existing Custom Patterns")
            
            try:
                custom_patterns = db.get_custom_patterns(active_only=False)
                
                if custom_patterns:
                    for pattern in custom_patterns:
                        with st.expander(f"{pattern['attack_type']} - {'✅ Active' if pattern['is_active'] else '❌ Inactive'}"):
                            st.write(f"**ID:** {pattern['id']}")
                            st.write(f"**Pattern:** `{pattern['pattern_regex']}`")
                            if pattern['description']:
                                st.write(f"**Description:** {pattern['description']}")
                            st.write(f"**Created:** {pattern['created_at']}")
                            
                            col_a, col_b = st.columns(2)
                            with col_a:
                                if pattern['is_active']:
                                    if st.button("🔴 Deactivate", key=f"deactivate_{pattern['id']}"):
                                        db.update_custom_pattern(pattern['id'], is_active=False)
                                        st.success("Pattern deactivated")
                                        st.rerun()
                                else:
                                    if st.button("🟢 Activate", key=f"activate_{pattern['id']}"):
                                        db.update_custom_pattern(pattern['id'], is_active=True)
                                        st.success("Pattern activated")
                                        st.rerun()
                            
                            with col_b:
                                if st.button("🗑️ Delete", key=f"delete_{pattern['id']}"):
                                    db.delete_custom_pattern(pattern['id'])
                                    st.success("Pattern deleted")
                                    st.rerun()
                else:
                    st.info("No custom patterns defined yet. Add your first pattern on the left.")
            except Exception as e:
                st.error(f"Error loading custom patterns: {e}")

with tab9:
    st.header("🚀 Automated Replay Execution")
    st.markdown("Execute generated replay scripts and capture results")
    
    if 'generated_files' in st.session_state and st.session_state['generated_files']['python_scripts']:
        scripts = st.session_state['generated_files']['python_scripts']
        
        st.subheader("🎯 Available Replay Scripts")
        st.info(f"Found {len(scripts)} Python replay scripts ready to execute")
        
        selected_scripts = st.multiselect(
            "Select scripts to execute",
            options=scripts,
            format_func=lambda x: os.path.basename(x)
        )
        
        target_host = st.text_input(
            "Target Host (Optional)",
            placeholder="http://your-test-server.com",
            help="Override the default http://example.com with your actual test target"
        )
        
        col1, col2, col3 = st.columns(3)
        with col1:
            timeout = st.number_input("Timeout (seconds)", min_value=5, max_value=60, value=10)
        with col2:
            max_concurrent = st.number_input("Max Concurrent", min_value=1, max_value=10, value=1)
        with col3:
            save_responses = st.checkbox("Save Response Bodies", value=False)
        
        if st.button("▶️ Execute Selected Scripts", type="primary"):
            if not selected_scripts:
                st.warning("Please select at least one script to execute")
            else:
                st.subheader("📊 Execution Results")
                
                results = []
                for script_path in selected_scripts:
                    st.write(f"**Executing:** {os.path.basename(script_path)}")
                    
                    try:
                        result = subprocess.run(
                            ['python3', script_path],
                            capture_output=True,
                            text=True,
                            timeout=timeout
                        )
                        
                        with st.expander(f"{'✅' if result.returncode == 0 else '❌'} {os.path.basename(script_path)}"):
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Exit Code", result.returncode)
                            with col2:
                                st.metric("Execution Time", f"{timeout}s max")
                            
                            if result.stdout:
                                st.write("**Output:**")
                                st.code(result.stdout, language='text')
                            
                            if result.stderr:
                                st.write("**Errors:**")
                                st.code(result.stderr, language='text')
                        
                        results.append({
                            'script': os.path.basename(script_path),
                            'success': result.returncode == 0,
                            'output': result.stdout,
                            'error': result.stderr
                        })
                    except subprocess.TimeoutExpired:
                        st.error(f"⏱️ Timeout: {os.path.basename(script_path)}")
                        results.append({
                            'script': os.path.basename(script_path),
                            'success': False,
                            'error': 'Execution timeout'
                        })
                    except Exception as e:
                        st.error(f"❌ Error: {e}")
                        results.append({
                            'script': os.path.basename(script_path),
                            'success': False,
                            'error': str(e)
                        })
                
                st.markdown("---")
                st.subheader("📈 Execution Summary")
                
                total = len(results)
                successful = sum(1 for r in results if r['success'])
                failed = total - successful
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Executed", total)
                with col2:
                    st.metric("Successful", successful)
                with col3:
                    st.metric("Failed", failed)
                
                report_data = {
                    'execution_time': str(datetime.now()),
                    'total_scripts': total,
                    'successful': successful,
                    'failed': failed,
                    'results': results
                }
                
                st.download_button(
                    label="📥 Download Execution Report (JSON)",
                    data=json.dumps(report_data, indent=2),
                    file_name=f"replay_execution_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
    else:
        st.info("👆 Generate replay scripts first (Tab 3) to enable automated execution")

st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: gray;'>"
    "Smart Web Application Attack Replay Generator | "
    "Advanced Edition with Pattern Learning & Batch Processing | "
    "For Ethical Hacking & Security Research Only"
    "</div>",
    unsafe_allow_html=True
)
