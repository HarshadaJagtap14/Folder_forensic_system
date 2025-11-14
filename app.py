import streamlit as st  # For creating the web app UI
import os                      # For folder and file operations
from pathlib import Path        # For easy path handling
import json                    # For saving and loading data in JSON format
from datetime import datetime   # For timestamps (date & time)
import hashlib                  # For hashing folder names (unique file IDs)
import pandas as pd             # For tabular data display


# Page Settings
st.set_page_config(page_title="Folder Forensics", layout="wide")

# Inject custom CSS
st.markdown("""
<style>
    body {
        font-family: 'Segoe UI', sans-serif;
    }
    .main {
        background-color: #f8fafc;
        padding: 20px;
    }
    .stMetric {
        background: white;
        padding: 15px;
        border-radius: 12px;
        box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        text-align: center;
    }
    .status-added {
        background: #d1fae5;
        color: #065f46;
        padding: 6px 12px;
        border-radius: 8px;
        display: inline-block;
        font-weight: 600;
    }
    .status-deleted {
        background: #fee2e2;
        color: #991b1b;
        padding: 6px 12px;
        border-radius: 8px;
        display: inline-block;
        font-weight: 600;
    }
    .status-changed {
        background: #fef9c3;
        color: #92400e;
        padding: 6px 12px;
        border-radius: 8px;
        display: inline-block;
        font-weight: 600;
    }
    .status-unchanged {
        background: #e0e7ff;
        color: #3730a3;
        padding: 6px 12px;
        border-radius: 8px;
        display: inline-block;
        font-weight: 600;
    }
    table {
        border-radius: 8px !important;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)

# Internal directory to store baselines
BASE_DIR = Path(".folder_forensics_baselines")
BASE_DIR.mkdir(exist_ok=True)

# --- Helper Functions ---
# Generate a unique hash for each folder path
def safe_name_hash(path_str: str):
    return hashlib.sha1(path_str.encode("utf-8")).hexdigest()
# Convert a timestamp into readable date-time format
def timestamp(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""
# Convert file size (in bytes) to KB, MB, GB, etc.
def human_readable_size(size_in_bytes):
    if size_in_bytes is None:
        return None
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_in_bytes < 1024:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024
    return f"{size_in_bytes:.2f} PB"

# Collect details about a single file (size, created time, modified time, etc.)
def get_file_info(path: Path):
    try:
        s = path.stat()
        return {
            "name": path.name,
            "relpath": str(path),
            "size": human_readable_size(s.st_size),
            "created": timestamp(s.st_ctime),
            "modified": timestamp(s.st_mtime),
            "accessed": timestamp(s.st_atime),
            "is_file": path.is_file()
        }
    except Exception as e:
        return {
            "name": path.name,
            "relpath": str(path),
            "size": None,
            "created": None,
            "modified": None,
            "accessed": None,
            "is_file": path.is_file(),
            "error": str(e)
        }
    
# Scan an entire folder and collect information about all files
def scan_folder(folder_path: str):
    p = Path(folder_path)
    if not p.exists():
        raise FileNotFoundError(f"Path not found: {folder_path}")
    results = {}
    for root, dirs, files in os.walk(p):
        for fname in files:
            # Skip Word temporary/lock files (~$ prefix)
            if fname.startswith("~$"):
                continue
            fpath = Path(root) / fname
            info = get_file_info(fpath)
            results[str(fpath)] = info
    return results

# Save folder scan result into a JSON file (baseline)
def save_baseline_for(path_str: str, data: dict):
    key = safe_name_hash(path_str)      # Create unique file name
    fp = BASE_DIR / f"{key}.json"              # Path to JSON file
    with open(fp, "w", encoding="utf-8") as f:
        json.dump({
            "folder": path_str,
            "created_at": datetime.now().isoformat(),
            "files": data
        }, f, indent=2, ensure_ascii=False)
    return fp


# Load baseline JSON (previous scan data)
def load_baseline_for(path_str: str):
    key = safe_name_hash(path_str)
    fp = BASE_DIR / f"{key}.json"
    if not fp.exists():
        return None
    with open(fp, "r", encoding="utf-8") as f:
        return json.load(f)

# Compare old baseline with new scan
def compare(old: dict, new: dict):
    old_set = set(old.keys())  #old file path
    new_set = set(new.keys())   #new file path

    # Find which files were added, deleted, or common
    added = sorted(list(new_set - old_set))
    deleted = sorted(list(old_set - new_set))
    common = sorted(list(old_set & new_set))
    changed = []
    unchanged = []

    # For files present in both — check if size or modified time changed
    for p in common:
        o, n = old[p], new[p]
        if (o.get("size") != n.get("size")) or (o.get("modified") != n.get("modified")):
            changed.append(p)
        else:
            unchanged.append(p)
    return {"added": added, "deleted": deleted, "changed": changed, "unchanged": unchanged}

# ------------------------------------------------------
# 🖥️ STREAMLIT USER INTERFACE
# ------------------------------------------------------

# App title and short description
st.title("🔍 Folder Forensics Dashboard")
st.markdown("A modern forensic analysis tool for **tracking file changes over time**.")

# Sidebar
with st.sidebar:
    st.header("⚙️ Options")
    folder_input = st.text_input("📂 Folder path", value=str(Path.home()))

    btn_scan_baseline = st.button("🔰 Create / Update Baseline")
    btn_load_baseline = st.button("📂 Load Existing Baseline")
    btn_compare = st.button("🔎 Scan & Compare with Baseline")

if folder_input:
    existing = load_baseline_for(folder_input)
    if existing:
        st.sidebar.success(f"✅ Baseline exists (Saved at {existing.get('created_at','?')})")
    else:
        st.sidebar.info("ℹ️ No baseline found for this folder.")

# --- Create Baseline ---
if btn_scan_baseline and folder_input:
    try:
        with st.spinner("📡 Scanning folder and creating baseline..."):
            current = scan_folder(folder_input)
            fp = save_baseline_for(folder_input, current)
        st.success(f"✅ Baseline saved → {fp}")
        st.info(f"Total files scanned: {len(current)}")
    except Exception as e:
        st.error(f"❌ Error: {e}")

# --- Load Baseline ---
if btn_load_baseline and folder_input:
    b = load_baseline_for(folder_input)
    if not b:
        st.warning("⚠️ Baseline not found for this folder.")
    else:
        st.subheader("📂 Baseline Preview")
        st.write(f"Folder: {b.get('folder')}")
        st.write(f"Saved at: {b.get('created_at')}")
        files = b.get("files", {})
        df = pd.DataFrame.from_dict(files, orient="index")
        if not df.empty:
            st.dataframe(df[["name","relpath","size","created","modified","accessed"]].head(500))
        else:
            st.write("No files in baseline.")

# --- Compare ---
if btn_compare and folder_input:
    baseline = load_baseline_for(folder_input)
    if not baseline:
        st.warning("⚠️ Baseline not found. Please create one first.")
    else:
        try:
            with st.spinner("🔎 Scanning current folder and comparing..."):
                curr = scan_folder(folder_input)
                comp = compare(baseline["files"], curr)

            # Summary
            st.subheader("📊 Comparison Summary")
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Baseline files", len(baseline["files"]))
            col2.metric("Current files", len(curr))
            col3.metric("Added", len(comp["added"]))
            col4.metric("Deleted", len(comp["deleted"]))

            # Added
            st.subheader("✅ Added files")
            if comp["added"]:
                df_added = pd.DataFrame([curr[p] for p in comp["added"]])
                st.dataframe(df_added[["name","relpath","size","created","modified"]])
            else:
                st.markdown("<span class='status-unchanged'>None</span>", unsafe_allow_html=True)

            # Deleted
            st.subheader("❌ Deleted files")
            if comp["deleted"]:
                df_del = pd.DataFrame([baseline["files"][p] for p in comp["deleted"]])
                st.dataframe(df_del[["name","relpath","size","created","modified"]])
            else:
                st.markdown("<span class='status-unchanged'>None</span>", unsafe_allow_html=True)

            # Changed
            st.subheader("🔁 Changed files")
            if comp["changed"]:
                df_ch = pd.DataFrame([curr[p] for p in comp["changed"]])
                st.dataframe(df_ch[["name","relpath","size","created","modified"]])
            else:
                st.markdown("<span class='status-unchanged'>None</span>", unsafe_allow_html=True)

        except Exception as e:
            st.error(f"❌ Error during compare: {e}")

# Footer
st.markdown("---")
st.caption("🕵️ Powered by Streamlit | For raw forensic disk images, use `pytsk3`.")


