import streamlit as st
import tempfile
import os
import json
import hashlib
from datetime import datetime
import cv2
import numpy as np
import wave
from Crypto.Cipher import AES
import base64
from mp4_stego import embed_mp4, extract_mp4, is_mp4_file
import pandas as pd
import time

# =========================
# FILES & CONSTANTS
# =========================
USERS_FILE = "users.json"
LOG_FILE = "logs.json"
OUTPUT_DIR = "outputs"
MAX_ATTEMPTS = 5

os.makedirs(OUTPUT_DIR, exist_ok=True)

# =========================
# JSON HELPERS
# =========================
def load_json(file):
    if not os.path.exists(file):
        return {}
    with open(file, "r") as f:
        return json.load(f)

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def log_action(user, action, details=""):
    logs = load_json(LOG_FILE)
    if not isinstance(logs, list):
        logs = []
    logs.append({
        "user": user,
        "action": action,
        "details": details,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    save_json(LOG_FILE, logs)

# =========================
# INIT ADMIN
# =========================
def init_admin():
    users = load_json(USERS_FILE)
    if "admin" not in users:
        users["admin"] = {
            "password": hash_password("admin"),
            "role": "admin",
            "attempts": 0,
            "locked": False,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        save_json(USERS_FILE, users)
        log_action("admin", "ADMIN_INITIALIZED")

init_admin()

# =========================
# AUTH FUNCTIONS
# =========================
def signup(username, password, role="user"):
    users = load_json(USERS_FILE)
    if username in users:
        return False, "User already exists"
    if username.lower() == "admin":
        return False, "Username 'admin' is reserved"

    users[username] = {
        "password": hash_password(password),
        "role": role,
        "attempts": 0,
        "locked": False,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    save_json(USERS_FILE, users)
    log_action(username, "SIGNUP")
    return True, "Signup successful"

def login(username, password):
    users = load_json(USERS_FILE)
    if username not in users:
        return False, "User not found"

    user = users[username]
    if user["locked"]:
        return False, "🔒 Account locked. Contact admin."

    if user["password"] == hash_password(password):
        user["attempts"] = 0
        user["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_json(USERS_FILE, users)
        log_action(username, "LOGIN_SUCCESS")
        return True, user["role"]
    else:
        user["attempts"] += 1
        remaining = MAX_ATTEMPTS - user["attempts"]
        log_action(username, "LOGIN_FAILED", f"Failed attempts: {user['attempts']}")

        if remaining <= 0:
            user["locked"] = True
            save_json(USERS_FILE, users)
            log_action(username, "ACCOUNT_LOCKED")
            return False, "🔒 Account locked after 5 attempts"

        save_json(USERS_FILE, users)
        return False, f"❌ Invalid password ({remaining} attempts left)"

# =========================
# AES-256-GCM
# =========================
def get_cipher_params(key):
    return hashlib.sha256(key.encode()).digest()

def encrypt_msg(data, key):
    cipher = AES.new(get_cipher_params(key), AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_msg(data, key):
    try:
        raw = base64.b64decode(data)
        if len(raw) < 32:
            raise ValueError("Invalid data")
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(get_cipher_params(key), AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception:
        raise ValueError("No hidden message found or invalid key")

# =========================
# UTILITIES
# =========================
def msg_to_bin(msg):
    return ''.join(format(ord(i), '08b') for i in msg) + '1111111111111110'

def bin_to_msg(binary):
    chars = []
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) < 8:
            break
        char_code = int(byte, 2)
        # Only accept printable ASCII characters for base64
        if char_code < 32 or char_code > 126:
            return ""  # Invalid character, return empty
        chars.append(chr(char_code))
    return ''.join(chars)

def get_capacity(path, media):
    try:
        if media == "Image":
            img = cv2.imread(path)
            return img.size // 8 if img is not None else 0
        if media == "Audio":
            with wave.open(path, 'rb') as a:
                return a.getnframes() // 8
        if media == "Video":
            cap = cv2.VideoCapture(path)
            frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            w, h = int(cap.get(3)), int(cap.get(4))
            cap.release()
            return (frames * w * h * 3) // 8
    except:
        return 0

# =========================
# MEDIA FUNCTIONS
# =========================
def embed_image(ip, op, msg, key):
    img = cv2.imread(ip)
    if img is None:
        raise ValueError("Could not load image")
    data = msg_to_bin(encrypt_msg(msg, key))
    flat = img.flatten()
    if len(data) > len(flat):
        raise ValueError("Message too large")
    flat[:len(data)] = (flat[:len(data)] & ~1) | np.array(list(data), dtype=np.uint8)
    cv2.imwrite(op, flat.reshape(img.shape), [cv2.IMWRITE_PNG_COMPRESSION, 0])

def extract_image(ip, key):
    img = cv2.imread(ip)
    if img is None:
        raise ValueError("Could not load image")
    bits = []
    for v in img.flatten():
        bits.append(str(v & 1))
        if len(bits) >= 16 and ''.join(bits[-16:]) == '1111111111111110':
            break
    if len(bits) < 16:
        return "No hidden message found"
    return decrypt_msg(bin_to_msg(''.join(bits[:-16])), key)

def embed_audio(ip, op, msg, key):
    with wave.open(ip, 'rb') as a:
        params = a.getparams()
        frames = bytearray(a.readframes(a.getnframes()))
    data = msg_to_bin(encrypt_msg(msg, key))
    for i, b in enumerate(data):
        frames[i] = (frames[i] & ~1) | int(b)
    with wave.open(op, 'wb') as o:
        o.setparams(params)
        o.writeframes(frames)

def extract_audio(ip, key):
    with wave.open(ip, 'rb') as a:
        frames = bytearray(a.readframes(a.getnframes()))
    bits = []
    for b in frames:
        bits.append(str(b & 1))
        if len(bits) >= 16 and ''.join(bits[-16:]) == '1111111111111110':
            break
    if len(bits) < 16:
        return "No hidden message found"
    return decrypt_msg(bin_to_msg(''.join(bits[:-16])), key)

def embed_video(ip, op, msg, key):
    cap = cv2.VideoCapture(ip)
    fps = cap.get(cv2.CAP_PROP_FPS)
    width = int(cap.get(3))
    height = int(cap.get(4))
    
    # Use FFV1 codec - lossless compression that preserves LSB data
    # Output as MKV for best FFV1 compatibility, but rename if needed
    fourcc = cv2.VideoWriter_fourcc(*'FFV1')
    out = cv2.VideoWriter(op, fourcc, fps, (width, height))
    
    if not out.isOpened():
        raise ValueError("Failed to create video writer. FFV1 codec may not be available.")
    
    data = msg_to_bin(encrypt_msg(msg, key))
    ptr = 0
    
    while cap.isOpened():
        r, f = cap.read()
        if not r:
            break
        
        # Embed data in frame
        if ptr < len(data):
            flat = f.flatten()
            for i in range(len(flat)):
                if ptr >= len(data):
                    break
                flat[i] = (flat[i] & ~1) | int(data[ptr])
                ptr += 1
            f = flat.reshape(f.shape)
        
        out.write(f)
    
    cap.release()
    out.release()

def extract_video(ip, key):
    cap = cv2.VideoCapture(ip)
    bits = []
    
    # Read all frames and extract LSB
    while cap.isOpened():
        r, f = cap.read()
        if not r:
            break
        for v in f.flatten():
            bits.append(str(v & 1))
            if len(bits) >= 16 and ''.join(bits[-16:]) == '1111111111111110':
                cap.release()
                try:
                    msg = bin_to_msg(''.join(bits[:-16]))
                    if not msg:
                        return "No hidden message found"
                    return decrypt_msg(msg, key)
                except:
                    return "No hidden message found or invalid key"
    
    cap.release()
    return "No hidden message found"

# =========================
# STREAMLIT UI CONFIG
# =========================
st.set_page_config("GetStego Elite", "🛡️", "wide")

if "user" not in st.session_state:
    st.session_state.user = None
    st.session_state.role = None
    st.session_state.admin_view = False

# =========================
# SIDEBAR AUTHENTICATION
# =========================
st.sidebar.title("🔐 SecureVault Auth")

# Add Admin Login as separate option for better UX
auth_option = st.sidebar.radio("Access Portal", ["User Login", "Sign Up", "🔒 Admin Login"])

if auth_option == "Sign Up":
    st.sidebar.subheader("Create Account")
    new_u = st.sidebar.text_input("Choose Username", key="signup_u")
    new_p = st.sidebar.text_input("Choose Password", type="password", key="signup_p")
    confirm_p = st.sidebar.text_input("Confirm Password", type="password", key="confirm_p")
    
    if st.sidebar.button("Create Account", key="btn_signup"):
        if new_p != confirm_p:
            st.sidebar.error("Passwords do not match")
        elif len(new_p) < 4:
            st.sidebar.error("Password too short (min 4 chars)")
        else:
            ok, msg = signup(new_u, new_p)
            if ok:
                st.sidebar.success(msg)
            else:
                st.sidebar.error(msg)

elif auth_option == "User Login":
    st.sidebar.subheader("User Access")
    u = st.sidebar.text_input("Username", key="user_u")
    p = st.sidebar.text_input("Password", type="password", key="user_p")
    
    if st.sidebar.button("Login", key="btn_user_login"):
        ok, role = login(u, p)
        if ok:
            st.session_state.user = u
            st.session_state.role = role
            st.session_state.admin_view = False
            st.rerun()
        else:
            st.sidebar.error(role)

elif auth_option == "🔒 Admin Login":
    st.sidebar.subheader("Administrator Access")
    admin_u = st.sidebar.text_input("Admin ID", value="admin", key="admin_u")
    admin_p = st.sidebar.text_input("Master Password", type="password", key="admin_p")
    
    if st.sidebar.button("🔐 Admin Login", key="btn_admin_login"):
        ok, role = login(admin_u, admin_p)
        if ok and role == "admin":
            st.session_state.user = admin_u
            st.session_state.role = role
            st.session_state.admin_view = True
            st.rerun()
        else:
            st.sidebar.error("Invalid admin credentials or insufficient privileges")

# Logout button
if st.session_state.user:
    st.sidebar.markdown("---")
    st.sidebar.write(f"**Logged in as:** `{st.session_state.user}`")
    st.sidebar.write(f"**Role:** `{st.session_state.role}`")
    if st.sidebar.button("🚪 Logout"):
        st.session_state.user = None
        st.session_state.role = None
        st.session_state.admin_view = False
        st.rerun()

# =========================
# MAIN APPLICATION
# =========================
if not st.session_state.user:
    # Landing page for non-logged in users
    st.title("🛡️ GetStego Elite")
    st.markdown("""
    ### AES-256-GCM Secure Multimedia Steganography
    
    **Features:**
    - 🔒 Military-grade AES-256-GCM encryption
    - 🖼️ Image steganography (PNG)
    - 🔊 Audio steganography (WAV)
    - 🎬 Video steganography (AVI/MP4)
    - 👤 User management with role-based access
    - 📊 Admin dashboard with activity monitoring
    
    *Please login to access the system*
    """)
    st.stop()

# =========================
# ADMIN DASHBOARD (TABLE VIEW)
# =========================
if st.session_state.role == "admin" and st.session_state.admin_view:
    st.title("🛡️ Admin Control Center")
    st.markdown(f"*Administrator: `{st.session_state.user}`*")
    
    tab1, tab2, tab3 = st.tabs(["👥 User Management", "📜 System Logs", "📊 Statistics"])
    
    # --- TAB 1: USER MANAGEMENT ---
    with tab1:
        st.subheader("User Management Console")
        users = load_json(USERS_FILE)
        
        if not users or len(users) <= 1:  # Only admin exists
            st.info("No regular users found in system")
        else:
            # Prepare user data for table
            user_data = []
            for username, info in users.items():
                if username != "admin":  # Don't show admin in manageable list
                    user_data.append({
                        "Username": username,
                        "Role": info.get("role", "user"),
                        "Status": "🔒 Locked" if info.get("locked") else "✅ Active",
                        "Failed Attempts": info.get("attempts", 0),
                        "Created": info.get("created_at", "N/A"),
                        "Last Login": info.get("last_login", "Never")
                    })
            
            if user_data:
                df_users = pd.DataFrame(user_data)
                
                # Search functionality
                col1, col2 = st.columns([2, 1])
                with col1:
                    search_term = st.text_input("🔍 Search users", placeholder="Type username...")
                with col2:
                    status_filter = st.selectbox("Filter by status", ["All", "Active", "Locked"])
                
                # Apply filters
                filtered_df = df_users.copy()
                if search_term:
                    filtered_df = filtered_df[filtered_df['Username'].str.contains(search_term, case=False, na=False)]
                if status_filter == "Active":
                    filtered_df = filtered_df[filtered_df['Status'] == "✅ Active"]
                elif status_filter == "Locked":
                    filtered_df = filtered_df[filtered_df['Status'] == "🔒 Locked"]
                
                st.markdown(f"**Showing {len(filtered_df)} of {len(user_data)} users**")
                st.dataframe(filtered_df, use_container_width=True, hide_index=True)
                
                # Action section
                st.markdown("---")
                st.subheader("User Actions")
                
                col_a, col_b, col_c = st.columns(3)
                
                with col_a:
                    selected_user = st.selectbox("Select User", 
                                               [u for u in users.keys() if u != "admin"],
                                               key="action_select")
                
                with col_b:
                    action = st.selectbox("Action", 
                                        ["🔒 Lock Account", "🔓 Unlock Account", 
                                          "🗑️ Delete Account"])
                
                with col_c:
                    st.write("")  # Spacing
                    st.write("")  # Spacing
                    execute_btn = st.button("Execute Action", type="primary", use_container_width=True)
                
                # Confirmation checkbox for delete action (outside button check)
                confirm_delete = False
                if action == "🗑️ Delete Account" and selected_user:
                    confirm_delete = st.checkbox(f"⚠️ Confirm deletion of `{selected_user}`")
                
                if execute_btn and selected_user:
                    if action == "🔒 Lock Account":
                        users[selected_user]["locked"] = True
                        log_action(st.session_state.user, "ADMIN_LOCK", f"Target: {selected_user}")
                        st.success(f"🔒 Locked user: {selected_user}")
                        
                    elif action == "🔓 Unlock Account":
                        users[selected_user]["locked"] = False
                        users[selected_user]["attempts"] = 0
                        log_action(st.session_state.user, "ADMIN_UNLOCK", f"Target: {selected_user}")
                        st.success(f"🔓 Unlocked user: {selected_user}")
                        
                    elif action == "🔄 Reset Attempts":
                        users[selected_user]["attempts"] = 0
                        users[selected_user]["locked"] = False
                        log_action(st.session_state.user, "ADMIN_RESET", f"Target: {selected_user}")
                        st.success(f"🔄 Reset attempts and unlocked: {selected_user}")
                        
                    elif action == "🗑️ Delete Account":
                        if confirm_delete:
                            del users[selected_user]
                            log_action(st.session_state.user, "ADMIN_DELETE", f"Target: {selected_user}")
                            st.success(f"🗑️ Deleted user: {selected_user}")
                        else:
                            st.warning("⚠️ Please check the confirmation box to delete")
                            st.stop()
                    
                    save_json(USERS_FILE, users)
                    time.sleep(1)
                    st.rerun()
    
    # --- TAB 2: SYSTEM LOGS ---
    with tab2:
        st.subheader("System Activity Logs")
        logs = load_json(LOG_FILE)
        
        if not logs:
            st.info("No logs available")
        else:
            # Convert to DataFrame
            logs_df = pd.DataFrame(logs)
            if not logs_df.empty:
                logs_df = logs_df.sort_values("time", ascending=False)
                
                # Search and filter
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    log_search = st.text_input("🔍 Search logs", placeholder="User, action, or details...")
                with col2:
                    user_filter = st.selectbox("Filter by User", 
                                             ["All"] + sorted(logs_df['user'].unique().tolist()))
                with col3:
                    action_filter = st.selectbox("Filter by Action", 
                                               ["All"] + sorted(logs_df['action'].unique().tolist()))
                
                # Apply filters
                display_df = logs_df.copy()
                if log_search:
                    mask = (display_df['user'].str.contains(log_search, case=False, na=False)) | \
                           (display_df['action'].str.contains(log_search, case=False, na=False)) | \
                           (display_df['details'].str.contains(log_search, case=False, na=False))
                    display_df = display_df[mask]
                
                if user_filter != "All":
                    display_df = display_df[display_df['user'] == user_filter]
                if action_filter != "All":
                    display_df = display_df[display_df['action'] == action_filter]
                
                st.markdown(f"**Showing {len(display_df)} of {len(logs_df)} entries**")
                
                # Show table
                st.dataframe(display_df, use_container_width=True, hide_index=True)
                
                # Export options
                col_exp1, col_exp2, col_exp3 = st.columns([1, 1, 2])
                with col_exp1:
                    if st.button("🗑️ Clear All Logs"):
                        if st.checkbox("Confirm destruction of all logs"):
                            save_json(LOG_FILE, [])
                            st.success("Logs cleared")
                            time.sleep(1)
                            st.rerun()
                
                with col_exp2:
                    st.download_button(
                        label="📥 Export JSON",
                        data=json.dumps(logs, indent=2),
                        file_name=f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
                
                with col_exp3:
                    # Raw JSON view toggle
                    if st.checkbox("Show Raw JSON"):
                        st.json(logs)
    
    # --- TAB 3: STATISTICS ---
    with tab3:
        st.subheader("System Overview")
        users = load_json(USERS_FILE)
        logs = load_json(LOG_FILE)
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        total_users = len([u for u in users if u != "admin"])
        active_users = len([u for u in users.values() if not u.get("locked") and u.get("role") != "admin"])
        locked_count = len([u for u in users.values() if u.get("locked")])
        total_logs = len(logs)
        
        with col1:
            st.metric("Total Users", total_users)
        with col2:
            st.metric("Active Users", active_users)
        with col3:
            st.metric("Locked Accounts", locked_count)
        with col4:
            st.metric("Total Actions", total_logs)
        
        # Activity Chart (if enough data)
        if logs and len(logs) > 0:
            st.markdown("---")
            st.subheader("Activity Timeline")
            try:
                logs_times = pd.DataFrame(logs)
                logs_times['time'] = pd.to_datetime(logs_times['time'])
                daily_counts = logs_times.groupby(logs_times['time'].dt.date).size().reset_index()
                daily_counts.columns = ['Date', 'Actions']
                st.line_chart(daily_counts.set_index('Date'))
            except:
                st.info("Insufficient data for timeline visualization")

# =========================
# REGULAR USER INTERFACE
# =========================
else:
    st.title("🛡️ GetStego Elite")
    st.write("AES-256-GCM Secure Multimedia Steganography")
    
    mode = st.radio("Mode", ["Embed Message", "Extract Message"], horizontal=True)
    media = st.selectbox("Carrier Type", ["Image", "Audio", "Video"])
    
    # Show video format info
    if media == "Video":
        with st.expander("📹 **MP4 Format Support (NEW)**", expanded=True):
            st.markdown("""
            **That single bit change can corrupt the hidden message.**
            
            **But there are exceptions**
            
            Hidden data can survive in MP4 if different techniques are used:
            
            • **Metadata embedding** (inside container metadata)
            • **Frequency-domain steganography** (DCT coefficients used by codecs)
            • **Watermarking methods** designed for video compression
            
            These methods are used in research and DRM systems.
            
            ---
            
            **This system now supports:**
            • **MP4 Output** using advanced DCT/metadata methods
            • **AVI Output** using traditional LSB (more reliable)
            
            *Choose your preferred output format below*
            """)
            
            mp4_method = st.radio("MP4 Method", 
                                 ["Metadata (Container) - Most Reliable", 
                                  "DCT (Frequency Domain) - Higher Capacity"],
                                 help="Metadata embeds in file headers. DCT embeds in video data.")
    
    key = st.text_input("Encryption Key", type="password")
    
    exts = {"Image": ["png"], "Audio": ["wav"], "Video": ["mp4", "avi"]}
    up = st.file_uploader("Upload Carrier", type=exts[media])
    
    if up and key:
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(up.name)[1]) as t:
            t.write(up.getvalue())
            tmp = t.name
        
        try:
            cap = get_capacity(tmp, media)
            st.metric("Capacity", f"{cap:,} Bytes")
            
            out = os.path.join(OUTPUT_DIR, f"vault_{up.name}")
            
            if mode == "Embed Message":
                # Video output format selection
                if media == "Video":
                    video_output_format = st.radio("Output Format", ["MP4 (Append Method)", "AVI (Lossless LSB)"])
                    use_mp4_output = "MP4" in video_output_format
                
                msg = st.text_area("Secret Message", height=150)
                if st.button("🔐 Encrypt & Embed"):
                    if not msg:
                        st.error("Please enter a message")
                    else:
                        try:
                            if media == "Image":
                                embed_image(tmp, out, msg, key)
                            elif media == "Audio":
                                embed_audio(tmp, out, msg, key)
                            else:
                                if use_mp4_output:
                                    # Use MP4 append method - encrypted data appended at end
                                    embed_mp4(tmp, out.replace('.avi', '.mp4'), msg, key)
                                else:
                                    # Output as AVI for lossless steganography
                                    out = out.replace('.mp4', '.avi')
                                    embed_video(tmp, out, msg, key)
                            
                            log_action(st.session_state.user, "EMBED", f"Media: {media}")
                            
                            with open(out, "rb") as f:
                                st.download_button(
                                    "⬇️ Download Stego File",
                                    data=f,
                                    file_name=os.path.basename(out),
                                    mime="application/octet-stream"
                                )
                            st.success("✅ Message embedded successfully!")
                        except Exception as e:
                            st.error(f"Error: {str(e)}")
            
            else:  # Extract
                if st.button("🔓 Extract & Decrypt"):
                    try:
                        if media == "Image":
                            res = extract_image(tmp, key)
                        elif media == "Audio":
                            res = extract_audio(tmp, key)
                        else:
                            # Extract from video (MP4 or AVI)
                            if up.name.lower().endswith('.mp4'):
                                # Try MP4 methods first
                                try:
                                    res = extract_mp4(tmp, key, method='auto')
                                except:
                                    res = extract_video(tmp, key)
                            else:
                                res = extract_video(tmp, key)
                        
                        log_action(st.session_state.user, "EXTRACT", f"Media: {media}")
                        
                        st.subheader("Extracted Message:")
                        st.code(res)
                        st.success("✅ Extraction successful!")
                    except Exception as e:
                        st.error(f"Extraction failed: {str(e)}")
        
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

# Footer
st.markdown("---")
st.caption("🔒 GetStego Elite v2.0 | Secure Communications Platform")