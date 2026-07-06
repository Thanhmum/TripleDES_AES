import os
import base64
from datetime import datetime
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
# ==========================================
app = Flask(__name__)
app.secret_key = 'S3CR3T_S3SS10N_K3Y_CH0_FL4SK'

# --- ĐOẠN SỬA ĐƯỜNG DẪN CHUẨN CHO RENDER ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'users.db')
LOG_FILE = os.path.join(BASE_DIR, 'access_log.txt')


# ==========================================
# 1. CƠ CHẾ QUẢN LÝ KHÓA (KEY MANAGEMENT)
# ==========================================
# Trong thực tế, các khóa này nên được lưu trữ trong Hệ thống quản lý khóa độc lập (KMS).
# Ở đây ta cố định độ dài khóa chuẩn: AES-256 cần 32 bytes, TripleDES cần 24 bytes.
AES_KEY = b'12345678901234567890123456789012'  # Khóa mã hóa AES (32 bytes)
DES_KEY = b'abcdefghijklmnopqrstuvwx'         # Khóa mã hóa TripleDES (24 bytes)

# ==========================================
# 2. HỆ THỐNG GHI NHẬT KÝ KIỂM TOÁN (AUDIT LOG)
# ==========================================
def write_audit_log(username, role, action, status):
    """Bắt buộc ghi log lại mọi hành vi nhạy cảm (Đặc biệt là khi giải mã)"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] [USER: {username}] [ROLE: {role}] ACTION: {action} -> STATUS: {status}\n"
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_entry)

# ==========================================
# 3. THUẬT TOÁN MÃ HÓA & GIẢI MÃ
# ==========================================

# --- BIẾN THỂ A: AES-256-GCM (Chế độ chính thức, an toàn cao) ---
def encrypt_aes_gcm(plaintext):
    if not plaintext: return ""
    # Tạo ngẫu nhiên Vector khởi tạo (Nonce/IV) 12 bytes cho chế độ GCM
    cipher = AES.new(AES_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    
    # Gom tụ các thành phần để lưu trữ vào CSDL dưới dạng chuỗi chuỗi Hex dễ quản lý
    # Cấu trúc chuỗi lưu DB: nonce_hex + tag_hex + ciphertext_hex
    result = cipher.nonce.hex() + ":" + tag.hex() + ":" + ciphertext.hex()
    return result

def decrypt_aes_gcm(encrypted_text):
    try:
        if not encrypted_text or ":" not in encrypted_text: return "Lỗi định dạng dữ liệu"
        nonce_hex, tag_hex, ciphertext_hex = encrypted_text.split(":")
        
        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=bytes.fromhex(nonce_hex))
        decrypted_bytes = cipher.decrypt_and_verify(
            bytes.fromhex(ciphertext_hex), 
            bytes.fromhex(tag_hex)
        )
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        return f"[Lỗi giải mã AES: Khóa sai hoặc dữ liệu bị giả mạo]"

# --- BIẾN THỂ B: TripleDES (Chế độ Legacy / So sánh dữ liệu cũ) ---
def pad_3des(text):
    """Bổ sung khoảng trống (Padding) vì 3DES yêu cầu dữ liệu là bội số của 8 bytes"""
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt_3des(plaintext):
    if not plaintext: return ""
    padded_text = pad_3des(plaintext)
    # Sử dụng chế độ ECB để mô phỏng tương thích ngược hệ thống cũ dễ dàng so sánh
    cipher = DES3.new(DES_KEY, DES3.MODE_ECB)
    ciphertext = cipher.encrypt(padded_text.encode('utf-8'))
    return ciphertext.hex()

def decrypt_3des(encrypted_hex):
    try:
        if not encrypted_hex: return ""
        cipher = DES3.new(DES_KEY, DES3.MODE_ECB)
        decrypted_bytes = cipher.decrypt(bytes.fromhex(encrypted_hex))
        return decrypted_bytes.decode('utf-8').strip()
    except Exception as e:
        return f"[Lỗi giải mã TripleDES]"

# ==========================================
# 4. KẾT NỐI VÀ KHỞI TẠO CƠ SỞ DỮ LIỆU
# ==========================================
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Cho phép truy xuất dữ liệu theo tên cột
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
        # -------------------------------------------------------------------------------
def init_sqlite_db():
    """Khởi tạo bảng người dùng và dữ liệu mã hóa nhạy cảm an toàn"""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # Tạo bảng lưu tài khoản đăng nhập
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        # Tạo bảng lưu thông tin khách hàng nhạy cảm
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sensitive_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullname TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                cipher_method TEXT NOT NULL,
                created_by TEXT
            )
        ''')
        conn.commit()

# ==========================================
# 5. ĐỊNH TUYẾN GIAO DIỆN (ROUTES & RBAC LOGIC)
# ==========================================

@app.route('/')
def index():
    return redirect(url_for('signin'))

# --- ĐĂNG KÝ / ĐĂNG NHẬP ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role'] # user, admin, auditor
        
        db = get_db()
        try:
            db.execute('INSERT INTO accounts (username, password, role) VALUES (?, ?, ?)', 
                       (username, password, role))
            db.commit()
            write_audit_log(username, role, f"Đăng ký tài khoản với vai trò {role}", "Thành công")
            flash('Đăng ký tài khoản thành công! Hãy đăng nhập.', 'success')
            return redirect(url_for('signin'))
        except sqlite3.IntegrityError:
            flash('Tên tài khoản đã tồn tại!', 'danger')
            
    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM accounts WHERE username = ? AND password = ?', 
                          (username, password)).fetchone()
        
        if user:
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = True
            
            write_audit_log(user['username'], user['role'], "Đăng nhập vào hệ thống", "Thành công")
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'auditor':
                return redirect(url_for('admin_view')) # Hoặc trang riêng của auditor để đọc log
            else:
                return redirect(url_for('home'))
        else:
            flash('Sai tên đăng nhập hoặc mật khẩu!', 'danger')
            write_audit_log(username, "Unknown", "Cố gắng đăng nhập bất hợp pháp", "Thất bại")
            
    return render_template('signin.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Khách')
    role = session.get('role', 'Không rõ')
    write_audit_log(username, role, "Đăng xuất khỏi hệ thống", "Thành công")
    session.clear()
    return redirect(url_for('signin'))

# --- TRANG CHỦ DÀNH CHO USER (NHẬP LIỆU & XEM) ---
@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' not in session or session['role'] != 'user':
        return redirect(url_for('signin'))
        
    db = get_db()
    username = session['username']
    role = session['role']
    
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        phone = request.form['phone']
        cipher_method = request.form['cipher_method'] # AES-GCM hoặc TripleDES
        
        # Tiền xử lý: Mã hóa dữ liệu TRƯỚC KHI đẩy xuống CSDL (Application-level Encryption)
        if cipher_method == 'AES-GCM':
            enc_email = encrypt_aes_gcm(email)
            enc_phone = encrypt_aes_gcm(phone)
        else:
            enc_email = encrypt_3des(email)
            enc_phone = encrypt_3des(phone)
            
        db.execute('INSERT INTO sensitive_data (fullname, email, phone, cipher_method, created_by) VALUES (?, ?, ?, ?, ?)',
                   (fullname, enc_email, enc_phone, cipher_method, username))
        db.commit()
        write_audit_log(username, role, f"Mã hóa & Lưu thông tin cho {fullname} ({cipher_method})", "Thành công")
        flash('Dữ liệu nhạy cảm đã được mã hóa an toàn và lưu vào CSDL!', 'success')
        
    # Lấy danh sách để User xem lại dữ liệu (Mặc định User tạo ra thì được quyền xem rõ)
    raw_data = db.execute('SELECT * FROM sensitive_data WHERE created_by = ?', (username,)).fetchall()
    
    processed_list = []
    for item in raw_data:
        # Giải mã trực tiếp để hiển thị lên màn hình của User
        if item['cipher_method'] == 'AES-GCM':
            dec_email = decrypt_aes_gcm(item['email'])
            dec_phone = decrypt_aes_gcm(item['phone'])
        else:
            dec_email = decrypt_3des(item['email'])
            dec_phone = decrypt_3des(item['phone'])
            
        processed_list.append({
            'id': item['id'],
            'fullname': item['fullname'],
            'email': dec_email,
            'phone': dec_phone,
            'cipher_method': item['cipher_method'],
            'raw_email': item['email'], # Truyền chuỗi mã hóa xuống để test hiển thị CSDL
            'raw_phone': item['phone']
        })
        
    return render_template('home.html', data_list=processed_list)

# --- TRANG XEM DÀNH CHO ADMIN VÀ AUDITOR ---
@app.route('/admin/view')
def admin_view():
    if 'username' not in session or session['role'] not in ['admin', 'auditor']:
        return redirect(url_for('signin'))
        
    db = get_db()
    username = session['username']
    role = session['role']
    
    # Kiểm tra xem Admin đã bấm nút xác nhận kích hoạt quyền giải mã chưa (Yêu cầu 12.3.0.8)
    # Mặc định Admin không xem được, Auditor không bao giờ được xem dữ liệu rõ.
    allow_decrypt = request.args.get('activate_override') == 'true' and role == 'admin'
    
    raw_data = db.execute('SELECT * FROM sensitive_data').fetchall()
    processed_list = []
    
    for item in raw_data:
        if allow_decrypt:
            # Chỉ giải mã khi Admin kích hoạt quyền khẩn cấp chủ động
            if item['cipher_method'] == 'AES-GCM':
                dec_email = decrypt_aes_gcm(item['email'])
                dec_phone = decrypt_aes_gcm(item['phone'])
            else:
                dec_email = decrypt_3des(item['email'])
                dec_phone = decrypt_3des(item['phone'])
            status_action = "Xác thực & Giải mã thành công"
        else:
            # Ngược lại, hoặc nếu là Auditor -> Giữ nguyên chuỗi mã hóa hoặc ẩn đi
            dec_email = "🔴 [BỊ CHẶN HOẶC CHƯA CẤP QUYỀN GIẢI MÃ]"
            dec_phone = "🔴 [BỊ CHẶN HOẶC CHƯA CẤP QUYỀN GIẢI MÃ]"
            status_action = "Xem dữ liệu ở dạng mã hóa ẩn"
            
        processed_list.append({
            'id': item['id'],
            'fullname': item['fullname'],
            'email': dec_email,
            'phone': dec_phone,
            'cipher_method': item['cipher_method'],
            'raw_email': item['email'],
            'raw_phone': item['phone']
        })
        
    if allow_decrypt:
        write_audit_log(username, role, "Kích hoạt khóa giải mã toàn bộ danh sách khách hàng nhạy cảm", "XÁC THỰC THÀNH CÔNG")
        
    # Đọc log hệ thống để hiển thị riêng cho Auditor/Admin giám sát
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = f.readlines()[::-1] # Đảo ngược để log mới nhất lên đầu
            
    return render_template('admin_view.html', data_list=processed_list, logs=logs, allow_decrypt=allow_decrypt)

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('signin'))
    return render_template('admin_dashboard.html')

# Khởi tạo DB khi ứng dụng bắt đầu chạy
init_sqlite_db()

# --- ĐOẠN SỬA CỔNG TỰ ĐỘNG CHO RENDER ---
# --- KHỞI CHẠY CHÍNH THỨC TRÊN RENDER ---
if __name__ == '__main__':
    init_sqlite_db()  # Khởi tạo database tại đây
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
