import os
import subprocess
import streamlit as str

# Giao diện hiển thị trạng thái trên Streamlit Cloud
str.title("Hệ Thống Bảo Mật Mã Hóa Đang Hoạt Động")
str.write("Ứng dụng Flask đang chạy ngầm trên máy chủ.")

# Lấy cổng mạng (Port) do Streamlit cấp phát ngẫu nhiên
port = os.environ.get("PORT", 8501)

# Lệnh kích hoạt file Flask của bạn chạy ngầm
subprocess.Popen(["python", "baomatdulieu.py", "--port", str(port)])