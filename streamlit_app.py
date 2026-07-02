import subprocess
import streamlit as st

# Giao diện hiển thị trạng thái trên Streamlit Cloud
st.title("Hệ Thống Bảo Mật Mã Hóa Đang Hoạt Động")
st.success("Ứng dụng Flask đang được kích hoạt chạy ngầm trên máy chủ!")

# Gọi trực tiếp file Flask của bạn chạy ngầm trên cổng 5000 cố định
subprocess.Popen(["python", "baomatdulieu.py"])
