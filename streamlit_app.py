import subprocess
import streamlit as st
import streamlit.components.v1 as components
import time

# Kích hoạt Flask chạy ngầm nếu chưa chạy
@st.cache_resource
def start_flask():
    return subprocess.Popen(["python", "baomatdulieu.py"])

start_flask()

# Đợi 2 giây cho Flask khởi động xong
time.sleep(2)

# Cấu hình giao diện Streamlit tràn màn hình
st.set_page_config(layout="wide")

# Nhúng thẳng giao diện Flask (cổng 5000) vào giao diện Streamlit
components.iframe("http://127.0.0.1:5000", height=800, scrolling=True)
