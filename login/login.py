import sys
import os
import time
import datetime
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
from Node1.node import create_torrent
import json
from pathlib import Path
from tkinter import Tk, Canvas, Entry, Button, PhotoImage, Frame, messagebox, Label, Toplevel
from Node1.node import Connection

OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r".\assets\frame0")

def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)

# Hàm đọc dữ liệu người dùng từ user.json
def read_users():
    try:
        with open('user.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []  # Trả về danh sách trống nếu tệp không tồn tại

# Hàm ghi dữ liệu người dùng vào user.json
def write_users(users):
    with open('user.json', 'w') as f:
        json.dump(users, f)

# Hàm kiểm tra thông tin đăng nhập và chuyển sang dashboard
def login():
    email = entry_login_email.get()
    password = entry_login_password.get()
    users = read_users()
    # Kiểm tra thông tin đăng nhập
    for user in users:
        if user['email'] == email and user['password'] == password:
            messagebox.showinfo("Đăng nhập thành công", "Chào mừng bạn đến STA")
            show_dashboard()  # Chuyển sang trang dashboard
            return
    messagebox.showerror("Lỗi đăng nhập", "Email hoặc mật khẩu không đúng")

# Hàm chuyển sang giao diện đăng ký
def show_registration():
    registration_frame.lift()  # Hiển thị trang đăng ký

# Hàm mở giao diện dashboard sau khi đăng nhập thành công
def show_dashboard():
    dashboard_frame.lift()  # Hiển thị trang dashboard

# Hàm chuyển sang giao diện tracker
def show_tracker():
    tracker_frame.lift() # Hiển thị trang tracker

# Hàm chuyển sang giao diện peer
def show_peer():
    peer_frame.lift() # Hiển thị trang peer

# Hàm xử lý đăng ký tài khoản mới
def register():
    new_email = entry_reg_email.get()
    new_password = entry_reg_password.get()
    confirm_password = entry_confirm_password.get()
    users = read_users()

    if not new_email or not new_password:
        messagebox.showerror("Lỗi đăng ký", "Vui lòng điền đủ thông tin")
    elif new_password != confirm_password:
        messagebox.showerror("Lỗi đăng ký", "Mật khẩu xác nhận không khớp")
    elif any(user['email'] == new_email for user in users):
        messagebox.showerror("Lỗi đăng ký", "Email đã tồn tại")
    else:
        # Thêm người dùng mới vào danh sách và lưu vào tệp
        users.append({'email': new_email, 'password': new_password})
        write_users(users)
        messagebox.showinfo("Đăng ký thành công", "Tài khoản đã được tạo thành công!")
        login_frame.lift()  # Quay lại trang đăng nhập sau khi đăng ký thành công

def open_input_dialog():
    # Tạo cửa sổ mới
    dialog = Toplevel(dashboard_frame)
    dialog.title("Nhập Thông Tin")

    # Nhãn và ô nhập cho đường dẫn tệp/thư mục
    label_path = Label(dialog, text="Đường dẫn tệp/thư mục:")
    label_path.pack()
    entry_path = Entry(dialog, width=50)
    entry_path.pack()

    # Nhãn và ô nhập cho URL tracker
    label_tracker = Label(dialog, text="URL Tracker:")
    label_tracker.pack()
    entry_tracker = Entry(dialog, width=50)
    entry_tracker.pack()

    # Nút để xác nhận và gọi hàm create_torrent
    button_confirm = Button(dialog, text="Xác Nhận", command=lambda: confirm_and_create_torrent(entry_path.get(), entry_tracker.get(), dialog))
    button_confirm.pack()

# Cấu hình cửa sổ chính
window = Tk()
window.geometry("700x400")
window.configure(bg="#FFFFFF")

# Tạo các frame cho từng trang
login_frame = Frame(window, bg="#FFFFFF")
registration_frame = Frame(window, bg="#FFFFFF")
dashboard_frame = Frame(window, bg="#FFFFFF")
tracker_frame = Frame(window, bg="#FFFFFF")
peer_frame = Frame(window, bg="#FFFFFF")

for frame in (login_frame, registration_frame, dashboard_frame, tracker_frame, peer_frame):
    frame.place(x=0, y=0, width=700, height=400)

# --------------------- Nội dung trang đăng nhập ---------------------
canvas_login = Canvas(login_frame, bg="#FFFFFF", height=400, width=700, bd=0, highlightthickness=0, relief="ridge")
canvas_login.place(x=0, y=0)

image_background = PhotoImage(file=relative_to_assets("bg1.png"))
image_bg1 = canvas_login.create_image(502.0, 200.0, image=image_background)
image_image_hcmut = PhotoImage(file=relative_to_assets("hcmut.png"))
image_hcmut = canvas_login.create_image(160.0, 199.0, image=image_image_hcmut)

canvas_login.create_text(340.0, 24.0, anchor="nw", text="Welcome to", fill="#0E0E0F", font=("Montserrat Bold", 12 * -1))
canvas_login.create_text(343.0, 44.0, anchor="nw", text="Simple Torrent-like Application (STA)", fill="#0A27CF", font=("Montserrat ExtraBold", 16 * -1))

image_image_bg2 = PhotoImage(file=relative_to_assets("bg2.png"))
image_bg2 = canvas_login.create_image(495.0, 224.0, image=image_image_bg2)
image_image_bg_2 = PhotoImage(file=relative_to_assets("bg2.png"))
image_bg_2 = canvas_login.create_image(495.0, 270.0, image=image_image_bg_2)

canvas_login.create_text(375.0, 206.0, anchor="nw", text="Email", fill="#000000", font=("Montserrat Light", 10 * -1))
canvas_login.create_text(372.0, 250.0, anchor="nw", text="Password", fill="#000000", font=("Montserrat Light", 10 * -1))

canvas_login.create_text(397.0, 362.0, anchor="nw", text="Don’t have an account?", fill="#000000", font=("Montserrat Regular", 10 * -1))
# Tạo ô nhập liệu cho email và mật khẩu
image_login_email = PhotoImage(file=relative_to_assets("email.png"))
image_email = canvas_login.create_image(360.0, 223.0, image=image_login_email)
entry_login_email = Entry(login_frame, bd=0, bg="#D9D9D9", fg="#000716", highlightthickness=0)
entry_login_email.place(x=380.0, y=223.0, width=260.0, height=18.0)

image_login_password = PhotoImage(file=relative_to_assets("password.png"))
image_password = canvas_login.create_image(360.0, 268.0, image=image_login_password)
entry_login_password = Entry(login_frame, bd=0, bg="#D9D9D9", fg="#000716", highlightthickness=0, show="*")
entry_login_password.place(x=375.0, y=268.0, width=260.0, height=18.0)

# Tạo nút đăng nhập và liên kết với hàm login
button_login_image = PhotoImage(file=relative_to_assets("login.png"))
button_login = Button(login_frame, image=button_login_image, command=login, relief="flat")
button_login.place(x=345.0, y=315.0, width=300.0, height=35.0)

# Tạo nút chuyển sang giao diện đăng ký
button_image_register = PhotoImage(file=relative_to_assets("register.png"))
button_to_registration = Button(login_frame, image=button_image_register, command=show_registration, relief="flat")
button_to_registration.place(x=517.0, y=362.0, width=50.0, height=10.0)

# --------------------- Nội dung trang đăng ký ---------------------
canvas_reg = Canvas(registration_frame, bg="#FFFFFF", height=400, width=700, bd=0, highlightthickness=0, relief="ridge")
canvas_reg.place(x=0, y=0)

canvas_reg.create_text(280.0, 24.0, anchor="nw", text="REGISTER ACCOUNT", fill="#0A27CF", font=("Montserrat ExtraBold", 16 * -1))

# Ô nhập email, mật khẩu và xác nhận mật khẩu
canvas_reg.create_text(220.0, 85.0, anchor="nw", text="Email", fill="#000000", font=("Nunito Light", 10 * -1))
entry_reg_email = Entry(registration_frame, bd=0, bg="#D9D9D9", fg="#000716", highlightthickness=0)
entry_reg_email.place(x=220.0, y=100.0, width=260.0, height=30.0)

canvas_reg.create_text(220.0, 135.0, anchor="nw", text="Password", fill="#000000", font=("Nunito Light", 10 * -1))
entry_reg_password = Entry(registration_frame, bd=0, bg="#D9D9D9", fg="#000716", highlightthickness=0, show="*")
entry_reg_password.place(x=220.0, y=150.0, width=260.0, height=30.0)

canvas_reg.create_text(220.0, 185.0, anchor="nw", text="Comfirm Password", fill="#000000", font=("Nunito Light", 10 * -1))
entry_confirm_password = Entry(registration_frame, bd=0, bg="#D9D9D9", fg="#000716", highlightthickness=0, show="*")
entry_confirm_password.place(x=220.0, y=200.0, width=260.0, height=30.0)

# Nút đăng ký
button_register_image = PhotoImage(file=relative_to_assets("signup.png"))
button_register = Button(registration_frame,image=button_register_image, text="Đăng ký", command=register, relief="flat")
button_register.place(x=220.0, y=250.0, width=260.0, height=35.0)

# Nút quay lại đăng nhập
button_back_to_login = Button(registration_frame, text="Back", command=login_frame.lift, relief="flat")
button_back_to_login.place(x=10, y=10, width=100, height=35)

# --------------------- Nội dung trang dashboard ---------------------
canvas_dash = Canvas(dashboard_frame, bg="#FFFFFF", height=400, width=700, bd=0, highlightthickness=0, relief="ridge")
canvas_dash.place(x=0, y=0)

canvas_dash.create_text(42.0, 6.0, anchor="nw", text="Simple Torrent-like Application (STA)", fill="#000000", font=("Montserrat Regular", 14 * -1))

def confirm_and_create_torrent(path, tracker_url, dialog):
    # Gọi hàm create_torrent với các thông tin đã nhập
    create_torrent(path, tracker_url)
    
    # Hiển thị thông tin torrent
    display_torrent_info(path)
    
    # Đóng cửa sổ nhập thông tin
    dialog.destroy()

def display_torrent_info(path):
    # Tạo tên tệp torrent
    torrent_name = os.path.basename(path) + '.torrent'

    # Hiển thị tên tệp torrent
    canvas_dash.create_text(150, 100, anchor="nw", text=f"Tên tệp: {torrent_name}", fill="#000000", font=("Montserrat Regular", 12))

    # Hiển thị ngày tải tệp
    download_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Lấy ngày giờ hiện tại
    canvas_dash.create_text(150, 130, anchor="nw", text=f"Ngày tải: {download_date}", fill="#000000", font=("Montserrat Regular", 12))
    global progress_bar

    # Tạo thanh tiến trình (có thể đặt sẵn)
    progress_bar = Canvas(dashboard_frame, bg="#D3D3D3", height=30, width=450, bd=0, highlightthickness=0, relief="ridge")
    progress_bar.place(x=150, y=170)
    
    # Hiển thị thanh tiến trình, ở đây có thể để không hiển thị gì (rỗng)
    progress_bar.create_rectangle(0, 0, 0, 30, fill="#4CAF50")  # Mặc định thanh tiến trình rỗng

image_image_hcmut2 = PhotoImage(file=relative_to_assets("hcmut2.png"))
image_hcmut2 = canvas_dash.create_image(16.0, 15.0, image=image_image_hcmut2)
image_image_folder = PhotoImage(file=relative_to_assets("folder.png"))
image_folder = canvas_dash.create_image(81.0, 182.0, image=image_image_folder)

button_image_dashboard1 = PhotoImage(file=relative_to_assets("dashboard.png"))
button_dashboard1 = Button(dashboard_frame, image=button_image_dashboard1, borderwidth=0, highlightthickness=0, command=show_dashboard, relief="flat")
button_dashboard1.place(x=17.0, y=34.0, width=80.0, height=20.0)

button_image_tracker1 = PhotoImage(file=relative_to_assets("tracker.png"))
button_tracker1 = Button(dashboard_frame, image=button_image_tracker1, borderwidth=0, highlightthickness=0, command=show_tracker, relief="flat")
button_tracker1.place(x=124.0, y=34.0, width=60.0, height=20.0)

button_image_peer1 = PhotoImage(file=relative_to_assets("peer.png"))
button_peer1 = Button(dashboard_frame, image=button_image_peer1, borderwidth=0, highlightthickness=0, command=show_peer, relief="flat")
button_peer1.place( x=211.0, y=35.0, width=100.0, height=20.0)

button_image_create = PhotoImage(file=relative_to_assets("create.png"))
button_create = Button(dashboard_frame, image=button_image_create, borderwidth=0, highlightthickness=0, command=open_input_dialog, relief="flat")
button_create.place(x=22.0, y=60.0, width=30.0, height=30.0)

button_image_start = PhotoImage(file=relative_to_assets("start.png"))
button_start = Button(dashboard_frame, image=button_image_start, borderwidth=0, highlightthickness=0, command=lambda: print("start clicked"), relief="flat")
button_start.place(x=73.0, y=60.0, width=30.0, height=30.0)

# button_image_pause = PhotoImage(file=relative_to_assets("pause.png"))
# button_pause = Button(dashboard_frame, image=button_image_pause, borderwidth=0, highlightthickness=0, command=lambda: print("button_7 clicked"), relief="flat")
# button_pause.place(x=124.0, y=59.0, width=30.0, height=30.0)

# button_image_stop = PhotoImage(file=relative_to_assets("stop.png"))
# button_stop = Button(dashboard_frame, image=button_image_stop, borderwidth=0, highlightthickness=0, command=lambda: print("button_6 clicked"), relief="flat")
# button_stop.place(x=175.0, y=60.0, width=30.0, height=30.0)

# Nút đăng xuất
# button_logout = Button(dashboard_frame, text="Đăng xuất", command=login_frame.lift, relief="flat")
# button_logout.place(x=10, y=10, width=100, height=35)

# --------------------- Nội dung trang tracker ---------------------
canvas_tracker = Canvas(tracker_frame, bg="#FFFFFF", height=400, width=700, bd=0, highlightthickness=0, relief="ridge")
canvas_tracker.place(x=0, y=0)

canvas_tracker.create_text(42.0, 6.0, anchor="nw", text="Simple Torrent-like Application (STA)", fill="#000000", font=("Montserrat Regular", 14 * -1))

image_image_hcmut23 = PhotoImage(file=relative_to_assets("hcmut3.png"))
image_hcmut23 = canvas_tracker.create_image(16.0, 15.0, image=image_image_hcmut23)

button_image_dashboard2 = PhotoImage(file=relative_to_assets("dashboard.png"))
button_dashboard2 = Button(tracker_frame, image=button_image_dashboard2, borderwidth=0, highlightthickness=0, command=show_dashboard, relief="flat")
button_dashboard2.place(x=17.0, y=34.0, width=80.0, height=20.0)

button_image_tracker2 = PhotoImage(file=relative_to_assets("tracker.png"))
button_tracker2 = Button(tracker_frame, image=button_image_tracker2, borderwidth=0, highlightthickness=0, command=show_tracker, relief="flat")
button_tracker2.place(x=124.0, y=34.0, width=60.0, height=20.0)

button_image_peer2 = PhotoImage(file=relative_to_assets("peer.png"))
button_peer2 = Button(tracker_frame, image=button_image_peer2, borderwidth=0, highlightthickness=0, command=show_peer, relief="flat")
button_peer2.place( x=211.0, y=35.0, width=100.0, height=20.0)

def load_tracker_info(info_hash):
    # Load the torrent information from the torrents.json file
    torrents_file = 'torrents_files.json'
    if os.path.exists(torrents_file):
        with open(torrents_file, 'r') as f:
            torrents = json.load(f)
            return torrents.get(info_hash, None)
    return None

def display_tracker_info(info_hash):
    tracker_info = load_tracker_info(info_hash)
    
    if tracker_info:
        name = tracker_info.get('name')
        file_size = tracker_info.get('file_size', 'Unknown')
        seeders = tracker_info.get('seeder', 0)
        leechers = tracker_info.get('leecher', 0)
        date_uploaded = datetime.fromtimestamp(tracker_info.get('date_uploaded')).strftime('%Y-%m-%d %H:%M:%S')
        created_by = tracker_info.get('created_by', 'Unknown')
        completed = tracker_info.get('completed', 0)

        # Displaying the information on the canvas
        canvas_tracker.create_text(42.0, 60.0, anchor="nw", text=f"Tên file: {name}", fill="#000000", font=("Montserrat Regular", 12))
        canvas_tracker.create_text(42.0, 80.0, anchor="nw", text=f"Kích thước: {file_size} bytes", fill="#000000", font=("Montserrat Regular", 12))
        canvas_tracker.create_text(42.0, 100.0, anchor="nw", text=f"Seeders: {seeders}", fill="#000000", font=("Montserrat Regular", 12))
        canvas_tracker.create_text(42.0, 120.0, anchor="nw", text=f"Leechers: {leechers}", fill="#000000", font=("Montserrat Regular", 12))
        canvas_tracker.create_text(42.0, 140.0, anchor="nw", text=f"Ngày tải: {date_uploaded}", fill="#000000", font=("Montserrat Regular", 12))
        canvas_tracker.create_text(42.0, 160.0, anchor="nw", text=f"Người tải: {created_by}", fill="#000000", font=("Montserrat Regular", 12))
        canvas_tracker.create_text(42.0, 180.0, anchor="nw", text=f"Số lần tải: {completed}", fill="#000000", font=("Montserrat Regular", 12))

    else:
        canvas_tracker.create_text(42.0, 60.0, anchor="nw", text="Thông tin không tìm thấy.", fill="#FF0000", font=("Montserrat Regular", 12))

# Example function to show tracker for a specific info_hash
def show_tracker(info_hash):
    canvas_tracker.delete("all")  # Clear previous content
    display_tracker_info(info_hash)  # Load and display tracker info

# --------------------- Nội dung trang peer ---------------------
canvas_peer = Canvas(peer_frame, bg="#FFFFFF", height=400, width=700, bd=0, highlightthickness=0, relief="ridge")
canvas_peer.place(x=0, y=0)

canvas_peer.create_text(42.0, 6.0, anchor="nw", text="Simple Torrent-like Application (STA)", fill="#000000", font=("Montserrat Regular", 14 * -1))

image_image_hcmut24 = PhotoImage(file=relative_to_assets("hcmut4.png"))
image_hcmut24 = canvas_peer.create_image(16.0, 15.0, image=image_image_hcmut24)

button_image_dashboard3 = PhotoImage(file=relative_to_assets("dashboard.png"))
button_dashboard3 = Button(peer_frame, image=button_image_dashboard3, borderwidth=0, highlightthickness=0, command=show_dashboard, relief="flat")
button_dashboard3.place(x=17.0, y=34.0, width=80.0, height=20.0)

button_image_tracker3 = PhotoImage(file=relative_to_assets("tracker.png"))
button_tracker3 = Button(peer_frame, image=button_image_tracker3, borderwidth=0, highlightthickness=0, command=show_tracker, relief="flat")
button_tracker3.place(x=124.0, y=34.0, width=60.0, height=20.0)

button_image_peer3 = PhotoImage(file=relative_to_assets("peer.png"))
button_peer3 = Button(peer_frame, image=button_image_peer3, borderwidth=0, highlightthickness=0, command=show_peer, relief="flat")
button_peer3.place( x=211.0, y=35.0, width=100.0, height=20.0)

# Hiển thị trang đăng nhập mặc định
login_frame.lift()
window.resizable(False, False)
window.mainloop()
