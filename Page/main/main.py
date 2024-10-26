
# This file was generated by the Tkinter Designer by Parth Jadhav
# https://github.com/ParthJadhav/Tkinter-Designer


from pathlib import Path

# from tkinter import *
# Explicit imports to satisfy Flake8
from tkinter import Tk, Canvas, Entry, Text, Button, PhotoImage


OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r".\assets\frame0")


def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)


window = Tk()

window.geometry("700x400")
window.configure(bg = "#FFFFFF")


canvas = Canvas(
    window,
    bg = "#FFFFFF",
    height = 400,
    width = 700,
    bd = 0,
    highlightthickness = 0,
    relief = "ridge"
)

canvas.place(x = 0, y = 0)
image_image_1 = PhotoImage(
    file=relative_to_assets("image_1.png"))
image_1 = canvas.create_image(
    350.0,
    15.0,
    image=image_image_1
)

image_image_2 = PhotoImage(
    file=relative_to_assets("image_2.png"))
image_2 = canvas.create_image(
    350.0,
    45.0,
    image=image_image_2
)

image_image_3 = PhotoImage(
    file=relative_to_assets("image_3.png"))
image_3 = canvas.create_image(
    350.0,
    75.0,
    image=image_image_3
)

canvas.create_text(
    42.0,
    6.0,
    anchor="nw",
    text="Simple Torrent-like Application (STA)",
    fill="#000000",
    font=("Montserrat Regular", 14 * -1)
)

button_image_1 = PhotoImage(
    file=relative_to_assets("button_1.png"))
button_1 = Button(
    image=button_image_1,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_1 clicked"),
    relief="flat"
)
button_1.place(
    x=17.0,
    y=34.0,
    width=30.0,
    height=20.0
)

button_image_2 = PhotoImage(
    file=relative_to_assets("button_2.png"))
button_2 = Button(
    image=button_image_2,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_2 clicked"),
    relief="flat"
)
button_2.place(
    x=63.0,
    y=34.0,
    width=35.0,
    height=20.0
)

button_image_3 = PhotoImage(
    file=relative_to_assets("button_3.png"))
button_3 = Button(
    image=button_image_3,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_3 clicked"),
    relief="flat"
)
button_3.place(
    x=114.0,
    y=34.0,
    width=60.0,
    height=20.0
)

button_image_4 = PhotoImage(
    file=relative_to_assets("button_4.png"))
button_4 = Button(
    image=button_image_4,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_4 clicked"),
    relief="flat"
)
button_4.place(
    x=190.0,
    y=34.0,
    width=60.0,
    height=20.0
)

button_image_5 = PhotoImage(
    file=relative_to_assets("button_5.png"))
button_5 = Button(
    image=button_image_5,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_5 clicked"),
    relief="flat"
)
button_5.place(
    x=266.0,
    y=35.0,
    width=40.0,
    height=20.0
)

button_image_6 = PhotoImage(
    file=relative_to_assets("button_6.png"))
button_6 = Button(
    image=button_image_6,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_6 clicked"),
    relief="flat"
)
button_6.place(
    x=322.0,
    y=35.0,
    width=40.0,
    height=20.0
)

button_image_7 = PhotoImage(
    file=relative_to_assets("button_7.png"))
button_7 = Button(
    image=button_image_7,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_7 clicked"),
    relief="flat"
)
button_7.place(
    x=12.0,
    y=60.0,
    width=30.0,
    height=30.0
)

button_image_8 = PhotoImage(
    file=relative_to_assets("button_8.png"))
button_8 = Button(
    image=button_image_8,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_8 clicked"),
    relief="flat"
)
button_8.place(
    x=48.0,
    y=60.0,
    width=29.18918800354004,
    height=30.0
)

image_image_4 = PhotoImage(
    file=relative_to_assets("image_4.png"))
image_4 = canvas.create_image(
    350.0,
    100.0,
    image=image_image_4
)

image_image_5 = PhotoImage(
    file=relative_to_assets("image_5.png"))
image_5 = canvas.create_image(
    350.0,
    247.0,
    image=image_image_5
)

image_image_6 = PhotoImage(
    file=relative_to_assets("image_6.png"))
image_6 = canvas.create_image(
    350.0,
    392.0,
    image=image_image_6
)

image_image_7 = PhotoImage(
    file=relative_to_assets("image_7.png"))
image_7 = canvas.create_image(
    249.0,
    137.0,
    image=image_image_7
)

canvas.create_rectangle(
    100.0,
    177.0,
    600.0,
    192.0,
    fill="#D9D9D9",
    outline="")

canvas.create_rectangle(
    100.0,
    177.0,
    199.0,
    192.0,
    fill="#2CEC2C",
    outline="")

canvas.create_text(
    103.0,
    130.0,
    anchor="nw",
    text="Tên Thư mục",
    fill="#000000",
    font=("Montserrat Regular", 12 * -1)
)

canvas.create_text(
    99.0,
    157.0,
    anchor="nw",
    text="82.3 MB of 450MB (20%) - 2 minutes, 13 seconds left",
    fill="#000000",
    font=("Montserrat Regular", 12 * -1)
)

canvas.create_text(
    99.0,
    200.0,
    anchor="nw",
    text="Downloading from 4 of 4 connected peers - ",
    fill="#000000",
    font=("Montserrat Regular", 11 * -1)
)

canvas.create_text(
    15.0,
    223.0,
    anchor="nw",
    text="Show:",
    fill="#000000",
    font=("Montserrat Regular", 11 * -1)
)

image_image_8 = PhotoImage(
    file=relative_to_assets("image_8.png"))
image_8 = canvas.create_image(
    350.0,
    309.0,
    image=image_image_8
)

canvas.create_text(
    25.0,
    250.0,
    anchor="nw",
    text="Connecting: ",
    fill="#000000",
    font=("Montserrat Regular", 11 * -1)
)

canvas.create_text(
    25.0,
    280.0,
    anchor="nw",
    text="Sharing:",
    fill="#000000",
    font=("Montserrat Regular", 11 * -1)
)

canvas.create_text(
    25.0,
    310.0,
    anchor="nw",
    text="Download: ",
    fill="#000000",
    font=("Montserrat Regular", 11 * -1)
)

button_image_9 = PhotoImage(
    file=relative_to_assets("button_9.png"))
button_9 = Button(
    image=button_image_9,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_9 clicked"),
    relief="flat"
)
button_9.place(
    x=84.0,
    y=60.0,
    width=30.0,
    height=30.0
)

button_image_10 = PhotoImage(
    file=relative_to_assets("button_10.png"))
button_10 = Button(
    image=button_image_10,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_10 clicked"),
    relief="flat"
)
button_10.place(
    x=164.0,
    y=60.0,
    width=30.0,
    height=30.0
)

button_image_11 = PhotoImage(
    file=relative_to_assets("button_11.png"))
button_11 = Button(
    image=button_image_11,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: print("button_11 clicked"),
    relief="flat"
)
button_11.place(
    x=124.0,
    y=60.0,
    width=30.0,
    height=30.0
)

image_image_9 = PhotoImage(
    file=relative_to_assets("image_9.png"))
image_9 = canvas.create_image(
    46.0,
    171.0,
    image=image_image_9
)

image_image_10 = PhotoImage(
    file=relative_to_assets("image_10.png"))
image_10 = canvas.create_image(
    16.0,
    15.0,
    image=image_image_10
)
window.resizable(False, False)
window.mainloop()
