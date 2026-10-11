"""Native drawn infinity animation, captured as a GIF; no application changes."""
from pathlib import Path
import ctypes
import math
import time
import tkinter as tk
from PIL import Image, ImageTk, ImageGrab, ImageChops

OUT = Path(__file__).resolve().parent
root = tk.Tk()
root.title('D’Vielle — Glowing infinity concept')
root.geometry('560x520+30+30')
root.resizable(False, False)
canvas = tk.Canvas(root, width=560, height=520, bg='#050D1B', highlightthickness=0)
canvas.pack()
with Image.open(OUT/'dv-infinity-master.png') as source:
    artwork = source.convert('RGBA').resize((360,360), Image.Resampling.LANCZOS)
photo = ImageTk.PhotoImage(artwork, master=canvas)

def point(t):
    return 280+245*math.sin(t), 320+80*math.sin(2*t)

def path_segment(start, end):
    points = [point(start+(end-start)*i/100) for i in range(101)]
    flat = [coordinate for xy in points for coordinate in xy]
    # Soft halo and one thin luminous core. No metal, bevel, or filled tube.
    for width,color in ((15,'#081C37'),(9,'#0A3454'),(5,'#116585'),(2,'#69E6FF')):
        canvas.create_line(*flat,fill=color,width=width,smooth=True)

def light(t):
    x,y=point(t)
    for r,color in ((10,'#0B3855'),(6,'#127FAD'),(3,'#9EF4FF'),(1.5,'#FFFFFF')):
        canvas.create_oval(x-r,y-r,x+r,y+r,fill=color,outline='')

def paint(phase):
    canvas.delete('all')
    path_segment(0,math.tau)
    for t in (phase,phase+math.pi):
        if point(t)[1]<320:
            light(t)
    canvas.create_image(280,218,image=photo)
    # Lower/front quarters cross in front; upper/rear quarters pass behind DV.
    path_segment(0,math.pi/2)
    path_segment(math.pi,math.pi*1.5)
    for t in (phase,phase+math.pi):
        if point(t)[1]>=320:
            light(t)
    canvas.create_text(280,457,text='D’Vielle',fill='#F2F7FF',font=('Segoe UI',27,'bold'))
    canvas.create_text(280,493,text='Intelligent Vigilance',fill='#ADCDEC',font=('Segoe UI',15))

paint(0)
root.update()
root.lift()
hwnd=ctypes.windll.user32.GetAncestor(root.winfo_id(),2)
ctypes.windll.user32.SetForegroundWindow(hwnd)
root.update()
frames=[]
try:
    for i in range(72):
        paint(i*math.tau/72)
        root.update()
        # Capture actual native vector animation, not an edited image composite.
        bounds=(canvas.winfo_rootx(),canvas.winfo_rooty(),
                canvas.winfo_rootx()+canvas.winfo_width(),canvas.winfo_rooty()+canvas.winfo_height())
        frames.append(ImageGrab.grab(bbox=bounds).convert('RGB'))
        time.sleep(.02)
    frames[0].save(OUT/'dv-glowing-infinity.gif',save_all=True,append_images=frames[1:],
                   duration=70,loop=0,disposal=2)
    frames[9].save(OUT/'dv-glowing-infinity-still.png')
    assert ImageChops.difference(frames[0],frames[18]).getbbox() is not None
    with Image.open(OUT/'dv-glowing-infinity.gif') as check:
        # GIF encoding coalesces identical frames when a light is occluded.
        assert check.n_frames>=24
        encoded_frames=check.n_frames
    print(f'Validated {encoded_frames}-frame glowing infinity preview:',OUT/'dv-glowing-infinity.gif')
finally:
    root.destroy()
