"""Quantum Key selection preview: glowing D, two cubes tracing V contours."""
from pathlib import Path
import math
import time
import tkinter as tk
import ctypes
from PIL import Image, ImageTk, ImageGrab, ImageChops

OUT=Path(__file__).resolve().parent
# Traced from the unchanged carved V in the 1254 px artwork. No enclosing orbit.
OUTER=[(364,382),(546,382),(525,420),(636,734),(751,420),(716,382),
       (893,382),(888,396),(815,431),(657,895),(594,899),(420,432),(367,399)]
INNER=[(458,422),(520,422),(637,731),(752,422),(788,422),(623,862),(588,862)]

def signed_area(points):
    return sum(x1*y2-x2*y1 for (x1,y1),(x2,y2) in zip(points,points[1:]+points[:1]))/2

def orient(points,clockwise):
    # Positive signed area is clockwise in screen coordinates (y points down).
    return points if (signed_area(points)>0)==clockwise else list(reversed(points))

OUTER=orient(OUTER,True)
INNER=orient(INNER,False)
assert signed_area(OUTER)>0 and signed_area(INNER)<0

def path_point(points,fraction):
    segments=list(zip(points,points[1:]+points[:1]))
    lengths=[math.dist(a,b) for a,b in segments]
    distance=(fraction%1)*sum(lengths)
    for (a,b),length in zip(segments,lengths):
        if distance<=length:
            t=distance/length
            return a[0]+(b[0]-a[0])*t,a[1]+(b[1]-a[1])*t
        distance-=length
    return points[0]

root=tk.Tk(); root.title('D’Vielle — Quantum Key / dual cube animation')
root.geometry('600x650+15+15'); root.resizable(False,False)
canvas=tk.Canvas(root,width=600,height=650,bg='#050D1B',highlightthickness=0); canvas.pack()
with Image.open(OUT/'glowing-d-master.png') as source:
    assert source.size==(1254,1254)
    photo=ImageTk.PhotoImage(source.convert('RGB').resize((600,600),Image.Resampling.LANCZOS),master=canvas)

def cube(x,y,color):
    x,y=x*600/1254,y*600/1254
    r=7
    top=[(x,y-r),(x+r,y-r/2),(x,y),(x-r,y-r/2)]
    left=[(x-r,y-r/2),(x,y),(x,y+r),(x-r,y+r/2)]
    right=[(x,y),(x+r,y-r/2),(x+r,y+r/2),(x,y+r)]
    # Native isometric cube faces: dark solid faces, luminous edges, bright top.
    for points,fill in ((left,'#173144'),(right,'#304759'),(top,'#A9D2D7' if color=='#8AEFFF' else '#E8BB76')):
        flat=[v for point in points for v in point]
        canvas.create_polygon(*flat,fill=fill,outline=color,width=2)

def paint(fraction):
    canvas.delete('all')
    canvas.create_image(300,300,image=photo)
    cube(*path_point(OUTER,fraction+.12),'#FFD792')
    cube(*path_point(INNER,fraction+.62),'#8AEFFF')
    canvas.create_text(300,563,text='D’Vielle — Intelligent Vigilance',fill='#F2F6FF',font=('Segoe UI',18,'bold'))
    canvas.create_text(300,605,text='Gold cube: outer edge · clockwise',fill='#FFD792',font=('Segoe UI',11))
    canvas.create_text(300,630,text='Cyan cube: inner edge · anticlockwise',fill='#8AEFFF',font=('Segoe UI',11))

frames=[]
try:
    for i in range(80):
        paint(i/80)
        root.update()
        if i==0:
            root.lift()
            ctypes.windll.user32.SetForegroundWindow(ctypes.windll.user32.GetAncestor(root.winfo_id(),2))
            root.update(); time.sleep(.15)
        x,y=canvas.winfo_rootx(),canvas.winfo_rooty()
        frames.append(ImageGrab.grab(bbox=(x,y,x+600,y+650)).convert('RGB'))
        time.sleep(.015)
    frames[0].save(OUT/'quantum-key-dual-cubes.gif',save_all=True,append_images=frames[1:],duration=80,loop=0,disposal=2)
    frames[18].save(OUT/'quantum-key-dual-cubes-still.png')
    assert ImageChops.difference(frames[0],frames[20]).getbbox() is not None
    with Image.open(OUT/'quantum-key-dual-cubes.gif') as check:
        assert check.n_frames>=60 and check.size==(600,650)
    for path in (OUTER,INNER):
        assert path_point(path,0)==path_point(path,1)
    print('Verified opposite contour directions, closed paths, and animated GIF.',flush=True)
finally:
    root.destroy()
