"""Quantum Key slow decorative communication preview; no audio or telemetry."""
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
with Image.open(OUT/'cool-blue-d-master.png') as source:
    assert source.size==(1254,1254)
    photo=ImageTk.PhotoImage(source.convert('RGB').resize((600,600),Image.Resampling.LANCZOS),master=canvas)

def cube(x,y,color,phase,active):
    x,y=x*600/1254,y*600/1254
    r=8
    top=[(x,y-r),(x+r,y-r/2),(x,y),(x-r,y-r/2)]
    left=[(x-r,y-r/2),(x,y),(x,y+r),(x-r,y+r/2)]
    right=[(x,y),(x+r,y-r/2),(x+r,y+r/2),(x,y+r)]
    blue=color=='#8AEFFF'
    # Soft native glow strokes around the three dimensional-looking faces.
    for points in (left,right,top):
        flat=[v for point in points for v in point]
        canvas.create_polygon(*flat,fill='',outline='#123F64' if blue else '#654119',width=7)
    for points,fill in ((left,'#125A88' if blue else '#966010'),
                        (right,'#238EBC' if blue else '#C68920'),
                        (top,'#B0F1FF' if blue else '#FFE3A2')):
        flat=[v for point in points for v in point]
        canvas.create_polygon(*flat,fill=fill,outline=color,width=2)

    # Wi-Fi fan follows each cube. Progressive arcs suggest sending/listening.
    signal=int(phase*12)%3+1
    for level in range(1,4):
        radius=4+level*4
        canvas.create_arc(x-radius,y-19-radius,x+radius,y-19+radius,
                          start=45,extent=90,style='arc',
                          outline=color if level<=signal else '#344653',width=1.5)
    canvas.create_oval(x-1.5,y-20.5,x+1.5,y-17.5,fill=color,outline='')
    # Speaker and moving sound bars are visual symbols, not actual sound.
    sx,sy=x+15,y+3
    canvas.create_polygon(sx,sy-3,sx+3,sy-3,sx+6,sy-6,sx+6,sy+6,sx+3,sy+3,sx,sy+3,
                          fill=color if active else '#657782',outline='')
    for index in range(3):
        amplitude=(3+4*(.5+.5*math.sin(phase*math.tau*6+index))) if active else 2
        bx=sx+10+index*4
        canvas.create_line(bx,sy-amplitude,bx,sy+amplitude,fill=color if active else '#344653',width=1.5)

def investigating_progress(fraction):
    # Four slow legs, smoothly accelerating and stopping to inspect each quarter.
    leg=fraction*4
    index=math.floor(leg)
    step=min(1,(leg-index)/.78)
    eased=step*step*(3-2*step)
    return (index+eased)/4

def paint(fraction):
    canvas.delete('all')
    canvas.create_image(300,300,image=photo)
    progress=investigating_progress(fraction)
    gold_talking=int(fraction*8)%2==0
    cube(*path_point(OUTER,progress+.12),'#FFD792',fraction,gold_talking)
    cube(*path_point(INNER,progress+.62),'#8AEFFF',fraction,not gold_talking)
    canvas.create_text(300,563,text='D’Vielle — Intelligent Vigilance',fill='#F2F6FF',font=('Segoe UI',18,'bold'))
    canvas.create_text(300,605,text='Gold: clockwise · Blue: anticlockwise',fill='#CFDDF0',font=('Segoe UI',11))
    canvas.create_text(300,630,text='Slow inspection · visual Wi-Fi and communication',fill='#8CBAD6',font=('Segoe UI',10))

frames=[]
try:
    for i in range(160):
        paint(i/160)
        root.update()
        if i==0:
            root.lift()
            ctypes.windll.user32.SetForegroundWindow(ctypes.windll.user32.GetAncestor(root.winfo_id(),2))
            root.update(); time.sleep(.15)
        x,y=canvas.winfo_rootx(),canvas.winfo_rooty()
        frames.append(ImageGrab.grab(bbox=(x,y,x+600,y+650)).convert('RGB'))
        time.sleep(.015)
    frames[0].save(OUT/'quantum-key-communicating-cubes.gif',save_all=True,append_images=frames[1:],duration=180,loop=0,disposal=2)
    frames[18].save(OUT/'quantum-key-communicating-cubes-still.png')
    assert ImageChops.difference(frames[0],frames[20]).getbbox() is not None
    with Image.open(OUT/'quantum-key-communicating-cubes.gif') as check:
        assert check.n_frames>=100 and check.size==(600,650)
        duration=sum((check.seek(i) or check.info.get('duration',0)) for i in range(check.n_frames))
        assert duration>=28000
    for path in (OUTER,INNER):
        assert path_point(path,0)==path_point(path,1)
    assert investigating_progress(0)==0 and investigating_progress(1)==1
    assert investigating_progress(.21)==investigating_progress(.24)
    print('Verified slow 28.8-second cycle, inspection pauses, opposite directions and visual communication.',flush=True)
finally:
    root.destroy()
