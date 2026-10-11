"""Ten code-native animated DV concept surrounds; capture actual Tk renders."""
from pathlib import Path
import math
import time
import ctypes
import sys
import tkinter as tk
from PIL import Image, ImageTk, ImageGrab, ImageChops

OUT=Path(__file__).resolve().parent/'quantum-ten'
OUT.mkdir(exist_ok=True)
SOURCE=OUT.parent/'dv-infinity-master.png'
NAMES=['Azure Infinity','Violet Entanglement','Foldspace Drift','Aurora Circuit',
       'Quantum Lattice','Photon Wake','Split Phase','Prism Gate','Stellar Vigil','Zero Point']
TAU=math.tau
BG='#050D1B'
root=tk.Tk()
root.title('D’Vielle — ten animated quantum-inspired concepts')
root.geometry('900x660+10+10')
root.resizable(False,False)
canvas=tk.Canvas(root,width=900,height=660,bg=BG,highlightthickness=0)
canvas.pack()
with Image.open(SOURCE) as source:
    photo=ImageTk.PhotoImage(source.convert('RGBA').resize((178,178),Image.Resampling.LANCZOS),master=canvas)

def draw_tile(number,ox,oy,phase):
    def line(points,color,width=1):
        coords=[v for x,y in points for v in (x+ox,y+oy)]
        canvas.create_line(*coords,fill=color,width=width,smooth=True)
    def dot(x,y,color,r=2):
        canvas.create_oval(ox+x-r,oy+y-r,ox+x+r,oy+y+r,fill=color,outline='')
    def orbit(t,angle=0,shift=0,scale=1):
        x,y=128*math.sin(t)*scale,37*math.sin(2*t)*scale
        return 150+x*math.cos(angle)-y*math.sin(angle),190+shift+x*math.sin(angle)+y*math.cos(angle)
    def path(color,angle=0,shift=0,scale=1):
        points=[orbit(i*TAU/160,angle,shift,scale) for i in range(161)]
        for width,tone in ((9,'#091E39'),(5,'#143653'),(1.5,color)):
            line(points,tone,width)
    def particle(t,color,angle=0,shift=0,scale=1):
        x,y=orbit(t,angle,shift,scale)
        dot(x,y,'#123950',6); dot(x,y,color,3); dot(x,y,'#EEFCFF',1)

    canvas.create_rectangle(ox+7,oy+7,ox+293,oy+323,fill=BG,outline='#1D3552')
    canvas.create_text(ox+150,oy+27,text=f'{number:02} · {NAMES[number-1]}',
                       fill='#C9E2FA',font=('Segoe UI',11,'bold'))
    angle=0; color='#72ECFF'; shift=0
    if number==2: angle=.25; color='#BDA0FF'
    if number==3: angle=.20*math.sin(phase)
    if number==4: color='#74F2CF'
    if number==7: shift=-8; color='#79DAFF'
    if number==10: color='#D9F7FF'

    if number==5:
        for x in (62,102,142,182,222):
            line([(x,64),(x+20,88),(x,112),(x+20,136),(x,160)],'#14354B')
        line([(38,80),(150,48),(262,80),(262,215),(150,246),(38,215),(38,80)],'#224457')
    if number==8:
        points=[(150,52),(270,238),(30,238),(150,52)]
        line(points,'#255576',3); line(points,'#77DCFF')
        t=(phase/TAU*3)%3; index=int(t); u=t-index
        a,b=points[index],points[index+1]
        dot(a[0]+(b[0]-a[0])*u,a[1]+(b[1]-a[1])*u,'#D2FAFF',3)
    if number==9:
        stars=[(38,73),(76,57),(225,62),(267,103),(246,152),(46,149)]
        line(stars[:2],'#263C65'); line(stars[2:5],'#263C65')
        for i,(x,y) in enumerate(stars): dot(x,y,'#AEC9FF',1.5+.4*math.sin(phase+i))
    if number==10:
        line([(150,56),(242,148),(150,241),(58,148),(150,56)],'#2C5265')
    path(color,angle,shift)
    if number==2: path('#65E5FF',-.25,8)
    if number==4: path('#BD97FF',-.12,4,.94)
    if number==7: path('#E9C68A',0,8)
    float_y=3*math.sin(phase) if number in (3,8,9) else 0
    canvas.create_image(ox+150,oy+137+float_y,image=photo)
    # Redraw the lower front arcs; remaining path passes behind the DV.
    for start in (0,math.pi):
        points=[orbit(start+i*math.pi/2/50,angle,shift) for i in range(51)]
        line(points,'#143653',5); line(points,color,1.5)
    for t in (phase,phase+math.pi):
        particle(t,color,angle,shift)
    if number==2:
        for t in (-phase,-phase+math.pi): particle(t,'#7DDCFF',-.25,8)
    if number==4:
        particle(-phase,'#D3AEFF',-.12,4,.94)
    if number==6:
        for offset in (.10,.20,.30,.40):
            x,y=orbit(phase-offset)
            dot(x,y,'#3583A7',max(1,3-offset*4))
            x,y=orbit(phase+math.pi-offset)
            dot(x,y,'#3583A7',max(1,3-offset*4))
        particle(phase+math.pi/2,'#B8F6FF')
    if number==7: particle(-phase,'#FFE4AD',0,8)
    if number==10:
        particle(phase+math.pi/2,color); particle(phase+math.pi*1.5,color)
    canvas.create_text(ox+150,oy+272,text='D’Vielle',fill='#F2F7FF',font=('Segoe UI',18,'bold'))
    canvas.create_text(ox+150,oy+302,text='Intelligent Vigilance',fill='#8EADC9',font=('Segoe UI',10))

try:
    for board in (() if '--verify-only' in sys.argv else (0,1)):
        frames=[]; tiles=[[] for _ in range(5)]
        for i in range(48):
            canvas.delete('all')
            phase=i*TAU/48
            for slot in range(5):
                draw_tile(board*5+slot+1,(slot%3)*300,(slot//3)*330,phase)
            canvas.create_text(750,460,text='D’Vielle',fill='#CFE8FF',font=('Segoe UI',25,'bold'))
            canvas.create_text(750,500,text='Quantum-inspired concepts',fill='#A9BDD6',font=('Segoe UI',11))
            canvas.create_text(750,530,text=f'Choose {board*5+1:02}–{board*5+5:02}',fill='#67DFFF',font=('Segoe UI',15))
            root.update()
            if i==0:
                root.lift()
                hwnd=ctypes.windll.user32.GetAncestor(root.winfo_id(),2)
                ctypes.windll.user32.SetForegroundWindow(hwnd)
                root.update(); time.sleep(.15)
            x,y=canvas.winfo_rootx(),canvas.winfo_rooty()
            frame=ImageGrab.grab(bbox=(x,y,x+900,y+660)).convert('RGB')
            frames.append(frame)
            for slot in range(5):
                left,top=(slot%3)*300,(slot//3)*330
                tiles[slot].append(frame.crop((left,top,left+300,top+330)))
            time.sleep(.015)
        frames[0].save(OUT/f'board-{board+1}.gif',save_all=True,append_images=frames[1:],duration=90,loop=0,disposal=2)
        frames[6].save(OUT/f'board-{board+1}-still.png')
        for slot,sample in enumerate(tiles):
            number=board*5+slot+1
            sample[0].save(OUT/f'concept-{number:02}.gif',save_all=True,append_images=sample[1:],duration=90,loop=0,disposal=2)
            sample[6].save(OUT/f'concept-{number:02}-still.png')
            assert ImageChops.difference(sample[0],sample[7]).getbbox() is not None
            with Image.open(OUT/f'concept-{number:02}.gif') as check:
                assert check.n_frames>=24 and check.size==(300,330)
            print(f'Validated {number:02} {NAMES[number-1]}',flush=True)
finally:
    root.destroy()

for number in range(1,11):
    with Image.open(OUT/f'concept-{number:02}.gif') as check:
        assert check.n_frames>=24 and check.size==(300,330)
        first=check.convert('RGB')
        check.seek(7)
        assert ImageChops.difference(first,check.convert('RGB')).getbbox() is not None
    print(f'GIF decoded and motion verified: {number:02}',flush=True)

cards=''.join(f'<article><h2>{i:02} · {name}</h2><img src="concept-{i:02}.gif" data-gif="concept-{i:02}.gif" data-still="concept-{i:02}-still.png" alt="Animated DV logo concept {name}"></article>' for i,name in enumerate(NAMES,1))
html='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>D’Vielle — 10 logo concepts</title><style>body{background:#050d1b;color:#eaf4ff;font:16px Segoe UI,sans-serif;margin:32px}h1{font-size:28px}button{background:#91c9ff;border:0;border-radius:8px;padding:12px 20px;cursor:pointer}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-top:25px}article{border:1px solid #25415f;border-radius:16px;padding:14px;text-align:center}h2{font-size:18px}img{max-width:100%;height:auto}</style><h1>D’Vielle — Intelligent Vigilance</h1><p>10 quantum-inspired animated logo concepts. Decorative designs; application unchanged.</p><button id="motion">Pause animations</button><main>'''+cards+'''</main><script>let paused=matchMedia('(prefers-reduced-motion: reduce)').matches;function paint(){document.querySelectorAll('img').forEach(i=>i.src=paused?i.dataset.still:i.dataset.gif);document.getElementById('motion').textContent=paused?'Play animations':'Pause animations'}document.getElementById('motion').onclick=()=>{paused=!paused;paint()};paint()</script></html>'''
(OUT/'gallery.html').write_text(html,encoding='utf-8')
print('Saved ten individual GIFs, two animated boards, and gallery.',flush=True)
