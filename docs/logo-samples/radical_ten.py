"""Render new emblem concepts as native animated selection boards, without orbits."""
from pathlib import Path
import math
import tkinter as tk
import ctypes
import time
import sys
from PIL import Image, ImageTk, ImageGrab, ImageChops

OUT=Path(__file__).resolve().parent/'radical-ten'
OUT.mkdir(exist_ok=True)
NAMES=['Phase Fold','Quantum Key','Interference Bloom','Prismatic Vault','Light Weave',
       'Void Split','Flux Crystal','Spectral Gate','Singularity Shard','Aurora Ribbon']
BG='#050D1B'
root=tk.Tk(); root.title('D’Vielle — radically new logo concepts')
root.geometry('900x660+10+10'); root.resizable(False,False)
canvas=tk.Canvas(root,width=900,height=660,bg=BG,highlightthickness=0); canvas.pack()
photos=[]
for number in range(1,11):
    if not (OUT/f'art-{number:02}.png').exists():
        photos.append(None)
        continue
    with Image.open(OUT/f'art-{number:02}.png') as source:
        photos.append(ImageTk.PhotoImage(source.convert('RGB').resize((240,240),Image.Resampling.LANCZOS),master=canvas))

def tile(number,x,y,phase):
    local=(phase/(math.tau))%1
    canvas.create_rectangle(x+6,y+6,x+294,y+324,fill=BG,outline='#24354F')
    float_y=3*math.sin(phase) if number in (1,4,7,10) else 0
    canvas.create_image(x+150,y+152+float_y,image=photos[number-1])
    # Selection animations are native masks/lighting cues, not orbit decoration.
    if number in (1,5,6,8):
        opening=min(1,local*4,(1-local)*4)
        edge=120*(1-opening)
        canvas.create_rectangle(x+30,y+32,x+30+edge,y+272,fill=BG,outline='')
        canvas.create_rectangle(x+270-edge,y+32,x+270,y+272,fill=BG,outline='')
        if edge>2:
            canvas.create_line(x+30+edge,y+65,x+30+edge,y+238,fill='#8FE4FF',width=1)
            canvas.create_line(x+270-edge,y+65,x+270-edge,y+238,fill='#C9B0FF',width=1)
    if number in (2,3,9):
        beam=55+185*local
        color={2:'#E8BB78',3:'#9BBAE9',9:'#B694D6'}[number]
        canvas.create_line(x+39,y+beam,x+57,y+beam,fill=color,width=2)
        canvas.create_line(x+243,y+beam,x+261,y+beam,fill=color,width=2)
    if number in (4,7,10):
        pulse=3+3*(.5+.5*math.sin(phase))
        color={4:'#E6D5AE',7:'#93E6BB',10:'#C7ACEE'}[number]
        for px,py,dx,dy in [(37,55,1,1),(263,55,-1,1),(37,248,1,-1),(263,248,-1,-1)]:
            canvas.create_line(x+px,y+py,x+px+12*dx,y+py,fill=color,width=1)
            canvas.create_line(x+px,y+py,x+px,y+py+12*dy,fill=color,width=1)
        canvas.create_line(x+150-pulse,y+270,x+150+pulse,y+270,fill=color,width=2)
    canvas.create_text(x+150,y+22,text=f'{number:02} · {NAMES[number-1]}',fill='#D6E6F8',font=('Segoe UI',11,'bold'))
    canvas.create_text(x+150,y+286,text='D’Vielle',fill='#F5F8FF',font=('Segoe UI',17,'bold'))
    canvas.create_text(x+150,y+310,text='Intelligent Vigilance',fill='#9EAFCB',font=('Segoe UI',9))

try:
    boards=() if '--verify-only' in sys.argv else (0,) if '--board-one' in sys.argv else (1,) if '--board-two' in sys.argv else (0,1)
    for board in boards:
        samples=[[] for _ in range(5)]; frames=[]
        for frame_no in range(40):
            canvas.delete('all'); phase=((frame_no+10)%40)*math.tau/40
            for slot in range(5): tile(board*5+slot+1,(slot%3)*300,(slot//3)*330,phase)
            canvas.create_text(750,452,text='NEW DIRECTION',fill='#E6ECFA',font=('Segoe UI',16,'bold'))
            canvas.create_text(750,493,text='No rings. No infinity. No orbits.',fill='#ADC1DA',font=('Segoe UI',10))
            canvas.create_text(750,530,text=f'Concepts {board*5+1:02}–{board*5+5:02}',fill='#89D2EF',font=('Segoe UI',15))
            root.update()
            if frame_no==0:
                root.lift(); ctypes.windll.user32.SetForegroundWindow(ctypes.windll.user32.GetAncestor(root.winfo_id(),2))
                root.update(); time.sleep(.15)
            x,y=canvas.winfo_rootx(),canvas.winfo_rooty()
            capture=ImageGrab.grab(bbox=(x,y,x+900,y+660)).convert('RGB'); frames.append(capture)
            for slot in range(5):
                left,top=(slot%3)*300,(slot//3)*330
                samples[slot].append(capture.crop((left,top,left+300,top+330)))
            time.sleep(.015)
        frames[0].save(OUT/f'board-{board+1}.gif',save_all=True,append_images=frames[1:],duration=100,loop=0,disposal=2)
        frames[15].save(OUT/f'board-{board+1}-still.png')
        for slot,sample in enumerate(samples):
            number=board*5+slot+1
            sample[0].save(OUT/f'concept-{number:02}.gif',save_all=True,append_images=sample[1:],duration=100,loop=0,disposal=2)
            sample[15].save(OUT/f'concept-{number:02}-still.png')
            assert ImageChops.difference(sample[0],sample[10]).getbbox() is not None
            print(f'Rendered animated concept {number:02}',flush=True)
finally:
    root.destroy()

for number in (range(1,6) if '--board-one' in sys.argv else range(1,11)):
    with Image.open(OUT/f'concept-{number:02}.gif') as check:
        assert check.n_frames>=15 and check.size==(300,330)
        start=check.convert('RGB'); check.seek(min(10,check.n_frames-1))
        assert ImageChops.difference(start,check.convert('RGB')).getbbox() is not None
    print(f'Animation decoded and verified: {number:02}',flush=True)
cards=''.join(f'<article><h2>{i:02} · {name}</h2><img src="concept-{i:02}.gif" data-gif="concept-{i:02}.gif" data-still="concept-{i:02}-still.png" alt="{name} animated concept"><p><a href="art-{i:02}.png">Full-resolution artwork</a></p></article>' for i,name in enumerate(NAMES,1))
html='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>D’Vielle — New logo directions</title><style>body{background:#050d1b;color:#eff4ff;font:16px Segoe UI,sans-serif;margin:30px}button{padding:12px 20px;border:0;border-radius:8px;background:#91c9ff;cursor:pointer}main{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px;margin-top:24px}article{border:1px solid #294060;border-radius:12px;text-align:center;padding:16px}h2{font-size:18px}img{max-width:100%;height:auto}a{color:#9bd9ff}</style><h1>D’Vielle — Intelligent Vigilance</h1><p>Ten new emblem structures. Quantum-inspired art, not quantum technology claims. Application unchanged.</p><button id="motion">Pause animations</button><main>'''+cards+'''</main><script>let paused=matchMedia('(prefers-reduced-motion: reduce)').matches;function paint(){document.querySelectorAll('img').forEach(i=>i.src=paused?i.dataset.still:i.dataset.gif);document.getElementById('motion').textContent=paused?'Play animations':'Pause animations'}document.getElementById('motion').onclick=()=>{paused=!paused;paint()};paint()</script></html>'''
(OUT/'gallery.html').write_text(html,encoding='utf-8')
print('Ten artwork masters and animated previews ready.',flush=True)
