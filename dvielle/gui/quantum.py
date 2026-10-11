"""Approved Quantum Key artwork and silent, decorative electrical animation."""
from functools import lru_cache
import math
from PIL import Image, ImageDraw, ImageFilter
from dvielle.brand import BRAND_DIR

CIRCUIT_SECONDS = 45.0
THUNDER_SECONDS = 5.0
MASTER = BRAND_DIR / 'quantum-key-master.png'
OUTER = [(364,382),(546,382),(525,420),(636,734),(751,420),(716,382),(893,382),(888,396),(815,431),(657,895),(594,899),(420,432),(367,399)]
INNER = [(458,422),(520,422),(637,731),(752,422),(788,422),(623,862),(588,862)]
def _area(p):
    return sum(a[0]*b[1]-b[0]*a[1] for a,b in zip(p,p[1:]+p[:1]))
if _area(OUTER)<0: OUTER.reverse()
if _area(INNER)>0: INNER.reverse()

def position(path, fraction):
    lengths=[math.dist(a,b) for a,b in zip(path,path[1:]+path[:1])]
    d=(fraction%1)*sum(lengths)
    for i,length in enumerate(lengths):
        if d<=length:
            a,b=path[i],path[(i+1)%len(path)]
            return (a[0]+(b[0]-a[0])*d/length,a[1]+(b[1]-a[1])*d/length)
        d-=length
    return path[0]

@lru_cache(maxsize=8)
def _base(size):
    with Image.open(MASTER) as im:
        return im.convert('RGBA').resize((size,size),Image.Resampling.LANCZOS)

def _rim():
    points=[(296,228),(665,228)]
    def curve(a,b,c,d):
        for i in range(1,81):
            t=i/80;u=1-t
            points.append(tuple(u**3*a[j]+3*u*u*t*b[j]+3*u*t*t*c[j]+t**3*d[j] for j in (0,1)))
    curve((665,228),(880,224),(1002,404),(998,680))
    curve((998,680),(1000,880),(891,1015),(710,1014))
    points.extend([(297,1015),(260,1005),(260,886)])
    curve((260,886),(299,864),(302,835),(301,808))
    points.append((301,414))
    curve((301,414),(300,384),(280,373),(260,362))
    points.extend([(260,246),(296,228)])
    return points
RIM=_rim()

def render(size, seconds):
    """Render at real elapsed time; no frame cache or playback-speed dependence."""
    scale=size/1254
    base=_base(size).copy()
    layer=Image.new('RGBA',base.size)
    draw=ImageDraw.Draw(layer)
    def line(points,color,width=2):
        draw.line([(x*scale,y*scale) for x,y in points],fill=color,width=max(1,round(width*scale)),joint='curve')
    phase=seconds%THUNDER_SECONDS
    power=math.sin(math.pi*phase/1.15)**3 if phase<1.15 else 0
    if power>.002:
        for strand in range(5):
            points=[]
            for i,p in enumerate(RIM):
                q=RIM[(i+1)%len(RIM)];dx=q[0]-p[0];dy=q[1]-p[1];n=math.hypot(dx,dy) or 1
                jitter=math.sin(i*17.19+strand*23.7+math.floor(seconds/5)*9.3)*(5+strand*4)
                points.append((p[0]-dy/n*jitter,p[1]+dx/n*jitter))
            line(points,(83,207,255,round(power*220)),4.5 if strand==0 else 2)
            for i in range(20,len(points)-1,37):
                x,y=points[i]
                line([(x,y),(x-12,y-9),(x-8,y-21),(x-25,y-32)],(119,221,255,round(power*180)))
    gold=position(OUTER,seconds/45+.12);blue=position(INNER,seconds/45+.62)
    distance=math.dist(gold,blue)
    if distance<135:
        strength=(1-distance/135)**1.2
        x=(gold[0]+blue[0])/2;y=(gold[1]+blue[1])/2
        for radius,color in [(75,(140,105,255)),(48,(105,255,230)),(24,(228,255,247))]:
            draw.ellipse(((x-radius)*scale,(y-radius)*scale,(x+radius)*scale,(y+radius)*scale),fill=(*color,round(60*strength)))
        for strand,color in enumerate([(114,220,255),(246,197,104)]):
            points=[]
            dx=blue[0]-gold[0];dy=blue[1]-gold[1];n=distance or 1
            for i in range(33):
                u=i/32;wave=math.sin(u*math.pi)*math.sin(u*19-seconds*3+strand*math.pi)*12
                points.append((gold[0]+dx*u-dy/n*wave,gold[1]+dy*u+dx/n*wave))
            line(points,(*color,round(strength*255)),3)
    for path,offset,color in [(OUTER,.12,(246,197,104)),(INNER,.62,(114,220,255))]:
        lengths=[math.dist(a,b) for a,b in zip(path,path[1:]+path[:1])];total=sum(lengths);travel=0
        for i,(x,y) in enumerate(path):
            event=((travel/total-offset)%1)*45;age=(seconds-event)%45;travel+=lengths[i]
            if age>.85:continue
            strength=math.sin(math.pi*age/.85)
            for ray in range(5):
                angle=ray*math.tau/5+i*.7;r=30+age*28
                line([(x+math.cos(angle+(k%2*.22-.11))*(22+k*r/4),y+math.sin(angle+(k%2*.22-.11))*(22+k*r/4)) for k in range(5)],(*color,round(strength*220)))
    base.alpha_composite(layer.filter(ImageFilter.GaussianBlur(max(.6,size/90))))
    base.alpha_composite(layer.filter(ImageFilter.GaussianBlur(max(.4,size/300))))
    base.alpha_composite(layer)
    # Glass faces are composited separately so the approved ceramic art stays visible.
    glass=Image.new('RGBA',base.size);d=ImageDraw.Draw(glass)
    for (x,y),color in [(gold,(246,197,104)),(blue,(114,220,255))]:
        for face,alpha in [([(0,-29),(23,-16),(0,-3),(-23,-16)],155),([(-23,-16),(0,-3),(0,25),(-23,12)],70),([(0,-3),(23,-16),(23,12),(0,25)],110)]:
            p=[((x+a)*scale,(y+b)*scale) for a,b in face]
            d.polygon(p,fill=(*color,alpha));d.line(p+[p[0]],fill=(*color,220),width=max(1,round(scale)))
        d.line([((x-18)*scale,(y-14)*scale),((x-18)*scale,(y+8)*scale)],fill=(255,255,255,180),width=1)
    base.alpha_composite(glass)
    return base
