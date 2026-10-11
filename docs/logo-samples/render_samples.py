"""Code-native logo concepts and animated GIF previews; no application changes."""
from pathlib import Path
import math
from PIL import Image, ImageDraw, ImageFont, ImageFilter

OUT = Path(__file__).resolve().parent
FONT = 'C:/Windows/Fonts/segoeuib.ttf'
BG = (5, 13, 27)

def metal(mask, blue=False):
    layer = Image.new('RGBA', mask.size)
    draw = ImageDraw.Draw(layer)
    stops = [(0,(52,82,124)),(.25,(238,249,255)),(.42,(130,162,204)),
             (.49,(248,253,255)),(.54,(55,87,136)),(.80,(183,216,245)),(1,(75,115,174))]
    if blue:
        stops = [(0,(17,57,130)),(.28,(138,235,255)),(.48,(39,145,249)),
                 (.55,(13,55,145)),(.83,(100,214,255)),(1,(24,78,170))]
    for y in range(mask.height):
        t=y/(mask.height-1)
        for (a,ca),(b,cb) in zip(stops,stops[1:]):
            if a <= t <= b:
                p=(t-a)/(b-a)
                c=tuple(round(x+(z-x)*p) for x,z in zip(ca,cb))
                draw.line((0,y,mask.width,y),fill=c+(255,))
                break
    layer.putalpha(mask)
    return layer

def glyph(image, text, size, xy, blue=False):
    mask=Image.new('L',image.size)
    ImageDraw.Draw(mask).text(xy,text,font=ImageFont.truetype(FONT,size),fill=255,anchor='lt')
    expanded=mask.filter(ImageFilter.MaxFilter(7))
    rim=Image.new('RGBA',image.size,(137,213,255,255)); rim.putalpha(expanded)
    image.alpha_composite(rim)
    inset=Image.new('RGBA',image.size,(6,21,44,255)); inset.putalpha(mask.filter(ImageFilter.MaxFilter(3)))
    image.alpha_composite(inset)
    image.alpha_composite(metal(mask,blue))

def oval_point(angle):
    u,v=160*math.cos(angle),45*math.sin(angle)
    tilt=math.radians(-19)
    return 180+u*math.cos(tilt)-v*math.sin(tilt),155+u*math.sin(tilt)+v*math.cos(tilt)

def ring(image,front=False):
    draw=ImageDraw.Draw(image)
    start,end=(0,math.pi) if front else (math.pi,math.tau)
    points=[oval_point(start+(end-start)*i/100) for i in range(101)]
    draw.line(points,fill=(22,82,160,255),width=8)
    draw.line(points,fill=(145,217,255,255),width=3)

def emblem(kind):
    image=Image.new('RGBA',(360,300))
    ring(image)
    if kind==1:
        glyph(image,'D',260,(62,25))
        glyph(image,'V',138,(148,91),True)
    elif kind==2:
        glyph(image,'D',237,(40,37),True)
        glyph(image,'V',207,(178,57))
    else:
        glyph(image,'D',189,(60,61))
        glyph(image,'V',189,(182,61),True)
    ring(image,True)
    return image

def preview(mark,kind,stage,angle=0):
    canvas=Image.new('RGB',(560,460),BG)
    draw=ImageDraw.Draw(canvas)
    draw.rounded_rectangle((10,10,550,450),radius=22,outline=(38,67,103),width=2)
    titles=['01 · Chrome D / Sapphire V','02 · Interlocking D + V','03 · Twin-letter Vigil']
    draw.text((280,35),titles[kind-1],font=ImageFont.truetype(FONT,21),fill=(185,220,251),anchor='mm')
    canvas.paste(mark,(100,67),mark)
    draw.text((280,376),'D’Vielle — Intelligent Vigilance',font=ImageFont.truetype(FONT,25),fill=(240,247,255),anchor='mm')
    draw.text((280,408),'Vigilia — Always Watching',font=ImageFont.truetype(FONT,18),fill=(148,189,228),anchor='mm')
    return canvas

def main():
    for kind in (1,2,3):
        base=emblem(kind)
        base.save(OUT/f'dv-distinct-{kind}.png')
        frames=[]
        for i in range(32):
            angle=math.tau*i/31
            facing=math.cos(angle)
            source=base if facing>=0 else base.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
            projected=source.resize((max(3,round(360*abs(facing))),300),Image.Resampling.BICUBIC)
            mark=Image.new('RGBA',base.size)
            mark.alpha_composite(projected,((360-projected.width)//2,0))
            frames.append(preview(mark,kind,'turn'))
        for i in range(48):
            mark=base.copy(); draw=ImageDraw.Draw(mark)
            for offset,color in [(0,(206,248,255,255)),(math.pi,(110,199,255,255))]:
                x,y=oval_point(i*math.tau/48+offset)
                draw.ellipse((x-5,y-5,x+5,y+5),fill=color)
                draw.ellipse((x-2,y-2,x+2,y+2),fill='white')
            frames.append(preview(mark,kind,'orbit'))
        frames[0].save(OUT/f'dv-distinct-{kind}.gif',save_all=True,append_images=frames[1:],duration=90,loop=0,disposal=2)
        preview(base,kind,'still').save(OUT/f'dv-distinct-{kind}-still.png')
        with Image.open(OUT/f'dv-distinct-{kind}.gif') as check:
            assert check.n_frames>=75 and check.size==(560,460)
        print(f'Validated animated concept {kind}: {OUT/f"dv-distinct-{kind}.gif"}')

if __name__=='__main__':
    main()
