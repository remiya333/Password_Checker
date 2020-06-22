from PIL import Image, ImageFilter, ImageMorph
img = Image.open("C:\Rem\Personal_Docs\IMG_20191008_183954.jpg")
#filtered_Img=img.filter(ImageFilter.SHARPEN)
filtered_Img = img.convert('L')
filtered_Img.show()
flip_img=img.transpose(Image.FLIP_LEFT_RIGHT)
flip_img.show()

#print(filtered_Img.mode)
#img.show()