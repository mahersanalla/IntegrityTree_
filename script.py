

x = chr(0);
for i in range(256):
	print(",\'%c\',",x)
	x = chr(ord(x) + 1) 
	
