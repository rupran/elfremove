#!/usr/bin/python3

import sys

READ = sys.argv[1]
TMP = READ + '_tmp'
WRITE = READ + '_converted'
START = 0
END = sys.argv[2]

r = open(READ)
w = open(TMP, 'w')

w.write(str(START))
for line in r:
	numbers = line.split()
	end = int(numbers[0])
	start = end + int(numbers[1])
	w.write("-{0:#x}\n{1:#x}".format(end, start))
w.write("-" + str(END))

w.close()
r.close()

s = open(TMP)
x = open(WRITE, 'w')

for line in s:
	numbers = line.split(sep="-")
	if int(numbers[0], 16) != int(numbers[1], 16):
		x.write("-k " + numbers[0] + "-" + numbers[1] + "")

x.close()
s.close()
