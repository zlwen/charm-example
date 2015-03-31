import sys

def main(fname):
	f = open(fname)
	times = 0
	data = {}
	for line in f:
		index = line.find("*")
		if index == -1:
			array = line.split("\t")
			k = array[0]
			if not data.has_key(k):
				data[k] = {}
				data[k]["setup"] = 0
				data[k]["keygen"] = 0
				data[k]["encrypt"] = 0
				data[k]["decrypt"] = 0
			data[k]["setup"] += float(array[1])
			data[k]["keygen"] += float(array[2])
			data[k]["encrypt"] += float(array[3])
			data[k]["decrypt"] += float(array[4])
		else:
			times += 1
	temp = sorted(data)
	for k in temp:
		print("%s:{setup:%.3f, keygen:%.3f, encrypt:%.3f, decrypt:%.3f}" % \
				(k, data[k]["setup"] / times, \
				    data[k]["keygen"] / times, \
					data[k]["encrypt"] / times, \
					data[k]["decrypt"] / times))

if __name__ == '__main__':
	main(sys.argv[1])
