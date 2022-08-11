import xxhash

def convert_to_int(x) -> int:
	result = 0
	if isinstance(x, dict):
		x = x['text']
	try:
		if (x[0] == '-'):
			x = x[1:]
		result = int(x, 16) & 0xffffffffffffffff
		return result
	except:
		return 0

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def custom_hash(arg1: str) -> int:
	if isinstance(arg1, dict):
		arg1 = arg1['class']
	return xxhash.xxh3_64_intdigest(arg1)