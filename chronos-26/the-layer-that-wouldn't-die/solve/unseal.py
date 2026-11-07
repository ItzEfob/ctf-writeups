import hmac, hashlib, sys
key = bytes.fromhex("ddc9bfb15738fbd10757eb936a593931")
sealed = open(sys.argv[1], "rb").read()
for marker_path in sys.argv[2:]:
    mac = hmac.new(key, open(marker_path, "rb").read(), hashlib.sha256).digest()
    pad = (mac * (len(sealed) // 32 + 1))[:len(sealed)]
    print(marker_path, "->", bytes(a ^ b for a, b in zip(sealed, pad)))
