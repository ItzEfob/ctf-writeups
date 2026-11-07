# The Layer That Wouldn't Die

**Category:** Forensics · **Difficulty:** Easy · **Points:** 120 · **Author:** Mohamed Amine Mzoughi

> Engineering sealed a site credential into the vendor's configuration image. After
> the intrusion, the marker that opens that seal is gone from the image's filesystem.
> Recover the sealed credential from the preserved OCI image layout. Inspect the files
> as data and execute nothing.

Attachment: `historian-image.zip` (9,578 bytes; the SHA-256 matched the one in the
briefing).

## First look

Unzipping gives a standard OCI image layout (`oci-layout`, `index.json`,
`blobs/sha256/`), a `manifest.sha256`, and a short brief. I ran `sha256sum` on every blob
first, and they all match their names, so nothing was tampered with.

The title was a big hint. A container image isn't one filesystem. It's a stack of tar
layers, and deleting a file in a later layer only adds a "whiteout" entry that hides it.
The original bytes are still in the earlier layer.

## Reading the image

`index.json` points to the manifest, the manifest lists the layers in order, and the
config blob has the build history. Listing every layer:

```bash
cd blobs/sha256
for d in eac5e15e 3fd0c555 928dc5c2 824c9dd2 be859646; do echo "== $d"; tar -tvzf $d*; done
```

| Layer | Build step | `.sealed_marker` |
|---|---|---|
| 1 | base rootfs | not there yet |
| 2 | `COPY site/` (Oct 8) | **original marker written** |
| 3 | `COPY historian.key.sealed` | unchanged; the seal is made here |
| 4 | `COPY site-rev-b/` (Oct 12, the intruder's push) | **overwritten** with a different 32-byte value |
| 5 | `RUN rm -f /etc/cascade/.sealed_marker` | whiteout `.wh..sealed_marker` |

The history comment on layer 3 gives the exact recipe:

```
sealed = plaintext XOR repeating(HMAC-SHA256(key=bytes.fromhex(Labels['build.seal']),
         msg=raw bytes of /etc/cascade/.sealed_marker as it stands in the image at the
         end of this layer))
```

and the label is `build.seal = ddc9bfb15738fbd10757eb936a593931`.

## The trap

The obvious move is "undo the whiteout and use the marker." That gets you the
**layer 4** marker, which is the intruder's rev-B version, and it decrypts to garbage.
The comment says "as it stands **at the end of this layer**": the seal was made in
layer 3, when the marker was still the layer 2 version. `config.yaml` changing from
`marker_rev: A` to `marker_rev: B` between layers 2 and 4 is the hint.

## Solving

I extracted each layer into its own folder (`tar -xzf <blob> -C L<n>`) and wrote a small
unseal script, [`unseal.py`](unseal.py):

```python
import hmac, hashlib, sys
key = bytes.fromhex("ddc9bfb15738fbd10757eb936a593931")
sealed = open(sys.argv[1], "rb").read()
for marker_path in sys.argv[2:]:
    mac = hmac.new(key, open(marker_path, "rb").read(), hashlib.sha256).digest()
    pad = (mac * (len(sealed) // 32 + 1))[:len(sealed)]
    print(marker_path, "->", bytes(a ^ b for a, b in zip(sealed, pad)))
```

```
$ python3 unseal.py L3/etc/cascade/historian.key.sealed L2/etc/cascade/.sealed_marker L4/etc/cascade/.sealed_marker
L2/etc/cascade/.sealed_marker -> b'CSCTF{layer_remembers_93e33478c}'
L4/etc/cascade/.sealed_marker -> b'\x9a\xf2\x830\x84\xe1\x80\x07...'
```

**Flag:** `CSCTF{layer_remembers_93e33478c}`

## Takeaway

`rm` in a Dockerfile never removes anything from earlier layers. If a secret ever lands
in a layer, it ships with the image. To audit an image, walk the layers in manifest
order and read the config history; you don't need to run anything.
