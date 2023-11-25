import gzip

with gzip.open('foo.py.gz', 'rb') as gzfile:
    lines = list(gzfile)

print(f'len(lines): {len(lines)}')
