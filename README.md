# ebil - Exploit code framework for CTFs
ebil is an exploit code framework for CTFs, based on pwntools

Command line tools + python library
## Runtime Environment
### config file (TODO)
`$HOME/.ebil.conf` > `./.ebil.conf`


## Command line tools
`ebil new` to generate `./exploit.py`  
`ebil new <filename>` to generate `./exploit.py` with target elf `filename`


## Python library
`pip install ebli`

```python
#!/usr/bin/env python
from pwn  import *
from ebil import *
e = ebil('./vuln', remote=('pwnable.example.com', 35555))
r = e.r

if e.local:
  log.info('LOCAL')

print r.recvline()

payload = 'xxxx'
print '>', payload
e.breakpoint()

r.sendline(payload)

```

