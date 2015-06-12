# ebil - Exploit code framework for CTFs
ebil is an exploit code framework for CTFs, based on pwntools

Command line tools + python library
### Runtime Environment
#### config file (TODO)
`$HOME/.ebil.conf`


### Command line tools
`ebil new <process>` -> `./exploit.py` with `process` will be generated


### Python library
`pip install ./py`

__usage__:
```sh
./exploit.py   # run locally
./exploit.py p # run locally (pauses on breakpoints)
./exploit.py r # remote

```
__exploit.py__:
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

## Installation
```bash
git clone https://github.com/193s/ebil && cd ebil
pip install ./py
cp ./ebil /usr/local/bin/
```

## License
Copyright (c) 2015 193s

Published under the GNU GPLv2, see ./LICENSE


