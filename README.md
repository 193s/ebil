# ebil - Exploit code framework for CTFs
ebil is an exploit code framework for CTFs, based on pwntools

Command line tools + python library


![](https://gist.githubusercontent.com/193s/bdcf6ed0864cfb051336/raw/44248717b121f93366ea8dc50762883da3c386a9/ss.png)

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
./exploit.py p # run locally (pause on breakpoints)
./exploit.py r # remote

```
__exploit.py__:
```python
#!/usr/bin/env python
from pwn  import *
from ebil import *

exec ebil('./vuln', remote=('pwnable.example.com', 35555), args=['wei'])
x86_64()

if LOCAL: log.info('** LOCAL **')

payload = 'a'*140

dummy = 0xbeefbeefbeefbeef
payload += chain([
  elf.symbols['write'], dummy, 1, 0x8049348, 4,
])
send(payload, 200)

print repr(r.recvrepeat())

r.wait_for_close()
```

## Installation
```bash
git clone https://github.com/193s/ebil && cd ebil
install -v ebil /usr/local/bin
pip install ./py
```

## License
Copyright (c) 2015 193s

Published under the GNU GPLv2, see ./LICENSE


