#!/usr/bin/env python
import elftools
from pwn import *
from sys import argv, exit
from termcolor import colored, cprint

# generator
def ebil(filename, remote=None, args=[], arch='x86'):
  code = 'e = Ebil(%s, %s, %s, %s)\n' % (repr(filename), repr(remote), repr(args), repr(arch))
  code += \
r'''
r = e.r
LOCAL  = e.LOCAL
REMOTE = e.REMOTE
DEBUG  = e.DEBUG
elf = e.elf
breakpoint = e.breakpoint

def send(payload, length=None, validator=None):
  highlight_payload(payload, length)

  # check payload length
  if length:
    if len(payload) > length:
      log.error('payload is too long')
  # payload validation
  if validator:
    if not validator(payload):
      log.error('payload validation failed')

  breakpoint()
  r.send(payload)

def sendline(payload, length=None, validator=None):
  send(payload+'\n', length, validator)

def interact():
  r.interactive()
'''
  return code

def highlight_payload(payload, length=None):
  if length: prefix = '(%d/%d)>' % (len(payload), length)
  else:      prefix = '(%d)>'    % (len(payload))
  print colored(prefix, attrs=['bold']),
  print colored(repr(payload), color='magenta')


def _is_elf(filename):
  try:
    ELF(filename)
    return True
  except elftools.common.exceptions.ELFError:
    return False

# set architecture; pwnlib.context.arch
def setarch(arch):
  context.clear()
  context.update(arch=arch, os='linux')


# pack; alias for p32/p64
def p(a):
  return p32(a) if context.bits == 32 else p64(a)
# unpack; alias for u32/u64
def u(a):
  return u32(a) if context.bits == 32 else u64(a)

# chain([addr_read, 'AAAA', 0, addr_buf, 0x200, ...]) -> str
def chain(ls):
  return ''.join(map(lambda x: x if type(x)==str else p(x), ls))

# repr_repeat('aaaaaaaaaaabc') -> "'a'*11 + 'bc'"
def repr_repeat(s):
  rep_mode = False
  n = 0
  block_list = []
  def repr_s_noquote(s): return repr(s)[1:-1]

  i = 0
  while i < len(s)-1:
    c, nc = s[i], s[i+1]
    #print '  ', 'rep' if rep_mode else 'single', n, i, '(%s, %s)'%(repr(c),repr(nc))
    # repeat mode
    if rep_mode:
      n += 1
      if nc != c:
        # 'a'*n + ?
        # repeat blocks
        block_list += ['%s*%d' % (repr(c), n)]
        n = 0
        rep_mode = False

    # single mode
    else:
      if nc == c:
        # single blocks
        # 'abc' + 'c'
        if n != 0: block_list += ['%s' % (repr(s[i-n:i]))]
        n = 0
        rep_mode = True
        continue
      else:
        n += 1

    i += 1
  # fin
  c = s[-1]
  n += 1
  if rep_mode:
    if n == 1:
      block_list += ['%s' % (repr(c))]
    else:
      block_list += ['%s*%d' % (repr(c), n)]
  else:
    block_list += ['%s' % (repr(s[-n:]))]

  # export
  def get_or_else(value, els): return value if value else els
  return get_or_else(' + '.join(block_list), "''")


# open interactive console
# exec console()
def console():
  return "__import__('code').InteractiveConsole(locals=globals()).interact()"

class PayloadValidator:
  def ng_bytes(self, st, except_last=False):
    return lambda p: all([
      not byte in p
        for byte in (st[:-1] if except_last else st)
    ])

class Ebil:

  def __init__(self, filename, remote, args, arch):
    self.remote_info = remote

    # detect null byte in args
    for arg in args:
      if '\0' in arg:
        log.error('*** null byte detected in args ***')

    # set arch
    context.clear()
    context.update(arch=arch, os='linux')

    # already loaded or not a elf file -> pass
    # else -> load elf
    self.elf = self.elf if 'elf' in dir(self) else None
    if not(self.elf) and _is_elf(filename):
      self.load(filename)

    # return whether argv[1] contains `s` or not
    def _opt(s):
      return len(argv) == 2 and s in argv[1]

    local = not _opt('r')
    pause =     _opt('p')

    self.LOCAL  = local
    self.REMOTE = not local
    self.DEBUG  = pause

    if remote == None and not local:
      print 'No remote server information; remote=(host, port)'

    if local:
      r = process([filename] + args)
      self.pid = r.proc.pid
    else:
      r = pwnlib.tubes.remote.remote(remote[0], remote[1])
      self.pid = None

    self.r = r

  # static analysis: load ELF
  def load(self, filename):
    try:
      elf = ELF(filename)
      self.elf = elf
      # checksec
      print elf.checksec()
    except elftools.common.exceptions.ELFError:
      # not a elf file
      self.elf = None
      log.error('not a elf file: ' + elf)

  # set breakpoint; pause on pause mode
  def breakpoint(self):
    if self.DEBUG:
      log.success('pid = %d' % self.pid)
      ui.pause()



