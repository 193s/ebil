#!/usr/bin/env python
import elftools
from pwn import *
from sys import argv, exit
from termcolor import colored, cprint

# generator
def ebil(filename, remote=None, args=[], arch='x86'):
  s = 'e = Ebil(%s, %s, %s, %s)\n' % (repr(filename), repr(remote), repr(args), repr(arch))
  s += \
r'''
r = e.r
LOCAL  = e.LOCAL
REMOTE = e.REMOTE
DEBUG  = e.DEBUG
elf = e.elf
breakpoint = e.breakpoint

def send(payload, length=None):
  if length: prefix = '(%d/%d)>' % (len(payload), length)
  else:      prefix = '(%d)>'    % (len(payload))
  print colored(prefix, attrs=['bold']),
  print colored(repr(payload), color='magenta')

  # check payload length
  if length:
    if len(payload) > length:
      log.error('payload is too long')


  breakpoint()
  r.send(payload)

def sendline(payload, length=None):
  send(payload+'\n', length+1 if length else None)

'''
  return s

def _is_elf(filename):
  try:
    ELF(filename)
    return True
  except elftools.common.exceptions.ELFError:
    return False

# set pwnlib.context: i386 linux
def x86():
  context.clear()
  context.update(arch='i386', os='linux')
# set pwnlib.context: amd64 linux
def x86_64():
  context.clear()
  context.update(arch='amd64', os='linux')


# alias for p32/p64
def p(a):
  return p32(a) if context.bits == 32 else p64(a)
# alias for u32/u64
def u(a):
  return u32(a) if context.bits == 32 else u64(a)

# chain([addr_read, 0xdeadbeef, 0, addr_buf, 0x200, ...]) -> str
def chain(ls):
  return ''.join(map(p, ls))

# open interactive console
# exec console()
def console():
  return "__import__('code').InteractiveConsole(locals=globals()).interact()"

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
      r = remote(remote[0], remote[1])
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



