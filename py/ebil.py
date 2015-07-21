#!/usr/bin/env python
import pwn
import elftools
from sys import argv, exit
from termcolor import colored, cprint

# generator
def ebil(filename, remote=None, args=[]):
  s = 'e = Ebil(%s, %s, %s)\n' % (repr(filename), repr(remote), repr(args))
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
    pwn.ELF(filename)
    return True
  except elftools.common.exceptions.ELFError:
    return False



class Ebil:

  def __init__(self, filename, remote=None, args=[]):
    self.remote_info = remote

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
      r = pwn.process([filename] + args)
      self.pid = r.proc.pid
    else:
      r = pwn.remote(remote[0], remote[1])
      self.pid = None

    self.r = r

  # static analysis: load ELF
  def load(self, filename):
    try:
      elf = pwn.ELF(filename)
      self.elf = elf
      # checksec
      print elf.checksec()
    except elftools.common.exceptions.ELFError:
      # not a elf file
      self.elf = None
      pwn.log.error('not a elf file: ' + elf)

  # set breakpoint; pause on pause mode
  def breakpoint(self):
    if self.DEBUG:
      pwn.log.success('pid = %d' % self.pid)
      pwn.ui.pause()



