#!/usr/bin/env python
import pwn
import elftools
from sys import argv, exit

# generator method
def ebil(filename, remote=None):
  return Ebil(filename, remote)

class Ebil:

  def __init__(self, filename, remote):
    self.remote_info = remote

    # load ELF
    try:
      elf = pwn.ELF(filename)
      self.elf = elf
      # checksec
      print elf.checksec()
    except elftools.common.exceptions.ELFError:
      # not a elf file
      self.elf = None
      pass


    # return whether argv[1] contains `s` or not
    def _opt(s):
      return len(argv) == 2 and s in argv[1]

    local = not _opt('r')
    pause =     _opt('p')
    self.local = local
    self.pause = pause

    if remote == None and not local:
      print 'No remote server information; remote=(host, port)'

    if local:
      r = pwn.process(filename)
    else:
      r = pwn.remote(remote[0], remote[1])

    self.r   = r
    self.pid = r.proc.pid

  # set breakpoint; pause on pause mode
  def breakpoint(self):
    if self.pause:
      pwn.log.success('pid = %d' % self.pid)
      pwn.ui.pause()

