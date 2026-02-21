import pexpect
import sys

child = pexpect.spawn('cargo generate -a https://github.com/aya-rs/aya-template --name gateway-ebpf -d program_type=xdp -d aya_std=no')
child.logfile = sys.stdout.buffer
child.expect('Which interface to attach to by default', timeout=30)
child.sendline('eth0')
child.expect(pexpect.EOF, timeout=30)
