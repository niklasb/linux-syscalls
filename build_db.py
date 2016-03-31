import argparse
import os
import re
import string
import sys
from subprocess import Popen, PIPE

archs = ['x86', 'x86-64']

p = argparse.ArgumentParser()
p.add_argument('kernel_tree', help='path to Linux kernel source tree')
p.add_argument('arch', help='architecture', choices=archs)
args = p.parse_args()

bit32_archs = ['x86']
is_32bit_arch = (args.arch in bit32_archs)
if is_32bit_arch:
    syscall_numbers_file = os.path.join(args.kernel_tree, 'arch/sh/include/uapi/asm/unistd_32.h')
else:
    syscall_numbers_file = '/usr/include/asm/unistd_64.h'

print >>sys.stderr, '[*] Dumping syscall numbers from %s' % syscall_numbers_file
syscall_numbers = {}
with open(syscall_numbers_file) as f:
    for name, num in re.findall(r'#define __NR_([^\s]*)\s+(\d+)', f.read()):
        if name == 'restart_syscall':
            continue
        #print name, num
        syscall_numbers[name] = int(num)

print >>sys.stderr, '[*] Dumping syscall declarations'
dirs = 'block certs crypto fs include init ipc kernel lib mm net security sound tools usr virt arch/x86'
cmd = (['egrep', '-h', '-A', '5', '-e', r'^SYSCALL_DEFINE.?\(', '-R']
    + [os.path.join(args.kernel_tree, d) for d in dirs.split()])
p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
out, err = p.communicate()

syscall_declarations = {}
for name, args in re.findall(r'SYSCALL_DEFINE.?\(([^,\)]+)(,[^\)]*)?\)', out):
    params = list(map(string.strip, args.split(',')))[1:]
    params = zip(params, params[1:])[::2]
    if name in syscall_declarations:
        print >>sys.stderr, "Duplicate declaration for %s, using %s" % (name, repr(params))
    syscall_declarations[name] = params

aliases_16_to_32 = [
    'fchown',
    'getegid',
    'geteuid',
    'getgid',
    'getgroups',
    'getresgid',
    'getresuid',
    'getuid',
    'setgroups',
    'setregid',
    'setresgid',
    'setresuid',
    'setreuid',
    'setfsuid',
    'setuid',
    'setgid',
    'setfsgid',
    'lchown',
    'chown',
]
aliases = {
    'umount2': 'umount',

    '_sysctl': 'sysctl',
}

if is_32bit_arch:
    for a in aliases_16_to_32:
        aliases[a] = a + '16'
        aliases[a + '32'] = a
    aliases.update({
        'mmap': 'old_mmap',
        'mmap2': 'mmap_pgoff',

        'oldstat': 'stat',
        'stat': 'newstat',

        'oldlstat': 'lstat',
        'lstat': 'newlstat',

        'oldfstat': 'fstat',
        'fstat': 'newfstat',

        'umount': 'oldumount',

        'readdir': 'old_readdir',

        '_llseek': 'llseek',

        '_newselect': 'select',
    })
else:
    aliases.update({
        'stat': 'newstat',
        'lstat': 'newstat',
        'fstat': 'newstat',
    })

values = [syscall_declarations[v] for v in aliases.values()]
for k, v in zip(aliases, values):
    syscall_declarations[k] = v

for name, num in sorted(syscall_numbers.items(), key=lambda (x,y): y):
    if name not in syscall_declarations:
        print >>sys.stderr, "Missing syscall declaration for %s" % name
    if name in syscall_declarations:
        params = syscall_declarations[name]
        print num, '%s(%s)' % (name, ', '.join('%s %s' % p for p in params))
    else:
        print num, name
