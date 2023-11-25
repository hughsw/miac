#!/usr/bin/env python3

# extract MIAC blocks from miab setup scripts

# cd /home/hugh/work/miac/miab/setup && sed -n -e 's|^\s*source setup/\(.\+\.sh\b\)\(\s*#.*\)\?|\1|p' start.sh | xargs /home/hugh/work/miac/miacconf.py /home/hugh/work/miac/miacconf

# cd /home/hugh/work/miac/miab/setup && sed -n -e 's|^\s*source setup/\(.\+\.sh\b\)\(\s*#.*\)\?|\1|p' start.sh | xargs /home/hugh/work/miac/miacconf.py /home/hugh/work/miac/miacconf2

# sed -n -e 's|^\s*source setup/\(.\+\.sh\b\)\(\s*#.*\)\?|\1|p' start.sh | xargs ../tools/miacconf.py > miacconf.sh

# grep -o -e '\bsource setup/\(.\+\.sh\)\b' start.sh | sed -e 's|\bsource setup/\(.\+\.sh\)\b|\1|' | xargs ../tools/miacconf.py > miacconf.sh

import sys, os
import datetime
import re

#print(f"""datetime: {datetime.datetime.utcnow()}   {datetime.datetime.utcnow().strftime('%Y-%m-%d-%H%M-%S')}""")

main = __name__ == '__main__'

miac_block = re.compile(r'\bMIAC_(\w+)_(BEGIN|END)\b').search
#miac_block = re.compile(r'\bMIAC_\(\w+\)_\(BEGIN\|END\)\b').search


BEGIN = 'IF_MIAC_CONF_BEGIN'
ELSE = 'IF_MIAC_CONF_ELSE'
END = 'IF_MIAC_CONF_END'

def miacconf(args):
    directory = args[0]
    filenames = tuple(args[1:])

    miac_env_file = '/home/user-data/miac-env.sh'
    setup_dir = 'miac'
    prefix = 'miac-setup-'

    print(f"""
# miacconf:  {datetime.datetime.utcnow().strftime('%Y-%m-%d-%H%M-%S')}

# miacconf: {args}

""")

    def confname(typ):
        return f'{prefix}{typ.lower()}.sh'

    outfiles = dict()
    def ensure_outfile(typ):
        outfile = outfiles.get(typ)
        if outfile is None:
            fullname = os.path.join(directory, confname(typ))
            outfile = outfiles[typ] = open(fullname, 'wt')
            print(f'# MIAC: {typ}', file=outfile)
            print(file=outfile)

            # special case for VARS setting:
            special = 'VARS'
            # - don't put a recursion in the confname(special) file itself
            # - do put a source of confname(special) in every other file
            if typ != special:
                print(f'source {miac_env_file}', file=outfile)
                print(f'source {setup_dir}/{confname(special)}', file=outfile)

        return typ, outfile

    for filename in filenames:
        with open(filename, 'rt') as infile:
            print(f'# {filename}')

            labels = set()
            block_stack = list()
            for line in infile:
                match = miac_block(line)
                if match:
                    typ, verb = match.groups()
                    #print(f'# {typ} {verb}')
                    if verb == 'BEGIN':
                        block_stack.append(ensure_outfile(typ))
                        if typ not in labels:
                            new_file = block_stack[-1][1]
                            print(file=new_file)
                            print(file=new_file)
                            print('#' * 70, file=new_file)
                            print('#', file=new_file)
                            print(f'# {filename}', file=new_file)
                            print('#', file=new_file)
                            print(f'echo MIAC {typ} {filename}', file=new_file)
                            labels.add(typ)
                        continue
                    if verb == 'END':
                        assert block_stack, str((filename, line))
                        assert block_stack[-1][0] == typ, str((filename, block_stack[-1][0], typ, line))
                        block_stack.pop()
                        continue
                # every non-blank line must be in a block
                if not block_stack:
                    assert not line.strip(), str((filename, line))
                    continue

                print(line, end=('' if line.endswith('\n') else '\n'), file=block_stack[-1][1])
                
    for typ, outfile in outfiles.items():
        print("""
# ensure success code when this script is sourced
/bin/true
""", file=outfile)
        
        outfile.close()

                


def miacconfXXX(args):
    filenames = tuple(args)

    print(f"""#!/bin/sh

# miacconf:  {datetime.datetime.utcnow().strftime('%Y-%m-%d-%H%M-%S')}

# miacconf: {args}

# {BEGIN} / {END}


source miac-env.sh

source setup/functions.sh  # load our functions
source setup/locale.sh  # export locale env vars
""")

    for filename in filenames:
        with open(filename, 'rt') as infile:
            print()
            print(f'# {filename}  BEGIN >>>>>>>>>>>>>>>>>>>>')
            opens = list()
            for line in infile:
                if BEGIN in line:
                    opens.append(True)
                    continue
                if ELSE in line:
                    assert opens, str((filename, line))
                    opens[-1] = False
                if END in line:
                    assert opens, str((filename, line))
                    opens.pop()
                    continue
                if opens and opens[-1]:
                    print(line, end='' if line.endswith('\n') else '\n')
            print('true')
            assert not opens, str((filename, opens))
            print(f'# {filename}  END')


if main:
    sys.exit(miacconf(sys.argv[1:]))
