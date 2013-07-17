import hmac, hashlib, sys, re

numfinder = re.compile('[0-9a-f]+$')

def encrypt(infd, outfd, hashphrase, prefix, striplinenumbers=False):
    """
    Read a breakpad .sym file from infd. Using the given hashphrase,
    one-way-hash any function and file names mentioned in the symbol file.

    `hashphrase` should be a secret, and should be the same every time this
    script is run.

    `prefix` is a vendor prefix, and should be a string provided by Mozilla.

    If `striplinenumbers` is true, remove all line number information
    from the symbols.

    This method returns a dictionary mapping the encrypted names back to
    the real names. When run from the command line, these will be saved in a
    log file.
    """

    namemap = {}
    def encryptname(name):
        hash = prefix + hmac.new(hashphrase, name, digestmod=hashlib.sha256).hexdigest()
        namemap[hash] = name
        return hash

    for line in infd:
        line = line.strip()
        command, rest = line.split(None, 1)

        if command == 'FILE':
            number, name = rest.split(None, 1)
            line = ' '.join([command, number, encryptname(name)])
        elif command == 'PUBLIC':
            address, psize, name = rest.split(None, 2)
            line = ' '.join([command, address, psize, encryptname(name)])
        elif command == 'FUNC':
            address, size, psize, name = rest.split(None, 3)
            line = ' '.join([command, address, size, psize, encryptname(name)])
        elif command in ('STACK', 'MODULE'):
            pass # Nothing to encrypt
        elif numfinder.match(command):
            if striplinenumbers:
                continue
        else:
            raise KeyError("Unexpected symbol instruction: '%s'" % command)

        outfd.write(line + '\n')

    return namemap

if __name__ == '__main__':
    from optparse import OptionParser
    import csv

    o = OptionParser(usage="usage: %prog [options] sourcefile destfile hashphrase prefix")
    o.add_option('-s', '--strip-line-numbers', action="store_true", dest="striplinenumbers", default=False)

    options, args = o.parse_args()
    if len(args) != 4:
        o.print_help()
        sys.exit(1)

    sourcefile, destfile, hashphrase, prefix = args

    sourcefd = open(sourcefile, 'r')
    destfd = open(destfile, 'w')
    omap = encrypt(sourcefd, destfd, hashphrase, prefix, options.striplinenumbers)
    sourcefd.close()
    destfd.close()

    w = csv.writer(sys.stdout)
    for e, name in omap.iteritems():
        w.writerow([e, name])
