import sys
import checker
from optparse import OptionParser
 
options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160) with minimal impact to host.')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')

def main():
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return
 
    conn = checker.open_connection(args[0], opts.port)
    if type(conn) == tuple:
        print conn
        sys.exit(0)

    result = checker.check(conn)
    print result

if __name__ == '__main__':
    main()

