import sys
import argparse

import friendlybleed as checker

results = []

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test for SSL heartbeat vulnerability (CVE-2014-0160) with minimal impact to host.')
    parser.add_argument('-p', '--port', type=int, default=443, help='TCP port to test (default: 443)')
    parser.add_argument('-b', '--brute', default= False, action='store_true', help= "Brute force HeartBeats looking for non-random returns.")
    parser.add_argument("hostname")

    args = parser.parse_args()

    ### The 16-byte return is a pseudo-random padding string, use -b to test.
    for i in xrange(10000):
        if i % 100 == 0:
            print "Attempt %d..." % i
        conn = checker.open_connection(args.hostname, args.port)
        if type(conn) == tuple:
            print conn
            sys.exit(0)

        result = checker.check(conn)
        if result[2].encode("hex") not in results:
            results.append(result[2].encode("hex"))
        else:
            print "Detected duplicate response on iteration %d." % i
            print result
        if not args.brute:
            print result
            break

