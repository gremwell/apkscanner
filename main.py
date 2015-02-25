import sys
import argparse

sys.path.append('./core/')
import base


def main(arguments):

    x = base.AAAP(arguments.apk)
    x.analyze(arguments)

description = '%%(prog)s - %s %s' % (base.__author__, base.__email__)
parser = argparse.ArgumentParser(description=description, version=base.__version__)
parser.add_argument("apk")
parser.add_argument("--module")
parser.add_argument('-s', '--static-only', action="store_true")
args = parser.parse_args()
main(args)