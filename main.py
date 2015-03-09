import sys
import argparse
import os
sys.path.append('./core/')
from base import APKScanner, __author__, __email__, __version__


def main(arguments):

    apks = APKScanner(arguments)
    apks.analyze(module=arguments.module)

description = '%%(prog)s - %s %s' % (__author__, __email__)
parser = argparse.ArgumentParser(description=description, version=__version__)
parser.add_argument("apk")
parser.add_argument("--module", help="run the provided module only")
parser.add_argument("--static-only", help="rely only on static analysis", action="store_true")
parser.add_argument("--verbose", help="increase output verbosity", action="store_true")
args = parser.parse_args()

main(args)