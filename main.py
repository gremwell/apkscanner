import sys
import argparse
import os
reload(sys)
sys.setdefaultencoding("utf-8")
sys.path.append('./core/')
from base import APKScanner, __author__, __email__, __version__


def header():

    print
    print "\t\t    ||||||||||||||||||||||||||||||||||||||||||||||||||"
    print "\t\t    |||||||||||||||||_||||||||||||||||_|||||||||||||||"
    print "\t\t    |||||||||||||||||__||||||||||||||_||||||||||||||||"
    print "\t\t    ||||||||||||||||||_______________|||||||||||||||||"
    print "\t\t    ||||||||||||||||___________________|||||||||||||||"
    print "\t\t    ||||||||||||||____|||_________|||____|||||||||||||"
    print "\t\t    |||||||||||||_____|||_________|||_____||||||||||||"
    print "\t\t    ||||||||||||___________________________|||||||||||"
    print "\t\t    ||||||||||||___________________________|||||||||||"
    print "\t\t    ||||||||||||||||||||||||||||||||||||||||||||||||||"
    print "\t\t    ||||_____|||____________________________|||____|||"
    print "\t\t    ||||_____|||____________________________||______||"
    print "\t\t    ||||_____|||____________________________||______||"
    print "\t\t    ||||_____|||____________________________||______||"
    print "\t\t    ||||_____|||____________________________||______||"
    print "\t\t    ||||_____|||____________________________||______||"
    print "\t\t    ||||_____|||____________________________||______||"
    print "\t\t    ||||______||____________________________||______||"
    print "\t\t    ||||_____|||____________________________||______||"
    print "\t\t    |||||___||||____________________________|||___||||"
    print "\t\t    ||||||||||||____________________________||||||||||"
    print "\t\t    ||||||||||||____________________________||||||||||"
    print "\t\t    ||||||||||||___________________________|||||||||||"
    print "\t\t    |||||||||||||||||______||||||_____||||||||||||||||"
    print "\t\t    |||||||||||||||||______||||||_____||||||||||||||||"
    print "\t\t    |||||||||||||||||______||||||_____||||||||||||||||"
    print "\t\t    |||||||||||||||||______||||||_____||||||||||||||||"
    print "\t\t    |||||||||||||||||______||||||_____||||||||||||||||"
    print "\t\t    ||||||||||||||||||||||||||||||||||||||||||||||||||"
    print
    print "\t\t    _    ____  _  ______                                     "
    print "\t\t   / \  |  _ \| |/ / ___|  ___ __ _ _ __  _ __   ___ _ __    "
    print "\t\t  / _ \ | |_) | ' /\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|   "
    print "\t\t / ___ \|  __/| . \ ___) | (_| (_| | | | | | | |  __/ |      "
    print "\t\t/_/   \_\_|   |_|\_\____/ \___\__,_|_| |_|_| |_|\___|_|      "
    print
    print "\t\t[apkscanner v%s, %s(%s)]" % (__version__, __author__, __email__)
    print
    print "\t\t\t~ Gremwell bvba - www.gremwell.com ~"
    print


def main(arguments):

    header()
    apks = APKScanner(arguments)
    apks.analyze(module=arguments.module)
    apks.report("json")
    if not arguments.module:
        apks.report("html")
        apks.summary()

description = '%%(prog)s - %s %s' % (__author__, __email__)
parser = argparse.ArgumentParser(description=description, version=__version__)
parser.add_argument("apk")
parser.add_argument("--module", help="run the provided module only")
parser.add_argument("--static-only", help="rely only on static analysis", action="store_true")
parser.add_argument("--headless", help="run the emulator in headless modee", action="store_true")
parser.add_argument("--verbose", help="increase output verbosity", action="store_true")
args = parser.parse_args()

main(args)
