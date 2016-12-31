# The MIT License (MIT)
#
# Copyright (C) 2016 Michal Kosciesza <michal@mkiol.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""Mobile IP Home Agent"""

import logging
import mip
import colorer
import ConfigParser
import ast
import sys

ha = None


def start_home_agent(config_filename):
    global ha

    logging.info("Starting Home Agent.")

    try:
        # Config file
        config = ConfigParser.ConfigParser()
        config.read(config_filename)
        address = config.get("HomeAgent","address")
        auth_table = ast.literal_eval(config.get("HomeAgent","auth_table"))

        logging.debug("HA address: %s", address)
        logging.debug("HA authentications: %s", auth_table)

        # Creating and staring home agent object
        ha = mip.HomeAgent(address=address, auth_table=auth_table)
        ha.start()

        # App loop
        while True:
            pass

    except (KeyboardInterrupt, SystemExit, mip.Error):
        logging.info("Exiting...")
    finally:
        if ha is not None:
            ha.stop()


def main(argv):
    if len(argv) < 1:
        logging.critical("Config file is not provided.")
        return

    start_home_agent(argv[0])


if __name__ == "__main__":
   main(sys.argv[1:])
