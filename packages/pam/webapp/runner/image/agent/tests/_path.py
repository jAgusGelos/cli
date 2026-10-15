import os
import sys

AGENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")
if AGENT not in sys.path:
    sys.path.insert(0, AGENT)
