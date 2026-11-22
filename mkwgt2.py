import sys, os
sys.argv = ['x']
mode = os.environ.get('SIGMODE', 'authoronly')
import importlib.util
spec = importlib.util.spec_from_file_location('m', os.path.expanduser('~/tvroot/mkwgt_core.py'))
