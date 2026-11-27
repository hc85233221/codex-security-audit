"""Wait until the parent has bounded our process tree, then run a bundled module."""
import runpy
from pathlib import Path
import sys

if __name__ == '__main__':
    allowed = {'inspect_system.py', 'inspect_windows.py', 'inspect_browser.py',
               'inspect_skills.py', 'inspect_connectivity.py', 'inspect_scripts.py', 'inspect_background.py',
               'inspect_supplemental.py','inspect_recent_apps.py','inspect_exposure.py'}
    if len(sys.argv) < 2 or sys.argv[1] not in allowed or sys.stdin.readline() != 'go\n':
        sys.exit(2)
    sys.argv = [str(Path(__file__).resolve().parent / sys.argv[1])] + sys.argv[2:]
    runpy.run_path(sys.argv[0], run_name='__main__')
