"""Find the EXACT patterns file with the bad regex."""
import sys, traceback
sys.path.insert(0, '.')
import importlib

importlib.invalidate_caches()

# Pull in required modules first
import ethos.core.data_types
import ethos.core.exceptions

# Now test each pattern file separately
for mod in [
    'ethos.privacy._core.scanner.patterns.pii',
    'ethos.privacy._core.scanner.patterns.secrets',
    'ethos.privacy._core.scanner.patterns.financial',
    'ethos.privacy._core.scanner.patterns.infra',
]:
    # Clear from cache
    for k in list(sys.modules.keys()):
        if k.startswith('ethos.privacy'):
            del sys.modules[k]
    
    try:
        importlib.import_module(mod)
        print(f"OK   {mod}")
    except Exception as e:
        print(f"FAIL {mod}: {e}")
        # Print line info
        import regex, traceback as tb
        tb.print_exc()
        break
