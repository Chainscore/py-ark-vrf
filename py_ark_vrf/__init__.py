from .py_ark_vrf import *
import importlib.resources
import tempfile
import os
import sys

__doc__ = py_ark_vrf.__doc__
if hasattr(py_ark_vrf, "__all__"):
    __all__ = py_ark_vrf.__all__

def get_srs_file_path():
    """Get the path to the SRS file, extracting it from the package if needed."""
    
    # First, check if we're running in a PyInstaller bundle
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # PyInstaller bundle - check sys._MEIPASS directory first
        bundle_srs_path = os.path.join(sys._MEIPASS, 'bandersnatch_ring.srs')
        if os.path.exists(bundle_srs_path):
            return bundle_srs_path
        
        # Also check in py_ark_vrf subdirectory within bundle
        bundle_pkg_srs_path = os.path.join(sys._MEIPASS, 'py_ark_vrf', 'bandersnatch_ring.srs')
        if os.path.exists(bundle_pkg_srs_path):
            return bundle_pkg_srs_path
    
    try:
        # Python 3.9+ way
        files = importlib.resources.files('py_ark_vrf')
        srs_file = files / 'bandersnatch_ring.srs'
        
        # Create a temporary file if we need to extract from the package
        if hasattr(srs_file, 'read_bytes'):
            # File is in a package/zip, extract it
            temp_dir = tempfile.mkdtemp()
            temp_srs_path = os.path.join(temp_dir, 'bandersnatch_ring.srs')
            with open(temp_srs_path, 'wb') as f:
                f.write(srs_file.read_bytes())
            return temp_srs_path
        else:
            # File is on filesystem
            return str(srs_file)
    except (ImportError, AttributeError, Exception):
        # Fallback for older Python versions
        try:
            import importlib_resources
            files = importlib_resources.files('py_ark_vrf')
            srs_file = files / 'bandersnatch_ring.srs'
            
            temp_dir = tempfile.mkdtemp()
            temp_srs_path = os.path.join(temp_dir, 'bandersnatch_ring.srs')
            with open(temp_srs_path, 'wb') as f:
                f.write(srs_file.read_bytes())
            return temp_srs_path
        except (ImportError, Exception):
            # Final fallback - look in current directory
            return 'bandersnatch_ring.srs' 