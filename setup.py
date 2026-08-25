from setuptools import setup
from Cython.Build import cythonize
import os

# Files to compile to obfuscate license enforcement logic
target_files = [
    "api_gateway.py",
    "license_manager.py",
    "cgi_runtime.py",
]

existing_files = [f for f in target_files if os.path.exists(f)]

setup(
    name="CGI-Protocol Core",
    ext_modules=cythonize(
        existing_files,
        compiler_directives={'language_level': "3"},
        annotate=False
    ),
    zip_safe=False,
)
