from setuptools import setup

options = {"name" : "epqcrypto",
           "version" : "0.7a",
           "description" : "Ella's Post-Quantum Cryptography",
           "classifiers" : ["License :: Public Domain"],
           "packages" : ["epqcrypto", "epqcrypto.asymmetric", "epqcrypto.symmetric", "epqcrypto.protocol"],
           "py_modules" : ["persistence", "unittesting", "utilities"]}
           
setup(**options)
