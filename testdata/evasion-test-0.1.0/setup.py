"""
evasion-test — Kojuto detection boundary test.

!! THIS IS A TEST ARTIFACT FOR KOJUTO EDR VALIDATION !!
!! IT CONTAINS NO REAL MALWARE — ALL NETWORK TARGETS ARE UNREACHABLE !!
!! SHELLCODE IS NOP+RET ONLY (HARMLESS) !!
!! DO NOT PUBLISH TO PyPI !!
"""
from setuptools import setup
setup(
    name="evasion-test",
    version="0.1.0",
    packages=["evasion_test"],
)
