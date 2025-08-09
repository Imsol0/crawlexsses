#!/usr/bin/env python3
"""Setup script for crawlexsses."""

from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="crawlexsses",
    version="1.0.0",
    author="0xhollow",
    description="XSS discovery tool combining subfinder, httpx, waymore, katana, gau, gf, uro, and knoxnl",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Imsol0/crawlexsses",
    py_modules=["crawlexsses"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "crawlexsses=crawlexsses:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
