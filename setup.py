#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import (
    setup
)

extras_require = {
    "dev": [
        "bumpversion",
        "setuptools>=36.2.0",
        "wheel",
    ],
    "docs": [
        "Sphinx",
        "sphinx-rtd-theme"
    ],
}

extras_require["dev"] = (
    extras_require["docs"] +
    extras_require["dev"]
)

def readme():
    with open('README.md') as f:
        return f.read()

setup(
    name="secretstore",
    version="0.0.1",
    author="Adam Nagy",
    author_email="adam.nagy@energyweb.org",
    description="Python package for Parity's Secret Store API calls and sessions.",
    long_description=readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/energywebfoundation/secretstore-py",
    project_urls={
        "Documentation": "https://secretstore.readthedocs.io/"
    },
    python_requires='>=3.5.3,<4',
    extras_require=extras_require,
    include_package_data=True,
    install_requires=[
        "web3>=4.0.0",
        "requests>=2.16.0,<3.0.0",
        "decorator",
    ],
    license="MIT",
    zip_safe=False,
    keywords='secretstore secret store parity api energyweb ewf',
    packages=["secretstore",],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
