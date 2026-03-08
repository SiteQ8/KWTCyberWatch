#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="kwtcyberwatch",
    version="2.0.0",
    author="Ali AlEnezi",
    author_email="Site@hotmail.com",
    description="Kuwait Phishing Detection & Brand Protection Suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SiteQ8/KWTCyberWatch",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "certstream>=1.0.9",
        "flask>=3.0.0",
        "flask-cors>=4.0.0",
        "pyyaml>=6.0",
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "aiohttp>=3.9.0",
    ],
    extras_require={
        "dev": ["pytest", "pytest-cov", "flake8", "black", "mypy"],
    },
    entry_points={
        "console_scripts": [
            "kwtcyberwatch=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
