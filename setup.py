from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="SecHead", 
    version="1.0.0",
    
    author="Harith Dilshan",
    author_email="contact@h4rithd.com",
    description="A Python-based security auditing tool to analyze website security headers.",
    
    long_description=long_description,
    long_description_content_type="text/markdown",
    
    url="https://github.com/h4rithd/SecHead",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires='>=3.6',
    install_requires=[
        "requests",
    ],
    entry_points={
        'console_scripts': [
            'SecHead=SecHead.cli:main', 
        ],
    },
)