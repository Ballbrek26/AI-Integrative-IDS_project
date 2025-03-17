from setuptools import setup, find_packages

setup(
    name="ai-integrative-ids",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "scikit-learn>=1.0.2",
        "pandas>=1.3.0",
        "numpy>=1.21.0",
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="An AI-Integrative Intrusion Detection System",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/AI-Integrative-IDS",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "ai-ids=ids:main",
        ],
    },
) 