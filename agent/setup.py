"""
Sentinel360 Agent – pip package
Instale com: pip install .
Use com: s360-agent install --api-url ... --agent-key ...
"""
from setuptools import setup, find_packages

setup(
    name="sentinel360-agent",
    version="2.0.0",
    description="Sentinel360 Remote Agent – File Risk & PII Scanner",
    author="Cyber Defense Team",
    packages=find_packages(),
    py_modules=["agent", "service_installer"],
    install_requires=[
        "httpx>=0.27",
        "aiofiles>=23.0",
    ],
    extras_require={
        "windows": ["pywin32>=306"],
    },
    entry_points={
        "console_scripts": [
            "s360-agent=agent:main",
            "s360-service=service_installer:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
