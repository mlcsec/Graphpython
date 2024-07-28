from setuptools import setup, find_packages
import os

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

requirements = []
if os.path.exists('requirements.txt'):
    with open('requirements.txt', 'r', encoding='utf-8') as f:
        requirements = [x.strip() for x in f.readlines()]

setup(
    name="Graphpython",
    version="1.0",
    packages=find_packages(),
    author="mlcsec",
    author_email="mlcsec@proton.me",
    description="Modular cross-platform Microsoft Graph API (Entra, o365, and Intune) enumeration and exploitation toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mlcsec/Graphpython",
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires='>=3.6',
    entry_points={
        "console_scripts": [
            "Graphpython=Graphpython.__main__:main",
        ],
    },
    include_package_data=True,
    package_data={
        'Graphpython': ['commands/graphpermissions.txt'],
        'Graphpython': ['commands/directoryroles.txt']
    },
)