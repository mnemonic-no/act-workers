"""Setup script for the python-act library module"""

from os import path

from setuptools import setup

# read the contents of your README file
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), "rb") as f:
    long_description = f.read().decode('utf-8')

setup(
    name="act-workers",
    version="0.5.0",
    author="mnemonic AS",
    author_email="opensource@mnemonic.no",
    description="Python library to connect to the ACT rest API",
    long_description=long_description,
    long_description_content_type='text/markdown',
    license="MIT",
    keywords="ACT, mnemonic",
    entry_points={
        'console_scripts': [
            'act-vt = vt:main_log_error',
            'act-attack = attack:main_log_error',
            'act-mnemonic-pdns = mnemonic_pdns:main_log_error',
            'act-cyber-uio = cyber_uio:main_log_error',
            'act-misp-feeds = misp_feeds:main_log_error',
            'act-scio = scio:main_log_error',
            'act-uploader = generic_uploader:main_log_error',
            'act-shadowserver-asn = shadowserver_asn:main_log_error',
        ]
    },
    url="https://github.com/mnemonic-no/act-workers",
    install_requires=['act-api', 'requests', 'RashlyOutlaid', 'virustotal-api', 'stix2'],

    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
        "License :: OSI Approved :: ISC License (ISCL)",
    ],
)
