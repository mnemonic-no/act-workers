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
            'act-vt = act_worker.vt:main_log_error',
            'act-attack = act_worker.attack:main_log_error',
            'act-mnemonic-pdns = act_worker.mnemonic_pdns:main_log_error',
            'act-country-regions = act_worker.country_regions:main_log_error',
            'act-cyber-uio = act_worker.cyber_uio:main_log_error',
            'act-misp-feeds = act_worker.misp_feeds:main_log_error',
            'act-scio = act_worker.scio:main_log_error',
            'act-uploader = act_worker.generic_uploader:main_log_error',
            'act-shadowserver-asn = act_worker.shadowserver_asn:main_log_error',
        ]
    },
    packages=["act_workers", "act_workers_libs"],
    url="https://github.com/mnemonic-no/act-workers",
    install_requires=['act-api>=0.5.3', 'requests', 'RashlyOutlaid', 'virustotal-api', 'stix2'],

    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
        "License :: OSI Approved :: ISC License (ISCL)",
    ],
)
