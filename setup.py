"""Setup script for the python-act library module"""

from os import path

from setuptools import setup

# read the contents of your README file
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), "rb") as f:
    long_description = f.read().decode('utf-8')

setup(
    name="act-workers",
    version="0.5.2",
    author="mnemonic AS",
    author_email="opensource@mnemonic.no",
    description="Python library to connect to the ACT rest API",
    long_description=long_description,
    long_description_content_type='text/markdown',
    license="MIT",
    keywords="ACT, mnemonic",
    entry_points={
        'console_scripts': [
            'act-vt = act_workers.vt:main_log_error',
            'act-attack = act_workers.attack:main_log_error',
            'act-mnemonic-pdns = act_workers.mnemonic_pdns:main_log_error',
            'act-country-regions = act_workers.country_regions:main_log_error',
            'act-cyber-uio = act_workers.cyber_uio:main_log_error',
            'act-misp-feeds = act_workers.misp_feeds:main_log_error',
            'act-scio = act_workers.scio:main_log_error',
            'act-uploader = act_workers.generic_uploader:main_log_error',
            'act-shadowserver-asn = act_workers.shadowserver_asn:main_log_error',
        ]
    },
    packages=["act_workers", "act_workers_libs"],
    data_files=[('/etc/', ['etc/actworkers.ini'])],
    url="https://github.com/mnemonic-no/act-workers",
    install_requires=['act-api>=0.5.4', 'requests', 'RashlyOutlaid', 'virustotal-api', 'stix2'],

    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Utilities",
        "License :: OSI Approved :: ISC License (ISCL)",
    ],
)
