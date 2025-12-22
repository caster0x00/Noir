from setuptools import setup, find_packages

setup(
    name="noir",
    version="1.0.0",
    url="https://github.com/caster0x00/Noir",
    author="Magama Bazarov",
    author_email="magamabazarov@mailbox.org",
    scripts=['noir.py'],
    description="JunOS Security Inspector",
    long_description=open('README.md', encoding="utf8").read(),
    long_description_content_type='text/markdown',
    license="MIT",
    keywords=['juniper', 'junos', 'network security', 'config analyzer', 'hardening', 'netsec', 'networks', 'blue team'],
    packages=find_packages(where=".", exclude=("tests",)),
    py_modules=[],
    include_package_data=True,
    python_requires=">=3.11",
    install_requires=[
        "colorama",
        "netmiko",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "noir = noir:main",
        ],
    },
)
