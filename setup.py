import setuptools


setuptools.setup(
    name="zeratool",
    version="2.2",
    scripts=["bin/zerapwn.py"],
    author="Christopher Roberts",
    author_email="",
    description="Automatic Exploit Generation (AEG) and remote flag capture for exploitable CTF problems",
    url="https://github.com/ChrisTheCoolHut/Zeratool",
    packages=["zeratool"],
    install_package_data=True,
    install_requires=[
        "angr",
        "r2pipe",
        "claripy",
        "IPython",
        "timeout_decorator",
        "pwntools",
        "tox",
        "tqdm",
    ],
)
