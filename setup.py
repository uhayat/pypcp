import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pypcp-uhayat",
    version="0.0.1",
    author="Umar Hayat",
    author_email="m.umarkiani@gmail.com",
    description="Pgpool-II Communication Protocol(PCP) library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/uhayat/pypcp",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: ",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)