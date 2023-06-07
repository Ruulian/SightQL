import setuptools

long_description = "SightQL is a Python library which allows to exploit an SQL Injection using multiple entrypoints such as classical GET/POST parameters and cookies."

setuptools.setup(
    name="sightql",
    version="1.0",
    description="",
    url="https://github.com/Ruulian/SightQL",
    author="Ruulian",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email="ruulian@protonmail.com",
    packages=setuptools.find_packages(),
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ]
)
