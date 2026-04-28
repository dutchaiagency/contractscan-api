from setuptools import setup, find_packages

setup(
    name="contractscan",
    version="0.1.0",
    description="Scan smart contracts for rug pulls, honeypots, and hidden risks. CLI + API.",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Dutch AI Agency",
    url="https://github.com/dutchaiagency/contractscan-api",
    project_urls={
        "Live Demo": "https://dutchaiagency.github.io/contractscan-api/",
        "Bug Tracker": "https://github.com/dutchaiagency/contractscan-api/issues",
    },
    packages=find_packages(where="services"),
    package_dir={"": "services"},
    py_modules=["scanner_core", "payment_verify"],
    install_requires=["web3>=7.0.0", "requests"],
    entry_points={
        "console_scripts": [
            "contractscan=cli.contractscan:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    keywords="smart-contract security scanner ethereum defi blockchain rug-pull honeypot",
)
