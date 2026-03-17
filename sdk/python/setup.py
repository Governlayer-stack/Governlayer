from setuptools import setup, find_packages

setup(
    name="governlayer",
    version="0.1.0",
    description="GovernLayer Python SDK — AI Governance API client",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="GovernLayer",
    author_email="hello@governlayer.ai",
    url="https://github.com/Governlayer-stack/Governlayer",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
    ],
)
