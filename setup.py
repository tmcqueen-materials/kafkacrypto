import setuptools

with open("README.md", "r") as fh:
  long_description = fh.read()

setuptools.setup(
  name="kafkacrypto",
  version="0.9.10.2dev0",
  license="GNU GPLv2",
  keywords="kafka kafka-crypto kafka-security security crypo",
  author="Tyrel M. McQueen",
  author_email="tmcqueen-pypi@demoivre.com",
  description="Message layer security/crypto for Kafka",
  long_description=long_description,
  long_description_content_type="text/markdown",
  url="https://github.com/tmcqueen-materials/kafkacrypto",
  packages=setuptools.find_packages(),
  python_requires='>=3.3',
  install_requires=['pysodium>=0.7.5','msgpack>=1.0.0','certifi','dirhash>=0.2.1','kafka-python @ git+https://github.com/dpkp/kafka-python@0864817 ; python_version>="3.12"','kafka-python>=1.4.4; python_version<"3.12"'],
  classifiers=[
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    "Operating System :: OS Independent",
  ],
)
