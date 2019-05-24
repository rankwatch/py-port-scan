from setuptools import setup

setup(
    name='port_scanner',
    version='1.0',
    description='Port scanning tool',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache 2.0',
        'Programming Language :: Python :: 3.7',
        'Topic :: Networking :: Port Scanning',
    ],
    keywords='port scanning monitoring network optimisation',
    url='https://github.com/',
    author='Hari Ram, Aaditya Verma',
    author_email='hari16csu135@ncuindia.edu, aadityaverma1998@gmail.com',
    license='Apache 2.0',
    packages=['PortScanner'],
    include_package_data=True,
    zip_safe=False
)
