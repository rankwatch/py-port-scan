from setuptools import setup

setup(
    name='port_scanner',
    version='1.0',
    description='Port scanning tool',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: GPL v3',
        'Programming Language :: Python :: 3.7',
        'Topic :: Networking :: Port Scanning',
    ],
    keywords='port scanning monitoring network optimisation',
    url='https://github.com/rankwatch/py-port-scan/',
    author='Hari Ram, Aaditya Verma',
    author_email='hari16csu135@ncuindia.edu, aadityaverma1998@gmail.com',
    license='GPL v3',
    packages=['PortScanner'],
    include_package_data=True,
    zip_safe=False
)
