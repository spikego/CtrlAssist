from setuptools import setup, find_packages

setup(
    name='CtrlAssist',
    version='1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Flask',
        'psutil',
        'Werkzeug'
    ],
    entry_points={
        'console_scripts': [
            'CtrlAssist=main:app.run',
        ],
    },
)