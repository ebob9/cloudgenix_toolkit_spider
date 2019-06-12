from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup(name='cloudgenix_toolkit_spider',
      version='1.0.0',
      description='Utility to run commands/tests across large number of CloudGenix Toolkit instances.',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/ebob9/cloudgenix_toolkit_spider',
      author='Aaron Edwards',
      author_email='cloudgenix_toolkit_spider@ebob9.com',
      license='MIT',
      install_requires=[
            'cloudgenix >= 5.1.1b1, < 5.2.1b1',
            'progressbar2 >= 3.34.3',
            'tabulate >= 0.8.3',
            'netmiko'
      ],
      packages=['cloudgenix_toolkit_spider'],
      entry_points={
            'console_scripts': [
                  'spider_build_plan = cloudgenix_toolkit_spider:plan',
                  'spider_run_plan = cloudgenix_toolkit_spider:test'
                  ]
      },
      classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3",
      ]
      )
