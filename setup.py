from setuptools import setup

setup(
      name='elastalert_hive_alerter',
      version='1.0.0rc2',
      description='Custom Elastalert Alerter which creates TheHive alerts',
      url='https://github.com/Nclose-ZA/elastalert_hive_alerter',
      author='Daniel Browne',
      author_email='grimsqueaker13@gmail.com',
      license='MIT',
      classifiers=[
            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 2.7',
            'Intended Audience :: Information Technology'
      ],
      keywords='elasticsearch elastalert thehive',
      packages=['elastalert_hive_alerter'],
      install_requires=['elastalert', 'thehive4py'],
      test_suite='nose.collector',
      tests_require=['nose']
)
