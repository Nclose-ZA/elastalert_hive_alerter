from setuptools import setup

setup(
      name='elastalert_hive_alerter',
      version='1.0.0rc1',
      description='Custom Elastalert Alerter which creates TheHive alerts',
      url='',
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
