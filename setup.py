from setuptools import setup

setup(
      name='elastalert_hive_alerter',
      version='1.1.1',
      description='Elastalert alerter which creates TheHive alerts & enhancement which can suppress alerts',
      url='https://github.com/Nclose-ZA/elastalert_hive_alerter',
      author='Daniel Browne',
      author_email='grimsqueaker13@gmail.com',
      license='MIT',
      classifiers=[
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8',
            'Intended Audience :: Information Technology'
      ],
      keywords='elasticsearch elastalert thehive',
      packages=['elastalert_hive_alerter'],
      install_requires=['elastalert2', 'thehive4py==1.8.1', 'elasticsearch_dsl'],
      test_suite='nose.collector',
      tests_require=['nose']
)
