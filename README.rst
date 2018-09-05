Elastalert Hive Alerter
=======================

This package allows the use of a `custom Elastalert Alert
<https://elastalert.readthedocs.io/en/latest/recipes/adding_alerts.html#adding-a-new-alerter>`_
which creates alerts with observables in `TheHive <https://thehive-project.org/>`_ using
`TheHive4Py <https://github.com/CERT-BDF/TheHive4py>`_.

It provides two data contexts. The "rule" context provides information about the Elastalert rule,
eg. the rule name. The "match" context provides the data that the rule has matched.

Data from either context can be used to configure the alert and / or to create data for an observable.

The context data is specified via normal python string formatting (see examples below).

Note: Static configuration such as hive_connection can be placed in the Elastalert config file which is processed after
the active rule file during runtime.

----

Example usage (update your Elastalert rule / configuration file as directed below):

Use this package as the alert type:

::

 alert: "elastalert_hive_alerter.hive_alerter.HiveAlerter"

You will be required to configure connection details for TheHive (required fields first) into the Elastalert config file, example below:

::

 hive_connection:
   hive_host: http(s)://sample_host
   hive_port: <hive_port>
   hive_apikey: <hive_apikey>
	
   hive_proxies:
     http: ''
     https: ''

The alert should be configured by providing parameters consumed by TheHive4Py (required fields first):

::

 hive_alert_config:
   title: 'Sample Title'  ## This will default to {rule[index]_rule[name]} if not provided
   type: 'external'
   source: 'instance1'
   description: '{match[field1]} {rule[name]} Sample description'

   severity: 2
   tags: ['sample_tag_1', 'sample_tag_2 {rule[name]}']
   tlp: 3
   status: 'New'
   follow: True

If desired, matched data fields can be mapped to TheHive observable types using python string formatting:

::

 hive_observable_data_mapping:
   - domain: "{match[field1]}_{rule[name]}"
   - domain: "{match[field]}"
   - ip: "{match[ip_field]}"
