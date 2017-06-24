Elastalert Hive Alerter
=======================

This package allows the use of a `custom Elastalert Alert
<https://elastalert.readthedocs.io/en/latest/recipes/adding_alerts.html#adding-a-new-alerter>`_
which creates alerts with observables in `TheHive <https://thehive-project.org/>`_ using
`TheHive4Py <https://github.com/CERT-BDF/TheHive4py>`_.

----

It allows for mapping included fields in the data that Elastalert has matched to observable types in TheHive and also
allows the combining of the included fields using python string formatting.


Example usage:

Provide an Elastalert rule file using this package as the alert:

alert: "elastalert_hive_alerter.hive_alerter.HiveAlerter"


You will be required to provide connection details for TheHive:

hive_connection:
  hive_host: http(s)://sample_host
  hive_port: <hive_port>
  hive_username: <hive_username>
  hive_password: <hive_password>
  hive_proxies:
    http: ''
    https: ''


The alert can be configured by providing parameters consumed by TheHive4Py:

hive_alert_config:
  title: 'Sample Title'
  type: 'external'
  source: 'instance1'
  description: 'Sample description'
  severity: 2
  tags: ['sample_tag_1', 'sample_tag_2']
  tlp: 3
  status: 'New'
  follow: True

Included fields can be mapped to TheHive observable types either directly or using python string formatting:

include: ["field1", "field2", "ip_field"]
hive_observable_data_mapping:
  - domain: "{field1}_{field2}"
  - domain: "field"
  - ip: "ip_field"
