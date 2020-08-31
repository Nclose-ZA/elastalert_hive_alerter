Elastalert Hive Alerter
=======================

This package provides a `custom Elastalert Alerter
<https://elastalert.readthedocs.io/en/latest/recipes/adding_alerts.html#adding-a-new-alerter>`_ which creates alerts with observables in `TheHive <https://thehive-project.org/>`_ using `TheHive4Py <https://github.com/CERT-BDF/TheHive4py>`_.

It provides two data contexts. The "rule" context provides information about the Elastalert rule,
eg. the rule name. The "match" context provides the data that the rule has matched.

Data from either context can be used to configure the alert and / or to create data for an observable.

The context data is specified via normal python string formatting (see examples below).

----

This package also provides a `custom Elastalert Enhancement <https://elastalert.readthedocs.io/en/latest/recipes/adding_enhancements.html>`_ which will suppress alerts raised by the Alerter if a hash of the observables in the raised alert are found in the specified Elasticsearch database.

The hashes should be inserted into the database from another source, most likely the ObservableHashCreator `responder <https://github.com/TheHive-Project/CortexDocs/blob/master/api/how-to-create-a-responder.md>`_ in `CortexAnalyzers <https://github.com/TheHive-Project/Cortex-Analyzers>`_

----

Note: It is possible to place static configuration such as *hive_connection* or *es_alert_hashes_connection* in the Elastalert config file instead of the rule file.

----

**Installation (Debian)**

::

 1. wget https://github.com/Yelp/elastalert/archive/v0.2.1.tar.gz -O - | sudo tar -xz -C /opt/ # Download a stable release from the Elastalert repository and place it in whichever directory you wish. We will use /opt/ for this demostration.
 2. sudo apt-get install python3.6-venv  # Install a virtual enviroment
 3. cd /opt/elastalert{version} && python3.6 -m venv venv #  Create a virtual environment within the project directory
 4. . /opt/elastalert/venv/bin/activate #  Activate the virtual environment
 5. python setup.py install #  Install the provided Python package
 6. git clone https://github.com/Nclose-ZA/elastalert_hive_alerter.git #  Clone the Nclose Hive Alerter master branch
 7. python elastalert_hive_alerter/setup.py install #  Install the Nclose Hive Alerter python package
 
----

**Install TheHive responder**

::

 1. Copy the `thehive_suppressor`to the approriate directory on your TheHive instance (usually located in `/opt/Cortex-Analyzers/responders/ObservableHashCreator` on Docker deployments.
 2. Log into Cortex. Navigate to `Organization`, `Responders Config` and you should see the `ObservableHashCreator` if the above was followed correctly. Configure the necessary requirements.

----

**Example Alerter usage**

Set the alerter in the rule file:

::

 alert: "elastalert_hive_alerter.hive_alerter.HiveAlerter"

Configure connection details for TheHive (required fields shown first) in either the config file or the rule file:

::

 hive_connection:
   hive_host: http(s)://sample_host
   hive_port: <hive_port>
   hive_apikey: <hive_apikey>

   hive_proxies:
     http: ''
     https: ''

Configure the alert by providing parameters consumed by TheHive4Py (required fields shown first) in the rule file:

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

If desired, matched data fields can be mapped to TheHive observable types using python string formatting in the rule file:

::

 hive_observable_data_mapping:
   - domain: "{match[field1]}_{rule[name]}"
   - domain: "{match[field]}"
   - ip: "{match[ip_field]}"

**Example Enhancement usage**

Set the enhancement in the rule file:

::

 match_enhancements:
  - elastalert_hive_alerter.hive_alerter.HashSuppressorEnhancement

Configure connection details for Elasticsearch in either the config file or the rule file:

::

 es_alert_hashes_connection:
  es_host: 'localhost'
  es_port: 9200
  es_username:
  es_password:
  index: 'alert_hashes'
  use_ssl:
  verify_certs:
  ca_certs:
  client_cert:
  client_key:

**Additional Documentation**

https://elastalert.readthedocs.io/en/latest/ruletypes.html#thehive
