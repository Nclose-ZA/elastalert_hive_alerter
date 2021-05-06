# Elastalert Hive Alerter

- [About](#About)
- [Requirements](#Requirements)
- [Installation](#Installation)
    * [For Elastalert 2](#For-Elastalert-2)
    * [As Responder for theHive](#As-Responder-for-theHive)
- [Configuration](#Configuration)
- [Additional Documentation](#Additional-Documentation)

## About
- This package is an enhancement addon to Elastalert 2 <https://github.com/jertel/elastalert2>
- It provides a custom `Elastalert Alerter`
<https://elastalert2.readthedocs.io/en/latest/recipes/adding_alerts.html#adding-a-new-alerter> which creates alerts with observables in TheHive <https://thehive-project.org/> using `TheHive4Py` <https://github.com/TheHive-Project/TheHive4py>.

- It provides two data contexts. The "rule" context provides information about the Elastalert rule,
eg. the rule name. The "match" context provides the data that the rule has matched.

- Data from either context can be used to configure the alert and / or to create data for an observable.

- The context data is specified via normal python string formatting (see examples below).

----

This package also provides a `custom Elastalert Enhancement` <https://elastalert2.readthedocs.io/en/latest/recipes/adding_enhancements.html> which will suppress alerts raised by the Alerter if a hash of the observables in the raised alert is found in the specified Elasticsearch database.

The hashes should be inserted into the database from another source, most likely the ObservableHashCreator `responder` <https://github.com/TheHive-Project/CortexDocs/blob/master/api/how-to-create-a-responder.md> in `CortexAnalyzers` <https://github.com/TheHive-Project/Cortex-Analyzers>

----

Note: It is possible to place static configuration such as *hive_connection* or *es_alert_hashes_connection* in the Elastalert config file instead of the rule file.

----


## Requirements

- Python 3.6 (Python 3.8 recommended)
- Python Pip
- Python Pipenv or your flavour of Python virtual environment.

## Installation
### For Elastalert 2

#### Python Virtual Environment

1. Create and change into directory for Elastalert.
2. Create Python virtual environment.
    ```bash
    pipenv --python3.8
    # activate environment
    pipenv shell
    ```
3. Clone Elastalert Hive Alerter
    ```bash
    git clone git@github.com:Nclose-ZA/elastalert_hive_alerter.git
    ```
4. Install. Please note this will install Elastalert2 as well as ElastAlert Hive Alerter.
    ```bash
    pip install elastalert_hive_alerter
    ```

If you already have Elastalert2 running you can just follow steps 3 and 4.

 
----

## As Responder for theHive
### Install TheHive responder (To suppress events from theHive web instance)

 1. Copy the `thehive_suppressor`to the approriate directory on your theHive instance (usually located in `/opt/Cortex-Analyzers/responders/ObservableHashCreator` on Docker deployments).
 2. Log into Cortex. Navigate to `Organization`, `Responders Config` and you should see the `ObservableHashCreator` if the above was followed correctly. Configure the necessary requirements.

----
## Configuration

1. Set the alerter in the rule file:
    ```yaml
    alert: "elastalert_hive_alerter.hive_alerter.HiveAlerter"
    ```

2. Configure connection details for TheHive (required fields shown first) in either the config file or the rule file:
    ```yaml
    hive_connection:
      hive_host: http(s)://sample_host
      hive_port: <hive_port>
      hive_apikey: <hive_apikey>

    hive_proxies:
      http: ''
      https: ''
    ```

3. Configure the alert by providing parameters consumed by TheHive4Py (required fields shown first) in the rule file:
    ```yaml
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
    ```

4. If desired, matched data fields can be mapped to TheHive observable types using python string formatting in the rule file:
    ```yaml
    hive_observable_data_mapping:
      - domain: "{match[field1]}_{rule[name]}"
      - domain: "{match[field]}"
      - ip: "{match[ip_field]}"
    ```

5. Set the enhancement in the rule file:
    ```yaml
    match_enhancements:
      - elastalert_hive_alerter.hive_alerter.HashSuppressorEnhancement
    ```

6. Configure connection details for Elasticsearch in either the config file or the rule file:
    ```yaml
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
    ```

## Additional Documentation

https://elastalert2.readthedocs.io/en/latest/
