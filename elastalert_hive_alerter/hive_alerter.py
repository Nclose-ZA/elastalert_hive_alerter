# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import hashlib
import logging
import re
import uuid

from elastalert.alerts import Alerter
from elastalert.enhancements import BaseEnhancement, DropMatchException
from elasticsearch_dsl import connections, Document, Keyword, Index
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper


elastalert_logger = logging.getLogger('elastalert')


def _process_hive_match(rule, match):
    """
    This function processes a match which can raise an alert in TheHive
    It is used by both HiveAlerter and HashSuppressorEnhancement as the enhancement needs to be able to derive the
        same observable data from the alert as the alerter
    """

    context = {'rule': rule, 'match': match}

    artifacts = []
    for mapping in rule.get('hive_observable_data_mapping', []):
        for observable_type, match_data_key in mapping.iteritems():
            try:
                match_data_keys = re.findall(r'\{match\[([^\]]*)\]', match_data_key)
                if all([True for k in match_data_keys if k in context['match']]):
                    artifacts.append(AlertArtifact(dataType=observable_type, data=match_data_key.format(**context)))
            except KeyError:
                raise KeyError('\nformat string\n{}\nmatch data\n{}'.format(match_data_key, context))

    alert_config = {
        'artifacts': artifacts,
        'sourceRef': str(uuid.uuid4())[0:6],
        'title': '{rule[name]}'.format(**context)
    }
    alert_config.update(rule.get('hive_alert_config', {}))

    for alert_config_field, alert_config_value in alert_config.iteritems():
        if alert_config_field == 'customFields':
            custom_fields = CustomFieldHelper()
            for cf_key, cf_value in alert_config_value.iteritems():
                try:
                    func = getattr(custom_fields, 'add_{}'.format(cf_value['type']))
                except AttributeError:
                    raise Exception('unsupported custom field type {}'.format(cf_value['type']))
                value = cf_value['value'].format(**context)
                func(cf_key, value)
            alert_config[alert_config_field] = custom_fields.build()
        elif isinstance(alert_config_value, basestring):
            alert_config[alert_config_field] = alert_config_value.format(**context)
        elif isinstance(alert_config_value, (list, tuple)):
            formatted_list = []
            for element in alert_config_value:
                try:
                    formatted_list.append(element.format(**context))
                except:
                    formatted_list.append(element)
            alert_config[alert_config_field] = formatted_list

    return alert_config


class AlertHash(Document):
    alert_hash = Keyword()


class HashSuppressorEnhancement(BaseEnhancement):

    required_options = set(['es_suppression_hashes_connection'])  # This is not currently used, just informational

    def process(self, match):
        """
        This Elastalert enhancement will suppress an alert raise by HiveAlerter if a matching hash is found in the
            specified database
        It was written to be used in conjunction with the ObservableHashCreator responder for TheHive
        """

        connection_details = self.rule['es_alert_hashes_connection']

        kwargs = {}

        if connection_details.get('es_host'):
            kwargs['hosts'] = [{connection_details['es_host']: connection_details.get('es_port', 9200)}]

        if connection_details.get('es_username'):
            kwargs['http_auth'] = (connection_details['es_username'], connection_details['es_password'])

        kwargs.update({
            'use_ssl': connection_details.get('use_ssl', False),
            'verify_certs': connection_details.get('verify_certs', False),
            'client_cert': connection_details.get('client_cert', None),
            'client_key': connection_details.get('client_key', None),
            'ca_certs': connection_details.get('ca_certs', None),
            'timeout': connection_details.get('es_conn_timeout', 20)
        })

        connections.create_connection(**kwargs)

        alert_hashes = Index(connection_details.get('index', 'alert_hashes'))
        alert_hashes.document(AlertHash)

        if not alert_hashes.exists():
            alert_hashes.create()

        alert_config = _process_hive_match(self.rule, match)
        alert_hash_string = '|'.join([observable.jsonify() for observable in alert_config['artifacts']])
        alert_hash = hashlib.md5(alert_hash_string).hexdigest()
        results = AlertHash.search().filter('term', alert_hash=alert_hash).execute(ignore_cache=True)

        if results:
            elastalert_logger.info('Alert [{}] was not sent because hash [{}] was found'.format(
                alert_hash_string, alert_hash))
            raise DropMatchException()


class HiveAlerter(Alerter):
    """
    Use matched data to create alerts containing observables in an instance of TheHive
    """

    required_options = set(['hive_connection', 'hive_alert_config'])

    def alert(self, matches):

        connection_details = self.rule['hive_connection']

        api = TheHiveApi(
            '{hive_host}:{hive_port}'.format(**connection_details),
            connection_details.get('hive_apikey',''),
            proxies=connection_details.get('hive_proxies', {'http': '', 'https': ''}),
            cert=connection_details.get('hive_verify', False))

        for match in matches:
            alert_config = _process_hive_match(self.rule, match)
            alert = Alert(**alert_config)
            response = api.create_alert(alert)

            if response.status_code != 201:
                raise Exception('alert not successfully created in TheHive\n{}'.format(response.text))

    def get_info(self):

        return {
            'type': 'HiveAlerter',
            'hive_host': self.rule.get('hive_connection', {}).get('hive_host', '')
        }
