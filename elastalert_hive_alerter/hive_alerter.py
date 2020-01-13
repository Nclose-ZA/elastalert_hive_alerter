# -*- coding: utf-8 -*-
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


def _create_artifacts(rule, match):

    context = {'rule': rule, 'match': match}

    artifacts = []
    for mapping in rule.get('hive_observable_data_mapping', []):
        for observable_type, match_data_key in mapping.items():
            try:
                match_data_keys = re.findall(r'\{match\[([^\]]*)\]', match_data_key)
                rule_data_keys = re.findall(r'\{rule\[([^\]]*)\]', match_data_key)
                data_keys = match_data_keys + rule_data_keys
                context_keys = context['match'].keys() + context['rule'].keys()
                if all([True if k in context_keys else False for k in data_keys]):
                    artifacts.append(AlertArtifact(dataType=observable_type, data=match_data_key.format(**context)))
            except KeyError as e:
                print('format string failed for key {}\nformat string\n{}\ncontext\n{}'.format(
                    e, match_data_key, context))
    return artifacts


def _create_alert_config(rule, match):

    context = {'rule': rule, 'match': match}

    alert_config = {
        'artifacts': _create_artifacts(rule, match),
        'sourceRef': str(uuid.uuid4())[0:6],
        'title': '{rule[name]}'.format(**context)
    }

    alert_config.update(rule.get('hive_alert_config', {}))

    for alert_config_field, alert_config_value in alert_config.items():
        if alert_config_field == 'customFields':
            custom_fields = CustomFieldHelper()
            for cf_key, cf_value in alert_config_value.items():
                try:
                    func = getattr(custom_fields, 'add_{}'.format(cf_value['type']))
                except AttributeError:
                    raise Exception('unsupported custom field type {}'.format(cf_value['type']))
                value = cf_value['value'].format(**context)
                func(cf_key, value)
            alert_config[alert_config_field] = custom_fields.build()
        elif isinstance(alert_config_value, str):
            alert_config[alert_config_field] = alert_config_value.format(**context)
        elif isinstance(alert_config_value, (list, tuple)):
            formatted_list = []
            for element in alert_config_value:
                try:
                    formatted_list.append(element.format(**context))
                except (AttributeError, KeyError, IndexError):
                    formatted_list.append(element)
            alert_config[alert_config_field] = formatted_list

    return alert_config


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
            kwargs['hosts'] = ['{}:{}'.format(connection_details['es_host'], connection_details.get('es_port', 9200))]

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

        class AlertHash(Document):
            alert_hash = Keyword()

        connections.create_connection(**kwargs)
        alert_hashes = Index(connection_details.get('index', 'alert_hashes'))
        alert_hashes.document(AlertHash)
        if not alert_hashes.exists():
            alert_hashes.create()

        alert_config = _create_alert_config(self.rule, match)
        # The jsonify method provides a list of predictably sorted JSON strings which we then sort in order to make
        #   sure that the we generate the same hash that was written to the database by ObservableHashCreator
        observables = sorted([observable.jsonify() for observable in alert_config['artifacts']])
        observable_hash_string = '|'.join(observables)
        observable_hash = hashlib.md5(observable_hash_string).hexdigest()
        results = AlertHash.search().filter('term', alert_hash=observable_hash).execute(ignore_cache=True)

        if results:
            elastalert_logger.info('Alert was not sent because hash [{}] was found'.format(observable_hash))
            raise DropMatchException()
        else:
            elastalert_logger.info('Alert was sent because hash [{}] was not found'.format(observable_hash))


class HiveAlerter(Alerter):
    """
    Use matched data to create alerts containing observables in an instance of TheHive
    """

    required_options = set(['hive_connection', 'hive_alert_config'])

    def get_aggregation_summary_text(self, matches):
        text = super(HiveAlerter, self).get_aggregation_summary_text(matches)
        if text:
            text = '```\n{0}```\n'.format(text)
        return text

    def send_to_thehive(self, alert_config):
        connection_details = self.rule['hive_connection']
        api = TheHiveApi(
            '{hive_host}:{hive_port}'.format(**connection_details),
            connection_details.get('hive_apikey', ''),
            proxies=connection_details.get('hive_proxies', {'http': '', 'https': ''}),
            cert=connection_details.get('hive_verify', False))

        alert = Alert(**alert_config)
        response = api.create_alert(alert)

        if response.status_code != 201:
            raise Exception('alert not successfully created in TheHive\n{}'.format(response.text))

    def alert(self, matches):
        if self.rule.get('hive_alert_config_type', 'custom') != 'classic':
            for match in matches:
                alert_config = _create_alert_config(self.rule, match)
                self.send_to_thehive(alert_config)
        else:
            alert_config = _create_alert_config(self.rule, matches[0])
            artifacts = []
            for match in matches:
                artifacts += _create_artifacts(self.rule, match)
                if 'related_events' in match:
                    for related_event in match['related_events']:
                        artifacts += _create_artifacts(self.rule, related_event)

            alert_config['artifacts'] = artifacts
            alert_config['title'] = self.create_title(matches)
            alert_config['description'] = self.create_alert_body(matches)
            self.send_to_thehive(alert_config)

    def get_info(self):

        return {
            'type': 'hivealerter',
            'hive_host': self.rule.get('hive_connection', {}).get('hive_host', '')
        }
