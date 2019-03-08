# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import re
import uuid

from elastalert.alerts import Alerter
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper


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
            context = {'rule': self.rule, 'match': match}

            artifacts = []
            for mapping in self.rule.get('hive_observable_data_mapping', []):
                for observable_type, match_data_key in mapping.iteritems():
                    try:
                        match_data_keys = re.findall(r'\{match\[([^\]]*)\]', match_data_key)
                        if all([True if k in context['match'] else False for k in match_data_keys]):
                            artifacts.append(AlertArtifact(dataType=observable_type, data=match_data_key.format(**context)))
                    except KeyError:
                        raise KeyError('\nformat string\n{}\nmatch data\n{}'.format(match_data_key, context))

            alert_config = {
                'artifacts': artifacts,
                'sourceRef': str(uuid.uuid4())[0:6],
                'title': '{rule[name]}'.format(**context)
            }
            alert_config.update(self.rule.get('hive_alert_config', {}))

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

            alert = Alert(**alert_config)

            response = api.create_alert(alert)

            if response.status_code != 201:
                raise Exception('alert not successfully created in TheHive\n{}'.format(response.text))

    def get_info(self):

        return {
            'type': 'HiveAlerter',
            'hive_host': self.rule.get('hive_connection', {}).get('hive_host', '')
        }
