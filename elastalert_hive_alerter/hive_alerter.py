# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import uuid

from elastalert.alerts import Alerter
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact


class HiveAlerter(Alerter):
    """
    Use matched data to create alerts containing observables in an instance of TheHive
    """

    required_options = set(['hive_connection'])

    def alert(self, matches):

        connection_details = self.rule['hive_connection']
        api = TheHiveApi(
            '{hive_host}:{hive_port}'.format(**connection_details),
            '{hive_username}'.format(**connection_details),
            '{hive_password}'.format(**connection_details),
            connection_details.get('hive_proxies', {'http': '', 'https': ''}))

        for match in matches:
            artifacts = []
            for mapping in self.rule.get('hive_observable_data_mapping', []):
                for observable_type, match_data_key in mapping.iteritems():
                    if match_data_key in match:
                        artifacts.append(AlertArtifact(dataType=observable_type, data=match[match_data_key]))
                    else:
                        try:
                            artifacts.append(AlertArtifact(dataType=observable_type, data=match_data_key.format(**match)))
                        except KeyError:
                            raise KeyError('\nformat string\n{}\nmatch data\n{}'.format(match_data_key, match))

            alert_config = self.rule.get('hive_alert_config', {})

            alert_config['artifacts'] = artifacts
            if 'sourceRef' not in alert_config:
                alert_config['sourceRef'] = str(uuid.uuid4())[0:6]

            alert = Alert(**alert_config)

            response = api.create_alert(alert)

            if response.status_code != 201:
                raise Exception('alert not successfully created in TheHive\n{}'.format(response.text))

    def get_info(self):

        return {
            'type': 'HiveAlerter',
            'hive_host': self.rule.get('hive_connection', {}).get('hive_host', '')
        }
