# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from mock import patch
from elastalert.ruletypes import AnyRule
import time
from unittest import TestCase

a_date = int(time.time())*1000

rule = {
    'index': 'test_index',
    'name': 'test_rule_name',
    'hive_observable_data_mapping': [
        {'filename': '{match[domain]}_{match[ip_address]}.txt'},
        {'domain': '{match[domain]}'},
        {'domain': '{match[some_other_domain]}'},
        {'ip': '{match[ip_address]}'},
        {'domain': '{match[nested1][nested2]}'},
        {'other': '{match[NotInMatchData]}'}
    ],
    'hive_connection': {
        'hive_password': 'password',
        'hive_username': 'username',
        'hive_port': 9000,
        'hive_host': 'http://test_host',
        'hive_proxies': {'http': '', 'https': ''}
    },
    'hive_alert_config': {
        'status': 'New',
        'tlp': 3,
        'severity': 2,
        'tags': ['TheHive4Py', 'sample {rule[name]}'],
        'source': 'instance1',
        'follow': True,
        'type': 'external',
        'description': '{rule[name]}\n{match[domain]} Test desc',
        'customFields': {
            'test_date': {'type': 'date', 'value': '{match[a_date]}'},
            'test_string': {'type': 'string', 'value': '{match[some_other_domain]}'},
            'test_boolean': {'type': 'boolean', 'value': '{match[a_boolean]}'},
            'test_number': {'type': 'number', 'value': '{match[a_number]}'}
        }
    }
}

rule_classic = {
    'index': 'test_index',
    'name': 'test_rule_name',
    'type': AnyRule({}),
    'hive_observable_data_mapping': [
        {'filename': '{match[domain]}_{match[ip_address]}.txt'},
        {'domain': '{match[domain]}'},
        {'domain': '{match[some_other_domain]}'},
        {'ip': '{match[ip_address]}'},
        {'domain': '{match[nested1][nested2]}'}
    ],
    'hive_connection': {
        'hive_password': 'password',
        'hive_username': 'username',
        'hive_port': 9000,
        'hive_host': 'http://test_host',
        'hive_proxies': {'http': '', 'https': ''}
    },
    'hive_alert_config_type': 'classic',
    'hive_alert_config': {
        'status': 'New',
        'tlp': 3,
        'severity': 2,
        'tags': ['TheHive4Py', 'sample {rule[name]}'],
        'source': 'instance1',
        'follow': True,
        'type': 'external',
        'description': '{rule[name]}\n{match[domain]} Test desc',
        'customFields': {
            'test_date': {'type': 'date', 'value': '{match[a_date]}'},
            'test_string': {'type': 'string', 'value': '{match[some_other_domain]}'},
            'test_boolean': {'type': 'boolean', 'value': '{match[a_boolean]}'},
            'test_number': {'type': 'number', 'value': '{match[a_number]}'}
        }
    }
}

matches = [
    {
        'ip_address': '1.1.1.1',
        'domain': 'test.com',
        'some_other_domain': 'test2.com',
        'nested1': {'nested2': 'nested_value'},
        'a_boolean': True,
        'a_date': a_date,
        'a_number': 123
    }
]

matches_classic = [
    {
        'ip_address': '1.1.1.1',
        'domain': 'test.com',
        'some_other_domain': 'test2.com',
        'nested1': {'nested2': 'nested_value'},
        'a_boolean': True,
        'a_date': a_date,
        'a_number': 123
    },
    {
        'ip_address': '1.2.3.4',
        'domain': 'test.com',
        'some_other_domain': 'test2.com',
        'nested1': {'nested2': 'nested_value'},
        'a_boolean': True,
        'a_date': a_date,
        'a_number': 123
    }
]

class TestAlerter(TestCase):
    def test_alerter(self):
        class FakeResponse(object):
            status_code = 201
            text = ''

        class FakeApi(object):
            def create_alert(self, *args, **kwargs):
                return FakeResponse()

        with patch('thehive4py.api.TheHiveApi', return_value=FakeApi()) as mock_api, \
                patch.object(FakeApi, 'create_alert', return_value=FakeResponse()) as mock_create, \
                patch('thehive4py.models.Alert') as mock_alert, \
                patch('thehive4py.models.AlertArtifact', return_value='fake_artifact_return') as mock_artifact, \
                patch('uuid.uuid4', return_value='123456') as mock_uuid4:
            from elastalert_hive_alerter.hive_alerter import HiveAlerter
            hive_alerter = HiveAlerter(rule)
            hive_alerter.alert(matches)

            mock_api.assert_called_with(
                u'http://test_host:9000',
                u'',
                cert=False,
                proxies={u'http': u'', u'https': u''}
            )

            mock_artifact.assert_any_call(data=u'test.com_1.1.1.1.txt', dataType=u'filename')
            mock_artifact.assert_any_call(data=u'test.com', dataType=u'domain')
            mock_artifact.assert_any_call(data=u'test2.com', dataType=u'domain')
            mock_artifact.assert_any_call(data=u'nested_value', dataType=u'domain')
            mock_artifact.assert_any_call(data=u'1.1.1.1', dataType=u'ip')
            mock_alert.assert_called_with(
                artifacts=[u'fake_artifact_return' for i in xrange(len(rule['hive_observable_data_mapping'])-1)],
                description=u'test_rule_name\ntest.com Test desc',
                follow=True,
                severity=2,
                source=u'instance1',
                sourceRef='123456',
                status=u'New',
                tags=[u'TheHive4Py', u'sample test_rule_name'],
                title=u'test_rule_name',
                tlp=3,
                type=u'external',
                customFields={
                    u'test_number': {'order': 0, 'number': '123'},
                    u'test_boolean': {'order': 1, 'boolean': u'True'},
                    u'test_date': {'order': 2, 'date': unicode(a_date)},
                    u'test_string': {'order': 3, 'string': u'test2.com'}
                }
            )

            mock_api.reset_mock()
            mock_artifact.reset_mock()
            mock_alert.reset_mock()

            hive_alerter = HiveAlerter(rule_classic)
            hive_alerter.alert(matches_classic)

            mock_api.assert_called_with(
                u'http://test_host:9000',
                u'',
                cert=False,
                proxies={u'http': u'', u'https': u''}
            )

            mock_artifact.assert_any_call(data=u'test.com_1.1.1.1.txt', dataType=u'filename')
            mock_artifact.assert_any_call(data=u'test.com', dataType=u'domain')
            mock_artifact.assert_any_call(data=u'test2.com', dataType=u'domain')
            mock_artifact.assert_any_call(data=u'nested_value', dataType=u'domain')
            mock_artifact.assert_any_call(data=u'1.1.1.1', dataType=u'ip')
            mock_alert.assert_called_with(
                artifacts=[u'fake_artifact_return' for i in xrange(len(rule_classic['hive_observable_data_mapping'])*2)],
                description=u'test_rule_name\n\na_boolean: True\na_date: '+unicode(a_date)+'\na_number: 123\ndomain: test.com\nip_address: 1.1.1.1\nnested1: {\n    "nested2": "nested_value"\n}\nsome_other_domain: test2.com\n\n----------------------------------------\ntest_rule_name\n\na_boolean: True\na_date: '+unicode(a_date)+'\na_number: 123\ndomain: test.com\nip_address: 1.2.3.4\nnested1: {\n    "nested2": "nested_value"\n}\nsome_other_domain: test2.com\n\n----------------------------------------\n',
                follow=True,
                severity=2,
                source=u'instance1',
                sourceRef='123456',
                status=u'New',
                tags=[u'TheHive4Py', u'sample test_rule_name'],
                title=u'test_rule_name',
                tlp=3,
                type=u'external',
                customFields={
                    u'test_number': {'order': 0, 'number': '123'},
                    u'test_boolean': {'order': 1, 'boolean': u'True'},
                    u'test_date': {'order': 2, 'date': unicode(a_date)},
                    u'test_string': {'order': 3, 'string': u'test2.com'}
                }
            )
