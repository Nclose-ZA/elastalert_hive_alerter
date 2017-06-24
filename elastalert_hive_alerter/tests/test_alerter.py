# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from mock import patch
from unittest import TestCase


class TestAlerter(TestCase):

    def test_alerter(self):

        rule = {
            'hive_observable_data_mapping': [
                {'filename': '{domain}_{ip_address}.txt'},
                {'domain': 'domain'},
                {'domain': 'some_other_domain'},
                {'ip': 'ip_address'}
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
                'tags': ['TheHive4Py', 'sample'],
                'title': 'Test Title',
                'source': 'instance1',
                'follow': True,
                'type': 'external',
                'description': 'Test desc'
            }
        }

        matches = [
            {
                'ip_address': '1.1.1.1',
                'domain': 'test.com',
                'some_other_domain': 'test2.com'
            }
        ]

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
                u'username',
                u'password',
                {u'http': u'', u'https': u''}
            )

            mock_artifact.assert_any_call(data=u'test.com_1.1.1.1.txt', dataType=u'filename')
            mock_artifact.assert_any_call(data=u'test.com', dataType=u'domain')
            mock_artifact.assert_any_call(data=u'test2.com', dataType=u'domain')
            mock_artifact.assert_any_call(data=u'1.1.1.1', dataType=u'ip')
            mock_alert.assert_called_with(
                artifacts=[u'fake_artifact_return' for i in xrange(4)],
                description=u'Test desc',
                follow=True,
                severity=2,
                source=u'instance1',
                sourceRef='123456',
                status=u'New',
                tags=[u'TheHive4Py', u'sample'],
                title=u'Test Title',
                tlp=3,
                type=u'external'
            )
