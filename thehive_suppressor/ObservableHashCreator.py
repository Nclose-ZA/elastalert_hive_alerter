#!/usr/bin/env python
# encoding: utf-8

import datetime
import hashlib
import json
import sys

from cortexutils.responder import Responder
from elasticsearch_dsl import connections, Document, Keyword, Index, Date
from thehive4py.models import AlertArtifact, JSONSerializable, CustomJsonEncoder


# Monkey patch jsonify as the indent keyword results in different hashes between python 2 & 3
def jsonify(self):
    return json.dumps(self, sort_keys=True, cls=CustomJsonEncoder)
JSONSerializable.jsonify = jsonify


class ObservableHashCreator(Responder):
    """
    Creates an MD5 hash of the observables in the specified Elasticsearch database
    """

    def __init__(self):

        Responder.__init__(self)

        self.es_host = self.get_param('config.es_host', message='You have to configure an Elasticsearch host')
        self.es_port = self.get_param('config.es_port', default="9200")
        self.es_username = self.get_param('config.es_username')
        self.es_password = self.get_param('config.es_password')
        self.es_index = self.get_param('config.es_index', default='alert_hashes')

        self.es_kwargs = {
            'hosts': [':'.join([self.es_host, self.es_port])]
        }

        if self.es_username:
            self.es_kwargs['http_auth'] = (self.es_username, self.es_password)

        self.es_kwargs.update({
            'use_ssl': self.get_param('es_use_ssl', default=False),
            'verify_certs': self.get_param('es_verify_certs', default=False),
            'client_cert': self.get_param('es_client_cert'),
            'client_key': self.get_param('es_client_key'),
            'ca_certs': self.get_param('es_ca_certs'),
            'timeout': self.get_param('es_timeout', default=20)
        })

    def run(self):
        """
        Add a hash to the specified Elasticsearch index if some artifacts have been submitted and the hash does not
            already exist
        """

        Responder.run(self)

        data = self.get_data()
        artifacts = self.get_param('data.artifacts')
        rule_title = self.get_param('data.title', default='no data')
        suppressing_username = self.get_param('data.createdBy', default='no data')
        if not artifacts:  # If there are no artifacts we have no data to generate a hash
            self.error('No artifacts submitted')
        observables = []
        # The jsonify method provides a list of predictably sorted JSON strings which we then sort in order to make
        #   sure that the we generate the same hash that will be read from the database by HashSuppressorEnhancement
        for artifact in artifacts:
            observables.append(AlertArtifact(dataType=artifact.get('dataType'), data=artifact.get('data')))
        observable_hash_string = u'|'.join(sorted([observable.jsonify() for observable in observables]))
        observable_hash = hashlib.md5(observable_hash_string.encode('utf-8')).hexdigest()

        class AlertHash(Document):
            alert_hash = Keyword()
            date_suppressed = Date()
            rule_title = Keyword()
            suppressing_username = Keyword()
            class Index:
                name = self.es_index  # This is required because the commented registration below does not work

        connections.create_connection(**self.es_kwargs)
        alert_hashes = Index(self.es_index)
        # alert_hashes.document(AlertHash)  # Registering a Document to the Index does not work for some reason
        if not alert_hashes.exists():
            alert_hashes.create()
        results = AlertHash.search().filter('term', alert_hash=observable_hash).execute(ignore_cache=True)
        if not results:  # Don't save the same hash multiple times
            alert_hash = AlertHash(
                alert_hash=observable_hash,
                date_suppressed=datetime.datetime.now(),
                rule_title=rule_title,
                suppressing_username=suppressing_username
            )
            alert_hash.save()
            message = 'MD5 hash [{}] added to Elasticsearch database [{}:{}] index [{}]'.format(
                observable_hash, self.es_host, self.es_port, self.es_index)
        else:
            message = 'MD5 hash [{}] already existed in the Elasticsearch database [{}:{}] index [{}]'.format(
                observable_hash, self.es_host, self.es_port, self.es_index)

        self.report({'message': message})


if __name__ == '__main__':
    ObservableHashCreator().run()

