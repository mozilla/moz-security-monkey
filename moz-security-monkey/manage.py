#     Copyright 2014 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

from flask.ext.script import Manager, Command, Option
from security_monkey import app, db
from security_monkey.common.route53 import Route53Service
from gunicorn.app.base import Application

from flask.ext.migrate import Migrate, MigrateCommand

from moz_security_monkey.scheduler import run_change_reporter as sm_run_change_reporter
from moz_security_monkey.scheduler import find_changes as sm_find_changes
from moz_security_monkey.scheduler import audit_changes as sm_audit_changes
from moz_security_monkey.backup import backup_config_to_json as sm_backup_config_to_json

import csv

manager = Manager(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

@manager.command
def drop_db():
    """ Drops the database. """
    db.drop_all()

@manager.command
def create_db():
    """ Drops the database. """
    db.create_all()

@manager.option('-a', '--accounts', dest='accounts', type=unicode, default=u'all')
def run_change_reporter(accounts):
    """ Runs Reporter """
    sm_run_change_reporter(accounts)


@manager.option('-a', '--accounts', dest='accounts', type=unicode, default=u'all')
@manager.option('-m', '--monitors', dest='monitors', type=unicode, default=u'all')
def find_changes(accounts, monitors):
    """Runs watchers"""
    sm_find_changes(accounts, monitors)


@manager.option('-a', '--accounts', dest='accounts', type=unicode, default=u'all')
@manager.option('-m', '--monitors', dest='monitors', type=unicode, default=u'all')
@manager.option('-r', '--send_report', dest='send_report', type=bool, default=False)
def audit_changes(accounts, monitors, send_report):
    """ Runs auditors """
    sm_audit_changes(accounts, monitors, send_report)


@manager.option('-a', '--accounts', dest='accounts', type=unicode, default=u'all')
@manager.option('-m', '--monitors', dest='monitors', type=unicode, default=u'all')
@manager.option('-o', '--outputfolder', dest='outputfolder', type=unicode, default=u'backups')
def backup_config_to_json(accounts, monitors, outputfolder):
    """Saves the most current item revisions to a json file."""
    sm_backup_config_to_json(accounts, monitors, outputfolder)


@manager.command
def start_scheduler():
    """ starts the python scheduler to run the watchers and auditors"""
    from moz_security_monkey import scheduler
    scheduler.setup_scheduler()
    scheduler.scheduler.start()

@manager.option('-f', '--filename', dest='filename', type=unicode)
def add_accounts(filename):
    from security_monkey.common.utils.utils import add_account
    with open(filename, 'rb') as csvfile:
        csvreader = csv.reader(csvfile)
        for row in csvreader:
            number = row[0]
            name = row[1]
            role_name = row[2]
            res = add_account(number=number,
                              third_party=False,
                              name=name,
                              s3_name=None,
                              active=True,
                              notes=None,
                              role_name=role_name)
            if res:
                app.logger.info('Successfully added account {}'.format(name))
            else:
                app.logger.info('Account with id {} already exists'.format(number))

@manager.option('-b', '--bucket', dest='bucket', type=unicode, default=u'infosec-internal-data')
@manager.option('-k', '--key', dest='key', type=unicode, default=u'iam-roles/roles.json')
@manager.option('-t', '--trusted_entity', dest='trusted_entity', type=unicode, default=u'arn:aws:iam::371522382791:root')
@manager.option('-r', '--role_type', dest='role_type', type=unicode, default=u'InfosecSecurityAuditRole')
def add_all_accounts(bucket, key, trusted_entity, role_type):
    import boto3, json, botocore.exceptions
    from security_monkey.common.utils.utils import add_account

    # TODO : Convert this to boto instead of boto3
    # TODO : Describe json schema here
    client = boto3.client('s3')
    response = client.get_object(
        Bucket=bucket,
        Key=key)
    roles = json.load(response['Body'])

    for role in [x for x in roles if
                 x['TrustedEntity'] == trusted_entity
                 and x['Type'] == role_type]:
        session = boto3.Session()
        client_sts = session.client('sts')
        try:
            response_sts = client_sts.assume_role(
                RoleArn=role['Arn'],
                RoleSessionName='fetch_aliases')
        except botocore.exceptions.ClientError:
            print('Unable to assume role {}'.format(role['Arn']))
            continue
        credentials = {
            'aws_access_key_id': response_sts['Credentials']['AccessKeyId'],
            'aws_secret_access_key': response_sts['Credentials'][
                'SecretAccessKey'],
            'aws_session_token': response_sts['Credentials']['SessionToken']}
        client_iam = boto3.client('iam', **credentials)
        response_iam = client_iam.list_account_aliases()
        alias = response_iam['AccountAliases'][0] if len(
            response_iam['AccountAliases']) == 1 else str(
            role['Arn'].split(':')[4])
        params = {
            'number': role['Arn'].split(':')[4],
            'third_party': False,
            'name': alias[:32],
            's3_name': u'',
            'active': True,
            'notes': alias,
            'role_name': role['Arn'].split(':')[5].split('/')[1]
        }
        print(json.dumps(params))
        result = add_account(**params)
        if result:
            print('Successfully added account {}'.format(params['name']))
        else:
            print('Account with id {} already exists'.format(params['number']))

if __name__ == "__main__":
    manager.run()
