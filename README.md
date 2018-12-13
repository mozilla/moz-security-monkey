# Overview

`moz-security-monkey` is a python package, chef cookbook and AWS CloudFormation
template that will customize Netflix Security Monkey for use at Mozilla. This
customized deployment is referred to as AWS Security Auditing Platform (ASAP)
at Mozilla.

The `moz-security-monkey` python package overrides various parts of Security
Monkey in order to
* integrate it with the Mozilla SIEM, MozDef
* add new watchers and auditors not present in Security Monkey
* disable Security Monkey auditors that aren't used at Mozilla
* integrate it with Mozilla's single sign on service for authentication
* other customizations

# Deploying moz-security-monkey

## Pre-work

* Ensure SES is configured
  * Add your domain name as verified sending domain by setting up DNS records (in all 3 SES regions, or at least us-east-1, the default SES_REGION)
  * Request a sending limit increase to get out of sandbox mode (in all 3 SES regions, or at least us-east-1, the default SES_REGION)
* Ensure your target SQS queue exists and grants you permission to send to it. Currently to send to a queue in a foreign AWS account you must use a "sqs:*" permission resource policy for an unknown reason

      {
        "Version": "2012-10-17",
        "Id": "arn:aws:sqs:us-west-1:656532927350:infosec_mozdef_events/SQSDefaultPolicy",
        "Statement": [
          {
            "Sid": "infosec_mozdef_events_SendMessage",
            "Effect": "Allow",
            "Principal": {
              "AWS": "371522382791"
            },
            "Action": "sqs:*",
            "Resource": "arn:aws:sqs:us-west-1:656532927350:infosec_mozdef_events"
          }
        ]
      }


## Setup

* Deploy the CloudFormation template which uses /tmp/set-chef-secrets.py to generate secrets
  * Which fetches the dev branch of gene1wood/chef-security-monkey
  * But doesn't run chef as there are still work on the recipe yet to be published to GitHub
* Apply any dev changes to chef-security-monkey which aren't present on github
* Re-deploy those changes with berkshelf

        cd /root/security-monkey
        BERKSHELF_PATH=/root/.berkshelf HOME=/root berks install --berksfile=/root/security-monkey/Berksfile
        BERKSHELF_PATH=/root/.berkshelf HOME=/root berks vendor --berksfile=/root/security-monkey/Berksfile /opt/chef/cookbooks
* Apply any changes to the moz-security-monkey chef cookbook which are not yet 
  published to GitHub
  * rsync the contents over to /opt/moz-security-monkey

        ln -s /opt/moz-security-monkey/chef/cookbooks/moz-security-monkey /opt/chef/cookbooks/moz-security-monkey
  * modify node.json to add moz-security-monkey to runlist
* Run chef-client

      chef-client -z -c /etc/chef/client.rb -j /opt/chef/nodes/node.json --force-logger
* Logs are in
  * `/tmp/security_monkey-deploy.log`
  * `/tmp/security*.log`
  * `/tmp/mozsecuritymonkey*.log`
* Active code is in `/home/secmonkey/.virtualenv`
* Config is in `/opt/secmonkey/env-config/config-deploy.py`

# Developing moz-security-monkey

## Connecting and updating with berkshelf

    server=ec2-52-35-218-244.us-west-2.compute.amazonaws.com
    lsyncd -delay 0 -nodaemon -rsyncssh ~/code/github.com/gene1wood/chef-security-monkey/ centos@$server /home/centos/chef-security-monkey

    ssh centos@$server
    cd /home/centos/chef-security-monkey
    BERKSHELF_PATH=/root/.berkshelf sudo berks install
    BERKSHELF_PATH=/root/.berkshelf sudo berks package /dev/stdout | sudo tar -C /opt/chef -vzxf -
    sudo chef-client -z -c /etc/chef/client.rb -j /opt/chef/nodes/node.json

## Connecting and updating without berkshelf

You'll need to add your ssh key to the root users authorized_keys by overwriting the file

    sed -i -e 's/.* \(ssh-rsa .*\)/\1/g' /root/.ssh/authorized_keys
    service sshd reload


    server=ec2-52-35-218-244.us-west-2.compute.amazonaws.com
    lsyncd -delay 0 -nodaemon -rsyncssh ~/code/github.com/gene1wood/chef-security-monkey/ root@$server /opt/chef/cookbooks/security-monkey/

    sudo chef-client -z -c /etc/chef/client.rb -j /opt/chef/nodes/node.json

## Updating Security Monkey Code

    server=ec2-52-35-218-244.us-west-2.compute.amazonaws.com
    rsync --itemize-changes --recursive --exclude=/.git --exclude=/env-config/config-deploy.py --size-only ~/code/github.com/gene1wood/security_monkey/ root@${server}:/opt/secmonkey
    
    # Potentially rebuild dart pages if needed
    cd /opt/secmonkey/dart
    /root/.chef/local-mode-cache/cache/dart-sdk/bin/pub build
    rsync --itemize-changes --recursive /opt/secmonkey/dart/build/web/ /opt/secmonkey/security_monkey/static/
    
    # Install new security monkey code
    /home/secmonkey/.virtualenv/bin/pip uninstall security-monkey
    cd /opt/secmonkey
    HOME=/home/secmonkey USER=secmonkey SECURITY_MONKEY_SETTINGS=/opt/secmonkey/env-config/config-deploy.py /home/secmonkey/.virtualenv/bin/python setup.py install
    service nginx restart

    # Restart service
    supervisorctl -c /opt/secmonkey/supervisor/moz_security_monkey.ini restart securitymonkey

## Updating Moz Security Monkey Code

    # Edit files in /opt/moz-security-monkey/moz-security-monkey/moz_security_monkey
    /home/secmonkey/.virtualenv/bin/pip uninstall moz-security-monkey
    cd /opt/moz-security-monkey/moz-security-monkey
    HOME=/home/secmonkey USER=secmonkey SECURITY_MONKEY_SETTINGS=/opt/secmonkey/env-config/config-deploy.py /home/secmonkey/.virtualenv/bin/python setup.py install


## Debugging

    sudo -u secmonkey PYTHON_EGG_CACHE="/opt/secmonkey/.python-eggs" SECURITY_MONKEY_SETTINGS="/opt/secmonkey/env-config/config-deploy.py" /home/secmonkey/.virtualenv/bin/python /opt/secmonkey/manage.py run_api_server

## Resetting the database

    sudo -u postgres psql
        drop database secmonkey;
    sudo -u postgres createdb secmonkey
    cd /opt/secmonkey
    sudo -u secmonkey bash -c "SECURITY_MONKEY_SETTINGS=\"/opt/secmonkey/env-config/config-deploy.py\" PYTHON_EGG_CACHE=\"/opt/secmonkey/.python-eggs\" /home/secmonkey/.virtualenv/bin/python /opt/secmonkey/manage.py db upgrade"
    # Re-add the AWS accounts you want

## Exploring the database

    sudo -u postgres psql
        \c secmonkey
        \d
        \d+ itemaudit
        select * from itemaudit, item, account where itemaudit.item_id = item.id and item.account_id = account.id and itemaudit.score >= 10 and account.number = '012345678901' limit 30;

# Using moz-security-monkey

## Browsing to the interface

* Browse to https://asap.security.mozilla.org/

## Setting it up

* Register a user
* Add an IAM Role and account

      sudo -u secmonkey bash -c "SECURITY_MONKEY_SETTINGS=\"/opt/secmonkey/env-config/config-deploy.py\" PYTHON_EGG_CACHE=\"/opt/secmonkey/.python-eggs\" /home/secmonkey/.virtualenv/bin/python /opt/secmonkey/manage.py add_account -u 586912254304 -n \"General Content Services - 1500\" -r InfosecClientRoles-InfosecSecurityAuditRole-1RP4CZL3B675M"

* Restart the scheduler

      supervisorctl -c /opt/secmonkey/supervisor/moz_security_monkey.ini restart mozsecuritymonkeyscheduler

## Adding all AWS accounts

    sudo -u secmonkey bash -c "SECURITY_MONKEY_SETTINGS=\"/opt/secmonkey/env-config/config-deploy.py\" PYTHON_EGG_CACHE=\"/opt/secmonkey/.python-eggs\" /home/secmonkey/.virtualenv/bin/python /opt/secmonkey/moz_manage.py add_all_accounts"

# Other notes

## Things to run on the server upon reboot

These are potentially not built into systemd and startup scripts

    supervisord -c /opt/secmonkey/supervisor/moz_security_monkey.ini

## Gotchas

When rerunning chef you get the error

    * execute[postgresql-setup initdb postgresql] action run
      [execute] Data directory is not empty!

To fix run :

    rm -rf /var/lib/pgsql/9.2/data/*

When initially starting you get

    mozsecuritymonkeyscheduler       FATAL     Exited too quickly (process log may have details)
    
because there are no accounts loaded. See Setting it up above

## TODO

* Fully disable the stock scheduler in supervisord so there's no chance of it running
* Enable the moz security monkey scheduler
  * Add this block to security_monkey.ini.erb or a different file

        [program:mozsecuritymonkeyscheduler]
        command=<%= @virtualenv %>/bin/python /opt/moz_security_monkey/manage.py start_scheduler
        directory=/opt/moz_security_monkey/
        environment=PYTHON_EGG_CACHE="<%= node['security_monkey']['basedir'] %>/.python-eggs",PYTHONPATH='/opt/moz_security_monkey/',SECURITY_MONKEY_SETTINGS="<%= node['security_monkey']['basedir'] %>/env-config/config-deploy.py"
        user=<%= node['security_monkey']['user'] %>
        autostart=true
        autorestart=true
* Change file ownership so secmonkey can read but not write files
* Pull/revert to current security_monkey master
* Reapply add-cloudtrail-connection-support from gene1wood/dev
* Reapply fix-import-common-utils from gene1wood/dev
* Update chef-security-monkey to use flask / okta / saml (from ipquery) instead of browserid
