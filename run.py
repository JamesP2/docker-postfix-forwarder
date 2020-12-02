#!/usr/bin/python

# Copyright 2015 Joe Beda
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

from subprocess import *
import yaml
from yamlinclude import YamlIncludeConstructor
import io
import logging
import os
import os.path
import sys
from pathlib import Path

CONFIG_FILE = '/opt/config/config.yaml'
SYSLOG_FIFO = '/var/log/syslog-fifo'

YamlIncludeConstructor.add_to_loader_class(
    loader_class=yaml.FullLoader, base_dir='/opt/config')


def main():
    global config
    global start_services

    start_services = not (len(sys.argv) > 1 and sys.argv[1] == '--nostart')

    logging.getLogger().setLevel(logging.INFO)
    logging.info('Reading config: %s' % CONFIG_FILE)
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.load(f)

    spawn_rsyslogd()
    base_postfix_config()
    configure_postscreen()
    configure_sasl()
    configure_virtual_domains()
    configure_opendkim()
    spawn_opendkim()
    spawn_postsrsd()
    spawn_postfix()

    # Wait for something to exit.  As soon as some child process exits we exit
    if start_services:
        os.wait()

    logging.info('Exited')


def spawn_rsyslogd():
    logging.info('Starting rsyslogd')
    if os.path.exists(SYSLOG_FIFO):
        call(['rm', SYSLOG_FIFO])
    if os.path.exists('/var/run/rsyslogd.pid'):
        call(['rm', '/var/run/rsyslogd.pid'])
    check_call(['mkfifo', SYSLOG_FIFO])
    with open('/etc/rsyslog.conf', 'w') as f:
        f.write(r"""
$ModLoad imuxsock
$template TraditionalFormatWithPRI,"%timegenerated:::date-rfc3339% %pri-text% %HOSTNAME% %syslogtag%%msg:::drop-last-lf%\n"
$WorkDirectory /var/spool/rsyslog
*.* |/var/log/syslog-fifo;TraditionalFormatWithPRI
""".strip())
    Popen(['cat', SYSLOG_FIFO])
    Popen(['rsyslogd', '-n'])


def base_postfix_config():
    # Set up the spool directory so it hass all of the right sub-dirs.
    check_call(['postfix', 'post-install', 'create-missing'])

    # Turn off all the chrooting in postfix. This only works for postfix v2.11+.
    check_call(['postconf', '-F', '*/*/chroot = n'])

    # Set up a virtual map (placeholder for now)
    check_call(['postconf', '-e', 'myhostname=%s' % config['ptr_hostname']])
    check_call(['postconf', '-e', 'local_recipient_maps='])
    check_call(['postconf', '-e', 'mydomain=localdomain'])
    check_call(['postconf', '-e', 'mydestination='])
    check_call(['postconf', '-e', ('message_size_limit = %d' % (50*1024*1024,))])

    # Enable TLS for smtpd
    check_call(['postconf', '-e', 'smtpd_tls_security_level=may'])
    check_call(['postconf', '-e', 'smtpd_tls_auth_only=yes'])

    # Configure the submission service (587)
    check_call(
        ['postconf', '-Me', 'submission/inet = submission inet n - n - - smtpd'])
    check_call(
        ['postconf', '-Pe', 'submission/inet/syslog_name=postfix/submission'])
    check_call(
        ['postconf', '-Pe', 'submission/inet/smtpd_tls_security_level=encrypt'])
    check_call(['postconf', '-Pe', 'submission/inet/smtpd_sasl_auth_enable=yes'])
    check_call(
        ['postconf', '-Pe', 'submission/inet/smtpd_reject_unlisted_recipient=no'])
    check_call(
        ['postconf', '-Pe', 'submission/inet/smtpd_recipient_restrictions='])
    check_call(['postconf', '-Pe',
                'submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject'])
    check_call(
        ['postconf', '-Pe', 'submission/inet/milter_macro_daemon_name=ORIGINATING'])


def configure_postscreen():
    if not config['postscreen']['enable']:
        return

    check_call(['postconf', '-MX', 'smtp/inet'])
    check_call(['postconf', '-Me', 'smtpd/pass = smtpd pass - - n - - smtpd'])
    check_call(['postconf', '-Me', 'smtp/inet = smtp inet n - n - 1 postscreen'])
    check_call(
        ['postconf', '-Me', 'tlsproxy/unix = tlsproxy unix - - n - 0 tlsproxy'])
    check_call(
        ['postconf', '-Me', 'dnsblog/unix = dnsblog unix - - n - 0 dnsblog'])

    # Before-220 tests
    check_call(['postconf', '-e', 'postscreen_dnsbl_action = enforce'])
    check_call(['postconf', '-e', 'postscreen_dnsbl_threshold = 2'])
    check_call(['postconf', '-e', 'postscreen_dnsbl_sites = zen.spamhaus.org*2 bl.spamcop.net*1 b.barracudacentral.org*1 swl.spamhaus.org*-3'])

    check_call(['postconf', '-e', 'postscreen_greet_action = enforce'])

    if config['postscreen']['enable_slow_checks']:
        # After-220 tests -- these can cause significant delays so are disabled for now.
        check_call(
            ['postconf', '-e', 'postscreen_bare_newline_action = enforce'])
        check_call(['postconf', '-e', 'postscreen_bare_newline_enable = yes'])
        check_call(
            ['postconf', '-e', 'postscreen_non_smtp_command_enable = yes'])
        check_call(['postconf', '-e', 'postscreen_pipelining_enable = yes'])


def configure_sasl():
    check_call(['postconf', '-e', 'smtpd_sasl_type = cyrus'])
    check_call(['postconf', '-e', 'smtpd_sasl_auth_enable = yes'])
    check_call(['postconf', '-e', 'smtpd_tls_auth_only = no'])
    check_call(['postconf', '-e', 'smtp_sasl_security_options = noanonymous'])
    check_call(['postconf', '-e', 'broken_sasl_auth_clients = yes'])
    check_call(['adduser', 'postfix', 'sasl'])
    with open('/etc/postfix/sasl/smtpd.conf', 'w') as f:
        f.write("""
pwcheck_method: auxprop
auxprop_plugin: sasldb
mech_list: PLAIN
""".strip())

    for (domain, domain_info) in config['virtual_domains'].items():
        for account in domain_info['accounts']:
            logging.info("Creating SASL account for %s@%s" %
                         (account['name'], domain))
            cmd = ['saslpasswd2', '-p', '-c', '-u', domain, account['name']]
            p = Popen(cmd, stdin=PIPE)
            p.communicate(input=str.encode(account['password']))
            retcode = p.poll()
            if retcode:
                raise CalledProcessError(retcode, cmd)


def get_forward_list(account):
    forward = account['forward']
    if isinstance(forward, str):
        forward = [forward]
    return forward


def configure_virtual_domains():
    domains = config['virtual_domains'].keys()
    check_call(['postconf', '-e', 'virtual_alias_domains=%s' %
                ' '.join(domains)])
    check_call(['postconf', '-e',
                'virtual_alias_maps=hash:/etc/postfix/virtual regexp:/etc/postfix/virtual.regexp'])
    with open('/etc/postfix/virtual', 'w') as f:
        for (domain, domain_info) in config['virtual_domains'].items():
            for account in domain_info['accounts']:
                def forward(alias):
                    forward = ' '.join(get_forward_list(account))
                    logging.info("Forwarding %s@%s to %s" %
                                 (alias, domain, forward))
                    f.write('%s@%s %s\n' % (alias, domain, account['forward']))
                forward(account['name'])
                for alias in account.get('aliases', []):
                    forward(alias)
            f.write('\n')
    check_call(['postmap', '/etc/postfix/virtual'])

    with open('/etc/postfix/virtual.regexp', 'w') as f:
        for (domain, domain_info) in config['virtual_domains'].items():
            for account in domain_info['accounts']:
                if account.get('dot_plus_rewrite', True):
                    name = account['name']
                    forwards = ' '.join(["%s+$3@%s" % tuple(forward.split('@'))
                                         for forward in get_forward_list(account)])
                    logging.info("Forwarding %s.*@%s to %s" %
                                 (name, domain, forwards))
                    f.write(
                        '/^%s((\\+|\\.)([-a-zA-Z0-9_]+))?@%s$/ %s\n' % (name, domain, forwards))

    ai_fn = '/etc/postfix/access_inbound'
    check_call(['postconf', '-e',
                'smtpd_sender_restrictions=check_recipient_access hash:%s' % ai_fn])
    with open(ai_fn, 'w') as f:
        for (domain, domain_info) in config['virtual_domains'].items():
            for blackhole in domain_info.get('blackholes', []):
                bh_email = "%s@%s" % (blackhole, domain)
                logging.info("Blackholeing %s" % bh_email)
                f.write('%s REJECT\n' % bh_email)
    check_call(['postmap', ai_fn])


def configure_opendkim():
    if not config['dkim']['enable']:
        return

    logging.info('Configuring OpenDKIM')

    check_call(['adduser', 'postfix', 'opendkim'])

    with open('/etc/opendkim.conf', 'a+') as f:
        lines = [
            'KeyTable refile:/etc/opendkimKeyTable\n',
            'SigningTable refile:/etc/opendkimSigningTable\n',
            'ExternalIgnoreList refile:/etc/opendkimTrustedHosts\n',
            'InternalHosts refile:/etc/opendkimTrustedHosts\n',
            'RequireSafeKeys false'
        ]
        f.writelines(lines)

    with open('/etc/opendkimTrustedHosts', 'w') as f:
        f.write('127.0.0.1')

    with open('/etc/opendkimKeyTable', 'w') as key_table, open('/etc/opendkimSigningTable', 'w') as signing_table:
        for (domain, domain_info) in config['virtual_domains'].items():
            # If there's no DKIM configuration for this domain skip it
            if not 'dkim' in domain_info:
                continue

            logging.info('Adding DKIM Key information for %s', domain)

            key_line = domain_info['dkim']['selector'] + \
                '._domainkey.' + domain + ' ' + \
                domain + ':' + domain_info['dkim']['selector'] + \
                ':/opt/config/' + domain_info['dkim']['key']

            key_table.write(key_line + '\n')

            signing_line = '*@' + domain + ' ' + \
                domain_info['dkim']['selector'] + '._domainkey.' + domain

            signing_table.write(signing_line + '\n')

            check_call(['chown', 'opendkim:opendkim',
                        '/opt/config/' + domain_info['dkim']['key']])

    logging.info('Finished configuring OpenDKIM')


def spawn_opendkim():
    if not config['dkim']['enable']:
        return

    check_call(
        ['postconf', '-e', 'smtpd_milters=unix:/run/opendkim/opendkim.sock'])
    check_call(['postconf', '-e', 'non_smtpd_milters=$smtpd_milters'])

    if start_services:
        Popen('/usr/sbin/opendkim')


def spawn_postsrsd():
    if not config['srs']['enable']:
        return

    check_call(['postconf', '-e', 'sender_canonical_maps = tcp:127.0.0.1:10001'])
    check_call(['postconf', '-e', 'sender_canonical_classes = envelope_sender'])
    check_call(
        ['postconf', '-e', 'recipient_canonical_maps = tcp:127.0.0.1:10002'])
    check_call(['postconf', '-e',
                'recipient_canonical_classes = envelope_recipient,header_recipient'])

    with open('/opt/srs.secret', 'w') as f:
        f.write(config['srs']['srs_secret'])

    exclude_domains = ",".join(config['virtual_domains'].keys())

    if start_services:
        cmd = ['postsrsd-1.2/build/postsrsd', '-s/opt/srs.secret', '-upostfix',
               '-d%s' % config['srs']['srs_domain'],
               '-X%s' % exclude_domains]
        logging.info("Running postsrsd: %s", repr(cmd))
        Popen(cmd)


def spawn_postfix():
    if start_services:
        os.chdir('/var/spool/postfix')
        cmd = ['/usr/lib/postfix/sbin/master', '-d']
        logging.info("Running postfix master: %s", repr(cmd))
        process = Popen(cmd)
        logging.info('Waiting for process')
        process.wait()


if __name__ == "__main__":
    main()
