#!/usr/bin/env python3

# Get and validate MIAC configuration details from user
# writes config to file, shell script assignments, expect password which is printed to stdout

import sys
import dialog
import validators
from zoneinfo import available_timezones

main = __name__ == '__main__'


d = dialog.Dialog()

height = 11
width = 65

options = dict(
    cr_wrap=True,
    trim=True,
    #stdout=True,
)

def msgbox(text):
    d.msgbox(text, height - 2, width - 10, **options)

def inputbox(title, text, init, extra=0):
    status, result = d.inputbox(text,
                                height + extra, width,
                                init,
                                title=title,
                                **options)
    if status == d.CANCEL:
        sys.exit(1)

    return result

def passwordbox(title, text):
    status, password = d.passwordbox(text,
                                     height, width,
                                     title=title,
                                     insecure=True,
                                     **options)
    if status == d.CANCEL:
        sys.exit(1)

    return password

utc_timezone = 'Etc/UTC'
assert utc_timezone in available_timezones(), str((utc_timezone,))
newyork_timezone = 'America/New_York'
assert newyork_timezone in available_timezones(), str((newyork_timezone,))


def run_dialogs(ip_address):
    # The domain
    domain = 'cochleaudio.com'
    while False:
        domain = inputbox('Welcom to Miac Server Configuration', '\nJust a few questions and your mail-in-a-container server will be configured.\n\nEnter the domain name you are configuring.', domain, 2)
        domain = domain.strip().lower()
        domain = domain
        if not validators.domain(domain):
            msgbox('It needs to be a valid domain name.\n\nTry again.')
            continue
        break

    # The hostname
    # shed: Server Http Email Dns
    hostname = 'shed.' + domain
    while False:
        hostname = inputbox('Email Server Hostname','\nEnter a hostname for the server.  This will the be name of the website that users go to for their webmail.', hostname)
        hostname = hostname.strip().lower()
        if not validators.domain(hostname): 
            msgbox('It needs to be a valid hostname.\n\nTry again.')
            continue
        if not hostname.endswith(domain): 
            msgbox(f'Hostname needs to end with ".{domain}"\n\nTry again.')
            continue
        break

    # The timezone
    timezone = utc_timezone
    while False:
        timezone = inputbox('Timezone', f'\nEnter a timezone for the server.  We suggest using {utc_timezone}.', timezone)
        timezone = timezone.strip()
        if timezone not in available_timezones():
            msgbox(f'It needs to be a valid time zone. {utc_timezone} is your friend, as is {newyork_timezone}.\n\nTry again.')
            continue
        break

    # The admin account name, email address
    email = 'admin@' + domain
    while False:
        email = inputbox('Admin Email', '\nEnter an email address for the admin account.  This will be the administrative user who manages the webmail server.', email)
        email = email.strip().lower()
        if not validators.email(email): 
            msgbox('It needs to be a valid email address.\n\nTry again.')
            continue
        if not email.endswith(domain): 
            msgbox(f'Email needs to end with ".{domain}"\n\nTry again.')
            continue
        break

    # The password
    password = '12345678'
    while False:
        password = passwordbox('Admin Password', f'\nEnter a password for {email}')
        if len(password) < 4:
            msgbox('Password must be longer.\n\nTry again.')
            continue
        password2 = passwordbox('Admin Password verify', f'\nRe-enter the password for {email}')
        if password2 != password:
            msgbox('Passwords need to match.\n\nTry again.')
            continue
        break

    glue_message = f"""
Set these Glue Records at the registrar for {domain}

Nameservers:
  ns1.{hostname}
  ns2.{hostname}

IP Address:
  {ip_address}
"""
    d.msgbox(glue_message, height + 4, width - 15, **options)

    return dict(
        MIAC_DOMAIN=domain,
        MIAC_HOSTNAME=hostname,
        MIAC_TIMEZONE=timezone,
        MIAC_EMAIL=email,

        STORAGE_ROOT='/home/user-data',
        STORAGE_USER='user-data',
        PRIMARY_HOSTNAME=hostname,
        EMAIL_ADDR=email,
        
        # TODO: figure out how to make printing of this work...
        EMAIL_PW=password,
        
        # Setting these prevents certain default actions
        NONINTERACTIVE=1,
        SKIP_NETWORK_CHECKS=1,
        DISABLE_FIREWALL=1,
        
        MIAC_INSTALL=1,
        #MIAC_SYSTEMD='',
        #MIAC_CONF='',
        MIAC_VERBOSE=1,

        MIAC_PASSWORD=password,
        glue_message=glue_message,
    )

def miac_conf(args):
    ip_address, outfilename, = args

    # Fail early if we can't write to the file
    # This will have the unfortunate side effect of leaving an empty file if we fail before finishing...
    with open(outfilename, 'at'):
        pass
    
    config = run_dialogs(ip_address)

    password = config.pop('MIAC_PASSWORD')
    glue_message = config.pop('glue_message')

    with open(outfilename, 'wt') as outfile:
        for key, value in config.items():
            value = f'{value}'.strip()
            if value:
                print(f'export {key}={value}', file=outfile)

    # python/dialog uses stdout to communicate dialog results, but also, somehow, dialog fusses over stdout being a tty;
    # this stdout fussing appears to make for trouble trying to capture the password in shell syntax;
    # so, we send password to stderr and with the following fd duping it gets captured in the shell; and the glue message appears on the console...
    # $ pass=$(./miac-conf.py 1.2.3.4 foo.config 3>&2 2>&1 1>&3)
    print(glue_message)
    print(password, file=sys.stderr)

if main:
    sys.exit(miac_conf(sys.argv[1:]))
    
