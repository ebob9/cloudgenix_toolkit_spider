#!/usr/bin/env python
import sys
import os
import argparse
import socket
import datetime

####
#
# Enter other desired optional system modules here.
#
####

import json
import re
from copy import deepcopy
import itertools
from operator import itemgetter
import csv
import getpass

####
#
# End other desired system modules.
#
####

# Import CloudGenix Python SDK
try:
    import cloudgenix
    jdout = cloudgenix.jdout
    jdout_detailed = cloudgenix.jdout_detailed
    jd = cloudgenix.jd
except ImportError as e:
    cloudgenix = None
    sys.stderr.write("ERROR: 'cloudgenix' python module required. (try 'pip install cloudgenix').\n {0}\n".format(e))
    sys.exit(1)


# Import Progressbar2
try:
    from progressbar import Bar, ETA, Percentage, ProgressBar
except ImportError as e:
    Bar = None
    ETA = None
    Percentage = None
    ProgressBar = None
    sys.stderr.write("ERROR: 'progressbar2' python module required. (try 'pip install progressbar2').\n {0}\n".format(e))
    sys.exit(1)

# Import tabulate
try:
    from tabulate import tabulate
except ImportError as e:
    tabulate = None
    sys.stderr.write("ERROR: 'tabulate' python module required. (try 'pip install tabulate').\n {0}\n".format(e))
    sys.exit(1)


try:
    import netmiko
except ImportError as e:
    tabulate = None
    sys.stderr.write("ERROR: 'netmiko' python module required. (try 'pip install netmiko').\n {0}\n".format(e))
    sys.exit(1)

# Check for cloudgenix_settings.py config file in cwd.
sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # if cloudgenix_settings.py file does not exist,
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    # Also, seperately try and import USERNAME/PASSWORD from the config file.
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


# Handle differences between python 2 and 3. Code can use text_type and binary_type instead of str/bytes/unicode etc.
if sys.version_info < (3,):
    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes


####
#
# Start custom modifiable code
#
####

TCPING_RESULT = re.compile("time=(?P<latency>.*)ms")

TOOLKIT_PORT = 22
TOOLKIT_TEST_TIMEOUT = 5

GLOBAL_MY_SCRIPT_NAME = "CloudGenix Toolkit Spider"
GLOBAL_MY_SCRIPT_VERSION = "v1.0.0"


class CloudGenixToolkitSpiderError(Exception):
    """
    Custom exception for errors, allows errors to be caught if using as function instead of script.
    """
    pass


def tcping(host, port, timeout=5):
    s = None
    error = False
    start = 0
    stop = 0
    try:
        for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                s = socket.socket(af, socktype, proto)
                s.settimeout(timeout)
            except socket.error as msg:
                s = None
                continue
            try:
                start = datetime.datetime.utcnow()
                s.connect(sa)
                stop = datetime.datetime.utcnow()
                s.close()
            except socket.error as msg:
                s.close()
                s = None
                continue
            break
        if s is None:
            error = True
    except socket.gaierror:
        error = True
    if error is not True and start != 0 and stop != 0:
        delta = stop - start
        return_val = (float(delta.microseconds) / 1000)
    else:
        return_val = -1

    return return_val


def throw_error(message, resp=None, cr=True):
    """
    Non-recoverable error, write message to STDERR and exit or raise exception
    :param message: Message text
    :param resp: Optional - CloudGenix SDK Response object
    :param cr: Optional - Use (or not) Carriage Returns.
    :return: No Return, throws exception.
    """
    output = "ERROR: " + str(message)
    if cr:
        output += "\n"
    sys.stderr.write(output)
    if resp is not None:
        output2 = str(jdout_detailed(resp))
        if cr:
            output2 += "\n"
        sys.stderr.write(output2)
    raise CloudGenixToolkitSpiderError(message)


def throw_warning(message, resp=None, cr=True):
    """
    Recoverable Warning.
    :param message: Message text
    :param resp: Optional - CloudGenix SDK Response object
    :param cr: Optional - Use (or not) Carriage Returns.
    :return: None
    """
    output = "WARNING: " + str(message)
    if cr:
        output += "\n"
    sys.stderr.write(output)
    if resp is not None:
        output2 = str(jdout_detailed(resp))
        if cr:
            output2 += "\n"
        sys.stderr.write(output2)
    return


def extract_items(resp_object, error_label=None):
    """
    Extract
    :param resp_object: CloudGenix Extended Requests.Response object.
    :param error_label: Optional text to describe operation on error.
    :return: list of 'items' objects
    """
    items = resp_object.cgx_content.get('items')

    if resp_object.cgx_status and isinstance(items, list):

        # return data
        return items

    # handle 404 for certian APIs where objects may not exist
    elif resp_object.status_code in [404]:
        return [{}]

    else:
        if error_label is not None:
            throw_error("Unable to cache {0}.".format(error_label), resp_object)
            return [{}]
        else:
            throw_error("Unable to cache response.".format(error_label), resp_object)
            return [{}]


def diff_tags(list_a, list_b):
    """
    Return human readable diff string of tags changed between two tag lists
    :param list_a: Original tag list
    :param list_b: New tag list
    :return: Difference string
    """
    status_str = text_type("")
    tags_added = [tag for tag in list_b if tag not in list_a]
    tags_removed = [tag for tag in list_a if tag not in list_b]

    if tags_added and tags_removed:
        status_str += "added: {0}".format(text_type(tags_added))
        status_str += " removed: {0}".format(text_type(tags_removed))
    elif tags_added:
        status_str += "added: {0}".format(text_type(tags_added))
    elif tags_removed:
        status_str += "removed: {0}".format(text_type(tags_removed))

    if not status_str:
        status_str = "no changes required."

    return status_str


def check_match(key_name, compiled_pattern, cgx_dict):
    """
    Check match for key/pattern in cgx_dict, return info, but don't modify dict.
    :param key_name: Key name to check
    :param compiled_pattern: Compiled regex to use to check value of key_name cast to text.
    :param cgx_dict: CloudGenix config dict.
    :return: Tuple of Match (bool), 'name' in cgx_dict, and key value checked.
    """
    entry_name = cgx_dict.get("name")

    key_val = cgx_dict.get(key_name)
    if key_val is None:
        # not set, set it to ""
        key_val = ""

    # got key val, cast to string. This will allow regex matching on dict or list subkeys.
    match_string = text_type(key_val)

    # check for REGEX match
    if compiled_pattern.match(match_string):
        return True, entry_name, key_val

    else:
        return False, entry_name, key_val


def check_load_plan(plan_filename):
    with open(plan_filename, 'r') as plan_file:
        loaded_plan = list(csv.DictReader(plan_file))

    return loaded_plan


def check_load_test(test_filename):
    with open(test_filename, 'r') as test_file:
        loaded_test = json.load(test_file)

    return loaded_test


def tcping_test(ssh, indiv_test, plan_test_interface):
    test_type = indiv_test.get('test')
    test_name = indiv_test.get('name')
    test_run_count = indiv_test.get('count')
    test_host = indiv_test.get('host')
    # insure IF name is in Toolkit format
    test_if = text_type(plan_test_interface).lower().replace(' ', '')
    if test_type and test_name and test_run_count and test_host:
        test_results = [test_name]
        for test_run in range(1, test_run_count + 1):
            # run the command
            try:
                run_result = ssh.send_command("tcpping {0} {1}".format(test_if, test_host))
            except OSError as e:
                # something failed, just mark test dead and try again.
                run_result = ''
            # check the output
            parsed_output = TCPING_RESULT.search(run_result)
            if not parsed_output:
                # no match, test failed for some reason
                test_result = None
            else:
                # got a match, put the value
                test_result = int(parsed_output.group('latency'))
            # update the results
            test_results.append(test_result)
    else:
        # make null results for failed test config
        test_results = ["{0} - Invalid TCPING test config".format(test_name)]
        for test_run in range(1, test_run_count + 1):
            test_results.append(None)

    return test_results


def run_plan(plan_filename, test_filename, output_filename, toolkit_user, toolkit_pass, timeout=5):
    """

    :param plan_filename:
    :param test_filename:
    :param output_filename:
    :param toolkit_user:
    :param toolkit_pass:
    :param timeout:
    :return:
    """

    test_header_template = ["Site Name", "Element Name", "Test Interface Name", "Circuit Info", "Toolkit Connect"]

    loaded_plan = check_load_plan(plan_filename)
    loaded_test = check_load_test(test_filename)

    # sort plan by "Connect Interface IP"
    grouped_plan = {key: list(value) for key, value in
                    itertools.groupby(loaded_plan, key=lambda x: x['Connect Interface IP'])}

    # print(json.dumps(grouped_plan, indent=4))
    # print(json.dumps(loaded_test, indent=4))

    # expand test_results for toolkit tests.

    header_extension_list = []
    test_count = 1
    for indiv_test in loaded_test:
        test_run_count = indiv_test.get('count')
        test_column = "Test{0}".format(test_count)
        header_extension_list.append(test_column)
        test_count += 1
        for test_run in range(1, test_run_count + 1):
            test_run_name = "{0} Run{1}".format(test_column, test_run)
            header_extension_list.append(test_run_name)

    test_header = test_header_template + header_extension_list
    output_results = [test_header]

    # print("TEST_HEADER {0}".format(test_header))

    # ok, start running test.

    firstbar = len(grouped_plan) + 1
    barcount = 1

    print("Running Toolkit Spider Plan..")

    # could be a long query - start a progress bar.
    pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=firstbar).start()

    for connect_ip, plan_list in grouped_plan.items():
        connected = True
        try:
            ssh = netmiko.ConnectHandler(device_type="cloudgenix_ion", ip=connect_ip,
                                         username=toolkit_user, password=toolkit_pass, timeout=timeout)

            # print("CONNECTING TO {0}".format(connect_ip))
        except netmiko.ssh_exception.NetMikoAuthenticationException as err:
            connected = "Authentication Failed: {0}".format(str(err))
            ssh = None
        except netmiko.ssh_exception.NetMikoTimeoutException as err:
            connected = "Unable to Connect: {0}".format(str(err))
            ssh = None
        except ValueError as err:
            # something happened in Netmiko connect. Mark as failed.
            connected = "Error after connect: {0}".format(str(err))

        for iter_plan in plan_list:
            plan_site_name = iter_plan.get("Site Name")
            plan_element_name = iter_plan.get("Element Name")
            plan_test_if_name = iter_plan.get("Test Interface Name")
            plan_circuit_info = iter_plan.get("Test Interface Circuit")
            plan_result = [plan_site_name, plan_element_name, plan_test_if_name, plan_circuit_info,
                           text_type(connected)]

            # start running tests
            for indiv_test in loaded_test:
                test_type = indiv_test.get('test')
                test_name = indiv_test.get('name')
                test_run_count = indiv_test.get('count')
                # Check valid list of tests (eventually multiple tests)
                if connected is not True:
                    # Can't run test, make up results
                    test_results = [test_name]
                    for test_run in range(1, test_run_count + 1):
                        test_results.append(None)

                elif test_type in ['tcping']:
                    # if test_type == 'tcping':
                    test_results = tcping_test(ssh, indiv_test, plan_test_if_name)

                else:
                    # invalid test, make up fake results
                    test_results = ["{0} - Not run (invalid test type {1})".format(test_name, test_type)]
                    for test_run in range(1, test_run_count + 1):
                        test_results.append(None)

                # extend plan result.
                plan_result.extend(test_results)

            # tests in this plan entry are finished. Publish results.
            output_results.append(plan_result)

        # finished this toolkit connection. next.
        if ssh is not None:
            ssh.disconnect()
        barcount += 1
        pbar.update(barcount)

    # finish after iteration.
    pbar.finish()

    with open(output_filename, "w") as csv_output:
        writer = csv.writer(csv_output, quoting=csv.QUOTE_ALL)
        writer.writerows(output_results)
    return


def build_plan(sdk, site_key_name, site_compiled_pattern, element_key_name, element_compiled_pattern,
               connect_interfaces, test_interfaces, output):

    connect_interfaces_match_list = connect_interfaces.lower().split(',')
    test_interfaces_match_list = test_interfaces.lower().split(',')

    output_results = [["Site Name", "Site ID", "Element Name", "Element ID",
                       "Connect Interface Name", "Connect Interface IP", "Test Interface Name",
                       "Test Interface Circuit", "Test Interface ID", "Connect Interface Reachable"]]
    working_results = []

    sites_list = extract_items(sdk.get.sites(), 'sites')
    elements_list = extract_items(sdk.get.elements(), 'elements')
    wannetworks_list = extract_items(sdk.get.wannetworks(), 'wannetworks')
    # waninterfacelabels_list = extract_items(sdk.get.waninterfacelabels(), 'waninterfacelabels')

    wannetworks_id2n = {text_type(i.get('id')): i.get('name') for i in wannetworks_list}
    # waninterfacelabels_id2n = {text_type(i.get('id')): i.get('name') for i in waninterfacelabels_list}

    # lookup tables for matches on site id and element id
    site_match_lookup = {}
    element_match_lookup = {}

    # list of lists containing [site_id, element id]
    all_site_element_list = []

    # check site matches, build site match lookup table.
    for site in list(sites_list):
        site_id = site.get('id')
        site_match_status, site_entry_name, site_key_val, = check_match(site_key_name, site_compiled_pattern, site)
        # print("SITE: {0}, MATCH: {1}".format(site.get('name'), site_match_status))
        site_match_lookup[site_id] = {
            "site_entry_name": site_entry_name,
            "site_key_val": site_key_val,
            "site_match_status": site_match_status
        }

    # check element matches, build element match lookup table.
    for element in list(elements_list):
        element_id = element.get('id')
        element_site_id = element.get('site_id')

        # add to all site->element iteration list
        if element_id and element_site_id:
            all_site_element_list.append([element_site_id, element_id])

        # check for match.
        element_match_status, element_entry_name, element_key_val, = check_match(element_key_name,
                                                                                 element_compiled_pattern, element)
        # print("ELEMENT: {0}, MATCH: {1}".format(element.get('name'), element_match_status))

        element_match_lookup[element_id] = {
            "element_entry_name": element_entry_name,
            "element_key_val": element_key_val,
            "element_match_status": element_match_status
        }

    # Great, now we have max objects that can be queried. Set status bar
    firstbar = len(all_site_element_list) + 1
    barcount = 1

    print("Building Toolkit Spider connect plan..")

    # could be a long query - start a progress bar.
    pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=firstbar).start()

    for site_id_element_id_list in all_site_element_list:
        site_id = site_id_element_id_list[0]
        element_id = site_id_element_id_list[1]

        site_lookup = site_match_lookup.get(site_id)
        element_lookup = element_match_lookup.get(element_id)

        if site_id == "1":
            # site id 1 = unassigned. Silently skip, as can't modify interfaces for unassigned elements.
            barcount += 1
            pbar.update(barcount)
            continue
        if site_lookup is None:
            # error, these should not be missing. Throw warning.
            throw_warning("Unable to read site match data for site_id {0}. Skipping.".format(site_id))
            barcount += 1
            pbar.update(barcount)
            continue
        elif element_lookup is None:
            # error, these should not be missing. Throw warning.
            throw_warning("Unable to read element match data for element_id {0}. Skipping.".format(element_id))
            barcount += 1
            pbar.update(barcount)
            continue

        # get all of the saved match info.
        site_entry_name = site_lookup["site_entry_name"]
        site_key_val = site_lookup["site_key_val"]
        site_match_status = site_lookup["site_match_status"]
        element_entry_name = element_lookup["element_entry_name"]
        element_key_val = element_lookup["element_key_val"]
        element_match_status = element_lookup["element_match_status"]

        if site_match_status and element_match_status:
            # need to iterate and check interfaces.
            interfaces_list = extract_items(sdk.get.interfaces(site_id, element_id), 'interfaces')
            swi_list = extract_items(sdk.get.waninterfaces(site_id), 'waninterfaces')

            # build SWI lookup dict.
            swi_id2detail = {}
            for swi in swi_list:
                swi_network_id = swi.get('network_id')
                swi_name = swi.get('name')
                swi_id = swi.get('id')
                swi_wannetwork_name = wannetworks_id2n.get(swi_network_id, swi_network_id)

                if swi_name is None:
                    swi_name = "Circuit to {0}".format(swi_wannetwork_name)

                swi_id2detail[swi_id] = "{0} ({1})".format(swi_name, swi_wannetwork_name)

            # print("SWIDETAIL: {0}".format(json.dumps(swi_id2detail, indent=4)))

            test_interfaces_list = []
            connect_interfaces_list = []

            for interface in list(interfaces_list):

                interface_name = interface.get('name')
                interface_name_lower = text_type(interface_name).lower()

                if interface_name_lower in test_interfaces_match_list:
                    # add to match
                    test_interfaces_list.append(interface)

                if interface_name_lower in connect_interfaces_match_list:
                    # add to match
                    connect_interfaces_list.append(interface)

            # check if we need to run test.
            if test_interfaces_list and connect_interfaces_list:
                # we got matches in both, need to make test entries.

                for connect_if in connect_interfaces_list:
                    ip_list = []
                    connect_if_id = connect_if.get('id')
                    connect_if_name = connect_if.get('name')

                    # get interface status
                    status_result = sdk.get.status_interfaces(site_id, element_id, connect_if_id)
                    interface_status = status_result.cgx_content

                    if status_result.cgx_status:
                        # print(interface_status)

                        ipv4_addr = interface_status.get('ipv4_addresses', [])
                        ipv6_addr = interface_status.get('ipv6_addresses', [])

                        if ipv4_addr:
                            for address in ipv4_addr:
                                ip_list.append(address)

                        if ipv6_addr:
                            for address in ipv6_addr:
                                ip_list.append(address)

                        if ip_list:
                            # first IP only.
                            connect_if_ip_str = ip_list[0].split('/')[0]
                        else:
                            connect_if_ip_str = "No IP Address"

                    else:
                        connect_if_ip_str = "No IP Address"

                    # get test ifs
                    for test_if in test_interfaces_list:

                        test_if_name = test_if.get('name')
                        test_if_id = test_if.get('id')
                        test_swis = test_if.get('site_wan_interface_ids', None)

                        if not test_swis:
                            test_swi_text = "None"
                        elif len(test_swis) > 1:
                            test_swi_text = "Multiple circuits connected."
                        else:
                            # One circuit, get info.
                            # print(test_swis)
                            test_swi_text = text_type(swi_id2detail.get(test_swis[0]))

                        # print("Test IF: {0}".format(test_if_name))
                        working_results.append([site_entry_name, site_id, element_entry_name, element_id,
                                                connect_if_name, connect_if_ip_str, test_if_name, test_swi_text,
                                                test_if_id])

        # finished this site_id/element_id pair. next.
        barcount += 1
        pbar.update(barcount)

    # finish after iteration.
    pbar.finish()

    # Great, now we have max objects that can be queried. Set status bar
    firstbar = len(working_results) + 1
    barcount = 1

    print("Testing Toolkit Spider connect interfaces..")

    # could be a long query - start a progress bar.
    pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()], max_value=firstbar).start()

    # start toolkit reachability tests.

    for test_list in working_results:
        changeable_entry = list(test_list)
        ip_address = test_list[5]

        if ip_address is "No IP Address":
            # no address on interface.
            changeable_entry.append(False)

        else:
            toolkit_test = tcping(ip_address, TOOLKIT_PORT, TOOLKIT_TEST_TIMEOUT)
            if toolkit_test >= 0:
                changeable_entry.append(True)
            else:
                changeable_entry.append(False)

        # add the final table.
        output_results.append(changeable_entry)

        # finished this site_id/element_id pair. next.
        barcount += 1
        pbar.update(barcount)

    # finish after iteration.
    pbar.finish()

    with open(output, "w") as csv_output:
        writer = csv.writer(csv_output, quoting=csv.QUOTE_ALL)
        writer.writerows(output_results)


####
#
# End custom modifiable code
#
####


# Start the script.
def plan():
    """
    Stub script entry point. Authenticates CloudGenix SDK, and gathers options from command line to run do_site()
    :return: No return
    """
    global TOOLKIT_TEST_TIMEOUT

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0} Build Plan ({1})".format(GLOBAL_MY_SCRIPT_NAME,
                                                                               GLOBAL_MY_SCRIPT_VERSION))

    ####
    #
    # Add custom cmdline argparse arguments here
    #
    ####

    action_group = parser.add_argument_group('Build', 'Create a map/plan for the Toolkit Spider action.')

    action_group.add_argument('--site-key', '-SK', type=text_type, default='name',
                              help="Key in Site object to use for inclusion. Default 'name'")
    action_group.add_argument('--element-key', '-EK', type=text_type, default='name',
                              help="Key in Element object to use for inclusion. Default 'name'")

    action_group.add_argument('--site-pattern', '-SP', type=text_type, default='.*',
                              help="REGEX Pattern to match Site Object with for inclusion."
                                   " Default '.*'")
    action_group.add_argument('--element-pattern', '-EP', type=text_type, default='.*',
                              help="REGEX Pattern to match Element Object with for inclusion."
                                   " Default '.*'")
    action_group.add_argument('--output', type=text_type, required=True, help="Output to filename.")

    action_group.add_argument('--connect-interfaces', '-CI', type=text_type, required=True,
                              help="Comma separated list of interface to use as options to connect via SSH to run "
                                   "the test, if available.")
    action_group.add_argument('--test-interfaces', '-TI', type=text_type, required=True,
                              help="Comma separated list of interface to run the test FROM, if available")
    action_group.add_argument('--connect-timeout', '-CT', type=int, default=5,
                              help="Timeout for connect interface reachability test (seconds, default 5)")


    ####
    #
    # End custom cmdline arguments
    #
    ####

    # Standard CloudGenix script switches.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. https://api.elcapitan.cloudgenix.com",
                                  default=None)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of cloudgenix_settings.py "
                                                   "or prompting",
                             default=None)
    login_group.add_argument("--password", "-PW", help="Use this Password instead of cloudgenix_settings.py "
                                                       "or prompting",
                             default=None)
    login_group.add_argument("--insecure", "-I", help="Do not verify SSL certificate",
                             action='store_true',
                             default=False)
    login_group.add_argument("--noregion", "-NR", help="Ignore Region-based redirection.",
                             dest='ignore_region', action='store_true', default=False)

    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--sdkdebug", "-D", help="Enable SDK Debug output, levels 0-2", type=int,
                             default=0)

    args = vars(parser.parse_args())

    sdk_debuglevel = args["sdkdebug"]

    # Build SDK Constructor
    if args['controller'] and args['insecure']:
        sdk = cloudgenix.API(controller=args['controller'], ssl_verify=False)
    elif args['controller']:
        sdk = cloudgenix.API(controller=args['controller'])
    elif args['insecure']:
        sdk = cloudgenix.API(ssl_verify=False)
    else:
        sdk = cloudgenix.API()

    # check for region ignore
    if args['ignore_region']:
        sdk.ignore_region = True

    # SDK debug, default = 0
    # 0 = logger handlers removed, critical only
    # 1 = logger info messages
    # 2 = logger debug messages.

    if sdk_debuglevel == 1:
        # CG SDK info
        sdk.set_debug(1)
    elif sdk_debuglevel >= 2:
        # CG SDK debug
        sdk.set_debug(2)

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["password"]:
        user_password = args["password"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["password"]:
        sdk.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if sdk.tenant_id is None:
            raise CloudGenixToolkitSpiderError("AUTH_TOKEN login failure, please check token.")

    else:
        while sdk.tenant_id is None:
            sdk.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not sdk.tenant_id:
                user_email = None
                user_password = None

    ####
    #
    # Do your custom work here, or call custom functions.
    #
    ####

    if args['connect_timeout'] != 5:
        TOOLKIT_TEST_TIMEOUT = args['connect_timeout']

    build_plan(sdk, args['site_key'], re.compile(args['site_pattern']), args['element_key'],
               re.compile(args['element_pattern']), args['connect_interfaces'], args['test_interfaces'],
               args['output'])

    ####
    #
    # End custom work.
    #
    ####


def test():
    """
    Stub script entry point. Authenticates CloudGenix SDK, and gathers options from command line to run do_site()
    :return: No return
    """
    global TOOLKIT_TEST_TIMEOUT

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0} Run Plan ({1})".format(GLOBAL_MY_SCRIPT_NAME,
                                                                             GLOBAL_MY_SCRIPT_VERSION))

    action_group = parser.add_argument_group('Run', 'Execute a previously built Toolkit Spider plan.')

    action_group.add_argument('--plan', '-P', type=text_type, required=True, help="Plan (CSV) to run")

    action_group.add_argument('--test', '-T', type=text_type, required=True, help="Test (json) to load and run on Plan")

    action_group.add_argument('--output', '-O', type=text_type, required=True, help="Output to filename.")

    action_group.add_argument('--connect-timeout', '-CT', type=int, default=5,
                              help="Timeout for connect to run tests (seconds, default 5)")

    action_group.add_argument('--toolkit-user', '-U', type=text_type, required=True,
                              help="Toolkit username")

    action_group.add_argument('--toolkit-password', '-PW', type=text_type, default=None,
                              help="Toolkit password (will prompt if not given)")

    args = vars(parser.parse_args())


    ####
    #
    # Do your custom work here, or call custom functions.
    #
    ####

    if args["toolkit_password"] is None:
        password = getpass.getpass()
    else:
        password = args["toolkit_password"]

    run_plan(args['plan'], args['test'], args['output'], args['toolkit_user'], password,
             timeout=args['connect_timeout'],)

    ####
    #
    # End custom work.
    #
    ####


if __name__ == "__main__":
    print("Please do not run this library directly, call plan() or test().")
