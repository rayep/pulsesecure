"""
******************************************************************************************************************************************
Python Script to parse the PCS XML backup for identifying idle configuration objects like Realms & Roles.

Author - Ray A.
Creation Date - 16/05/2022 11:36 PM IST.
Last Modified Date - N/A.
*******************************************************************************************************************************************
"""

import xml.etree.ElementTree as ET
import logging
import argparse
from sys import stdout

# Logging handlers.

logger = logging.getLogger('pcs_idle_config')
logger.setLevel(logging.INFO)

console_formatter = logging.Formatter("%(asctime)s - CONSOLE - %(levelname)s - %(message)s")
consoleHandler = logging.StreamHandler(stdout)
consoleHandler.setLevel(logging.INFO)
consoleHandler.setFormatter(console_formatter)
logger.addHandler(consoleHandler)


# Argument parser

argparser = argparse.ArgumentParser(prog="PCS Idle Config Script", description="Python Script to identify the PCS idle config objects.", epilog="Version: 1.0")
argparser.add_argument('--xml-export-file', action="store", required=True, help="Path for XML export file. Export file should contain sign-in URLs, Realms, Roles.", dest='xml_export_file')
args = argparser.parse_args()

logger.info('Task Started!'"\n")

# Parsing the provided XML files and creating instances.

if args.xml_export_file:
    logger.info('Using the file "{}" for parsing XML export data.\n'.format(args.xml_export_file))
    try:
        with open(args.xml_export_file, encoding='utf-8') as frrs:
            frrs_xml = ET.parse(frrs)
    except Exception as e:
        print(e)
        exit()
else:
    logger.error('Path for XML file is invalid.')

# NAMESPACE function to add the NS value for each probe object.

def nc(tag):
    nc_constr = '{' + f'{ns_tag}' + '}' + f'{tag}'
    return nc_constr

def get_root(xml):
    return xml.getroot()

def get_root_tag(root):
    nc_draft = (root.tag).split('}')
    nc_ = nc_draft[0].split('{')[1]
    return nc_


# Main Iter XML tree for fetching element values.

def iter_xml(root, parent, child, avoid_dups=False, ignore=None):
    result = []
    for obj in root.iter(nc(f'{parent}')):
        if avoid_dups and ignore:
            if find_xml(obj, child) not in result:
                if isinstance(find_xml(obj, child), str): # Sometimes the find_xml function returns "NoneType" as a result, hence having isinstance check for 'str' type to ignore NONE value.
                    if find_xml(obj, child) != ignore:
                        result.append(find_xml(obj, child))
                else:
                    pass

        elif avoid_dups:
            if find_xml(obj, child) not in result:
                result.append(find_xml(obj, child))

        elif ignore:
            if isinstance(find_xml(obj, child), str):
                if find_xml(obj, child) != ignore:
                    result.append(find_xml(obj, child))
        else:
            result.append(find_xml(obj, child))

    return result


# Debug functions. - USED ONLY FOR TSHOOTING.

def check_parent(root, parent): # Just for checking the presence of XML parent tree object.
    for i in make_iter(root, parent):
        return i

def check_child(parent, child): # Just for checking the presence of child.
    return find_xml(parent, child)


# Used for checking the presence of XML tag so that the script will alert the missing components to the user.

def check_iter(root, iter): 
    for i in make_iter(root, iter): # Check_Iter function checks the presence of XML object. If present returns TRUE, else a default FALSE.
        if i:
            return True
    return False


# Makes Iter object for parsing down the XML tree.

def make_iter(root, iter):
    return root.iter(nc(f'{iter}'))


# Finds the value of child element under the Iter tree.

def find_xml(iter, find):
    try:
        if iter.find(nc(f'{find}')).text:
            # print(iter.find(nc(f'{find}')).text)
            return iter.find(nc(f'{find}')).text
    except AttributeError:
        pass

def findall_xml(iter, find):
    try:
        if iter.findall(nc(f'{find}')):
            # print(iter.find(nc(f'{find}')).text)
            if isinstance(iter.findall(nc(f'{find}')), list):
                find_all = [i.text for i in iter.findall(nc(f'{find}'))]
                return find_all
            else:
                print("Something Went Wrong. Find_all output returned incorrect data type -- {}".format(type(iter.findall(nc(f'{find}')))))
    except AttributeError:
        pass

# Check for the presence of child element.

def check_xml(iter, check):
    if iter.find(nc(f'{check}')):
        return True
    else:
        return False


# Creation of dict key/value.

def append_values(dict, key, values):
    # if values != None:
    if key not in dict:
        if isinstance(values, list):
            dict[key] = values
        else:
            dict[key] = [values]
    else:
        if isinstance(values, list):
            for i in range(len(values)):
                dict[key].append(values[i])
        else:
            dict[key].append(values)


# Uses the dict data to extract the used config objects.

def used_config(raw_data):
    collector=[]
    if isinstance(raw_data, dict):
        for data in list(raw_data.values()):
            for used in data:
                if used not in collector:
                    collector.append(used)
        return collector
    else:
        print("Used configuration data need to be in dictionary format")
        exit()


# Comparing used and total data to find the idle config objects.

def idle_config(total_data, used_data):
    collector=[]
    for conf in total_data:
        if conf not in used_data:
            collector.append(conf)
    return collector


# XML root and NS tag creation.

frrs_root = get_root(frrs_xml)
ns_tag = get_root_tag(frrs_root)


### ====================================================================================================================================================================================== ###                

if (check_iter(frrs_root, 'auth-server')):  # Make-Iter function checks the presence of XML object. If present returns TRUE, else a default FALSE.
    logger.info("Authentication Servers data found.")

    total_auth = iter_xml(frrs_root, 'auth-server', 'name')
    logger.info('Total number of Auth servers - {}'.format(len(total_auth)))

    pri_auth = iter_xml(frrs_root, 'realm', 'authentication-server', avoid_dups=True, ignore='None')
    logger.info('Total of Auth Servers used as PRIMARY - {}.'.format(len(pri_auth)))

    sec_auth = iter_xml(frrs_root, 'secondary-authentication-settings', 'name', avoid_dups=True, ignore='-')
    logger.info('Total of Auth Servers used as SECONDARY - {}.'.format(len(sec_auth)))

    dir_auth = iter_xml(frrs_root, 'realm', 'directory-server', ignore='None', avoid_dups=True)
    logger.info('Total of Auth Servers used as AUTHORIZATION SERVER - {}.'.format(len(dir_auth)))

    acc_auth = iter_xml(frrs_root, 'realm', 'accounting-server', ignore='None', avoid_dups=True)
    logger.info('Total of Auth Servers used as ACCOUNTING SERVER - {}.\n'.format(len(acc_auth)))

    merged_auth = pri_auth+sec_auth+dir_auth+acc_auth
    logger.info('Merged all auth-server data to a single list.\n')

    unused_auth = [i for i in total_auth if i not in merged_auth]
    logger.info('Total of Unused Auth servers - {}'.format(len(unused_auth)))

else:
    logger.warning("XML Export file does not contain Authentication Servers data.\n")
    unused_auth=[]

if unused_auth:
    for i in unused_auth:
        print(i)
print()


# *** FINDING UNUSED PCS CONFIG OBJECTS *** #

# Finding the total roles and realms configured on the PCS.

if (check_iter(frrs_root, 'admin-roles')):  # Make-Iter function checks the presence of XML object. If present returns TRUE, else a default FALSE.
    logger.info("Admin roles data found.\n")
    total_admin_roles = iter_xml(frrs_root, 'admin-role', 'name')
else:
    logger.warning("XML Export file does not contain Admin Roles data.\n")
    total_admin_roles=[] # if not found, setting the list to empty.


if (check_iter(frrs_root, 'user-roles')):
    logger.info("User roles data found.\n")
    total_user_roles = iter_xml(frrs_root, 'user-role', 'name', ignore="Outlook Anywhere User Role")
else:
    logger.warning("XML Export file does not contain User Roles data.\n")
    total_user_roles = [] # if not found, setting the list to empty.


if (check_iter(frrs_root, 'user-roles')) or (check_iter(frrs_root, 'admin-roles')):
    total_roles = total_user_roles+total_admin_roles
else:
    logger.error("Total roles calculation failed. Setting the total roles count to Zero.\n")
    total_roles=[] # if not found, setting the list to empty.


if (check_iter(frrs_root, 'user-realms')):
    logger.info("User realms data found.\n")
else:
    logger.warning("User realms data is missing in the XML export. Results might not be accurate.\n")


if (check_iter(frrs_root, 'admin-realms')):
    logger.info("Admin realms data found.\n")
else:
    logger.warning("Admin realms data is missing in the XML export. Results might not be accurate.\n")


if (check_iter(frrs_root, 'user-realms')) or (check_iter(frrs_root, 'admin-realms')):
    total_realms = iter_xml(frrs_root, 'realm', 'name', ignore="None")
    role_mapping_rules={}
    for realm in make_iter(frrs_root, 'realm'): # Making "realm" tree as the iter object.
        for rmap in make_iter(realm, 'rule'): # Since the roles mapped under each role mapping are present under "rule" tree, we are making the rule as an iter object.
            append_values(role_mapping_rules, find_xml(realm, 'name'), findall_xml(rmap, 'roles')) # Passing the realm name as KEY and roles mapped as VALUES.

    # Result step.
    print(role_mapping_rules)
    used_roles = used_config(role_mapping_rules)

    if total_roles:
        idle_roles = idle_config(total_roles, used_roles)
    else:
        logger.error("Cannot identify identify Idle roles as the Total Roles returned Empty/Zero value.\n")
        idle_roles=[] # Setting the idle roles to zero only if the total roles is zero.

else:
    logger.error("XML Export file does not contain User or Admin Realms data.\n")
    total_realms=[]
    idle_roles=[]


if (check_iter(frrs_root, 'signin')):
    logger.info("Signing URL data found.\n")

    user_signing_url = {}
    admin_signing_url = {}

    for url in make_iter(frrs_root, 'access-url'): # Making "access-url" as the iter object.

        if check_xml(url, 'user'): # Only scans for user URLs.
            for realms in make_iter(url, 'user'):
                append_values(user_signing_url, find_xml(url, 'url-pattern'), findall_xml(realms, 'realms')) # Passing the signing urls as KEY and realms as VALUES.

        elif check_xml(url, 'admin'): # Only scans for admin URLs.
            for realms in make_iter(url, 'admin'):
                append_values(admin_signing_url, find_xml(url, 'url-pattern'), findall_xml(realms, 'realms'))

    # Result step.

    user_signing_url.update(admin_signing_url) # Merging the user and admin URLs in user_signing_url dict.
    used_realms = used_config(user_signing_url)

    if total_realms:
        idle_realms = idle_config(total_realms, used_realms)
    else:
        logger.error("Cannot identify identify Idle realms as the Total Realms returned Empty/Zero value.\n")
        idle_realms=[]
    
else:
    logger.warning("XML Export file does not contain signing URL data.\n")
    idle_realms=[]


# Printing the final output.

if idle_roles:
    logger.info("Total Idle roles:\n")
    for i in idle_roles:
        print(i)
    print()
else:
    if total_roles:
        logger.info("No Idle roles found.\n")


if idle_realms:
    logger.info("Total Idle realms:\n")
    for i in idle_realms:
        print(i)
    print()
else:
    if total_realms:
        logger.info("No Idle realms found.\n")

logger.info('Task Completed!')