CloudGenix Toolkit Spider
----------

#### Synopsis
Utility to run commands/tests across large number of CloudGenix Toolkit instances.

#### Features
Early release -
* Create a "Plan" using REGEX patterns of site/element data, and interface names for "connecting to" and "testing".
* Run a "test" (JSON file, see included `azurelatency.json` for example) against previously created "Plan".

#### Requirements
* Active CloudGenix Account
* Python >= 2.7 or >=3.6
* Python modules:
    * CloudGenix Python SDK >= 5.1.1b1 - <https://github.com/CloudGenix/sdk-python>
    * ProgresBar2 >= 3.34.3 - <https://github.com/WoLpH/python-progressbar>
    * Tabulate >= 0.8.3 - <https://bitbucket.org/astanin/python-tabulate>
    * Netmiko (`develop` branch as of 06/07/2019 for CloudGenix ION Support.)


#### License
MIT

#### Installation:
 - **PIP:** `pip install cloudgenix-toolkit-spider`. After install, `spider_build_plan` or `spider_run_plan`.
 - **Github:** Download files to a local directory, manually run `spider_build_plan.py` or `spider_run_plan.py` scripts. 

### Examples of usage:
 1. Create a test plan to connect to controller interfaces, and test out of 'Internet 1', 'Internet 2', '1' and '2' interfaces.
    ```bash
    edwards-mbp-pro:toolkit_spider aaron$ export AUTH_TOKEN=`cat auth_token`
    edwards-mbp-pro:toolkit_spider aaron$ ./spider_build_plan.py --connect-interfaces "Controller 1,Controller" --test-interfaces "Internet 1,Internet 2,1,2" --output test_plan.csv
    Building Toolkit Spider connect plan..
    100%|######################################################################################################################################################################|Time:  0:00:01
    Testing Toolkit Spider connect interfaces..
    100%|######################################################################################################################################################################|Time:  0:02:00
    edwards-mbp-pro:toolkit_spider aaron$
    ```
 2. Execute the previous created test plan to do an Azure DC latency test.
    ```bash
    edwards-mbp-pro:toolkit_spider aaron$ ./spider_run_plan.py --plan ./test_plan.csv --test ./azurelatency.json --output test_results.csv -U toolkituser
    Password: 
    Running Toolkit Spider Plan..
    100%|######################################################################################################################################################################|Time:  0:01:00
    edwards-mbp-pro:toolkit_spider aaron$ 
    ```

### Caveats and known issues:
 - Need latest `develop` branch of Netmiko, until release with CloudGenix ION support.
 - Only one test supported today: tcping
 - TODO need to add multiprocessing, script currently runs all tests in serial.
 - Script is early access, needs lots of cleanup.
 
#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |

#### Command line help
```bash
edwards-mbp-pro:toolkit_spider aaron$ ./spider_build_plan.py -h
usage: spider_build_plan.py [-h] [--site-key SITE_KEY]
                            [--element-key ELEMENT_KEY]
                            [--site-pattern SITE_PATTERN]
                            [--element-pattern ELEMENT_PATTERN] --output
                            OUTPUT --connect-interfaces CONNECT_INTERFACES
                            --test-interfaces TEST_INTERFACES
                            [--connect-timeout CONNECT_TIMEOUT]
                            [--controller CONTROLLER] [--email EMAIL]
                            [--password PASSWORD] [--insecure] [--noregion]
                            [--sdkdebug SDKDEBUG]

CloudGenix Toolkit Spider Build Plan (v1.0.0)

optional arguments:
  -h, --help            show this help message and exit

Build:
  Create a map/plan for the Toolkit Spider action.

  --site-key SITE_KEY, -SK SITE_KEY
                        Key in Site object to use for inclusion. Default
                        'name'
  --element-key ELEMENT_KEY, -EK ELEMENT_KEY
                        Key in Element object to use for inclusion. Default
                        'name'
  --site-pattern SITE_PATTERN, -SP SITE_PATTERN
                        REGEX Pattern to match Site Object with for inclusion.
                        Default '.*'
  --element-pattern ELEMENT_PATTERN, -EP ELEMENT_PATTERN
                        REGEX Pattern to match Element Object with for
                        inclusion. Default '.*'
  --output OUTPUT       Output to filename.
  --connect-interfaces CONNECT_INTERFACES, -CI CONNECT_INTERFACES
                        Comma separated list of interface to use as options to
                        connect via SSH to run the test, if available.
  --test-interfaces TEST_INTERFACES, -TI TEST_INTERFACES
                        Comma separated list of interface to run the test
                        FROM, if available
  --connect-timeout CONNECT_TIMEOUT, -CT CONNECT_TIMEOUT
                        Timeout for connect interface reachability test
                        (seconds, default 5)

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex.
                        https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of
                        cloudgenix_settings.py or prompting
  --password PASSWORD, -PW PASSWORD
                        Use this Password instead of cloudgenix_settings.py or
                        prompting
  --insecure, -I        Do not verify SSL certificate
  --noregion, -NR       Ignore Region-based redirection.

Debug:
  These options enable debugging output

  --sdkdebug SDKDEBUG, -D SDKDEBUG
                        Enable SDK Debug output, levels 0-2

edwards-mbp-pro:toolkit_spider aaron$ ./spider_run_plan.py -h
usage: spider_run_plan.py [-h] --plan PLAN --test TEST --output OUTPUT
                          [--connect-timeout CONNECT_TIMEOUT] --toolkit-user
                          TOOLKIT_USER [--toolkit-password TOOLKIT_PASSWORD]

CloudGenix Toolkit Spider Run Plan (v1.0.0)

optional arguments:
  -h, --help            show this help message and exit

Run:
  Execute a previously built Toolkit Spider plan.

  --plan PLAN, -P PLAN  Plan (CSV) to run
  --test TEST, -T TEST  Test (json) to load and run on Plan
  --output OUTPUT, -O OUTPUT
                        Output to filename.
  --connect-timeout CONNECT_TIMEOUT, -CT CONNECT_TIMEOUT
                        Timeout for connect to run tests (seconds, default 5)
  --toolkit-user TOOLKIT_USER, -U TOOLKIT_USER
                        Toolkit username
  --toolkit-password TOOLKIT_PASSWORD, -PW TOOLKIT_PASSWORD
                        Toolkit password (will prompt if not given)
edwards-mbp-pro:toolkit_spider aaron$ 
```



