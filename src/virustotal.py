"""Given one or more URLs, queries the VirusTotal API for available scan reports. If no report is
found for any URL, the URL is automatically submitted for scanning and the result is fetched when
completed.

URLs are passed either as command line arguments with the -u flag, or in a .csv file with the
filepath and the -uf flag.

The number of API calls is limited to 4 per minute to conform with VirusTotal's
public API limit.

VirusTotal: https://www.virustotal.com
Public API reference: https://developers.virustotal.com/v2.0/reference
"""
import os
import time
import validators
import argparse
import requests
from prettytable import PrettyTable
from ratelimit import limits, sleep_and_retry

a_counter = 0


def counter():
    """Increments and resets a global counter variable used for regulating the 4 allowed VirusTotal
    API calls per minute."""
    global a_counter

    if a_counter < 4:
        a_counter += 1
    else:
        a_counter = 1
        print("Maximum of 4 VirusTotal API calls per minute has been reached. Waiting 60 seconds "
              "to resume.")
        time.sleep(60)
    return


class ScanBatch:
    _batch_items = []

    def __init__(self, item):
        self._batch_items.append(self)
        self.item = item
        self.scan_id = None
        self.scan_date = None
        self.positives = None
        self.total_scans = None
        self.verbose_msg = None

    def __repr__(self):
        return self.item

    def __str__(self):
        return self.item

    @sleep_and_retry
    @limits(calls=4, period=61)
    def get_url_report(self, attempts=0):
        """Queries the VT API for a given URL. If no report found, submits URL for scanning.
        Decorators prevent exceeding VT's public API limit of 4/min."""
        base_url = "https://www.virustotal.com/vtapi/v2/"
        vt_url = base_url + "url/report"
        params = {"apikey": "8edecb7ecee60fc4662f54becad5cad6ca20fcf5f59f52e772b163dc8437e54f",
                  "resource": self,
                  "scan": 1}
        # counter()
        print(f"Querying VirusTotal for {self}")
        r = requests.get(vt_url, params=params)

        if r.status_code == 204:
            print('VT public API rate limit reached. Automatic retry in 60 seconds.')
            time.sleep(60)
            self.get_url_report()

        elif r.status_code == requests.codes.ok:
            resp = r.json()
            # check if URL has report
            if "total" in resp:
                self.scan_date = resp["scan_date"]
                self.positives = resp["positives"]
                self.scan_id = resp["scan_id"]
                self.total_scans = resp["total"]
            else:
                if attempts < 4:
                    attempts += 1
                    time.sleep(2)
                    ScanBatch.get_url_report(self, attempts)
                else:
                    self.verbose_msg = resp["verbose_msg"]
        else:
            self.verbose_msg = f"Http Error: response {r.status_code}"
        return


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--urls', '-u', type=str, nargs='*',
                       help='1 or more URLs, space separated')
    group.add_argument('--urls_file', '-uf', type=str, nargs='?',
                       help='path to .csv file listing URLs to scan, 1 URL per line')

    args = parser.parse_args()

    if args.urls:
        print("urls:", args.urls)
        urls = args.urls

    else:  # args.urls_file:
        with open(args.urls_file, 'r') as f:
            urls = [i.rstrip() for i in f.readlines()]
        print("urls from file:", urls)

    incidents = [ScanBatch(i) for i in urls]
    invalid_urls = []

    while incidents:
        try:
            i = incidents.pop()
            if validators.url(str(i)) is True:
                ScanBatch.get_url_report(i)
            else:
                invalid_urls.append(i)
        except IndexError:
            pass

    print("Invalid URLs:", invalid_urls)

    # NOTE: anti-pattern, accessing protected member outside class
    all_items = ScanBatch._batch_items

    p = PrettyTable()
    p.field_names = ["URL", "positive hits", "total scans", "scan date"]

    for i in all_items:
        if i not in invalid_urls:
            p.add_row([i.item, i.positives, i.total_scans, i.scan_date])
    print()
    print(p)
