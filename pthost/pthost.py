#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    pthost is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    pthost is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of

    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with pthost.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import socket
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

import requests
import validators

from modules.scanner import VulnerabilityTester

from _version import __version__
from ptlibs import ptjsonlib, ptmisclib, ptprinthelper, ptnethelper, tldparser


class PtHost:
    def __init__(self, args):
        self.ptjsonlib      = ptjsonlib.PtJsonLib()
        self.test           = self._load_tests(args.test)
        self.scanner    = VulnerabilityTester(args, self.ptjsonlib, self.test)
        self.use_json       = args.json

    def run(self, args):
        domain = self._get_domain(args.domain)
        ptprinthelper.ptprint(f"Testing domain: {domain}\n", "TITLE", not self.use_json, colortext=True)
        for protocol in args.protocol:
            self.scanner.protocol = protocol
            ptprinthelper.ptprint(f"Protocol: {protocol.upper()}\n", "TITLE", not self.use_json, colortext=True)
            self._run_tests(domain, protocol=protocol)
            if not self.use_json and protocol != args.protocol[-1]: print(" ") # add whitespace

        if self.use_json:
            self.ptjsonlib.set_status("finished")
            print(self.ptjsonlib.get_result_json())

    def _run_tests(self, domain, protocol):
        """Perform specified tests"""
        target_ip, base_url, full_url = self._resolve_and_construct_urls(domain, protocol)
        base_domain = base_url.split("://")[-1]
        try:
            response_dump, response, response_content = self.scanner._get_initial_response(full_url)
        except Exception as e:
            ptprinthelper.ptprint(f"Cannot retrieve initial response for protocol {protocol.upper()}", "ERROR", not self.use_json)
            return

        if protocol == "http":
            if self.test['redir-to-https']:
                self.scanner._test_missing_http_redirect_to_https(response, response_dump)
            if self.test['crlf'] and response.is_redirect:
                self.scanner._test_crlf_injection(full_url, "when redirect from HTTP to HTTPS")

        if self.test["crlf"]:
            if full_url != f"{protocol}://{base_domain}":
                self.scanner._test_crlf_injection(f"{protocol}://{base_domain}", "when redirect to subdomain")
            self.scanner._test_crlf_injection(f"{protocol}://www.{base_domain}", "when redirect to subdomain")

        if protocol == "https":
            if self.test['seo-fragmentation']:
                self.scanner._check_domain_seo_fragmentation(base_url)

        if self.test['default-vhost']:
            self.scanner._test_default_vhost(protocol, target_ip, response, response_content)

        if self.test['subdomain-reflection-www']:
            self.scanner._test_subdomain_reflection(base_url, with_www=True)
        if self.test['subdomain-reflection-no-www']:
            self.scanner._test_subdomain_reflection(base_url, with_www=False)

        if self.test["host-injection"] or self.test["open-redirect"]:
            self.scanner._host_header_injection(full_url, response, response_content)

    def _resolve_and_construct_urls(self, domain: str, protocol: str) -> tuple[str, str, str]:
        """Extracts and returns details from a provided domain.

        Parameters:
        - domain (str): The domain name to be parsed. This is expected to be
                            a domain without protocol or subpaths.
        - protocol (str): The protocol (e.g., "http" or "https") to be used in crafting
                        the URLs.

        Returns:
        - tuple[str, str, str]: A tuple containing the following elements in order:
            1. target_ip: The extracted target IP address from the provided domain.
            2. base_url: A valid URL crafted from the domain (without subdomains),
                        incorporating the provided protocol.
            3. full_url: A valid URL crafted from the domain (with subdomains),
                        incorporating the provided protocol.

        Example:
        - If `domain` is "example.com" and `protocol` is "https", this function
        might return ("93.184.216.34", "https://example.com", "https://www.example.com/").
        """

        extract = tldparser.parse(domain)
        if validators.ipv4(extract.domain): # if <extract.domain> is ipv4 address
            base_url   = f"{protocol}://{extract.domain}"
            full_url   = f"{protocol}://{extract.domain}"
            target_ip  = extract.domain
        else:
            base_url   = f"{protocol}://{'.'.join((extract.domain, extract.suffix))}"
            full_url   = f"{protocol}://{'.'.join(filter(None, (extract.subdomain, extract.domain, extract.suffix)))}"
            try:
                target_ip  = socket.gethostbyname(domain)
            except OSError:
                self.ptjsonlib.end_error(f"No IP address associated with provided domain", self.use_json)

        return target_ip, base_url, full_url

    def _get_domain(self, domain: str) -> str:
        while domain.endswith("/"):
            domain = domain[:-1]
        if not any([validators.url(domain), validators.domain(domain), validators.ipv4(domain)]):
            self.ptjsonlib.end_error("Provided domain is not in a valid format", self.use_json)
        return domain.split("/", 2)[-1].rsplit("/")[0] if validators.url(domain) else domain

    def _load_tests(self, specified_tests: list) -> dict:
        selected_tests = {test: False for test in TEST_CHOICES}
        for test in specified_tests:
            if test in selected_tests:
                selected_tests[test] = True
        return selected_tests


def get_help():
    return [
        {"description": ["Default vhost tester"]},
        {"usage": ["pthost <options>"]},
        {"usage_example": [
            "pthost -d www.example.com"
        ]},
        {"options": [
            ["-d",  "--domain",       "<domain>",                      "Test Domain"],
            ["-t",  "--test",         "<test-types>",                  "Specify tests to perform (default all)"],
            ["",    " ",              " default-vhost",                "Test Default vhost"],
            ["",    " ",              " open-redirect",                "Test Open Redirect"],
            ["",    " ",              " crlf",                         "Test CRLF injection"],
            ["",    " ",              " host-injection",               "Test Host injection"],
            ["",    " ",              " redir-to-https",               "Test HTTP to HTTPS redirects"],
            ["",    " ",              " seo-fragmentation",            "Test SEO fragmentation"],
            ["",    " ",              " subdomain-reflection-www",     "Test Subdomain reflection (with www)"],
            ["",    " ",              " subdomain-reflection-no-www",  "Test Subdomain reflection (without www)"],
            ["",    " ",              "",                              ""],
            ["-H",  "--headers",      "<header:value>",                "Set custom headers"],
            ["-T",  "--timeout",      "<timeout>",                     "Set timeout (default 7s)"],
            ["-ua", "--user-agent",   "<user-agent>",                  "Set user agent"],
            ["-c",  "--cookie",       "<cookie=value>",                "Set cookie(s)"],
            ["-p",  "--proxy",        "<proxy>",                       "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-P",  "--protocol",     "<protocol>",                    "Set protocol to test (HTTP, HTTPS), default both"],
            ["-C",  "--cache",        "",                              "Cache requests (load from tmp in future)"],
            ["-v",  "--version",      "",                              "Show script version and exit"],
            ["-h",  "--help",         "",                              "Show this help message and exit"],
            ["-j",  "--json",         "",                              "Output in JSON format"],
        ]
        }]


def parse_args():
    global TEST_CHOICES
    TEST_CHOICES = ["default-vhost", "open-redirect", "crlf", "host-injection", "redir-to-https", "seo-fragmentation", "subdomain-reflection-www", "subdomain-reflection-no-www"]
    parser = argparse.ArgumentParser(add_help=False, usage=f"{SCRIPTNAME} <options>")
    parser.add_argument("-d",  "--domain",     type=str, required=True)
    parser.add_argument("-P",  "--protocol",   type=str.lower, nargs="+", default=["http", "https"], choices=["http", "https"])
    parser.add_argument("-t",  "--test",       type=str.lower, nargs="+", default=TEST_CHOICES, choices=TEST_CHOICES)
    parser.add_argument("-p",  "--proxy",      type=str)
    parser.add_argument("-c",  "--cookie",     type=str, nargs="+")
    parser.add_argument("-a", "--user-agent",  type=str, default="Penterep Tools")
    parser.add_argument("-T",  "--timeout",    type=int, default=7)
    parser.add_argument("-H",  "--headers",    type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-C",  "--cache",      action="store_true")
    parser.add_argument("-j",  "--json",       action="store_true")
    parser.add_argument("-v",  "--version",    action="version", version=f"%(prog)s {__version__}")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "pthost"
    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    script = PtHost(args)
    script.run(args)


if __name__ == "__main__":
    main()
