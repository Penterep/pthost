import re, requests

from ptlibs import ptprinthelper, ptmisclib, ptnethelper, tldparser

class VulnerabilityTester:
    def __init__(self, args, ptjsonlib, tests: dict):
        self.protocol  = None
        self.ptjsonlib = ptjsonlib
        self.use_json  = args.json
        self.timeout   = args.timeout
        self.cache     = args.cache
        self.test      = tests
        self.headers   = ptnethelper.get_request_headers(args)
        self.proxy     = {"http": args.proxy, "https": args.proxy}

    def _test_missing_http_redirect_to_https(self, response, response_dump) -> None:
        """Tests whether HTTP response contains redirect to HTTPS"""
        ptprinthelper.ptprint(f"Testing HTTP to HTTPS redirect", "TITLE", not self.use_json, colortext=True)
        if response.headers.get('location', "").startswith("https"):
            ptprinthelper.ptprint(f"Redirect to HTTPS: OK", "OK", not self.use_json)
        else:
            ptprinthelper.ptprint(f"Missing redirect from HTTP to HTTPS", "VULN", not self.use_json)
            self.ptjsonlib.add_vulnerability("PTV-WEB-CRYPT-REDIR")
        ptprinthelper.ptprint(f" ", "", not self.use_json)

    def _check_domain_seo_fragmentation(self, base_url):
        """Test domain for SEO fragmentation"""
        ptprinthelper.ptprint(f"Testing Domain for SEO fragmentation", "TITLE", not self.use_json, colortext=True)
        protocol, base_domain = base_url.split("://") # split by scheme
        response1 = requests.get(f"{protocol}://{base_domain}", allow_redirects=True)
        response2 = requests.get(f"{protocol}://www.{base_domain}", allow_redirects=True)
        if response1.url == response2.url:
            ptprinthelper.ptprint(f"Not vulnerable to domain SEO fragmentation", "OK", not self.use_json)
        else:
            ptprinthelper.ptprint(f"Vulnerable to domain SEO fragmentation", "VULN", not self.use_json)
            self.ptjsonlib.add_vulnerability(f"PTV-WEB-MISCONF-REDIRSUB")
        ptprinthelper.ptprint(f" ", "", not self.use_json)

    def _test_crlf_injection(self, url: str, when_text: str) -> None:
        """Send request and check if it's vulnerable to CRLF injection"""
        ptprinthelper.ptprint(f"Testing CRLF injection: {url}/?foo=foo%0D%0Atestfoo:testfoo", "TITLE", not self.use_json, colortext=True)

        response, response_dump = self._get_response(f'{url}/?foo=foo%0D%0Atestfoo:testfoo', "GET", self.headers)
        if response.headers.get('testfoo'):
            #ptprinthelper.ptprint(f"Vulnerable to CRLF injection ({when_text})", "VULN", not self.use_json)
            ptprinthelper.ptprint(f"Vulnerable to CRLF injection", "VULN", not self.use_json)
            self.ptjsonlib.add_vulnerability("PTV-WEB-ACC-CRLF", request=response_dump['request'], response=response_dump['response'])
        else:
            #ptprinthelper.ptprint(f"Not vulnerable to CRLF injection ({when_text})", "OK", not self.use_json)
            ptprinthelper.ptprint(f"Not vulnerable to CRLF injection", "OK", not self.use_json)
        ptprinthelper.ptprint(f" ", "", not self.use_json)

    def _test_default_vhost(self, protocol, target_ip, initial_response, initial_response_content):
        """Test if tested domain is a default vhost by connecting to <target_ip> and comparing it's responses"""
        ptprinthelper.ptprint(f"Testing domain for default vhost", "TITLE", not self.use_json, colortext=True)
        ptprinthelper.ptprint(f"Request to IP address: {target_ip}", "INFO", not self.use_json)

        try:
            _, response, content = self._get_response_and_content(f'{protocol}://{target_ip}')
        except requests.RequestException as e:
            ptprinthelper.ptprint(f"Server not responding\n", "ERROR", not self.use_json)
            return

        is_equal = self._compare_responses((initial_response, initial_response_content), (response, content))
        if is_equal and response.status_code == 200:
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-DEFLT")
            ptprinthelper.ptprint(f"Domain is default vhost", "VULN", not self.use_json)
        else:
            ptprinthelper.ptprint(f"Domain is not a default vhost", "OK", not self.use_json)
        ptprinthelper.ptprint(f" ", "", not self.use_json)

    def _test_redirect_to_subdomain(self, base_domain: str) -> bool:
        """Checks whether request to base domain contains redirect to subdomain (e.g. example.com to www.example.com)."""
        ptprinthelper.ptprint(f"Request to: {base_domain}", "INFO", not self.use_json, colortext=True)
        try:
            _, response, _ = self._get_response_and_content(base_domain)
        except requests.RequestException as e:
            return False

        if response.is_redirect:
            ptprinthelper.ptprint(f"Redirect to subdomain: OK", "OK", not self.use_json)
        else:
            if response.status_code < 300:
                ptprinthelper.ptprint(f"Domain is available without subdomain", "INFO", not self.use_json)
            ptprinthelper.ptprint(f"Missing Redirect to subdomain", "VULN", not self.use_json)
            self.ptjsonlib.add_vulnerability(f"PTV-WEB-MISCONF-REDIRSUB")
            ptprinthelper.ptprint(f" ", "", not self.use_json)

        """
        FIXME: It's not possible to recognize if the vulnerability was catched on HTTP/HTTPS protocol
                If vulnerable on both protocols, the vulnerability will be overwritten by the other protocol
                {self.protocol}
        """
        return response.is_redirect

    def _test_subdomain_reflection(self, base_url, with_www=False):
        """Check <base_url> for subdomain reflection"""
        protocol, base_domain = base_url.split("://")
        url = f'{protocol}://fo0o0o0o1.www.{base_domain}' if with_www else f'{protocol}://fo0o0o0o1.{base_domain}'
        ptprinthelper.ptprint(f"Testing subdomain reflection: {url}", "TITLE", not self.use_json, colortext=True)
        try:
            response = requests.get(url, proxies=self.proxy, headers=self.headers, allow_redirects=False, verify=False, timeout=self.timeout)
        except requests.RequestException:
            ptprinthelper.ptprint(f"Server not responding\n", "ERROR", not self.use_json)
            return
        is_vulnerable = True if response.status_code == 200 else False
        if is_vulnerable:
            self.ptjsonlib.add_vulnerability("PTV-WEB-MISCONF-SUBRFLX")
        ptprinthelper.ptprint(f" ", "", not self.use_json)


    def _host_header_injection(self, target_with_subdomain, original_response, original_response_content):
        """Send request to <target_with_subdomain> with Host header set to: www.example.com"""
        ptprinthelper.ptprint(f"Test domain for Host Header Injection", "TITLE", not self.use_json, colortext=True)
        ptprinthelper.ptprint(f"Request with Host header set to: www.example.com", "INFO", not self.use_json)

        try:
            response_dump, response, content = self._get_response_and_content(target_with_subdomain, host='www.example.com')
        except requests.Timeout:
            ptprinthelper.ptprint(f"Request timed out\n", "ERROR", not self.use_json)
            return
        except requests.ConnectionError:
            ptprinthelper.ptprint(f"Connection error\n", "ERROR", not self.use_json)
            return
        self._compare_responses((original_response, original_response_content), (response, content))

        host_injection = open_redirect = False

        if self.test['host-injection']:
            example_in_content = re.search('(https?\:\/\/)?www\.example\.com\/?', response.text)
            if example_in_content and response.status_code == 200:
                host_injection = True
                self.ptjsonlib.add_vulnerability("PTV-WEB-ACC-HHI", vuln_request=response_dump['request'], vuln_response=response_dump['response'])
                ptprinthelper.ptprint(f"Vulnerable to Host header injection", "VULN", not self.use_json)
            else:
                ptprinthelper.ptprint(f"Not vulnerable to Host header injection", "OK", not self.use_json)

        if self.test['open-redirect']:
            if response.headers.get('location') and re.search('^(http(s)?:\/\/)?www\.example\.com', response.headers['location']):
                ptprinthelper.ptprint(f"Open Redirect vulnerability inside Host header", "VULN", not self.use_json)
                self.ptjsonlib.add_vulnerability("PTV-WEB-MISCONF-REDIRHST", vuln_request=response_dump['request'], vuln_response=response_dump['response'])
                ptprinthelper.ptprint(f"Open Redirect vulnerability inside when testing Host header injection", "VULN", not self.use_json)
            else:
                ptprinthelper.ptprint(f"Open Redirect vulnerability not found when testing Host header injection", "OK", not self.use_json)
                """FIXME: It's not possible to recognize if the vulnerability was catched on HTTP/HTTPS protocol
                   If vulnerable on both protocols, the vulnerability will be overwritten by the other protocol
                """

        ptprinthelper.ptprint(f" ", "", not self.use_json)


    def _get_initial_response(self, url: str):
        """Retrieves the initial response from the specified url for later comparison.

        Parameters:
        - url (str): The url to which the HTTP request is sent.

        Returns:
        - tuple: A tuple containing the response dump, the response object, and the content of the response.

        Raises:
        - requests.Timeout: If the request to the url times out.
        - requests.ConnectionError: If the connection to the server fails.
        """
        ptprinthelper.ptprint(f"Getting initial response", "TITLE", not self.use_json, colortext=True)
        ptprinthelper.ptprint(f"Request to: {url}", "INFO", not self.use_json)
        try:
            initial_response_dump, initial_response, initial_content = self._get_response_and_content(url)
            ptprinthelper.ptprint(f" ", "", not self.use_json)
            return initial_response_dump, initial_response, initial_content
        except requests.RequestException:
            raise

    def _get_response_and_content(self, url, host=None):
        """Retrieves response and its content (either title or )"""
        if host:
            headers = self.headers.copy()
            headers.update({"Host": host})
        else:
            headers = self.headers
        try:
            response, response_dump = self._get_response(url, 'GET', headers)
        except requests.RequestException as e:
            raise e
        ptprinthelper.ptprint(f"Response status code: {response.status_code}", "INFO", not self.use_json)
        if response.is_redirect and response.headers.get('location'):
            ptprinthelper.ptprint(f"Redirect to: {response.headers['location']}", "INFO", not self.use_json)
        content = self._get_content(response)
        return response_dump, response, content


    def _get_response(self, url, method, headers):
        try:
            response, response_dump = ptmisclib.load_url_from_web_or_temp(url=url, method=method, headers=headers, proxies=self.proxy, timeout=self.timeout, redirects=False, cache=self.cache, dump_response=True)
            return response, response_dump
        except requests.RequestException:
            raise


    def _compare_responses(self, r1: tuple, r2: tuple) -> bool:
        """Compare two response objects and their status code, returns True if they match"""
        if r1[0].status_code == r2[0].status_code and r1[1] == r2[1]:
            return True
        if r1[0].status_code != r2[0].status_code:
            ptprinthelper.ptprint(f"Different status code from original request to domain  ({r1[0].status_code}, {r2[0].status_code})", "INFO", not self.use_json)
            return False
        if r1[1] != r2[1]:
            ptprinthelper.ptprint(f"Different response content ({r1[1]}, {r2[1]})", "INFO", not self.use_json)
            return False


    def _get_content(self, response):
        """Retrieves response content (used for comparing)"""
        content = re.search(r'<title.*?>([\s\S]*?)</title>', response.text, re.IGNORECASE)
        title = ""
        if content:
            content = content[1]
            title = content
        if not content:
            content = re.search(r'<head.*?>([\s\S]*?)</head>', response.text, re.IGNORECASE)
        if type(content) == type(re.match("", "")):
            content = content[1]
        if not content:
            content = response.text
        if title:
            ptprinthelper.ptprint(f"Title: {title}", "INFO", not self.use_json)
        return content