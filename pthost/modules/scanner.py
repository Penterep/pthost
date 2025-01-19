import re, requests
import tldextract
from ptlibs import ptprinthelper, ptmisclib, ptnethelper, tldparser

from urllib.parse import urlparse

class VulnerabilityTester:
    def __init__(self, tests: dict, protocol, args, ptjsonlib):
        self.protocol  = None
        self.ptjsonlib = ptjsonlib
        self.use_json  = args.json
        self.timeout   = args.timeout if not args.proxy else None
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
        """
        Test the given domain for SEO fragmentation vulnerability.

        This method checks if a domain is vulnerable to SEO fragmentation by comparing
        the responses of the base domain (e.g., "example.com") and the "www" subdomain
        (e.g., "www.example.com"). If the responses redirect to the same final URL,
        the domain is considered not vulnerable. Otherwise, the domain is flagged as
        vulnerable to SEO fragmentation.

        :param base_url: The base URL to test, including the protocol
                        (e.g., "http://example.com" or "https://example.com").
        :type base_url: str

        :raises ValueError: If the `base_url` is not properly formatted or does not include a protocol.

        :return: None
        :rtype: None


        :example:

        >>> _check_domain_seo_fragmentation("http://example.com")
        Testing Domain for SEO fragmentation
        Vulnerable to domain SEO fragmentation
        """
        ptprinthelper.ptprint(f"Testing Domain for SEO fragmentation", "TITLE", not self.use_json, colortext=True)

        protocol, base_domain = base_url.split("://") # split by scheme
        response1 = requests.get(f"{protocol}://{base_domain}", allow_redirects=True, verify=False)
        response2 = requests.get(f"{protocol}://www.{base_domain}", allow_redirects=True, verify=False)
        if response1.url.rstrip("/") == response2.url.rstrip("/"):
            ptprinthelper.ptprint(f"Not vulnerable to domain SEO fragmentation", "OK", not self.use_json)
        else:
            ptprinthelper.ptprint(f"Vulnerable to domain SEO fragmentation", "VULN", not self.use_json)
            self.ptjsonlib.add_vulnerability(f"PTV-WEB-MISCONF-REDIRSUB-{protocol}")
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


    def _get_page_title(self, html_content):
        """Extracts the page title from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        title = soup.title.string if soup.title else "No title"
        return title

    def _test_subdomain_reflection(self, base_url, with_www=False):
        """
        Tests for subdomain reflection vulnerabilities by checking if the server responds
        with the same content or redirects when accessing a subdomain.

        :param base_url: The base URL to test for subdomain reflection.
        :param with_www: Flag to determine if 'www.' should be prefixed to the subdomain (default is False).
        """
        protocol, base_domain = base_url.split("://")
        url = f'{protocol}://fo0o0o0o1.www.{base_domain}' if with_www else f'{protocol}://fo0o0o0o1.{base_domain}'
        ptprinthelper.ptprint(f"Testing subdomain reflection: {url}", "TITLE", not self.use_json, colortext=True)
        try:
            response = requests.get(url, proxies=self.proxy, headers=self.headers, allow_redirects=False, verify=False, timeout=self.timeout)

            if response.is_redirect:
                redirect_url = response.headers.get('location')
                redirect_domain = urlparse(redirect_url).netloc
                base_domain_only = urlparse(base_url).netloc

                # Extract root domain using tldextract
                base_domain_parts = tldextract.extract(base_domain)
                redirect_domain_parts = tldextract.extract(redirect_domain)

                # Compare root domains (ignoring subdomains)
                if base_domain_parts.domain != redirect_domain_parts.domain or base_domain_parts.suffix != redirect_domain_parts.suffix:
                    ptprinthelper.ptprint(f"Redirect to a different domain: {redirect_url}", "OK", not self.use_json)
                else:
                    ptprinthelper.ptprint(f"Redirect to: {redirect_url}", "OK", not self.use_json)

            # Same page as base domain (subdomain reflection) — Check for title or specific element
            elif response.status_code == 200 and self._get_page_title(response.text) == self._get_page_title(requests.get(base_url)):
                ptprinthelper.ptprint(f"Vulnerable to subdomain reflection", "ERROR", not self.use_json)
                self.ptjsonlib.add_vulnerability("PTV-WEB-MISCONF-SUBRFLX")

            elif response.status_code == 200:
                ptprinthelper.ptprint(f"Warning: Server returned a default page (status 200). Check manually.", "WARNING", not self.use_json)

            elif response.status_code >= 400:
                ptprinthelper.ptprint(f"Server returned error [{response.status_code}]\n", "OK", not self.use_json)

        except requests.RequestException:
            ptprinthelper.ptprint(f"Domain not exists\n", "OK", not self.use_json)

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
            example_in_content = re.search(r'(https?://)?www.example.com/?', response.text)
            if example_in_content and response.status_code == 200:
                host_injection = True
                self.ptjsonlib.add_vulnerability("PTV-WEB-ACC-HHI", vuln_request=response_dump['request'], vuln_response=response_dump['response'])
                ptprinthelper.ptprint(f"Vulnerable to Host header injection", "VULN", not self.use_json)
            else:
                ptprinthelper.ptprint(f"Not vulnerable to Host header injection", "OK", not self.use_json)

        if self.test['open-redirect']:
            if response.headers.get('location') and re.search(r'^(http(s)?://)?www.example.com', response.headers['location']):
                ptprinthelper.ptprint(f"Open Redirect vulnerability inside Host header", "VULN", not self.use_json)
                self.ptjsonlib.add_vulnerability("PTV-WEB-MISCONF-REDIRHST", vuln_request=response_dump['request'], vuln_response=response_dump['response'])
                ptprinthelper.ptprint(f"Open Redirect vulnerability inside when testing Host header injection", "VULN", not self.use_json)
            else:
                ptprinthelper.ptprint(f"Open Redirect vulnerability not found when testing Host header injection", "OK", not self.use_json)
                """FIXME: It's not possible to recognize if the vulnerability was catched on HTTP/HTTPS protocol
                   If vulnerable on both protocols, the vulnerability will be overwritten by the other protocol
                """

        if self.test['xss'] and host_injection:
            try:
                _headers = self.headers.copy(); _headers.update({"Host": "<foo>"})
                response, response_dump = self._get_response(target_with_subdomain, "GET", headers=_headers)
                if re.findall(r"<foo>", response.text):
                    ptprinthelper.ptprint(f"Vulnerable to Cross Site Scripting via Host header injection", "VULN", not self.use_json)
                    self.ptjsonlib.add_vulnerability("HHI-XSS", vuln_request=response_dump['request'], vuln_response=response_dump['response'])
                else:
                    ptprinthelper.ptprint(f"Not vulnerable to Cross Site Scripting via Host header injection", "OK", not self.use_json)
            except requests.RequestException:
                pass
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