"""This module contains function for printing results"""

from ptlibs import ptprinthelper


def print_vulnerabilities(test_types: dict, test_result: dict, use_json: bool):
    import json
    print(json.dumps(test_result, indent=4))
    return
    for protocol in test_result.keys():
        print(" ")
        ptprinthelper.ptprint(f"Results for {protocol.upper()} protocol", "TITLE", colortext=True)
        if protocol == "http" and test_types['redir-to-https']:
            #elif test_result['missing_redirect_http_to_https'] is None:
                #ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Could not retrive result: Test for redirect from HTTP to HTTPS", "VULN", use_json))
            if test_result[protocol]['missing_redirect_http_to_https']['vulnerable']:
                ptprinthelper.ptprint(f"Missing Redirect from HTTP to HTTPS", "VULN")
            else:
                ptprinthelper.ptprint(f"Redirect to HTTPS: OK", "NOTVULN")

        if test_types['redir-to-sub']:
            #ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Could not retrive result: Test for redirect to subdomain", "VULN", use_json))
            if test_result[protocol]['missing_redirect_to_subdomain']:
                ptprinthelper.ptprint(f"Missing Redirect to subdomain", "VULN")
            else:
                ptprinthelper.ptprint(f"Redirect to subdomain: OK", "NOTVULN")

            #elif test_result[protocol]['is_available_without_subdomain'] is None:
            #ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Domain is not available without subdomain", "VULN", use_json))
            if test_result[protocol]['is_available_without_subdomain']:
                ptprinthelper.ptprint(f"Domain is available without subdomain", "NOTVULN")
            else:
                ptprinthelper.ptprint(f"Domain is not available without subdomain", "VULN")

        if test_types['is-default']:
            #ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Could not retrive result: Test for default domain", "VULN", use_json))
            if test_result[protocol]['is_default']:
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Domain is default", "VULN", use_json))
            else:
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Domain is not default", "NOTVULN", use_json))

        if test_types['open-redirect']:
            #ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Could not retrive result: Test for open redirect vulnerability", "VULN", use_json))
            if test_result[protocol].get('open_redirect'):
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Vulnerable to Open redirect", "VULN", use_json))
            else:
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Not vulnerable to Open redirect", "NOTVULN", use_json))

        if test_types['host-injection']:
            #ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Could not retrive result: Test for default vhost", "VULN", use_json))
            if test_result[protocol].get('host_injection'):
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Vulnerable to Host header injection", "VULN", use_json))
            else:
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Not vulnerable to Host header injection", "NOTVULN", use_json))

        if test_types['subdomain-reflection-www']:
            #if test_result[protocol]['subdomain_reflection_with_www'] is None:
                #ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Test for subdomain reflection (with www): OK", "NOTVULN", use_json))
            if test_result[protocol]['subdomain_reflection_with_www'].get('vulnerable'):
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Vulnerable to subdomain reflection ({test_result[protocol]['subdomain_reflection_with_www']['msg']})", "VULN", use_json))
            else:
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Not vulnerable to subdomain reflection ({test_result[protocol]['subdomain_reflection_with_www']['msg']})", "NOTVULN", use_json))

        if test_types['subdomain-reflection-no-www']:
            #if test_result['subdomain_reflection_without_www'] is None:
            #ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Test for subdomain reflection (without www): OK", "NOTVULN", use_json))
            if test_result[protocol]['subdomain_reflection_without_www'].get("vulnerable"):
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Vulnerable to subdomain reflection ({test_result[protocol]['subdomain_reflection_without_www']['msg']})", "VULN", use_json))
            else:
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Not vulnerable to subdomain reflection ({test_result[protocol]['subdomain_reflection_without_www']['msg']})", "NOTVULN", use_json))

        if test_types['crlf']:
            if test_result[protocol].get('crlf_subdomain'):
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Domain is vulnerable to CRLF (when redirect to subdomain)", "VULN", use_json))
            else:
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Domain is not vulnerable to CRLF (when redirect to subdomain)", "NOTVULN", use_json))

            if test_result[protocol].get('crlf_http2https'):
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Domain is vulnerable to CRLF (when redirect from HTTP to HTTPS)", "VULN", use_json))
            else:
                ptprinthelper.ptprint_(ptprinthelper.out_ifnot(f"Domain is not vulnerable to CRLF (when redirect from HTTP to HTTPS)", "NOTVULN", use_json))