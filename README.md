[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


# pthost
Default vhost testing tool

pthost is a script for testing the default vhost on a target server and checks for various vulnerabilities via the Host HTTP header. It includes options to test for:

- default-vhost: Tests the default virtual host configuration.
- open-redirect: Checks for vulnerabilities that allow open redirects.
- crlf: Tests for CRLF injection.
- host-injection: Looks for Host header injection issues.
- redir-to-https: Tests redirection from HTTP to HTTPS.
- seo-fragmentation: Evaluates SEO fragmentation vulnerabilities.
- subdomain-reflection-www: Tests subdomain reflection including 'www'.
- subdomain-reflection-no-www: Checks subdomain reflection excluding 'www'.


## Installation
```
pip install pthost
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples

```
pthost -d https://www.example.com/
pthost -d www.example.com
```


### Options:

```
-d   --domain      <domain>                      Test Domain
-t   --test        <test-types>                  Specify tests to perform (default all)
                    default-vhost                Test Default vhost
                    open-redirect                Test Open Redirect
                    crlf                         Test CRLF injection
                    host-injection               Test Host injection
                    redir-to-https               Test HTTP to HTTPS redirects
                    seo-fragmentation            Test SEO fragmentation
                    subdomain-reflection-www     Test Subdomain reflection (with www)
                    subdomain-reflection-no-www  Test Subdomain reflection (without www)

-H   --headers     <header:value>                Set custom headers
-T   --timeout     <timeout>                     Set timeout (default 7s)
-ua  --user-agent  <user-agent>                  Set user agent
-c   --cookie      <cookie=value>                Set cookie(s)
-p   --proxy       <proxy>                       Set proxy (e.g. http://127.0.0.1:8080)
-P   --protocol    <protocol>                    Set protocol to test (HTTP, HTTPS), default both
-C   --cache                                     Cache requests (load from tmp in future)
-v   --version                                   Show script version and exit
-h   --help                                      Show this help message and exit
-j   --json                                      Output in JSON format

```

## Dependencies

```
ptlibs
validators
```


## License

Copyright (c) 2024 Penterep Security s.r.o.

pthost is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

pthost is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with pthost. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!
