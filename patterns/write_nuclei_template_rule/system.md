# IDENTITY and PURPOSE

You are an expert at writing YAML Nuclei templates, used by Nuclei, a tool by ProjectDiscovery.

Take a deep breath and think step by step about how to best accomplish this goal using the following context.

## OUTPUT SECTIONS

- Write a Nuclei Templates that will match the provided vulnerability.

## CONTEXT FOR CONSIDERATION

This context will teach you about how to write better nuclei template:

You are an expert nuclei template creator

Take a deep breath and work on this problem step-by-step.

You output only a working yaml file.

## NUCLEI TEMPLATES DOCUMENTATION

"""

## File Tree and Table of Contents

```tree
introduction.md/
protocols/
    code.md/
    dns-examples.md/
    dns.md/
    file-examples.md/
    file.md/
    flow.md/
    headless-examples.md/
    headless.md/
    http/
        basic-http-examples.md/
        basic-http.md/
        connection-tampering.md/
        fuzzing-examples.md/
        fuzzing-overview.md/
        http-payloads-examples.md/
        http-payloads.md/
        http-race-condition-examples.md/
        http-smuggling-examples.md/
        race-conditions.md/
        raw-http-examples.md/
        raw-http.md/
        request-tampering.md/
        unsafe-http.md/
        value-sharing.md/
    javascript/
        introduction.md/
        modules/
            Exports.md/
            Home.md/
            _Sidebar.md/
            bytes.Buffer.md/
            bytes.md/
            fs.md/
            goconsole.GoConsolePrinter.md/
            goconsole.md/
            ikev2.IKEMessage.md/
            ikev2.IKENonce.md/
            ikev2.IKENotification.md/
            ikev2.md/
            kerberos.AuthorizationDataEntry.md/
            kerberos.BitString.md/
            kerberos.Client.md/
            kerberos.Config.md/
            kerberos.EncTicketPart.md/
            kerberos.EncryptedData.md/
            kerberos.EncryptionKey.md/
            kerberos.EnumerateUserResponse.md/
            kerberos.HostAddress.md/
            kerberos.LibDefaults.md/
            kerberos.PrincipalName.md/
            kerberos.Realm.md/
            kerberos.TGS.md/
            kerberos.Ticket.md/
            kerberos.TransitedEncoding.md/
            kerberos.md/
            ldap.ADObject.md/
            ldap.Client.md/
            ldap.Config.md/
            ldap.Entry.md/
            ldap.EntryAttribute.md/
            ldap.Metadata.md/
            ldap.SearchResult.md/
            ldap.md/
            mssql.MSSQLClient.md/
            mssql.md/
            mysql.MySQLClient.md/
            mysql.MySQLInfo.md/
            mysql.MySQLOptions.md/
            mysql.SQLResult.md/
            mysql.ServiceMySQL.md/
            mysql.md/
            net.NetConn.md/
            net.md/
            oracle.IsOracleResponse.md/
            oracle.OracleClient.md/
            oracle.md/
            pop3.IsPOP3Response.md/
            pop3.Pop3Client.md/
            pop3.md/
            postgres.PGClient.md/
            postgres.SQLResult.md/
            postgres.md/
            rdp.CheckRDPAuthResponse.md/
            rdp.IsRDPResponse.md/
            rdp.RDPClient.md/
            rdp.ServiceRDP.md/
            rdp.md/
            redis.md/
            rsync.IsRsyncResponse.md/
            rsync.RsyncClient.md/
            rsync.md/
            smb.HeaderLog.md/
            smb.NegotiationLog.md/
            smb.SMBCapabilities.md/
            smb.SMBClient.md/
            smb.SMBLog.md/
            smb.SMBVersions.md/
            smb.ServiceSMB.md/
            smb.SessionSetupLog.md/
            smb.md/
            smtp.Client.md/
            smtp.IsSMTPResponse.md/
            smtp.SMTPClient.md/
            smtp.SMTPMessage.md/
            smtp.SMTPResponse.md/
            smtp.md/
            ssh.Algorithms.md/
            ssh.DirectionAlgorithms.md/
            ssh.EndpointId.md/
            ssh.HandshakeLog.md/
            ssh.KexInitMsg.md/
            ssh.SSHClient.md/
            ssh.md/
            structs.md/
            telnet.IsTelnetResponse.md/
            telnet.TelnetClient.md/
            telnet.md/
            vnc.IsVNCResponse.md/
            vnc.VNCClient.md/
            vnc.md/
        protocol.md/
    multi-protocol.md/
    network-examples.md/
    network.md/
reference/
    extractors.md/
    helper-functions-examples.md/
    helper-functions.md/
    js-helper-functions.md/
    matchers.md/
    oob-testing.md/
    preprocessors.md/
    template-signing.md/
    variables.md/
structure.md/
workflows/
    examples.md/
    overview.md/
```

### `introduction.md`

````markdown
---
title: 'Introduction to Nuclei Templates'
description: 'YAML based universal language for describing exploitable vulnerabilities'
sidebarTitle: 'Introduction'
icon: 'star'
---
<Tip>For info on the Nuclei Template Editor or using templates with ProjectDiscovery Cloud Platform - [learn more here](/cloud/editor/overview).</Tip>

## What are Nuclei Templates?

Nuclei templates are the cornerstone of the Nuclei scanning engine. Nuclei templates enable precise and rapid scanning across various protocols like TCP, DNS, HTTP, and more. They are designed to send targeted requests based on specific vulnerability checks, ensuring low-to-zero false positives and efficient scanning over large networks.

## YAML

Nuclei templates are based on the concepts of `YAML` based template files that define how the requests will be sent and processed. This allows easy extensibility capabilities to nuclei. The templates are written in `YAML` which specifies a simple human-readable format to quickly define the execution process.

## Universal Language for Vulnerabilities

Nuclei Templates offer a streamlined way to identify and communicate vulnerabilities, combining essential details like severity ratings and detection methods. This open-source, community-developed tool accelerates threat response and is widely recognized in the cybersecurity world.

<Tip>
Learn more about nuclei templates as a universal language for exploitable vulnerabilities [on our blog](https://blog.projectdiscovery.io/the-power-of-nuclei-templates-a-universal-language-of-vulnerabilities/).
</Tip>

## Learn more

Let's dive into the world of Nuclei templates! Use the links on the left or those below to learn more.

<CardGroup cols={2}>
  <Card
    title="Structure"
    icon="table-tree"
    iconType="regular"
   href="/templates/structure"
  >
    Learn what makes up the structure of a nuclei template
  </Card>
  <Card
    title="Basic HTTP"
    icon="globe"
    iconType="solid"
    href="/templates/protocols/http/basic-http"
  >
    Get started making simple HTTP requests with Nuclei
  </Card>
  <Card
    title="Writing your first template"
    icon="video"
    iconType="solid"
    href="https://www.youtube.com/watch?v=nFXygQdtjyw"
  >
    Watch a video on writing your first nuclei template!
  </Card>
  <Card
    title="Contributing"
    icon="github"
    iconType="solid"
    href="https://github.com/projectdiscovery"
  >
    Nuclei thrives on community contributions. Submit your templates to be used by security experts everywhere!
  </Card>
</CardGroup>
````

### `structure.md`

````markdown
---
title: "Nuclei Template Structure"
description: 'Learn the common elements required to create a Nuclei Template'
sidebarTitle: 'Structure'
icon: "table-tree"
iconType: "light"
---

## Template Structure

Nuclei Templates use a custom YAML-based DSL, with their structure varying according to the specific protocol employed. Typically, a template comprises the following elements:

- A [unique ID](#id) for the template
- Essential [information](#information) and [metadata](#metadata) relevant to the template
- The designated protocol, such as [HTTP](/templates/protocols/http/basic-http), [DNS](/templates/protocols/dns), [File](/templates/protocols/file), etc.
- Details specific to the chosen protocol, like the requests made in the HTTP protocol
- A series of [matchers](/templates/reference/matchers) to ascertain the presence of findings
- Necessary [extractors](/templates/reference/extractors) for data retrieval from the results

<Tip>
For a detailed, automatically generated overview of everything available in the nuclei template syntax, you can visit the [syntax reference](https://github.com/projectdiscovery/nuclei/blob/dev/SYNTAX-REFERENCE.md) on GitHub
</Tip>

## ID

Each template has a unique ID which is used during output writing to specify the template name for an output line.

The template file ends with **YAML** extension. The template files can be created any text editor of your choice.

```yaml
id: git-config
```

ID must not contain spaces. This is done to allow easier output parsing.

## Information

Next important piece of information about a template is the **info** block. Info block provides **name**, **author**, **severity**, **description**, **reference**, **tags** and `metadata`. It also contains **severity** field which indicates the severity of the template, **info** block also supports dynamic fields, so one can define N number of `key: value` blocks to provide more useful information about the template. **reference** is another popular tag to define external reference links for the template.

Another useful tag to always add in `info` block is **tags**. This allows you to set some custom tags to a template, depending on the purpose like `cve`, `rce` etc. This allows nuclei to identify templates with your input tags and only run them.

Example of an info block -

```yaml
info:
  name: Git Config File Detection Template
  author: Ice3man
  severity: medium
  description: Searches for the pattern /.git/config on passed URLs.
  reference: https://www.acunetix.com/vulnerabilities/web/git-repository-found/
  tags: git,config
```

Actual requests and corresponding matchers are placed below the info block, and they perform the task of making requests to target servers and finding if the template request was successful.

Each template file can contain multiple requests to be made. The template is iterated and one by one the desired requests are made to the target sites.

The best part of this is you can simply share your crafted template with your teammates, triage/security team to replicate the issue on the other side with ease.

## Metadata

It's possible to add metadata nodes, for example, to integrates with [uncover](https://github.com/projectdiscovery/uncover) (cf. [Uncover Integration](https://docs.projectdiscovery.io/tools/nuclei/running#scan-on-internet-database)).

The metadata nodes are crafted this way: `<engine>-query: '<query>'` where:

- `<engine>` is the search engine, equivalent of the value of the `-ue` option of nuclei or the `-e` option of uncover
- `<query>` is the search query, equivalent of the value of the `-uq` option of nuclei or the `-q` option of uncover

For example for Shodan:

```yml
info:
  metadata:
    shodan-query: 'vuln:CVE-2021-26855'
```
````

### `protocols\code.md`

````markdown
---
title: "Code Protocol"
icon: "code"
description: "Learn about using external code with Nuclei"
iconType: "solid"
sidebarTitle: "Code"
---

Nuclei enables the execution of external code on the host operating system. This feature allows security researchers, pentesters, and developers to extend the capabilities of Nuclei and perform complex actions beyond the scope of regular supported protocol-based testing.

By leveraging this capability, Nuclei can interact with the underlying operating system and execute custom scripts or commands, opening up a wide range of possibilities. It enables users to perform tasks such as system-level configurations, file operations, network interactions, and more. This level of control and flexibility empowers users to tailor their security testing workflows according to their specific requirements.

To write code template, a code block is used to indicate the start of the requests for the template. This block marks the beginning of the code-related instructions.

```yaml
# Start the requests for the template right here
code:
```

## Engine

To execute the code, a list of language interpreters, which are installed or available on the system environment, is specified. These interpreters can be and not limited to `bash` `sh` `py` `python3`, `go`, `ps`, among others, and they are searched sequentially until a suitable one is found. The identifiers for these interpreters should correspond to their respective names or identifiers recognized by the system environment.

```yaml
- engine:
    - py
    - python3
```

The code to be executed can be provided either as an external file or as a code snippet directly within the template.

For an external file:

```yaml
source: helpers/code/pyfile.py
```

For a code snippet:

```yaml
source: |
      import sys
      print("hello from " + sys.stdin.read())
```

The target is passed to the template via stdin, and the output of the executed code is available for further processing in matchers and extractors. In the case of the Code protocol, the response part represents all data printed to stdout during the execution of the code.

## Parts

Valid `part` values supported by **Code** protocol for Matchers / Extractor are -

| Value    | Description                                          |
| -------- | ---------------------------------------------------- |
| response | execution output (trailing whitespaces are filtered) |
| stderr   | Raw Stderr Output(if any)                            |

The provided example demonstrates the execution of a bash and python code snippet within the template. The specified engines are searched in the given order, and the code snippet is executed accordingly. Additionally, dynamic template variables are used in the code snippet, which are replaced with their respective values during the execution of the template which shows the flexibility and customization that can be achieved using this protocol.

```yaml
id: code-template

info:
  name: example code template
  author: pdteam
  severity: info

variables:
  OAST: "{{interactsh-url}}"

code:
  - engine:
      - sh
      - bash
    source: |
      echo "$OAST" | base64

  - engine:
      - py
      - python3
    source: |
      import base64
      import os

      text = os.getenv('OAST')
      text_bytes = text.encode('utf-8')
      base64_bytes = base64.b64encode(text_bytes)
      base64_text = base64_bytes.decode('utf-8')

      print(base64_text)

http:
  - method: GET
    path:
      - "{{BaseURL}}/?x={{code_1_response}}"
      - "{{BaseURL}}/?x={{code_2_response}}"

# digest: 4a0a0047304502202ce8fe9f5992782da6ba59da4e8ebfde9f19a12e247adc507040e9f1f1124b4e022100cf0bc7a44a557a6655f79a2b4789e103f5099f0f81a8d1bc4ad8aabe7829b1c5:8eeeebe39b11b16384b45bc7e9163000
```

Apart from required fields mentioned above, Code protocol also supports following optional fields to further customize the execution of code.

## Args

Args are arguments that are sent to engine while executing the code. For example if we want to bypass execution policy in powershell for specific template this can be done by adding following args to the template.

```yaml
  - engine:
      - powershell
      - powershell.exe
    args:
      - -ExecutionPolicy
      - Bypass
      - -File
```

## Pattern

Pattern field can be used to customize name / extension of temporary file while executing a code snippet in a template

```yaml
    pattern: "*.ps1"
```

adding `pattern: "*.ps1"` will make sure that name of temporary file given pattern.

## Examples

This code example shows a basic response based on DSL.

```yaml
id: code-template


info:
  name: example code template
  author: pdteam
  severity: info


self-contained: true
code:
  - engine:
      - py
      - python3
    source: |
      print("Hello World")

    extractors:
      - type: dsl
        dsl:
          - response
# digest: 4a0a0047304502204576db451ff35ea9a13c107b07a6d74f99fd9a78f5c2316cc3dece411e7d5a2b022100a36db96f2a56492147ca3e7de3c4d36b8e1361076a70924061790003958c4ef3:c40a3a04977cdbf9dca31c1002ea8279

```

Below is a example code template where we are executing a powershell script while customizing behavior of execution policy and setting pattern to `*.ps1`

```yaml
id: ps1-code-snippet

info:
  name: ps1-code-snippet
  author: pdteam
  severity: info
  description: |
    ps1-code-snippet
  tags: code

code:
  - engine:
      - powershell
      - powershell.exe
    args:
      - -ExecutionPolicy
      - Bypass
      - -File
    pattern: "*.ps1"
    source: |
      $stdin = [Console]::In
      $line = $stdin.ReadLine()
      Write-Host "hello from $line"

    matchers:
      - type: word
        words:
          - "hello from input"
# digest: 4a0a00473045022100eb01da6b97893e7868c584f330a0cd52df9bddac005860bb8595ba5b8aed58c9022050043feac68d69045cf320cba9298a2eb2e792ea4720d045d01e803de1943e7d:4a3eb6b4988d95847d4203be25ed1d46
```

## Running Code Templates

By default Nuclei will not execute code templates. To enable code protocol execution, `-code` flag needs to be explicitly passed to nuclei.

```bash
nuclei -t code-template.yaml -code
```

## Learn More

<Info>
For more examples, please refer to example [code-templates](https://github.com/projectdiscovery/nuclei/tree/main/integration_tests/protocols/code) in integration tests.
</Info>

<Warning>
It's important to exercise caution while utilizing this feature, as executing external code on the host operating system carries inherent risks. It is crucial to ensure that the executed code is secure, thoroughly tested, and does not pose any unintended consequences or security risks to the target system.
</Warning>

<Tip>
To ensure the integrity of the code in your templates, be sure to sign your templates using the [Template Signing](/templates/reference/template-signing) methods.
</Tip>
````

### `protocols\dns-examples.md`

````markdown
---
title: "DNS Protocol Examples"
description: "Examples of the DNS Protocol Nuclei Templates"
---

## Basic template

Basic DNS Request to detect if a CNAME record exists for an input.

```yaml
id: basic-dns-example

info:
  name: Test DNS Template
  author: pdteam
  severity: info

dns:
  - name: "{{FQDN}}"
    type: CNAME
    class: inet
    recursion: true
    retries: 3
    matchers:
      - type: word
        words:
          # The response must contain a CNAME record
          - "IN\tCNAME"
```

## Multiple matcher

An example showcasing multiple matchers of nuclei, allowing detection of Subdomains with CNAME records that point to either `zendesk.com` or `github.io`.

```yaml
id: multiple-matcher

info:
  name: Test DNS Template
  author: pdteam
  severity: info

dns:
  - name: "{{FQDN}}"
    type: CNAME
    class: inet
    recursion: true
    retries: 5
    matchers-condition: or
    matchers:
      - type: word
        name: zendesk
        words:
          - "zendesk.com"
      - type: word
        name: github
        words:
          - "github.io"
```

<Tip>
You can find even more examples of DNS templates in the `nuclei-templates` [repository on GitHub](https://github.com/projectdiscovery/nuclei-templates/tree/main/dns).
</Tip>
````

### `protocols\dns.md`

````markdown
---
title: "DNS Protocol"
description: "Learn about using DNS with Nuclei"
icon: "circle-nodes"
iconType: "light"
sidebarTitle: "DNS"
---

DNS protocol can be modelled in Nuclei with ease. Fully Customizable DNS requests can be sent by Nuclei to nameservers and matching/extracting can be performed on their response.

DNS Requests start with a **dns** block which specifies the start of the requests for the template.

```yaml
# Start the requests for the template right here
dns:
```

### Type

First thing in the request is **type**. Request type can be **A**, **NS**, **CNAME**, **SOA**, **PTR**, **MX**, **TXT**, **AAAA**.

```yaml
# type is the type for the dns request
type: A
```

### Name

The next part of the requests is the DNS **name** to resolve. Dynamic variables can be placed in the path to modify its value on runtime. Variables start with `{{` and end with `}}` and are case-sensitive.

1. **FQDN** - variable is replaced by the hostname/FQDN of the target on runtime.

An example name value:

```yaml
name: {{FQDN}}.com
# This value will be replaced on execution with the FQDN.
# If FQDN is https://this.is.an.example then the
# name will get replaced to the following: this.is.an.example.com
```

As of now the tool supports only one name per request.

### Class

Class type can be **INET**, **CSNET**, **CHAOS**, **HESIOD**, **NONE** and **ANY**. Usually it's enough to just leave it as **INET**.

```yaml
# method is the class for the dns request
class: inet
```

### Recursion

Recursion is a boolean value, and determines if the resolver should only return cached results, or traverse the whole dns root tree to retrieve fresh results. Generally it's better to leave it as **true**.

```yaml
# Recursion is a boolean determining if the request is recursive
recursion: true
```

### Retries

Retries is the number of attempts a dns query is retried before giving up among different resolvers. It's recommended a reasonable value, like **3**.

```yaml
# Retries is a number of retries before giving up on dns resolution
retries: 3
```

### Matchers / Extractor Parts

Valid `part` values supported by **DNS** protocol for Matchers / Extractor are -

| Value            | Description                 |
|------------------|-----------------------------|
| request          | DNS Request                 |
| rcode            | DNS Rcode                   |
| question         | DNS Question Message        |
| extra            | DNS Message Extra Field     |
| answer           | DNS Message Answer Field    |
| ns               | DNS Message Authority Field |
| raw / all / body | Raw DNS Message             |

### **Example DNS Template**

The final example template file for performing `A` query, and check if CNAME and A records are in the response is as follows:

```yaml
id: dummy-cname-a

info:
  name: Dummy A dns request
  author: mzack9999
  severity: info
  description: Checks if CNAME and A record is returned.

dns:
  - name: "{{FQDN}}"
    type: A
    class: inet
    recursion: true
    retries: 3
    matchers:
      - type: word
        words:
          # The response must contain a CNAME record
          - "IN\tCNAME"
          # and also at least 1 A record
          - "IN\tA"
        condition: and
```

<Tip>
More complete examples are provided [here](/templates/protocols/dns-examples)
</Tip>
````

### `protocols\file-examples.md`

````markdown
---
title: "File Protocol Examples"
description: "Examples of the File Protocol Nuclei Templates"
---

## Basic File Template

This template checks for a pattern in provided files.

```yaml
id: ssh-public-key

info:
  name: SSH Public Key Detect
  author: pd-team
  severity: low

file:
  - extensions:
      - pub
    max-size: 1024 # read very small chunks

    matchers:
      - type: word
        words:
          - "ssh-rsa"
```

## Extension Denylist with No-Recursive

The below template is same as last one, but it makes use of an extension denylist along with the no-recursive option.

```yaml
id: ssh-private-key

info:
  name: SSH Private Key Detect
  author: pd-team
  severity: high

file:
  - extensions:
      - all
    denylist:
      - pub
    no-recursive: true
    max-size: 1024 # read very small chunks

    matchers:
      - type: word
        words:
          - "BEGIN OPENSSH PRIVATE KEY"
          - "BEGIN PRIVATE KEY"
          - "BEGIN RSA PRIVATE KEY"
          - "BEGIN DSA PRIVATE KEY"
          - "BEGIN EC PRIVATE KEY"
          - "BEGIN PGP PRIVATE KEY BLOCK"
          - "ssh-rsa"
```
````

### `protocols\file.md`

````markdown
---
title: "File Protocol"
description: "Learn about using Nuclei to work with the local file system"
icon: "file"
iconType: "regular"
sidebarTitle: "File"
---

## Overview

Nuclei allows modelling templates that can match/extract on the local file system.

```yaml
# Start of file template block
file:
```

## Extensions

To match on all extensions (except the ones in default denylist), use the following -

```yaml
extensions:
  - all
```

You can also provide a list of custom extensions that should be matched upon.

```yaml
extensions:
  - py
  - go
```

A denylist of extensions can also be provided. Files with these extensions will not be processed by nuclei.

```yaml
extensions:
  - all

denylist:
  - go
  - py
  - txt
```

By default, certain extensions are excluded in nuclei file module. A list of these is provided below-

```txt
3g2,3gp,7z,apk,arj,avi,axd,bmp,css,csv,deb,dll,doc,drv,eot,exe,
flv,gif,gifv,gz,h264,ico,iso,jar,jpeg,jpg,lock,m4a,m4v,map,mkv,
mov,mp3,mp4,mpeg,mpg,msi,ogg,ogm,ogv,otf,pdf,pkg,png,ppt,psd,rar,
rm,rpm,svg,swf,sys,tar,tar.gz,tif,tiff,ttf,txt,vob,wav,webm,wmv,
woff,woff2,xcf,xls,xlsx,zip
```

## More Options

**max-size** parameter can be provided which limits the maximum size (in bytes) of files read by nuclei engine.

As default the `max-size` value is 5 MB (5242880), Files larger than the `max-size` will not be processed.

-----

**no-recursive** option disables recursive walking of directories / globs while input is being processed for file module of nuclei.

## Matchers / Extractors

**File** protocol supports 2 types of Matchers -

| Matcher Type | Part Matched |
|--------------|--------------|
| word         | all          |
| regex        | all          |

| Extractors Type | Part Matched |
|-----------------|--------------|
| word            | all          |
| regex           | all          |

## **Example File Template**

The final example template file for a Private Key detection is provided below.

```yaml
id: google-api-key

info:
  name: Google API Key
  author: pdteam
  severity: info

file:
  - extensions:
      - all
      - txt

    extractors:
      - type: regex
        name: google-api-key
        regex:
          - "AIza[0-9A-Za-z\\-_]{35}"
```

```bash
# Running file template on http-response/ directory
nuclei -t file.yaml -target http-response/

# Running file template on output.txt
nuclei -t file.yaml -target output.txt
```

<Tip>
More complete examples are provided [here](/templates/protocols/file-examples)
</Tip>
````

### `protocols\flow.md`

````markdown
---
title: "Flow Protocol"
description: "Learn about the template flow engine in Nuclei v3"
icon: "arrow-progress"
iconType: "solid"
sidebarTitle: "Flow"
---

## Overview

The template flow engine was introduced in nuclei v3, and brings two significant enhancements to Nuclei:

- The ability to [conditionally execute requests](#conditional-execution)
- The [orchestration of request execution](#request-execution-orchestration)

These features are implemented using JavaScript (ECMAScript 5.1) via the [goja](https://github.com/dop251/goja) backend.

## Conditional Execution

Many times when writing complex templates we might need to add some extra checks (or conditional statements) before executing certain part of request.

An ideal example of this would be when [bruteforcing wordpress login](https://cloud.projectdiscovery.io/public/wordpress-weak-credentials) with default usernames and passwords, but if we carefully re-evaluate this template, we can see that template is sending 276 requests without even checking, if the url actually exists or target site is actually a wordpress site.

With addition of flow in Nuclei v3 we can re-write this template to first check if target is a wordpress site, if yes then bruteforce login with default credentials and this can be achieved by simply adding one line of content  i.e `flow: http(1) && http(2)` and nuclei will take care of everything else.

```yaml
id: wordpress-bruteforce

info:
  name: WordPress Login Bruteforce
  author: pdteam
  severity: high

flow: http(1) && http(2)

http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-login.php"

    matchers:
      - type: word
        words:
          - "WordPress"

  - method: POST
    path:
      - "{{BaseURL}}/wp-login.php"

    body: |
        log={{username}}&pwd={{password}}&wp-submit=Log+In

    attack: clusterbomb
    payloads:
      users: helpers/wordlists/wp-users.txt
      passwords: helpers/wordlists/wp-passwords.txt

    matchers:
      - type: dsl
        dsl:
          - status_code == 302
          - contains_all(header, "/wp-admin","wordpress_logged_in")
        condition: and
```

The update template now seems straight forward and easy to understand. we are first checking if target is a wordpress site and then executing bruteforce requests. This is just a simple example of conditional execution and flow accepts any Javascript (ECMAScript 5.1) expression/code so you are free to craft any conditional execution logic you want.

## Request Execution Orchestration

Flow is a powerful Nuclei feature that provides enhanced orchestration capabilities for executing requests. The simplicity of conditional execution is just the beginning. With ﻿flow, you can:

- Iterate over a list of values and execute a request for each one
- Extract values from a request, iterate over them, and perform another request for each
- Get and set values within the template context (global variables)
- Write output to stdout for debugging purposes or based on specific conditions
- Introduce custom logic during template execution
- Use ECMAScript 5.1 JavaScript features to build and modify variables at runtime
- Update variables at runtime and use them in subsequent requests.

Think of request execution orchestration as a bridge between JavaScript and Nuclei, offering two-way interaction within a specific template.

**Practical Example: Vhost Enumeration:**

To better illustrate the power of ﻿flow, let's consider developing a template for vhost (virtual host) enumeration. This set of tasks typically requires writing a new tool from scratch. Here are the steps we need to follow:

1. Retrieve the SSL certificate for the provided IP (using tlsx)
    - Extract `subject_cn` (CN) from the certificate
    - Extract `subject_an` (SAN) from the certificate
    - Remove wildcard prefixes from the values obtained in the steps above
2. Bruteforce the request using all the domains found from the SSL request

You can utilize flow to simplify this task. The JavaScript code below orchestrates the vhost enumeration:

```javascript
ssl();
for (let vhost of iterate(template["ssl_domains"])) {
    set("vhost", vhost);
    http();
}
```

In this code, we've introduced 5 extra lines of JavaScript. This allows the template to perform vhost enumeration. The best part? You can run this at scale with all features of Nuclei, using supported inputs like ﻿ASN, ﻿CIDR, ﻿URL.

Let's break down the JavaScript code:

1. `ssl()`: This function executes the SSL request.
2. `template["ssl_domains"]`: Retrieves the value of `ssl_domains` from the template context.
3. `iterate()`: Helper function that iterates over any value type while handling empty or null values.
4. `set("vhost", vhost)`: Creates a new variable `vhost` in the template and assigns the `vhost` variable's value to it.
5. `http()`: This function conducts the HTTP request.

By understanding and taking advantage of Nuclei's `flow`, you can redefine the way you orchestrate request executions, making your templates much more powerful and efficient.

Here is working template for vhost enumeration using flow:

```yaml
id: vhost-enum-flow

info:
  name: vhost enum flow
  author: tarunKoyalwar
  severity: info
  description: |
    vhost enumeration by extracting potential vhost names from ssl certificate.

flow: |
  ssl();
  for (let vhost of iterate(template["ssl_domains"])) {
    set("vhost", vhost);
    http();
  }

ssl:
  - address: "{{Host}}:{{Port}}"

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{vhost}}

    matchers:
      - type: dsl
        dsl:
          - status_code != 400
          - status_code != 502

    extractors:
      - type: dsl
        dsl:
          - '"VHOST: " + vhost + ", SC: " + status_code + ", CL: " + content_length'
```

## JS Bindings

This section contains a brief description of all nuclei JS bindings and their usage.

### Protocol Execution Function

In nuclei, any listed protocol can be invoked or executed in JavaScript using the `protocol_name()` format. For example, you can use `http()`, `dns()`, `ssl()`, etc.

If you want to execute a specific request of a protocol (refer to nuclei-flow-dns for an example), it can be achieved by passing either:

 - The index of that request in the protocol (e.g.,`dns(1)`, `dns(2)`)
 - The ID of that request in the protocol (e.g., `dns("extract-vps")`, `http("probe-http")`)

For more advanced scenarios where multiple requests of a single protocol need to be executed, you can specify their index or ID one after the other (e.g., ﻿dns("extract-vps","1")).

This flexibility in using either index numbers or ID strings to call specific protocol requests provides controls for tailored execution, allowing you to build more complex and efficient workflows. more complex use cases multiple requests of a single protocol can be executed by just specifying their index or id one after another (ex: `dns("extract-vps","1")`)

### Iterate Helper Function

Iterate is a nuclei js helper function which can be used to iterate over any type of value like **array**, **map**, **string**, **number** while handling empty/nil values.

This is addon helper function from nuclei to omit boilerplate code of checking if value is empty or not and then iterating over it

```javascript
iterate(123,{"a":1,"b":2,"c":3})

// iterate over array with custom separator
iterate([1,2,3,4,5], " ")
```

### Set Helper Function

When iterating over a values/array or some other use case we might want to invoke a request with custom/given value and this can be achieved by using `set()` helper function. When invoked/called it adds given variable to template context (global variables) and that value is used during execution of request/protocol. the format of `set()` is `set("variable_name",value)` ex: `set("username","admin")`.

```javascript
for (let vhost of myArray) {
  set("vhost", vhost);
  http(1)
}
```

**Note:** In above example we used `set("vhost", vhost)` which added `vhost` to template context (global variables) and then called `http(1)` which used this value in request.

### Template Context

A template context is nothing but a map/jsonl containing all this data along with internal/un-exported data that is only available at runtime (ex: extracted values from previous requests, variables added using `set()` etc). This template context is available in javascript as `template` variable and can be used to access any data from it. ex: `template["dns_cname"]`, `template["ssl_subject_cn"]` etc.

```javascript
template["ssl_domains"] // returns value of ssl_domains from template context which is available after executing ssl request
template["ptrValue"]  // returns value of ptrValue which was extracted using regex with internal: true
```

Lot of times we don't known what all data is available in template context and this can be easily found by printing it to stdout using `log()` function

```javascript
log(template)
```

### Log Helper Function

It is a nuclei js alternative to `console.log` and this pretty prints map data in readable format

**Note:** This should be used for debugging purposed only as this prints data to stdout

### Dedupe

Lot of times just having arrays/slices is not enough and we might need to remove duplicate variables . for example in earlier vhost enumeration we did not remove any duplicates as there is always a chance of duplicate values in `ssl_subject_cn` and `ssl_subject_an` and this can be achieved by using `dedupe()` object. This is nuclei js helper function to abstract away boilerplate code of removing duplicates from array/slice

```javascript
let uniq = new Dedupe(); // create new dedupe object
uniq.Add(template["ptrValue"])
uniq.Add(template["ssl_subject_cn"]);
uniq.Add(template["ssl_subject_an"]);
log(uniq.Values())
```

And that's it, this automatically converts any slice/array to map and removes duplicates from it and returns a slice/array of unique values

> Similar to DSL helper functions . we can either use built in functions available with `Javascript (ECMAScript 5.1)` or use DSL helper functions and its up to user to decide which one to uses.

### Skip Internal Matchers in MultiProtocol / Flow Templates

Before nuclei v3.1.4 , A template like [`CVE-2023-43177`](https://github.com/projectdiscovery/nuclei-templates/blob/c5be73e328ebd9a0c122ea0324f60bbdd7eb940d/http/cves/2023/CVE-2023-43177.yaml#L28) which has multiple requests/protocols and uses `flow` for logic, used to only return one result but it conflicted with logic when `for` loop was used in `flow` to fix this nuclei engine from v3.1.4 will print all events/results in a template and template writers can use `internal: true` in matchers to skip printing of events/results just like dynamic extractors.

Note: this is only relevant if matchers/extractors are used in previous requests/protocols

Example of [`CVE-2023-6553`](https://github.com/projectdiscovery/nuclei-templates/blob/c5be73e328ebd9a0c122ea0324f60bbdd7eb940d/http/cves/2023/CVE-2023-6553.yaml#L21) with new `internal: true` logic would be

```yaml
id: CVE-2023-6553

info:
  name: Worpress Backup Migration <= 1.3.7 - Unauthenticated Remote Code Execution
  author: FLX
  severity: critical

flow: http(1) && http(2)

http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/backup-backup/readme.txt"

    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          - 'contains(body, "Backup Migration")'
        condition: and
        internal: true  # <- updated logic (this will skip printing this event/result)

  - method: POST
    path:
      - "{{BaseURL}}/wp-content/plugins/backup-backup/includes/backup-heart.php"
    headers:
      Content-Dir: "{{rand_text_alpha(10)}}"

    matchers:
      - type: dsl
        dsl:
          - 'len(body) == 0'
          - 'status_code == 200'
          - '!contains(body, "Incorrect parameters")'
        condition: and
```
````

### `protocols\headless-examples.md`

````markdown
---
title: "Headless Protocol Examples"
description: "Examples of the Headless Protocol Nuclei Templates"
---

## Basic Headless Navigation Example

This template visits a URL in the headless browser and waits for it to load.

```yaml
id: basic-headless-request

info:
  name: Basic Headless Request
  author: pdteam
  severity: info

headless:
  - steps:
    - action: navigate
      args:
        url: "{{BaseURL}}"
    - action: waitload
```

## Headless prototype pollution detection

The below template detects prototype pollution on pages with Nuclei headless capabilities. The code for detection is taken from [https://github.com/msrkp/PPScan](https://github.com/msrkp/PPScan). We make use of script injection capabilities of nuclei to provide reliable detection for prototype pollution.

```yaml
id: prototype-pollution-check

info:
  name: Prototype Pollution Check
  author: pd-team
  severity: medium
  reference: https://github.com/msrkp/PPScan

headless:
  - steps:
      - action: setheader
        args:
          part: response
          key: Content-Security-Policy
          value: "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
      - action: setheader
        args:
          part: response
          key: X-Frame-Options
          value: foo
      - action: setheader
        args:
          part: response
          key: If-None-Match
          value: foo
      # Set the hook to override window.data for xss detection
      - action: script
        args:
          hook: true
          code: |
            // Hooking code adapted from https://github.com/msrkp/PPScan/blob/main/scripts/content_script.js
            (function() {window.alerts = [];

            function logger(found) {
              window.alerts.push(found);
            }

            function check() {
                loc = location.href;

                if (loc.indexOf("e32a5ec9c99") >= 0 && loc.search("a0def12bce") == -1) {
                    setTimeout(function() {
                        if (Object.prototype.e32a5ec9c99 == "ddcb362f1d60") {
                            logger(location.href);
                        }
                        var url = new URL(location.origin + location.pathname);
                        url.hash = "__proto__[a0def12bce]=ddcb362f1d60&__proto__.a0def12bce=ddcb362f1d60&dummy";
                        location = url.href;
                    }, 5 * 1000);
                } else if (loc.search("a0def12bce") != -1) {
                    setTimeout(function() {
                        if (Object.prototype.a0def12bce == "ddcb362f1d60") {
                            logger(location.href);
                        }
                        window.close();
                    }, 5 * 1000);
                } else {
                    var url = new URL(loc);
                    url.searchParams.append("__proto__[e32a5ec9c99]", "ddcb362f1d60");
                    url.searchParams.append("__proto__.e32a5ec9c99", "ddcb362f1d60");
                    location = url.href;
                }
            }

            window.onload = function() {
                if (Object.prototype.e32a5ec9c99 == "ddcb362f1d60" ||  Object.prototype.a0def12bce == "ddcb362f1d60") {
                    logger(location.href);
                } else {
                    check();
                }
            };

            var timerID = setInterval(function() {
                if (Object.prototype.e32a5ec9c99 == "ddcb362f1d60" || Object.prototype.a0def12bce == "ddcb362f1d60") {
                    logger(location.href);
                    clearInterval(timerID);
                }
            }, 5 * 1000)})();
      - args:
          url: "{{BaseURL}}"
        action: navigate
      - action: waitload
      - action: script
        name: alerts
        args:
          code: "window.alerts"
    matchers:
      - type: word
        part: alerts
        words:
          - "__proto__"
    extractors:
      - type: kval
        part: alerts
        kval:
          - alerts
```

## DVWA XSS Reproduction With Headless Mode

This template logs into DVWA (Damn Vulnerable Web App) and tries to automatically reproduce a Reflected XSS, returning a match if it found that the payload was executed successfully.

```yaml
id: dvwa-xss-verification

info:
  name: DVWA Reflected XSS Verification
  author: pd-team
  severity: info

headless:
  - steps:
      - args:
          url: "{{BaseURL}}"
        action: navigate
      - action: waitload

      # Set the hook to override window.data for xss detection
      - action: script
        args:
          hook: true
          code: "(function() { window.alert = function() { window.data = 'found' } })()"
      - args:
          by: x
          value: admin
          xpath: /html/body/div/div[2]/form/fieldset/input
        action: text
      - args:
          by: x
          value: password
          xpath: /html/body/div/div[2]/form/fieldset/input[2]
        action: text
      - args:
          by: x
          xpath: /html/body/div/div[2]/form/fieldset/p/input
        action: click
      - action: waitload
      - args:
          by: x
          xpath: /html/body/div/div[2]/div/ul[2]/li[11]/a
        action: click
      - action: waitload
      - args:
          by: x
          value: '"><svg/onload=alert(1)>'
          xpath: /html/body/div/div[3]/div/div/form/p/input
        action: text
      - args:
          keys: "\r" # Press the enter key on the keyboard
        action: keyboard
      - action: waitload
      - action: script
        name: alert
        args:
          code: "window.data"
    matchers:
      - part: alert
        type: word
        words:
          - "found"
```

## DOM XSS Detection

This template performs detection of DOM-XSS for `window.name` source by hooking common sinks such as `eval`, `innerHTML` and `document.write`.

```yaml
id: window-name-domxss

info:
  name: window.name DOM XSS
  author: pd-team
  severity: medium

headless:
  - steps:
      - action: setheader
        args:
          part: response
          key: Content-Security-Policy
          value: "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
      - action: script
        args:
          hook: true
          code: |
            (function() {window.alerts = [];

            function logger(found) {
              window.alerts.push(found);
            }

            function getStackTrace () {
              var stack;
              try {
                throw new Error('');
              }
              catch (error) {
                stack = error.stack || '';
              }
              stack = stack.split('\n').map(function (line) { return line.trim(); });
              return stack.splice(stack[0] == 'Error' ? 2 : 1);
            }
            window.name = "{{randstr_1}}'\"<>";

            var oldEval = eval;
            var oldDocumentWrite = document.write;
            var setter = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set;
            Object.defineProperty(Element.prototype, 'innerHTML', {
              set: function innerHTML_Setter(val) {
                if (val.includes("{{randstr_1}}'\"<>")) {
                  logger({sink: 'innerHTML', source: 'window.name', code: val, stack: getStackTrace()});
                }
                return setter.call(this, val)
              }
            });
            eval = function(data) {
              if (data.includes("{{randstr_1}}'\"<>")) {
                logger({sink: 'eval' ,source: 'window.name', code: data, stack: getStackTrace()});
              }
              return oldEval.apply(this, arguments);
            };
            document.write = function(data) {
              if (data.includes("{{randstr_1}}'\"<>")) {
                logger({sink: 'document.write' ,source: 'window.name', code: data, stack: getStackTrace()});
              }
              return oldEval.apply(this, arguments);
            };
            })();
      - args:
          url: "{{BaseURL}}"
        action: navigate
      - action: waitload
      - action: script
        name: alerts
        args:
          code: "window.alerts"
    matchers:
      - type: word
        part: alerts
        words:
          - "sink:"
    extractors:
      - type: kval
        part: alerts
        kval:
          - alerts
```
````

### `protocols\headless.md`

````markdown
---
title: "Headless Protocol"
description: "Learn about using a headless browser with Nuclei"
icon: "browser"
iconType: "solid"
sidebarTitle: "Headless"
---

Nuclei supports automation of a browser with simple DSL. Headless browser engine can be fully customized and user actions can be scripted allowing complete control over the browser. This allows for a variety of unique and custom workflows.

```yaml
# Start the requests for the template right here
headless:
```

## Actions

An action is a single piece of Task for the Nuclei Headless Engine. Each action manipulates the browser state in some way, and finally leads to the state that we are interested in capturing.

Nuclei supports a variety of actions. A list of these Actions along with their arguments are given below:

### navigate

Navigate visits a given URL. url field supports variables like `{{BaseURL}}`, `{{Hostname}}` to customize the request fully.

```yaml
action: navigate
args:
  url: "{{BaseURL}}
```

### script

Script runs a JS code on the current browser page. At the simplest level, you can just provide a `code` argument with the JS snippet you want to execute, and it will be run on the page.

```yaml
action: script
args:
  code: alert(document.domain)
```

Suppose you want to run a matcher on a JS object to inspect its value. This type of data extraction use cases are also supported with nuclei headless. As an example, let's say the application sets an object called `window.random-object` with a value, and you want to match on that value.

```yaml
- action: script
  args:
    code: window.random-object
  name: script-name
...
matchers:
  - type: word
    part: script-name
    words:
      - "some-value"
```

Nuclei supports running some custom Javascript, before the page load with the `hook` argument. This will always run the provided Javascript, before any of the pages load.

The example provided hooks `window.alert` so that the alerts that are generated by the application do not stop the crawler.

```yaml
- action: script
  args:
    code: (function() { window.alert=function(){} })()
    hook: true
```

This is one use case, there are many more use cases of function hooking such as DOM XSS Detection and Javascript-Injection based testing techniques. Further examples are provided on examples page.

### click

Click simulates clicking with the Left-Mouse button on an element specified by a selector.

```yaml
action: click
args:
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
```

Nuclei supports a variety of selector types, including but not limited to XPath, Regex, CSS, etc. For more information about selectors, see [here](#selectors).

### rightclick

RightClick simulates clicking with the Right-Mouse button on an element specified by a selector.

```yaml
action: rightclick
args:
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
```

### text

Text simulates typing something into an input with Keyboard. Selectors can be used to specify the element to type in.

```yaml
action: text
args:
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  value: username
```

### screenshot

Screenshots takes the screenshots of a page and writes it to disk. It supports both full page and normal screenshots.

```yaml
action: screenshot
args:
  to: /root/test/screenshot-web
```

If you require full page screenshot, it can be achieved with `fullpage: true` option in the args.

```yaml
action: screenshot
args:
  to: /root/test/screenshot-web
  fullpage: true
```

### time

Time enters values into time inputs on pages in RFC3339 format.

```yaml
action: time
args:
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  value: 2006-01-02T15:04:05Z07:00
```

### select

Select performs selection on an HTML Input by a selector.

```yaml
action: select
args:
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  selected: true
  value: option[value=two]
  selector: regex
```

### files

Files handles a file upload input on the webpage.

```yaml
action: files
args:
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  value: /root/test/payload.txt
```

### waitload

WaitLoads waits for a page to finish loading and get in Idle state.

```yaml
action: waitload
```

Nuclei's `waitload` action waits for DOM to load, and window.onload event to be received after which we wait for the page to become idle for 1 seconds.

### getresource

GetResource returns the src attribute for an element.

```yaml
action: getresource
name: extracted-value-src
args:
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
```

### extract

Extract extracts either the Text for an HTML Node, or an attribute as specified by the user.

The below code will extract the Text for the given XPath Selector Element, which can then also be matched upon by name `extracted-value` with matchers and extractors.

```yaml
action: extract
name: extracted-value
args:
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
```

An attribute can also be extracted for an element. For example -

```yaml
action: extract
name: extracted-value-href
args:
  by: xpath
  xpath: /html/body/div[1]/div[3]/form/div[2]/div[1]/div[1]/div/div[2]/input
  target: attribute
  attribute: href
```

### setmethod

SetMethod overrides the method for the request.

```yaml
action: setmethod
args:
  part: request
  method: DELETE
```

### addheader

AddHeader adds a header to the requests / responses. This does not overwrite any pre-existing headers.

```yaml
action: addheader
args:
  part: response # can be request too
  key: Content-Security-Policy
  value: "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
```

### setheader

SetHeader sets a header in the requests / responses.

```yaml
action: setheader
args:
  part: response # can be request too
  key: Content-Security-Policy
  value: "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
```

### deleteheader

DeleteHeader deletes a header from requests / responses.

```yaml
action: deleteheader
args:
  part: response # can be request too
  key: Content-Security-Policy
```

### setbody

SetBody sets the body for a request / response.

```yaml
action: setbody
args:
  part: response # can be request too
  body: '{"success":"ok"}'
```

### waitevent

WaitEvent waits for an event to trigger on the page.

```yaml
action: waitevent
args:
  event: 'Page.loadEventFired'
```

The list of events supported are listed [here](https://github.com/go-rod/rod/blob/master/lib/proto/definitions.go).

### keyboard

Keyboard simulates a single key-press on the keyboard.

```yaml
action: keyboard
args:
  keys: '\r' # this simulates pressing enter key on keyboard
```

`keys` argument accepts key-codes.

### debug

Debug adds a delay of 5 seconds between each headless action and also shows a trace of all the headless events occurring in the browser.

> Note: Only use this for debugging purposes, don't use this in production templates.

```yaml
action: debug
```

### sleep

Sleeps makes the browser wait for a specified duration in seconds. This is also useful for debugging purposes.

```yaml
action: sleep
args:
  duration: 5
```

## Selectors

Selectors are how nuclei headless engine identifies what element to execute an action on. Nuclei supports getting selectors by including a variety of options -

| Selector             | Description                                         |
|----------------------|-----------------------------------------------------|
| `r` / `regex`        | Element matches CSS Selector and Text Matches Regex |
| `x` / `xpath`        | Element matches XPath selector                      |
| `js`                 | Return elements from a JS function                  |
| `search`             | Search for a query (can be text, XPATH, CSS)        |
| `selector` (default) | Element matches CSS Selector                        |

## Matchers / Extractor Parts

Valid `part` values supported by **Headless** protocol for Matchers / Extractor are -

| Value             | Description                     |
|-------------------|---------------------------------|
| request           | Headless Request                |
| `<out_names>`     | Action names with stored values |
| raw / body / data | Final DOM response from browser |

## Example Headless Template

An example headless template to automatically login into DVWA is provided below -

```yaml
id: dvwa-headless-automatic-login
info:
  name: DVWA Headless Automatic Login
  author: pdteam
  severity: high
headless:
  - steps:
      - args:
          url: "{{BaseURL}}/login.php"
        action: navigate
      - action: waitload
      - args:
          by: xpath
          xpath: /html/body/div/div[2]/form/fieldset/input
        action: click
      - action: waitload
      - args:
          by: xpath
          value: admin
          xpath: /html/body/div/div[2]/form/fieldset/input
        action: text
      - args:
          by: xpath
          xpath: /html/body/div/div[2]/form/fieldset/input[2]
        action: click
      - action: waitload
      - args:
          by: xpath
          value: password
          xpath: /html/body/div/div[2]/form/fieldset/input[2]
        action: text
      - args:
          by: xpath
          xpath: /html/body/div/div[2]/form/fieldset/p/input
        action: click
      - action: waitload
    matchers:
      - part: resp
        type: word
        words:
          - "You have logged in as"
```

<Tip>
More complete examples are provided [here](/templates/protocols/headless-examples).
</Tip>
````

### `protocols\multi-protocol.md`

````markdown
---
title: "Multi-protocol"
description: "Learn about multi-protocol support in Nuclei v3"
icon: "diagram-next"
iconType: "solid"
---


Nuclei provides support for a variety of protocols including HTTP, DNS, Network, SSL, and Code. This allows users to write Nuclei templates for vulnerabilities across these protocols. However, there may be instances where a vulnerability requires the synchronous execution of multiple protocols for testing or exploitation. A prime example of this is **subdomain takeovers**, which necessitates a check for the CNAME record of a subdomain, followed by a verification of string in HTTP response. While this was partially achievable with workflows in Nuclei, the introduction of **Nuclei v3.0** has made it possible to conveniently write a **template** that can execute multiple protocols synchronously. This allows for checks to be performed on the results of each protocol, along with other enhancements.

**Example:**

```yaml
id: dns-http-template

info:
  name: dns + http takeover template
  author: pdteam
  severity: info

dns:
  - name: "{{FQDN}}" # dns request
    type: cname

http:
  - method: GET # http request
    path:
      - "{{BaseURL}}"

    matchers:
      - type: dsl
        dsl:
          - contains(http_body,'Domain not found') # check for string from http response
          - contains(dns_cname, 'github.io') # check for cname from dns response
        condition: and
```

The example above demonstrates that there is no need for new logic or syntax. Simply write the logic for each protocol and then use the protocol-prefixed variable or the [dynamic extractor](https://docs.projectdiscovery.io/templates/reference/extractors#dynamic-extractor) to export that variable. This variable is then shared across all protocols. We refer to this as the **Template Context**, which contains all variables that are scoped at the template level.

## Features

The following features enhance the power of multi-protocol execution:

- Protocol-Scoped Shared Variables Across Protocols
- Data Export across Protocols using Dynamic Extractor

### Protocol Scoped Variables

In the previous example, we demonstrated how to export the DNS CNAME and use it in an HTTP request. However, you might encounter a scenario where a template includes more than four protocols, and you need to export various response fields such as `subject_dn`, `ns`, `cname`, `header`, and so on. While you could achieve this by adding more dynamic extractors, this approach could clutter the template and introduce redundant logic, making it difficult to track and maintain all the variables.

To address this issue, multi-protocol execution supports template-scoped protocol responses. This means that all response fields from all protocols in a template are available in the template context with a protocol prefix.

Here's an example to illustrate this:

 Protocol | Response Field | Exported Variable |
 -------- | -------------- | ----------------- |
 ssl      | subject_cn     | ssl_subject_cn    |
 dns      | cname          | dns_cname         |
 http     | header         | http_header       |
 code     | response       | code_response     |

This is just an example, but it's important to note that the response fields of all protocols used in a multi-protocol template are exported.

**Example:**

```yaml
id: dns-ssl-http-proto-prefix

info:
  name: multi protocol request with response fields
  author: pdteam
  severity: info

dns:
  - name: "{{FQDN}}" # DNS Request
    type: cname

ssl:
  - address: "{{Hostname}}" # ssl request

http:
  - method: GET # http request
    path:
      - "{{BaseURL}}"

    matchers:
      - type: dsl
        dsl:
          - contains(http_body,'ProjectDiscovery.io') # check for http string
          - trim_suffix(dns_cname,'.ghost.io.') == 'projectdiscovery' # check for cname (extracted information from dns response)
          - ssl_subject_cn == 'blog.projectdiscovery.io'
        condition: and
```

To list all exported response fields write a multi protocol template and run it with `-v -svd` flag and it will print all exported response fields

Example:

```bash
nuclei -t multi-protocol-template.yaml -u scanme.sh -debug -svd
```

### Data Export across Protocols

If you are unfamiliar with dynamic extractors, we recommend reading the [dynamic extractor](https://docs.projectdiscovery.io/templates/reference/extractors#dynamic-extractor) section first.

Previously, Dynamic Extractors were only supported for specific protocols or workflows. However, with multi-protocol execution, dynamically extracted values are stored in the template context and can be used across all protocols.

**Example:**

```yaml
id: dns-http-template

info:
  name: dns + http takeover template
  author: pdteam
  severity: info

dns:
  - name: "{{FQDN}}" # dns request
    type: cname

    extractors:
      - type: dsl
        name: exported_cname
        dsl:
          - cname
        internal: true

http:
  - method: GET # http request
    path:
      - "{{BaseURL}}"

    matchers:
      - type: dsl
        dsl:
          - contains(body,'Domain not found') # check for http string
          - contains(exported_cname, 'github.io') # check for cname (extracted information from dns response)
        condition: and
```

## How Multi Protocol Works?

At this point we have seen how multi protocol templates look like and what are the features it brings to the table. Now let's see how multi protocol templates work and things to keep in mind while writing them.

- Multi Protocol Templates are executed in order of protocols defined in template.
- Protocols in multi protocol templates are executed in serial i.e one after another.
- Response fields of protocols are exported to template context as soon as that protocol is executed.
- Variables are scoped at template level and evaluated after each protocol execution.
- Multi protocol brings limited indirect support for preprocessing(using variables) and postprocessing(using dynamic extractors) for protocols.

## FAQ

**What Protocols are supported in Multi-Protocol Execution Mode?**

> There is no restriction around any protocol and any protocol available/implemented in nuclei engine can be used in multi protocol templates

**How many protocols can be used in Multi-Protocol Execution Mode?**

> There is no restriction around number of protocols but currently duplicated protocols are not supported i.e dns -> http -> ssl -> http. Please open a issue if you have a vulnerability/use-case that requires duplicated protocols

**What happens if a protocol fails?**

> Multi Protocol Execution follows exit on error policy i.e if protocol fails to execute then execution of remaining protocols is skipped and template execution is stopped

**How is multi protocol execution different from workflows?**

> Workflow as name suggest is a workflow that executes templates based on workflow file
>
> - Workflow does not contain actual logic of vulnerability but just a workflow that executes different templates
> - Workflow supports conditional execution of multiple templates
> - Workflow has limited supported for variables and dynamic extractors

To summarize workflow is a step higher than template and manages execution of templates based on workflow file

**Is multi protocol execution supported in nuclei v2?**

> No, Multi Protocol Execution is only supported in nuclei v3 and above
````

### `protocols\network-examples.md`

````markdown
---
title: "Network Protocol Examples"
description: "Examples of the Network Protocol Nuclei Templates"
---

## Basic Network Request

This template connects to a network service, sends some data and reads 4 bytes from the response. Matchers are run to identify valid response, which in this case is `PONG`.

```yaml
id: basic-network-request

info:
  name: Basic Network Request
  author: pdteam
  severity: info

tcp:
  - host:
      - "{{Hostname}}"
    inputs:
      - data: "PING\r\n"
    read-size: 4
    matchers:
      - type: word
        part: data
        words:
          - "PONG"
```

## TLS Network Request

Similar to the above template, but the connection to the service is done with TLS enabled.

```yaml
id: basic-tls-network-request

info:
  name: Basic TLS Network Request
  author: pdteam
  severity: info

tcp:
  - host:
      - "tls://{{Hostname}}"
    inputs:
      - data: "PING\r\n"
    read-size: 4
    matchers:
      - type: word
        part: data
        words:
          - "PONG"
```

## Hex Input Request

This template connects to a network service, sends some data encoded in hexadecimal to the server and reads 4 bytes from the response. Matchers are run to identify valid response, which in this case is `PONG`. The match words here are encoded in Hexadecimal, using `encoding: hex` option of matchers.

```yaml
id: hex-network-request

info:
  name: Hex Input Network Request
  author: pdteam
  severity: info

tcp:
  - host:
      - "{{Hostname}}"
    inputs:
      - data: "50494e47"
        type: hex
      - data: "\r\n"

    read-size: 4
    matchers:
      - type: word
        part: data
        encoding: hex
        words:
          - "504f4e47"
```

## Input Expressions

Inputs specified in network also support DSL Helper Expressions, so you can create your own complex inputs using variety of nuclei helper functions. The below template is an example of using `hex_decode` function to send decoded input over wire.

```yaml
id: input-expressions-mongodb-detect

info:
  name: Input Expression MongoDB Detection
  author: pd-team
  severity: info
  reference: https://github.com/orleven/Tentacle

tcp:
  - inputs:
      - data: "{{hex_decode('3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000')}}"
    host:
      - "{{Hostname}}"
    read-size: 2048
    matchers:
      - type: word
        words:
          - "logicalSessionTimeout"
          - "localTime"
```

## Multi-Step Requests

This last example is an RCE in proFTPd which, if vulnerable, allows placing arbitrary files in any directory on the server. The detection process involves a random string on each nuclei run using `{{randstr}}`, and sending multiple lines of FTP input to the vulnerable server. At the end, a successful match is detected with the presence of `Copy successful` in the response.

```yaml
id: CVE-2015-3306

info:
  name: ProFTPd RCE
  author: pd-team
  severity: high
  reference: https://github.com/t0kx/exploit-CVE-2015-3306
  tags: cve,cve2015,ftp,rce

tcp:
  - inputs:
      - data: "site cpfr /proc/self/cmdline\r\n"
        read: 1024
      - data: "site cpto /tmp/.{{randstr}}\r\n"
        read: 1024
      - data: "site cpfr /tmp/.{{randstr}}\r\n"
        read: 1024
      - data: "site cpto /var/www/html/{{randstr}}\r\n"
    host:
      - "{{Hostname}}"
    read-size: 1024
    matchers:
      - type: word
        words:
          - "Copy successful"
```
````

### `protocols\network.md`

````markdown
---
title: "Network Protocol"
description: "Learn about network requests with Nuclei"
icon: "network-wired"
iconType: "solid"
sidebarTitle: "Network"
---

Nuclei can act as an automatable **Netcat**, allowing users to send bytes across the wire and receive them, while providing matching and extracting capabilities on the response.

Network Requests start with a **network** block which specifies the start of the requests for the template.

```yaml
# Start the requests for the template right here
tcp:
```

### Inputs

First thing in the request is **inputs**. Inputs are the data that will be sent to the server, and optionally any data to read from the server.

At its most simple, just specify a string, and it will be sent across the network socket.

```yaml
# inputs is the list of inputs to send to the server
inputs:
  - data: "TEST\r\n"
```

You can also send hex encoded text that will be first decoded and the raw bytes will be sent to the server.

```yaml
inputs:
  - data: "50494e47"
    type: hex
  - data: "\r\n"
```

Helper function expressions can also be defined in input and will be first evaluated and then sent to the server. The last Hex Encoded example can be sent with helper functions this way

```yaml
inputs:
  - data: 'hex_decode("50494e47")\r\n'
```

One last thing that can be done with inputs is reading data from the socket. Specifying `read-size` with a non-zero value will do the trick. You can also assign the read data some name, so matching can be done on that part.

```yaml
inputs:
  - read-size: 8
```

Example with reading a number of bytes, and only matching on them.

```yaml
inputs:
  - read-size: 8
    name: prefix
...
matchers:
  - type: word
    part: prefix
    words:
      - "CAFEBABE"
```

Multiple steps can be chained together in sequence to do network reading / writing.

### Host

The next part of the requests is the **host** to connect to. Dynamic variables can be placed in the path to modify its value on runtime. Variables start with `{{` and end with `}}` and are case-sensitive.

1. **Hostname** - variable is replaced by the hostname provided on command line.

An example name value:

```yaml
host:
  - "{{Hostname}}"
```

Nuclei can also do TLS connection to the target server. Just add `tls://` as prefix before the **Hostname** and you're good to go.

```yaml
host:
  - "tls://{{Hostname}}"
```

If a port is specified in the host, the user supplied port is ignored and the template port takes precedence.

### Port

Starting from Nuclei v2.9.15, a new field called `port` has been introduced in network templates. This field allows users to specify the port separately instead of including it in the host field.

Previously, if you wanted to write a network template for an exploit targeting SSH, you would have to specify both the hostname and the port in the host field, like this:

```yaml
host:
  - "{{Hostname}}"
  - "{{Host}}:22"
```

In the above example, two network requests are sent: one to the port specified in the input/target, and another to the default SSH port (22).

The reason behind introducing the port field is to provide users with more flexibility when running network templates on both default and non-default ports. For example, if a user knows that the SSH service is running on a non-default port of 2222 (after performing a port scan with service discovery), they can simply run:

```bash
nuclei -u scanme.sh:2222 -id xyz-ssh-exploit
```

In this case, Nuclei will use port 2222 instead of the default port 22. If the user doesn't specify any port in the input, port 22 will be used by default. However, this approach may not be straightforward to understand and can generate warnings in logs since one request is expected to fail.

Another issue with the previous design of writing network templates is that requests can be sent to unexpected ports. For example, if a web service is running on port 8443 and the user runs:

```bash
nuclei -u scanme.sh:8443
```

In this case, `xyz-ssh-exploit` template will send one request to `scanme.sh:22` and another request to `scanme.sh:8443`, which may return unexpected responses and eventually result in errors. This is particularly problematic in automation scenarios.

To address these issues while maintaining the existing functionality, network templates can now be written in the following way:

```yaml
host:
  - "{{Hostname}}"
port: 22
```

In this new design, the functionality to run templates on non-standard ports will still exist, except for the default reserved ports (`80`, `443`, `8080`, `8443`, `8081`, `53`). Additionally, the list of default reserved ports can be customized by adding a new field called exclude-ports:

```yaml
exclude-ports: 80,443
```

When `exclude-ports` is used, the default reserved ports list will be overwritten. This means that if you want to run a network template on port `80`, you will have to explicitly specify it in the port field.

Starting from Nuclei v3.1.0 `port` field supports comma separated values and multi ports can be specified in the port field. For example, if you want to run a network template on port `5432` and `5433`, you can specify it in the port field like this:

```yaml
port: 5432,5433
```

In this case, Nuclei will first check if port is open from list and run template only on open ports

#### Matchers / Extractor Parts

Valid `part` values supported by **Network** protocol for Matchers / Extractor are -

| Value            | Description                         |
|------------------|-------------------------------------|
| request          | Network Request                     |
| data             | Final Data Read From Network Socket |
| raw / body / all | All Data received from Socket       |

### **Example Network Template**

The final example template file for a `hex` encoded input to detect MongoDB running on servers with working matchers is provided below.

```yaml
id: input-expressions-mongodb-detect

info:
  name: Input Expression MongoDB Detection
  author: pdteam
  severity: info
  reference: https://github.com/orleven/Tentacle

tcp:
  - inputs:
      - data: "{{hex_decode('3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000')}}"
    host:
      - "{{Hostname}}"
    port: 27017
    read-size: 2048
    matchers:
      - type: word
        words:
          - "logicalSessionTimeout"
          - "localTime"
```

<Tip>
More complete examples are provided [here](/templates/protocols/network-examples).
</Tip>
````

### `protocols\http\basic-http-examples.md`

````markdown
---
title: "Basic HTTP Examples"
sidebarTitle: "Examples"
---

## Basic Template

This template requests `/` path of URL and match string in the response.


```yaml
id: basic-example

info:
  name: Test HTTP Template
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "This is test matcher text"
```

## Multiple matchers

This template requests `/` path of URL and run multiple OR based matchers against response.


```yaml
id: http-multiple-matchers

info:
  name: Test HTTP Template
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: word
        name: php
        words:
          - "X-Powered-By: PHP"
          - "PHPSESSID"
        part: header

      - type: word
        name: node
        words:
          - "Server: NodeJS"
          - "X-Powered-By: nodejs"
        condition: or
        part: header

      - type: word
        name: python
        words:
          - "Python/2."
          - "Python/3."
        part: header
```

## Matchers with conditions

This template requests `/` path of URL and runs two matchers, one with AND conditions with string match in header and another matcher against response body.


```yaml
id: matchers-conditions

info:
  name: Test HTTP Template
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: word
        words:
          - "X-Powered-By: PHP"
          - "PHPSESSID"
        condition: and
        part: header

      - type: word
        words:
          - "PHP"
        part: body
```
## Multiple matcher conditions

This template requests `/` path of URL and runs two matchers with AND conditions, one with OR conditions with string match in header and another matcher against response body, both condition has to be true in order to match this template.

```yaml
id: multiple-matchers-conditions

info:
  name: Test HTTP Template
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: and
    matchers:

      - type: word
        words:
          - "X-Powered-By: PHP"
          - "PHPSESSID"
        condition: or
        part: header

      - type: word
        words:
          - PHP
        part: body
```

## Custom headers

This template requests `/` path of the URL as GET request with additional custom headers defined in the template.

```yaml
id: custom-headers

info:
  name: Test HTTP Template
  author: pdteam
  severity: info

http:
  - method: GET

    # Example of sending some headers to the servers

    headers:

      X-Client-IP: 127.0.0.1
      X-Remote-IP: 127.0.0.1
      X-Remote-Addr: 127.0.0.1
      X-Forwarded-For: 127.0.0.1
      X-Originating-IP: 127.0.0.1

    path:
      - "{{BaseURL}}/server-status"

    matchers:
      - type: word
        words:
          - Apache Server Status
          - Server Version
        condition: and
```

## POST requests

This template makes POST request to `/admin` endpoint with defined data as body parameter in the template.



```yaml
id: post-request

info:
  name: Test HTTP Template
  author: pdteam
  severity: info

http:
  - method: POST
    path:
      - "{{BaseURL}}/admin"

    body: 'admin=test'

    matchers:
      - type: word
        words:
          - Welcome Admin
```

## Time based Matcher

This template is example of DSL based duration matcher that returns `true` when the response time matched the defined duration, in this case 6 or more than 6 seconds.

```yaml
id: time-based-matcher

info:
  name: DSL based response time matcher
  author: pdteam
  severity: info

http:
  - raw:
      - |
        GET /slow HTTP/1.1

    matchers:
      - type: dsl
        dsl:
          - 'duration>=6'
```
````

### `protocols\http\basic-http.md`

````markdown
---
title: "Basic HTTP Protocol"
description: "Learn about using Basic HTTP with Nuclei"
sidebarTitle: "Basic HTTP"
---

Nuclei offers extensive support for various features related to HTTP protocol. Raw and Model based HTTP requests are supported, along with options Non-RFC client requests support too. Payloads can also be specified and raw requests can be transformed based on payload values along with many more capabilities that are shown later on this Page.

HTTP Requests start with a `request` block which specifies the start of the requests for the template.


```yaml
# Start the requests for the template right here
http:
```

## Method

Request method can be **GET**, **POST**, **PUT**, **DELETE**, etc. depending on the needs.

```yaml
# Method is the method for the request
method: GET
```

<Note>
**Redirects**

Redirection conditions can be specified per each template. By default, redirects are not followed. However, if desired, they can be enabled with `redirects: true` in request details. 10 redirects are followed at maximum by default which should be good enough for most use cases. More fine grained control can be exercised over number of redirects followed by using `max-redirects` field.
</Note>

An example of the usage:

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/login.php"
    redirects: true
    max-redirects: 3
```

<Warning>Currently redirects are defined per template, not per request.</Warning>


## Path

The next part of the requests is the **path** of the request path. Dynamic variables can be placed in the path to modify its behavior on runtime.

Variables start with `{{` and end with `}}` and are case-sensitive.

`{{BaseURL}}` - This will replace on runtime in the request by the input URL as specified in the target file.

`{{RootURL}}` - This will replace on runtime in the request by the root URL as specified in the target file.

`{{Hostname}}` - Hostname variable is replaced by the hostname including port of the target on runtime.

`{{Host}}` - This will replace on runtime in the request by the input host as specified in the target file.

`{{Port}}` - This will replace on runtime in the request by the input port as specified in the target file.

`{{Path}}` - This will replace on runtime in the request by the input path as specified in the target file.

`{{File}}` - This will replace on runtime in the request by the input filename as specified in the target file.

`{{Scheme}}` - This will replace on runtime in the request by protocol scheme as specified in the target file.

An example is provided below - https://example.com:443/foo/bar.php

| Variable       | Value                               |
|----------------|-------------------------------------|
| `{{BaseURL}}`  | https://example.com:443/foo/bar.php |
| `{{RootURL}}`  | https://example.com:443             |
| `{{Hostname}}` | example.com:443                     |
| `{{Host}}`     | example.com                         |
| `{{Port}}`     | 443                                 |
| `{{Path}}`     | /foo                                |
| `{{File}}`     | bar.php                             |
| `{{Scheme}}`   | https                               |


Some sample dynamic variable replacement examples:

```yaml
path: "{{BaseURL}}/.git/config"
# This path will be replaced on execution with BaseURL
# If BaseURL is set to  https://abc.com then the
# path will get replaced to the following: https://abc.com/.git/config
```

Multiple paths can also be specified in one request which will be requested for the target.

## Headers

Headers can also be specified to be sent along with the requests. Headers are placed in form of key/value pairs. An example header configuration looks like this:

```yaml
# headers contain the headers for the request
headers:
  # Custom user-agent header
  User-Agent: Some-Random-User-Agent
  # Custom request origin
  Origin: https://google.com
```

## Body

Body specifies a body to be sent along with the request. For instance:

```yaml
# Body is a string sent along with the request
body: "{\"some random JSON\"}"

# Body is a string sent along with the request
body: "admin=test"
```

## Session

To maintain a cookie-based browser-like session between multiple requests, cookies are reused by default. This is beneficial when you want to maintain a session between a series of requests to complete the exploit chain or to perform authenticated scans. If you need to disable this behavior, you can use the disable-cookie field.

```yaml
# disable-cookie accepts boolean input and false as default
disable-cookie: true
```

## Request Condition

Request condition allows checking for the condition between multiple requests for writing complex checks and exploits involving various HTTP requests to complete the exploit chain.

The functionality will be automatically enabled if DSL matchers/extractors contain numbers as a suffix with respective attributes.

For example, the attribute `status_code` will point to the effective status code of the current request/response pair in elaboration. Previous responses status codes are accessible by suffixing the attribute name with `_n`, where n is the n-th ordered request 1-based. So if the template has four requests and we are currently at number 3:
- `status_code`: will refer to the response code of request number 3
- `status_code_1` and `status_code_2` will refer to the response codes of the sequential responses number one and two

For example with `status_code_1`, `status_code_3`, and`body_2`:

```yaml
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 404 && status_code_2 == 200 && contains((body_2), 'secret_string')"
```

<Note>Request conditions might require more memory as all attributes of previous responses are kept in memory</Note>

## Example HTTP Template

The final template file for the `.git/config` file mentioned above is as follows:

```yaml
id: git-config

info:
  name: Git Config File
  author: Ice3man
  severity: medium
  description: Searches for the pattern /.git/config on passed URLs.

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
```


<Tip>
More complete examples are provided [here](/templates/protocols/http/basic-http-examples)
</Tip>
````

### `protocols\http\connection-tampering.md`

````markdown
---
title: "Connection Tampering"
description: "Learn more about using HTTP pipelining and connection pooling with Nuclei"
---

### Pipelining

HTTP Pipelining support has been added which allows multiple HTTP requests to be sent on the same connection inspired from [http-desync-attacks-request-smuggling-reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn).

Before running HTTP pipelining based templates, make sure the running target supports HTTP Pipeline connection, otherwise nuclei engine fallbacks to standard HTTP request engine.

If you want to confirm the given domain or list of subdomains supports HTTP Pipelining, [httpx](https://github.com/projectdiscovery/) has a flag `-pipeline` to do so.

An example configuring showing pipelining attributes of nuclei.

```yaml
    unsafe: true
    pipeline: true
    pipeline-concurrent-connections: 40
    pipeline-requests-per-connection: 25000
```

An example template demonstrating pipelining capabilities of nuclei has been provided below-

```yaml
id: pipeline-testing
info:
  name: pipeline testing
  author: pdteam
  severity: info

http:
  - raw:
      - |+
        GET /{{path}} HTTP/1.1
        Host: {{Hostname}}
        Referer: {{BaseURL}}

    attack: batteringram
    payloads:
      path: path_wordlist.txt

    unsafe: true
    pipeline: true
    pipeline-concurrent-connections: 40
    pipeline-requests-per-connection: 25000

    matchers:
      - type: status
        part: header
        status:
          - 200
```

### Connection pooling

While the earlier versions of nuclei did not do connection pooling, users can now configure templates to either use HTTP connection pooling or not. This allows for faster scanning based on requirement.

To enable connection pooling in the template, `threads` attribute can be defined with respective number of threads you wanted to use in the payloads sections.

`Connection: Close` header can not be used in HTTP connection pooling template, otherwise engine will fail and fallback to standard HTTP requests with pooling.

An example template using HTTP connection pooling-

```yaml
id: fuzzing-example
info:
  name: Connection pooling example
  author: pdteam
  severity: info

http:

  - raw:
      - |
        GET /protected HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('admin:§password§')}}

    attack: batteringram
    payloads:
      password: password.txt
    threads: 40

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "Unique string"
        part: body
```
````

### `protocols\http\fuzzing-examples.md`

````markdown
---
title: "Fuzzing Examples"
description: "Review some examples of fuzzing with Nuclei"
---

## Basic SSTI Template

A simple template to discover `{{<number>*<number>}}` type SSTI vulnerabilities.

```yaml
id: fuzz-reflection-ssti

info:
  name: Basic Reflection Potential SSTI Detection
  author: pdteam
  severity: low

variables:
  first: "{{rand_int(10000, 99999)}}"
  second: "{{rand_int(10000, 99999)}}"
  result: "{{to_number(first)*to_number(second)}}"

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      reflection:
        - '{{concat("{{", "§first§*§second§", "}}")}}'

    fuzzing:
      - part: query
        type: postfix
        mode: multiple
        fuzz:
          - "{{reflection}}"

    matchers:
      - type: word
        part: body
        words:
          - "{{result}}"
```
## Basic XSS Template

A simple template to discover XSS probe reflection in HTML pages.

```yaml
id: fuzz-reflection-xss

info:
  name: Basic Reflection Potential XSS Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      reflection:
        - "6842'\"><9967"

    stop-at-first-match: true
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{reflection}}"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "{{reflection}}"

      - type: word
        part: header
        words:
          - "text/html"
```

## Basic OpenRedirect Template

A simple template to discover open-redirects issues.

```yaml
id: fuzz-open-redirect

info:
  name: Basic Open Redirect Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      redirect:
        - "https://example.com"

    fuzzing:
      - part: query
        type: replace
        mode: single
        keys-regex:
          - "redirect.*"
        fuzz:
          - "{{redirect}}"

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "{{redirect}}"

      - type: status
        status:
          - 301
          - 302
          - 307
```

## Basic Path Based SQLi

A example template to discover path-based SQLi issues.

```yaml
http:
    # pre-condition to determine if the template should be executed
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "POST"'       # only run if method is POST
          - 'contains(path,"reset")' # only run if path contains reset word
        condition: and

    # fuzzing rules
    fuzzing:
      - part: header # This rule will be applied to the header
        type: replace # replace the type of rule (i.e., existing values will be replaced with payload)
        mode: multiple # multiple mode (i.e., all existing values will be replaced/used at once)
        fuzz:
          X-Forwarded-For: "{{domain}}"  # here {{domain}} is attacker-controlled server
          X-Forwarded-Host: "{{domain}}"
          Forwarded: "{{domain}}"
          X-Real-IP: "{{domain}}"
          X-Original-URL: "{{domain}}"
          X-Rewrite-URL: "{{domain}}"
          Host: "{{domain}}"
```


## Basic Host Header Injection

A simple template to discover host header injection issues.

```yaml
http:
    # pre-condition to determine if the template should be executed
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "POST"'       # only run if method is POST
          - 'contains(path,"reset")' # only run if path contains reset word
        condition: and

    # fuzzing rules
    fuzzing:
      - part: header # This rule will be applied to the header
        type: replace # replace the type of rule (i.e., existing values will be replaced with payload)
        mode: multiple # multiple mode (i.e., all existing values will be replaced/used at once)
        fuzz:
          X-Forwarded-For: "{{domain}}"  # here {{domain}} is attacker-controlled server
          X-Forwarded-Host: "{{domain}}"
          Forwarded: "{{domain}}"
          X-Real-IP: "{{domain}}"
          X-Original-URL: "{{domain}}"
          X-Rewrite-URL: "{{domain}}"
          Host: "{{domain}}"
```


## Blind SSRF OOB Detection

A simple template to detect Blind SSRF in known-parameters using interactsh with HTTP fuzzing.

```yaml
id: fuzz-ssrf

info:
  name: Basic Blind SSRF Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run on GET URLs

    payloads:
      redirect:
        - "{{interactsh-url}}"

    fuzzing:
      - part: query
        type: replace
        mode: single
        keys:
          - "dest"
          - "redirect"
          - "uri"
          - "path"
          - "continue"
          - "url"
          - "window"
          - "next"
          - "data"
          - "reference"
          - "site"
          - "html"
          - "val"
          - "validate"
          - "domain"
          - "callback"
          - "return"
          - "page"
          - "feed"
          - "host"
          - "port"
          - "to"
          - "out"
          - "view"
          - "dir"
          - "show"
          - "navigation"
          - "open"
        fuzz:
          - "https://{{redirect}}"

    matchers:
      - type: word
        part: interactsh_protocol  # Confirms the DNS Interaction
        words:
          - "http"
```

## Blind CMDi OOB based detection

A simple template to detect blind CMDI using interactsh

```yaml
id: fuzz-cmdi

info:
  name: Basic Blind CMDI Detection
  author: pdteam
  severity: low

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    payloads:
      redirect:
        - "{{interactsh-url}}"
    fuzzing:
        fuzz:
          - "nslookup {{redirect}}"
    matchers:
      - type: word
        part: interactsh_protocol  # Confirms the DNS Interaction
        words:
          - "dns"
```
````

### `protocols\http\fuzzing-overview.md`

````markdown
---
title: "Fuzzing Overview"
description: "Learn about fuzzing HTTP requests with Nuclei"
sidebarTitle: "Overview"
---

Nuclei supports fuzzing of HTTP requests based on rules defined in the `fuzzing` section of the HTTP request. This allows creating templates for generic Web Application vulnerabilities like SQLi, SSRF, CMDi, etc without any information of the target like a classic web fuzzer. We call this concept as **Fuzzing for Unknown Vulnerabilities**.

## pre-condition

More often than not, we want to only attempt fuzzing on those requests where it makes sense. For example,

- Fuzz Body When Body is Present
- Ignore PreFlight and CONNECT requests

and so on. With Nuclei v3.2.4 we have introduced a new `pre-condition` section which contains conditions when the fuzzing template should be executed.

pre-condition can be considered a twin of [matchers](/templates/reference/matchers) in nuclei. They support all matcher types, including DSL, and the only difference is that this serves a different purpose.

For example, to only execute template on POST request with some body, you can use the following filter.

```yaml
- pre-condition:
    - type: dsl
      dsl:
        - method == POST
        - len(body) > 0
      condition: and
```

<Note>Currently, Only request data like header, host, input, method, path, etc is available, but soon, response data will be available once the support for loading the response along with the request is added. </Note>


<Tip>
 When writing/executing a template, you can use the -v -svd flags to see all variables available in filters before applying the filter.
</Tip>


### Part

Part specifies what part of the request should be fuzzed based on the specified rules. Available options for this parameter are -

**query** (`default`) - fuzz query parameters for URL

```yaml
fuzzing:
  - part: query # fuzz parameters in URL query
```

**path** - fuzz path parameters for requests

```yaml
fuzzing:
  - part: path # fuzz path parameters
```

**header** - fuzz header parameters for requests

```yaml
fuzzing:
  - part: header # fuzz headers
```

**cookie** - fuzz cookie parameters for requests

```yaml
fuzzing:
  - part: cookie # fuzz cookies
```

**body** - fuzz body parameters for requests

```yaml
fuzzing:
  - part: body # fuzz parameters in body
```


### Type

Type specifies the type of replacement to perform for the fuzzing rule value. Available options for this parameter are -

1. **replace** (`default`) - replace the value with payload
2. **prefix** - prefix the value with payload
3. **postfix** - postfix the value with payload
4. **infix** - infix the value with payload (place in between)
5. **replace-regex** - replace the value with payload using regex

```yaml
fuzzing:
  - part: query
    type: postfix # Fuzz query and postfix payload to params
```


### Key-Value Abstraction

In a HTTP request, there are various parts like query, path, headers, cookies, and body and each part has different in various formats. For example, the query part is a key-value pair, the path part is a list of values, the body part can be a JSON, XML, or form-data.

To effectively abstract these parts and allow them to be fuzzed, Nuclei exposes these values as `key` and `value` pairs. This allows users to fuzz based on the key or value of the request part.

For example, Below sample HTTP request can be abstracted as key-value pairs as shown below.

```http
POST /reset-password?token=x0x0x0&source=app HTTP/1.1
Host: 127.0.0.1:8082
User-Agent: Go-http-client/1.1
Cookie: PHPSESSID=1234567890
Content-Length: 23
Content-Type: application/json
Accept-Encoding: gzip
Connection: close

{"password":"12345678"}
```

- **`part: Query`**

| key    | value  |
| ------ | ------ |
| token  | x0x0x0 |
| source | app    |

- **`part: Path`**

| key   | value           |
| ----- | --------------- |
| value | /reset-password |

- **`part: Header`**

| key             | value              |
| --------------- | ------------------ |
| Host            | 127.0.0.1:8082     |
| User-Agent      | Go-http-client/1.1 |
| Content-Length  | 23                 |
| Content-Type    | application/json   |
| Accept-Encoding | gzip               |
| Connection      | close              |

- **`part: Cookie`**

| key       | value      |
| --------- | ---------- |
| PHPSESSID | 1234567890 |

- **`part: Body`**

| key      | value    |
| -------- | -------- |
| password | 12345678 |


**Note:** XML, JSON, Form, Multipart-FormData will be in kv format, but if the Body is binary or in any other format, the entire Body will be represented as a single key-value pair with key as `value` and value as the entire Body.

| key   | value                            |
| ----- | -------------------------------- |
| value | "\\x08\\x96\\x01\\x12\\x07\\x74" |


This abstraction really levels up the game since you only need to write a single rule for the Body, and it will be applied to all formats. For example, if you check for SQLi in body values, a single rule will work on all formats, i.e., JSON, XML, Form, Multipart-FormData, etc.

### Mode

Mode specifies the mode in which to perform the replacements. Available modes are -

1. **multiple** (`default`) - replace all values at once
2. **single** - replace one value at a time

```yaml
fuzzing:
  - part: query
    type: postfix
    mode: multiple # Fuzz query postfixing payloads to all parameters at once
```

> **Note**: default values are set/used when other options are not defined.

### Component Data Filtering

Multiple filters are supported to restrict the scope of fuzzing to only interesting parameter keys and values. Nuclei HTTP Fuzzing engine converts request parts into Keys and Values which then can be filtered by their related options.

The following filter fields are supported -

1. **keys** - list of parameter names to fuzz (exact match)
2. **keys-regex** - list of parameter regex to fuzz
3. **values** - list of value regex to fuzz

These filters can be used in combination to run highly targeted fuzzing based on the parameter input. A few examples of such filtering are provided below.

```yaml
# fuzzing command injection based on parameter name value
fuzzing:
  - part: query
    type: replace
    mode: single
    keys:
      - "daemon"
      - "upload"
      - "dir"
      - "execute"
      - "download"
      - "log"
      - "ip"
      - "cli"
      - "cmd"
```

```yaml
# fuzzing openredirects based on parameter name regex
fuzzing:
  - part: query
    type: replace
    mode: single
    keys-regex:
      - "redirect.*"
```

```yaml
# fuzzing ssrf based on parameter value regex
fuzzing:
  - part: query
    type: replace
    mode: single
    values:
      - "https?://.*"
```

### Fuzz

Fuzz specifies the values to replace with a `type` for a parameter. It supports payloads, DSL functions, etc and allows users to fully utilize the existing nuclei feature-set for fuzzing purposes.

```yaml
# fuzz section for xss fuzzing with stop-at-first-match
payloads:
  reflection:
    - "6842'\"><9967"
stop-at-first-match: true
fuzzing:
  - part: query
    type: postfix
    mode: single
    fuzz:
      - "{{reflection}}"
```

```yaml
# using interactsh-url placeholder for oob testing
payloads:
  redirect:
    - "{{interactsh-url}}"
fuzzing:
  - part: query
    type: replace
    mode: single
    keys:
      - "dest"
      - "redirect"
      - "uri"
    fuzz:
      - "https://{{redirect}}"
```

```yaml
# using template-level variables for SSTI testing
variables:
  first: "{{rand_int(10000, 99999)}}"
  second: "{{rand_int(10000, 99999)}}"
  result: "{{to_number(first)*to_number(second)}}"

http:
    ...
    payloads:
      reflection:
        - '{{concat("{{", "§first§*§second§", "}}")}}'
    fuzzing:
      - part: query
        type: postfix
        mode: multiple
        fuzz:
          - "{{reflection}}"
```

## Example **Fuzzing** template

An example sample template for fuzzing XSS vulnerabilities is provided below.

```yaml
id: fuzz-reflection-xss

info:
  name: Basic Reflection Potential XSS Detection
  author: pdteam
  severity: low

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'       # only run if method is GET
    payloads:
      reflection:
        - "6842'\"><9967"

    stop-at-first-match: true
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{reflection}}"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "{{reflection}}"

      - type: word
        part: header
        words:
          - "text/html"
```

<Tip>
More complete examples are provided [here](/templates/protocols/http/fuzzing-examples)
</Tip>
````

### `protocols\http\http-payloads-examples.md`

````markdown
---
title: "HTTP Payloads Examples"
description: "Review some HTTP payload examples for Nuclei"
sidebarTitle: "Payloads Examples"
---

## HTTP Intruder Bruteforcing

This template makes a defined POST request in RAW format along with in template defined payloads running `clusterbomb` intruder and checking for string match against response.


```yaml
id: multiple-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

# HTTP Intruder bruteforcing with in template payload support.

http:

  - raw:
      - |
        POST /?username=§username§&paramb=§password§ HTTP/1.1
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5)
        Host: {{Hostname}}
        another_header: {{base64('§password§')}}
        Accept: */*

        body=test

    payloads:
      username:
        - admin

      password:
        - admin
        - guest
        - password
        - test
        - 12345
        - 123456

    attack: clusterbomb # Available: batteringram,pitchfork,clusterbomb

    matchers:
      - type: word
        words:
          - "Test is test matcher text"
```

## BruteForcing multiple requests

This template makes a defined POST request in RAW format along with wordlist based payloads running `clusterbomb` intruder and checking for string match against response.

```yaml
id: multiple-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

http:

  - raw:
      - |
        POST /?param_a=§param_a§&paramb=§param_b§ HTTP/1.1
        User-Agent: §param_a§
        Host: {{Hostname}}
        another_header: {{base64('§param_b§')}}
        Accept: */*

        admin=test

      - |
        DELETE / HTTP/1.1
        User-Agent: nuclei
        Host: {{Hostname}}

        {{sha256('§param_a§')}}

      - |
        PUT / HTTP/1.1
        Host: {{Hostname}}

        {{html_escape('§param_a§')}} + {{hex_encode('§param_b§'))}}

    attack: clusterbomb # Available types: batteringram,pitchfork,clusterbomb
    payloads:
      param_a: payloads/prams.txt
      param_b: payloads/paths.txt

    matchers:
      - type: word
        words:
          - "Test is test matcher text"
```

## Authenticated Bruteforcing

This template makes a subsequent HTTP requests with defined requests maintaining sessions between each request and checking for string match against response.

```yaml
id: multiple-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}

      - |
        POST /testing HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}

        testing=parameter

    cookie-reuse: true # Cookie-reuse maintain the session between all request like browser.
    matchers:
      - type: word
        words:
          - "Test is test matcher text"
```
````

### `protocols\http\http-payloads.md`

````markdown
---
title: "HTTP Payloads"
description: "Learn about bruteforcing HTTP requests using payloads with Nuclei"
---

## Overview

Nuclei engine supports brute forcing any value/component of HTTP Requests using payloads module, that allows to run various type of payloads in multiple format, It's possible to define placeholders with simple keywords (or using brackets `{{helper_function(variable)}}` in case mutator functions are needed), and perform **batteringram**, **pitchfork** and **clusterbomb** attacks.

The **wordlist** for these attacks needs to be defined during the request definition under the Payload field, with a name matching the keyword, Nuclei supports both file based and in template wordlist support and Finally all DSL functionalities are fully available and supported, and can be used to manipulate the final values.

Payloads are defined using variable name and can be referenced in the request in between `{{ }}` marker.

### Difference between **HTTP Payloads** and **HTTP Fuzzing**

While both may sound similar, the major difference between  **Fuzzing** and **Payloads/BruteForce** is that Fuzzing is a superset of Payloads/BruteForce and has extra features related to finding Unknown Vulnerabilities while Payloads is just plain brute forcing of values with a given attack type and set of payloads.


## Examples

An example of the using payloads with local wordlist:

```yaml
# HTTP Intruder fuzzing using local wordlist.

payloads:
  paths: params.txt
  header: local.txt
```

An example of the using payloads with in template wordlist support:

```yaml
# HTTP Intruder fuzzing using in template wordlist.

payloads:
  password:
    - admin
    - guest
    - password
```

**Note:** be careful while selecting attack type, as unexpected input will break the template.

For example, if you used `clusterbomb` or `pitchfork` as attack type and defined only one variable in the payload section, template will fail to compile, as `clusterbomb` or `pitchfork` expect more than one variable to use in the template.

## Attack mode

Nuclei engine supports multiple attack types, including `batteringram` as default type which generally used to fuzz single parameter, `clusterbomb` and `pitchfork` for fuzzing multiple parameters which works same as classical burp intruder.

| **Type**    | batteringram | pitchfork | clusterbomb |
| ----------- | ------------ | --------- | ----------- |
| **Support** | ✔            | ✔         | ✔           |

### batteringram

The battering ram attack type places the same payload value in all positions. It uses only one payload set. It loops through the payload set and replaces all positions with the payload value.


### pitchfork
The pitchfork attack type uses one payload set for each position. It places the first payload in the first position, the second payload in the second position, and so on.

It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

### clusterbomb
The cluster bomb attack tries all different combinations of payloads. It still puts the first payload in the first position, and the second payload in the second position. But when it loops through the payload sets, it tries all combinations.

It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.

This attack type is useful for a brute-force attack. Load a list of commonly used usernames in the first payload set, and a list of commonly used passwords in the second payload set. The cluster bomb attack will then try all combinations.

More details [here](https://www.sjoerdlangkemper.nl/2017/08/02/burp-intruder-attack-types/).

## Attack Mode Example

An example of the using `clusterbomb` attack to fuzz.

```yaml
http:
  - raw:
      - |
        POST /?file={{path}} HTTP/1.1
        User-Agent: {{header}}
        Host: {{Hostname}}

    attack: clusterbomb # Defining HTTP fuzz attack type
    payloads:
      path: helpers/wordlists/prams.txt
      header: helpers/wordlists/header.txt
```
````

### `protocols\http\http-race-condition-examples.md`

````markdown
---
title: "HTTP Race Condition Examples"
description: "Review some race conditions examples with Nuclei"
---

## Race condition testing with single POST request.

This template makes a defined POST request in RAW format to `/coupons` endpoint, as the `race_count`is defined as `10`, this will make 10 requests at same time by holding last bytes for all the requests which sent together for all requests synchronizing the send event.

You can also define the matcher as any other template for the expected output which helps to identify if the race condition exploit worked or not.


```yaml
id: race-condition-testing

info:
  name: Race Condition testing
  author: pdteam
  severity: info

http:
  - raw:
      - |
        POST /coupons HTTP/1.1
        Host: {{Hostname}}
        Pragma: no-cache
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
        Cookie: user_session=42332423342987567896

        promo_code=20OFF

    race: true
    race_count: 10

    matchers:
      - type: status
        part: header
        status:
          - 200
```

## Race condition testing with multiple requests.

This template makes the defined and multiple POST requests in RAW format with `threads` sets to `5`, `threads` can be utilized in race condition templates when multiple requests needs to be sent to exploit the race condition, `threads` number should be same as the number of you are making with template and not needed if you're only making single request.

```yaml
id: race-condition-testing

info:
  name: Race condition testing with multiple requests
  author: pdteam
  severity: info

http:
  - raw:
      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=1

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=2

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=3

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=4

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=5

    threads: 5
    race: true

    matchers:
      - type: status
        status:
          - 200
```
````

### `protocols\http\http-smuggling-examples.md`

````markdown
---
title: "HTTP Smuggling Examples"
description: "Review some HTTP smuggling examples"
---

## Basic CL.TE

This template makes a defined malformed HTTP POST requests using rawhttp library and checking for string match against response.

```yaml
id: CL-TE-http-smuggling

info:
  name: HTTP request smuggling, basic CL.TE vulnerability
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked

      0

      G
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked

      0

      G

    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, "Unrecognized method GPOST")'
```

## Basic TE.CL

This template makes a defined malformed HTTP POST requests using rawhttp library and checking for string match against response.


```yaml
id: TE-CL-http-smuggling

info:
  name: HTTP request smuggling, basic TE.CL vulnerability
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-length: 4
      Transfer-Encoding: chunked

      5c
      GPOST / HTTP/1.1
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 15

      x=1
      0
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-length: 4
      Transfer-Encoding: chunked

      5c
      GPOST / HTTP/1.1
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 15

      x=1
      0

    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, "Unrecognized method GPOST")'
```

## Frontend bypass CL.TE

This template makes a defined malformed HTTP POST requests using rawhttp library and checking for string match against response.


```yaml
id: smuggling-bypass-front-end-controls-cl-te

info:
  name: HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 116
      Transfer-Encoding: chunked

      0

      GET /admin HTTP/1.1
      Host: localhost
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 10

      x=
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 116
      Transfer-Encoding: chunked

      0

      GET /admin HTTP/1.1
      Host: localhost
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 10

      x=

    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, "/admin/delete?username=carlos")'
```

## Differential responses based CL.TE

This template makes a defined malformed HTTP POST requests using rawhttp library and checking for string match against response.


```yaml
id: confirming-cl-te-via-differential-responses-http-smuggling

info:
  name: HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 35
      Transfer-Encoding: chunked

      0

      GET /404 HTTP/1.1
      X-Ignore: X
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 35
      Transfer-Encoding: chunked

      0

      GET /404 HTTP/1.1
      X-Ignore: X

    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code==404'
```

## Differential responses based TE.CL

This template makes a defined malformed HTTP POST requests using rawhttp library and checking for string match against response.


```yaml
id: confirming-te-cl-via-differential-responses-http-smuggling

info:
  name: HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-length: 4
      Transfer-Encoding: chunked

      5e
      POST /404 HTTP/1.1
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 15

      x=1
      0
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/x-www-form-urlencoded
      Content-length: 4
      Transfer-Encoding: chunked

      5e
      POST /404 HTTP/1.1
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 15

      x=1
      0

    unsafe: true
    matchers:
      - type: dsl
        dsl:
          - 'status_code==404'
```
````

### `protocols\http\race-conditions.md`

````markdown
---
title: "Race Conditions"
description: "Learn about using race conditions with Nuclei"
---

Race Conditions are another class of bugs not easily automated via traditional tooling. Burp Suite introduced a Gate mechanism to Turbo Intruder where all the bytes for all the requests are sent expect the last one at once which is only sent together for all requests synchronizing the send event.

We have implemented **Gate** mechanism in nuclei engine and allow them run via templates which makes the testing for this specific bug class simple and portable.

To enable race condition check within template, `race` attribute can be set to `true` and `race_count` defines the number of simultaneous request you want to initiate.

Below is an example template where the same request is repeated for 10 times using the gate logic.

```yaml
id: race-condition-testing

info:
  name: Race condition testing
  author: pdteam
  severity: info

http:
  - raw:
      - |
        POST /coupons HTTP/1.1
        Host: {{Hostname}}

        promo_code=20OFF

    race: true
    race_count: 10

    matchers:
      - type: status
        part: header
        status:
          - 200
```

You can simply replace the `POST` request with any suspected vulnerable request and change the `race_count` as per your need, and it's ready to run.

```bash
nuclei -t race.yaml -target https://api.target.com
```

**Multi request race condition testing**

For the scenario when multiple requests needs to be sent in order to exploit the race condition, we can make use of threads.

```yaml
    threads: 5
    race: true
```

`threads` is a total number of request you wanted make with the template to perform race condition testing.


Below is an example template where multiple (5) unique request will be sent at the same time using the gate logic.

```yaml
id: multi-request-race

info:
  name: Race condition testing with multiple requests
  author: pd-team
  severity: info

http:
  - raw:
      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=1

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=2

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=3

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=4

      - |
        POST / HTTP/1.1
        Pragma: no-cache
        Host: {{Hostname}}
        Cache-Control: no-cache, no-transform
        User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0

        id=5

    threads: 5
    race: true
```

<Tip>
More complete examples are provided [here](/templates/protocols/http/http-race-condition-examples)
</Tip>
````

### `protocols\http\raw-http-examples.md`

````markdown
---
title: "Raw HTTP Examples"
---

## Basic template

This template makes GET request to `/` path in RAW format and checking for string match against response.


```yaml
id: basic-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}
        Connection: close
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko)
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
        Accept-Language: en-US,en;q=0.9

    matchers:
      - type: word
        words:
          - "Test is test matcher text"
```

## Multiple RAW request

This template makes GET and POST request sequentially in RAW format and checking for string match against response.


```yaml
id: multiple-raw-example
info:
  name: Test RAW Template
  author: pdteam
  severity: info

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}
        Connection: close
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko)
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
        Accept-Language: en-US,en;q=0.9

      - |
        POST /testing HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}
        Connection: close
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko)
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
        Accept-Language: en-US,en;q=0.9

        testing=parameter

    matchers:
      - type: word
        words:
          - "Test is test matcher text"
```
````

### `protocols\http\raw-http.md`

````markdown
---
title: "Raw HTTP Protocol"
description: "Learn about using Raw HTTP with Nuclei"
sidebarTitle: "Raw HTTP"
---

Another way to create request is using raw requests which comes with more flexibility and support of DSL helper functions, like the following ones (as of now it's suggested to leave the `Host` header as in the example with the variable `{{Hostname}}`), All the Matcher, Extractor capabilities can be used with RAW requests in same the way described above.

```yaml
http:
  - raw:
    - |
        POST /path2/ HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        a=test&b=pd
```
Requests can be fine-tuned to perform the exact tasks as desired. Nuclei requests are fully configurable meaning you can configure and define each and every single thing about the requests that will be sent to the target servers.

RAW request format also supports [various helper functions](/templates/reference/helper-functions/) letting us do run time manipulation with input. An example of the using a helper function in the header.

```yaml
    - raw:
      - |
        GET /manager/html HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('username:password')}} # Helper function to encode input at run time.
```

To make a request to the URL specified as input without any additional tampering, a blank Request URI can be used as specified below which will make the request to user specified input.

```yaml
    - raw:
      - |
        GET HTTP/1.1
        Host: {{Hostname}}
```

<Tip>
More complete examples are provided [here](/templates/protocols/http/raw-http-examples)
</Tip>
````

### `protocols\http\request-tampering.md`

````markdown
---
title: 'Request Tampering'
description: "Learn about request tampering in HTTP with Nuclei"
---

## Requests Annotation

Request inline annotations allow performing per request properties/behavior override. They are very similar to python/java class annotations and must be put on the request just before the RFC line. Currently, only the following overrides are supported:

- `@Host:` which overrides the real target of the request (usually the host/ip provided as input). It supports syntax with ip/domain, port, and scheme, for example: `domain.tld`, `domain.tld:port`, `http://domain.tld:port`
- `@tls-sni:` which overrides the SNI Name of the TLS request (usually the hostname provided as input). It supports any literals. The special value `request.host` uses the `Host` header and `interactsh-url` uses an interactsh generated URL.
- `@timeout:` which overrides the timeout for the request to a custom duration. It supports durations formatted as string. If no duration is specified, the default Timeout flag value is used.

The following example shows the annotations within a request:

```yaml
- |
  @Host: https://projectdiscovery.io:443
  POST / HTTP/1.1
  Pragma: no-cache
  Host: {{Hostname}}
  Cache-Control: no-cache, no-transform
  User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
```
This is particularly useful, for example, in the case of templates with multiple requests, where one request after the initial one needs to be performed to a specific host (for example, to check an API validity):

```yaml
http:
  - raw:
      # this request will be sent to {{Hostname}} to get the token
      - |
        GET /getkey HTTP/1.1
        Host: {{Hostname}}

      # This request will be sent instead to https://api.target.com:443 to verify the token validity
      - |
        @Host: https://api.target.com:443
        GET /api/key={{token}} HTTP/1.1
        Host: api.target.com:443

    extractors:
      - type: regex
        name: token
        part: body
        regex:
          # random extractor of strings between prefix and suffix
          - 'prefix(.*)suffix'

    matchers:
      - type: word
        part: body
        words:
          - valid token
```

Example of a custom `timeout` annotations -

```yaml
- |
  @timeout: 25s
  POST /conf_mail.php HTTP/1.1
  Host: {{Hostname}}
  Content-Type: application/x-www-form-urlencoded

  mail_address=%3B{{cmd}}%3B&button=%83%81%81%5B%83%8B%91%97%90M
```

Example of `sni` annotation with `interactsh-url` -

```yaml
- |
  @tls-sni: interactsh-url
  POST /conf_mail.php HTTP/1.1
  Host: {{Hostname}}
  Content-Type: application/x-www-form-urlencoded

  mail_address=%3B{{cmd}}%3B&button=%83%81%81%5B%83%8B%91%97%90M
```

## Smuggling

HTTP Smuggling is a class of Web-Attacks recently made popular by [Portswigger’s Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) into the topic. For an in-depth overview, please visit the article linked above.

In the open source space, detecting http smuggling is difficult particularly due to the requests for detection being malformed by nature. Nuclei is able to reliably detect HTTP Smuggling vulnerabilities utilising the [rawhttp](https://github.com/projectdiscovery/rawhttp) engine.

The most basic example of an HTTP Smuggling vulnerability is CL.TE Smuggling. An example template to detect a CE.TL HTTP Smuggling vulnerability is provided below using the `unsafe: true` attribute for rawhttp based requests.

```yaml
id: CL-TE-http-smuggling

info:
  name: HTTP request smuggling, basic CL.TE vulnerability
  author: pdteam
  severity: info
  reference: https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te

http:
  - raw:
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked

      0

      G
    - |+
      POST / HTTP/1.1
      Host: {{Hostname}}
      Connection: keep-alive
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 6
      Transfer-Encoding: chunked

      0

      G

    unsafe: true
    matchers:
      - type: word
        words:
          - 'Unrecognized method GPOST'
```

<Tip>
More complete examples are provided [here](/templates/protocols/http/http-smuggling-examples)
</Tip>
````

### `protocols\http\unsafe-http.md`

````markdown
---
title: "Unsafe HTTP"
description: "Learn about using rawhttp or unsafe HTTP with Nuclei"

---

Nuclei supports [rawhttp](https://github.com/projectdiscovery/rawhttp) for complete request control and customization allowing **any kind of malformed requests** for issues like HTTP request smuggling, Host header injection, CRLF with malformed characters and more.

**rawhttp** library is disabled by default and can be enabled by including `unsafe: true` in the request block.

Here is an example of HTTP request smuggling detection template using `rawhttp`.

```yaml
http:
  - raw:
    - |+
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 150
        Transfer-Encoding: chunked

        0

        GET /post?postId=5 HTTP/1.1
        User-Agent: a"/><script>alert(1)</script>
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 5

        x=1
    - |+
        GET /post?postId=5 HTTP/1.1
        Host: {{Hostname}}

    unsafe: true # Enables rawhttp client
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, "<script>alert(1)</script>")'
```
````

### `protocols\http\value-sharing.md`

````markdown
---
title: "Value Sharing"
description: "Learn about sharing values between HTTP requests in the HTTP template."
---

## HTTP Value Sharing

In Nuclei, It is possible to extract value from one HTTP request and share/reuse it in another HTTP request. This has various use-cases like login, CSRF tokens and other complex.

This concept of value sharing is possible using [Dynamic Extractors](/templates/reference/extractors#dynamic-extractor). Here's a simple example demonstrating value sharing between HTTP requests.

This template makes a subsequent HTTP requests maintaining sessions between each request, dynamically extracting data from one request and reusing them into another request using variable name and checking for string match against response.

```yaml
id: CVE-2020-8193

info:
  name: Citrix unauthenticated LFI
  author: pdteam
  severity: high
  reference: https://github.com/jas502n/CVE-2020-8193

http:
  - raw:
      - |
        POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
        Content-Type: application/xml
        X-NITRO-USER: xpyZxwy6
        X-NITRO-PASS: xWXHUJ56

        <appfwprofile><login></login></appfwprofile>

      - |
        GET /menu/ss?sid=nsroot&username=nsroot&force_setup=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close

      - |
        GET /menu/neo HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close

      - |
        GET /menu/stc HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close

      - |
        POST /pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close
        Content-Type: application/xml
        X-NITRO-USER: oY39DXzQ
        X-NITRO-PASS: ZuU9Y9c1
        rand_key: §randkey§

        <appfwprofile><login></login></appfwprofile>

      - |
        POST /rapi/filedownload?filter=path:%2Fetc%2Fpasswd HTTP/1.1
        Host: {{Hostname}}
        User-Agent: python-requests/2.24.0
        Accept: */*
        Connection: close
        Content-Type: application/xml
        X-NITRO-USER: oY39DXzQ
        X-NITRO-PASS: ZuU9Y9c1
        rand_key: §randkey§

        <clipermission></clipermission>

    cookie-reuse: true # Using cookie-reuse to maintain session between each request, same as browser.

    extractors:
      - type: regex
        name: randkey # Variable name
        part: body
        internal: true
        regex:
          - "(?m)[0-9]{3,10}\\.[0-9]+"

    matchers:
      - type: regex
        regex:
          - "root:[x*]:0:0:"
        part: body
```
````

### `protocols\javascript\introduction.md`

````markdown
---
title: "JavaScript Protocol Introduction"
description: "Learn more about using JavaScript with Nuclei v3"
sidebarTitle: "Introduction"
---

## Introduction

Nuclei and the ProjectDiscovery community thrive on the ability to write exploits/checks in a fast and simple YAML format. We work consistently to improve our **Nuclei templates** to encourage those as the standard for writing security checks. We understand the limitations and are always working to address those, while we work on expanding our capabilities.

 Nuclei currently supports writing templates for complex HTTP, DNS, SSL protocol exploits/checks through a powerful and easy to use DSL in the Nuclei engine. However, we understand the current support may not be enough for addressing vulnerabilities across all protocols and in non-remote domains of security like local privilege escalation checks, kernel etc.

To address this, Nuclei v3 includes an embedded runtime for JavaScript that is tailored for **Nuclei** with the help of **[Goja](https://github.com/dop251/goja)**.

## Features

**Support for provider or driver-specific exploits:**

Some vulnerabilities are specific to software or a driver. For example, a Redis buffer overflow exploit, an exploit of specific VPN software, or exploits that are not part of the Internet Engineering Task Force (IETF) standard protocols.

Since these are not standard protocols they are not typically added to Nuclei. Detection for these types of exploits cannot be written using a 'network' protocol.
They are often very complex to write and detection for these exploits can be written by exposing the required library in Nuclei (if not already present). We now provide support for writing detection of these types of exploits with JavaScript.

**Non-network checks:**

Security is not limited to network exploits. Nuclei provides support for security beyond network issues like:

 - Local privilege escalation checks
 - Kernel exploits
 - Account misconfigurations
 - System misconfigurations

**Complex network protocol exploits:**

Some network exploits are very complex to write due to nature of the protocol or exploit itself. For example [CVE-2020-0796](https://nvd.nist.gov/vuln/detail/cve-2020-0796) requires you to manually construct a packet.
Detection for these exploits is usually written in Python but now can be written in JavaScript.

**Multi-step exploits:**

LDAP or Kerberos exploits usually involve a multi-step process of authentication and are difficult to write in YAML-based DSL. JavaScript support makes this easier.

**Scalable and maintainable exploits:**

One off exploit detection written in code are not scalable and maintainable due to nature of language, boilerplate code, and other factors. Our goal is to provide the tools to allow you to write the **minimum** code required to run detection of the exploit and let Nuclei do the rest.

**Leveraging Turing complete language:**

While YAML-based DSL is powerful and easy to use it is not Turing complete and has its own limitations. Javascript is Turing complete thus users who are already familiar with JavaScript can write network and other detection of exploits without learning new DSL or hacking around existing DSL.

## Requirements

- A basic knowledge of JavaScript (loops, functions, arrays) is required to write a JavaScript protocol template
- Nuclei v3.0.0 or above
````

### `protocols\javascript\protocol.md`

````markdown
---
title: "JavaScript Protocol"
description: "Review examples of JavaScript with Nuclei v3"
sidebarTitle: "Protocol"
---

The JavaScript protocol was added to Nuclei v3 to allow you to write checks and detections for exploits in JavaScript and to bridge the gap between network protocols.

- Internally any content written using the JavaScript protocol is executed in Golang.
- The JavaScript protocol is **not** intended to fit into or be imported with any existing JavaScript libraries or frameworks outside of the Nuclei ecosystem.
- Nuclei provides a set of functions, libraries that are tailor-made for writing exploits and checks and only adds required/necessary functionality to complement existing YAML-based DSL.
- The JavaScript protocol is **not** intended to be used as a general purpose JavaScript runtime and does not replace matchers, extractors, or any existing functionality of Nuclei.
- Nuclei v3.0.0 ships with **15+ libraries (ssh, ftp, RDP, Kerberos, and Redis)** tailored for writing exploits and checks in JavaScript and will be continuously expanded in the future.

## Simple Example

Here is a basic example of a JavaScript protocol template:

```yaml
id: ssh-server-fingerprint

info:
  name: Fingerprint SSH Server Software
  author: Ice3man543,tarunKoyalwar
  severity: info


javascript:
  - code: |
      var m = require("nuclei/ssh");
      var c = m.SSHClient();
      var response = c.ConnectSSHInfoMode(Host, Port);
      to_json(response);
    args:
      Host: "{{Host}}"
      Port: "22"

    extractors:
      - type: json
        json:
          - '.ServerID.Raw'
```

In the Nuclei template example above, we are fingerprinting SSH server software by connecting in non-auth mode and extracting the server banner.  Let's break down the template.

### Code Section

The `code:` contains actual JavaScript code that is executed by Nuclei at runtime. In the above template, we are:

- Importing `nuclei/ssh` module/library
- Creating a new instance of `SSHClient` object
- Connecting to SSH server in `Info` mode
- Converting response to json

### Args Section

The `args:` section can be simply understood as variables in JavaScript that are passed at runtime and support DSL usage.

### Output Section

The value of the last expression is returned as the output of JavaScript protocol template and can be used in matchers and extractors. If the server returns an error instead, then the `error` variable is exposed in the matcher or extractor with an error message.

## SSH Bruteforce Example

**SSH Password Bruteforce Template:**

```yaml
id: ssh-brute

info:
  name: SSH Credential Stuffing
  author: tarunKoyalwar
  severity: critical


javascript:
  - pre-condition: |
      var m = require("nuclei/ssh");
      var c = m.SSHClient();
      var response = c.ConnectSSHInfoMode(Host, Port);
      // only bruteforce if ssh server allows password based authentication
      response["UserAuth"].includes("password")

    code: |
      var m = require("nuclei/ssh");
      var c = m.SSHClient();
      c.Connect(Host,Port,Username,Password);

    args:
      Host: "{{Host}}"
      Port: "22"
      Username: "{{usernames}}"
      Password: "{{passwords}}"

    threads: 10
    attack: clusterbomb
    payloads:
      usernames: helpers/wordlists/wp-users.txt
      passwords: helpers/wordlists/wp-passwords.txt

    stop-at-first-match: true
    matchers:
      - type: dsl
        dsl:
          - "response == true"
          - "success == true"
        condition: and
```

In the example template above, we are bruteforcing ssh server with a list of usernames and passwords. We can tell that this might not have been possible to achieve with the network template. Let's break down the template.

### Pre-Condition

`pre-condition` is an optional section of JavaScript code that is executed before running “code” and acts as a pre-condition to exploit. In the above template, before attempting brute force, we check if:

- The address is actually an SSH server.
- The ssh server is configured to allow password-based authentication.

**Further explanation:**

- If pre-condition returns `true` only then `code` is executed; otherwise, it is skipped.
- In the code section, we import `nuclei/ssh` module and create a new instance of `SSHClient` object.
- Then we attempt to connect to the ssh server with a username and password.
This template uses [payloads](https://docs.projectdiscovery.io/templates/protocols/http/http-payloads) to launch a clusterbomb attack with 10 threads and exits on the first match.

Looking at this template now, we can tell that JavaScript templates are powerful for writing multi-step and protocol/vendor-specific exploits, which is a primary goal of the JavaScript protocol.

## Init

`init` is an optional JavaScript section that can be used to initialize the template, and it is executed just after compiling the template and before running it on any target. Although it is rarely needed, it can be used to load and pre-process data before running a template on any target.

For example, in the below code block, we are loading all ssh private keys from `nuclei-templates/helpers` directory and storing them as a variable in payloads with the name `keys`. If we were loading private keys from the "pre-condition" code block, then it would have been loaded for every target, which is not ideal.

```txt
variables:
  keysDir: "helpers/"  # load all private keys from this directory

javascript:
    # init field can be used to make any preparations before the actual exploit
    # here we are reading all private keys from helpers folder and storing them in a list
  - init: |
      let m = require('nuclei/fs');
      let privatekeys = m.ReadFilesFromDir(keysDir)
      updatePayload('keys',privatekeys)

    payloads:
      # 'keys' will be updated by actual private keys after init is executed
      keys:
        - key1
        - key2
```

Two special functions that are available in the `init` block are

| Function                   | Description                              |
| -------------------------- | ---------------------------------------- |
| `updatePayload(key,value)` | updates payload with given key and value |
| `set(key,value)`           | sets a variable with given key and value |

A collection of JavaScript protocol templates can be found [here](https://github.com/projectdiscovery/nuclei-templates/pull/8530).
````

### `protocols\javascript\modules\bytes.Buffer.md`

````markdown
# Class: Buffer

[bytes](/templates/protocols/javascript/modules/bytes).Buffer

Buffer is a bytes/Uint8Array type in javascript

**`Example`**

```javascript
const bytes = require('nuclei/bytes');
const bytes = new bytes.Buffer();
```

**`Example`**

```javascript
const bytes = require('nuclei/bytes');
// optionally it can accept existing byte/Uint8Array as input
const bytes = new bytes.Buffer([1, 2, 3]);
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/bytes.Buffer#constructor)

### Methods

- [Bytes](/templates/protocols/javascript/modules/bytes.Buffer#bytes)
- [Hex](/templates/protocols/javascript/modules/bytes.Buffer#hex)
- [Hexdump](/templates/protocols/javascript/modules/bytes.Buffer#hexdump)
- [Len](/templates/protocols/javascript/modules/bytes.Buffer#len)
- [Pack](/templates/protocols/javascript/modules/bytes.Buffer#pack)
- [String](/templates/protocols/javascript/modules/bytes.Buffer#string)
- [Write](/templates/protocols/javascript/modules/bytes.Buffer#write)
- [WriteString](/templates/protocols/javascript/modules/bytes.Buffer#writestring)

## Constructors

### constructor

• **new Buffer**(): [`Buffer`](/templates/protocols/javascript/modules/bytes.Buffer)

#### Returns

[`Buffer`](/templates/protocols/javascript/modules/bytes.Buffer)

#### Defined in

bytes.ts:21

## Methods

### Bytes

▸ **Bytes**(): `Uint8Array`

Bytes returns the byte representation of the buffer.

#### Returns

`Uint8Array`

**`Example`**

```javascript
const bytes = require('nuclei/bytes');
const buffer = new bytes.Buffer();
buffer.WriteString('hello');
log(buffer.Bytes());
```

#### Defined in

bytes.ts:60

___

### Hex

▸ **Hex**(): `string`

Hex returns the hex representation of the buffer.

#### Returns

`string`

**`Example`**

```javascript
const bytes = require('nuclei/bytes');
const buffer = new bytes.Buffer();
buffer.WriteString('hello');
log(buffer.Hex());
```

#### Defined in

bytes.ts:105

___

### Hexdump

▸ **Hexdump**(): `string`

Hexdump returns the hexdump representation of the buffer.

#### Returns

`string`

**`Example`**

```javascript
const bytes = require('nuclei/bytes');
const buffer = new bytes.Buffer();
buffer.WriteString('hello');
log(buffer.Hexdump());
```

#### Defined in

bytes.ts:120

___

### Len

▸ **Len**(): `number`

Len returns the length of the buffer.

#### Returns

`number`

**`Example`**

```javascript
const bytes = require('nuclei/bytes');
const buffer = new bytes.Buffer();
buffer.WriteString('hello');
log(buffer.Len());
```

#### Defined in

bytes.ts:90

___

### Pack

▸ **Pack**(`formatStr`, `msg`): `void`

Pack uses structs.Pack and packs given data and appends it to the buffer.
it packs the data according to the given format.

#### Parameters

| Name | Type |
| :------ | :------ |
| `formatStr` | `string` |
| `msg` | `any` |

#### Returns

`void`

**`Example`**

```javascript
const bytes = require('nuclei/bytes');
const buffer = new bytes.Buffer();
buffer.Pack('I', 123);
```

#### Defined in

bytes.ts:135

___

### String

▸ **String**(): `string`

String returns the string representation of the buffer.

#### Returns

`string`

**`Example`**

```javascript
const bytes = require('nuclei/bytes');
const buffer = new bytes.Buffer();
buffer.WriteString('hello');
log(buffer.String());
```

#### Defined in

bytes.ts:75

___

### Write

▸ **Write**(`data`): [`Buffer`](/templates/protocols/javascript/modules/bytes.Buffer)

Write appends the given data to the buffer.

#### Parameters

| Name | Type |
| :------ | :------ |
| `data` | `Uint8Array` |

#### Returns

[`Buffer`](/templates/protocols/javascript/modules/bytes.Buffer)

**`Example`**

```javascript
const bytes = require('nuclei/bytes');
const buffer = new bytes.Buffer();
buffer.Write([1, 2, 3]);
```

#### Defined in

bytes.ts:31

___

### WriteString

▸ **WriteString**(`data`): [`Buffer`](/templates/protocols/javascript/modules/bytes.Buffer)

WriteString appends the given string data to the buffer.

#### Parameters

| Name | Type |
| :------ | :------ |
| `data` | `string` |

#### Returns

[`Buffer`](/templates/protocols/javascript/modules/bytes.Buffer)

**`Example`**

```javascript
const bytes = require('nuclei/bytes');
const buffer = new bytes.Buffer();
buffer.WriteString('hello');
```

#### Defined in

bytes.ts:45
````

### `protocols\javascript\modules\bytes.md`

````markdown
# Namespace: bytes

## Table of contents

### Classes

- [Buffer](/templates/protocols/javascript/modules/bytes.Buffer)
````

### `protocols\javascript\modules\Exports.md`

````markdown
# nuclei

## Table of contents

### Namespaces

- [bytes](/templates/protocols/javascript/modules/bytes)
- [fs](/templates/protocols/javascript/modules/fs)
- [goconsole](/templates/protocols/javascript/modules/goconsole)
- [ikev2](/templates/protocols/javascript/modules/ikev2)
- [kerberos](/templates/protocols/javascript/modules/kerberos)
- [ldap](/templates/protocols/javascript/modules/ldap)
- [mssql](/templates/protocols/javascript/modules/mssql)
- [mysql](/templates/protocols/javascript/modules/mysql)
- [net](/templates/protocols/javascript/modules/net)
- [oracle](/templates/protocols/javascript/modules/oracle)
- [pop3](/templates/protocols/javascript/modules/pop3)
- [postgres](/templates/protocols/javascript/modules/postgres)
- [rdp](/templates/protocols/javascript/modules/rdp)
- [redis](/templates/protocols/javascript/modules/redis)
- [rsync](/templates/protocols/javascript/modules/rsync)
- [smb](/templates/protocols/javascript/modules/smb)
- [smtp](/templates/protocols/javascript/modules/smtp)
- [ssh](/templates/protocols/javascript/modules/ssh)
- [structs](/templates/protocols/javascript/modules/structs)
- [telnet](/templates/protocols/javascript/modules/telnet)
- [vnc](/templates/protocols/javascript/modules/vnc)
````

### `protocols\javascript\modules\fs.md`

````markdown
# Namespace: fs

## Table of contents

### Functions

- [ListDir](/templates/protocols/javascript/modules/fs#listdir)
- [ReadFile](/templates/protocols/javascript/modules/fs#readfile)
- [ReadFileAsString](/templates/protocols/javascript/modules/fs#readfileasstring)
- [ReadFilesFromDir](/templates/protocols/javascript/modules/fs#readfilesfromdir)

## Functions

### ListDir

▸ **ListDir**(`path`, `itemType`): `string`[] \| ``null``

ListDir lists itemType values within a directory
depending on the itemType provided
itemType can be any one of ['file','dir',”]

#### Parameters

| Name | Type |
| :------ | :------ |
| `path` | `string` |
| `itemType` | `string` |

#### Returns

`string`[] \| ``null``

**`Example`**

```javascript
const fs = require('nuclei/fs');
// this will only return files in /tmp directory
const files = fs.ListDir('/tmp', 'file');
```

**`Example`**

```javascript
const fs = require('nuclei/fs');
// this will only return directories in /tmp directory
const dirs = fs.ListDir('/tmp', 'dir');
```

**`Example`**

```javascript
const fs = require('nuclei/fs');
// when no itemType is provided, it will return both files and directories
const items = fs.ListDir('/tmp');
```

#### Defined in

fs.ts:26

___

### ReadFile

▸ **ReadFile**(`path`): `Uint8Array` \| ``null``

ReadFile reads file contents within permitted paths
and returns content as byte array

#### Parameters

| Name | Type |
| :------ | :------ |
| `path` | `string` |

#### Returns

`Uint8Array` \| ``null``

**`Example`**

```javascript
const fs = require('nuclei/fs');
// here permitted directories are $HOME/nuclei-templates/*
const content = fs.ReadFile('helpers/usernames.txt');
```

#### Defined in

fs.ts:42

___

### ReadFileAsString

▸ **ReadFileAsString**(`path`): `string` \| ``null``

ReadFileAsString reads file contents within permitted paths
and returns content as string

#### Parameters

| Name | Type |
| :------ | :------ |
| `path` | `string` |

#### Returns

`string` \| ``null``

**`Example`**

```javascript
const fs = require('nuclei/fs');
// here permitted directories are $HOME/nuclei-templates/*
const content = fs.ReadFileAsString('helpers/usernames.txt');
```

#### Defined in

fs.ts:58

___

### ReadFilesFromDir

▸ **ReadFilesFromDir**(`dir`): `string`[] \| ``null``

ReadFilesFromDir reads all files from a directory
and returns a string array with file contents of all files

#### Parameters

| Name | Type |
| :------ | :------ |
| `dir` | `string` |

#### Returns

`string`[] \| ``null``

**`Example`**

```javascript
const fs = require('nuclei/fs');
// here permitted directories are $HOME/nuclei-templates/*
const contents = fs.ReadFilesFromDir('helpers/ssh-keys');
log(contents);
```

#### Defined in

fs.ts:75
````

### `protocols\javascript\modules\goconsole.GoConsolePrinter.md`

````markdown
# Class: GoConsolePrinter

[goconsole](/templates/protocols/javascript/modules/goconsole).GoConsolePrinter

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/goconsole.GoConsolePrinter#constructor)

### Methods

- [Error](/templates/protocols/javascript/modules/goconsole.GoConsolePrinter#error)
- [Log](/templates/protocols/javascript/modules/goconsole.GoConsolePrinter#log)
- [Warn](/templates/protocols/javascript/modules/goconsole.GoConsolePrinter#warn)

## Constructors

### constructor

• **new GoConsolePrinter**(): [`GoConsolePrinter`](/templates/protocols/javascript/modules/goconsole.GoConsolePrinter)

#### Returns

[`GoConsolePrinter`](/templates/protocols/javascript/modules/goconsole.GoConsolePrinter)

#### Defined in

goconsole.ts:18

## Methods

### Error

▸ **Error**(`msg`): `void`

Error Method

#### Parameters

| Name | Type |
| :------ | :------ |
| `msg` | `string` |

#### Returns

`void`

#### Defined in

goconsole.ts:38

___

### Log

▸ **Log**(`msg`): `void`

Log Method

#### Parameters

| Name | Type |
| :------ | :------ |
| `msg` | `string` |

#### Returns

`void`

#### Defined in

goconsole.ts:22

___

### Warn

▸ **Warn**(`msg`): `void`

Warn Method

#### Parameters

| Name | Type |
| :------ | :------ |
| `msg` | `string` |

#### Returns

`void`

#### Defined in

goconsole.ts:30
````

### `protocols\javascript\modules\goconsole.md`

````markdown
# Namespace: goconsole

## Table of contents

### Classes

- [GoConsolePrinter](/templates/protocols/javascript/modules/goconsole.GoConsolePrinter)

### Functions

- [NewGoConsolePrinter](/templates/protocols/javascript/modules/goconsole#newgoconsoleprinter)

## Functions

### NewGoConsolePrinter

▸ **NewGoConsolePrinter**(): [`GoConsolePrinter`](/templates/protocols/javascript/modules/goconsole.GoConsolePrinter)

NewGoConsolePrinter Function

#### Returns

[`GoConsolePrinter`](/templates/protocols/javascript/modules/goconsole.GoConsolePrinter)

#### Defined in

goconsole.ts:6
````

### `protocols\javascript\modules\Home.md`

````markdown
# ProjectDiscovery Documentation

<h4 align="center">
    This is the source code for the ProjectDiscovery documentation located at https://docs.projectdiscovery.io
</h4>

<p align="center">
<a href="https://github.com/projectdiscovery/docs/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat" /></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter" /></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord" /></a>
</p>

<p align="center">
  <a href="#development">Development</a> •
  <a href="#deploying">Deploying</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

---

## Development

1. Checkout this repository
1. Install mintlify with `npm i -g mintlify@latest`
1. Run `mintlify dev`

## Deploying

To build the final product, we have a couple of additional steps:

1. Build the JS Protocol Docs

- `npm install -g jsdoc-to-markdown`
- `./bin/jsdocs.sh`

2. Build the PDCP API reference documentation

- Either download the latest `openapi.yaml` manually or run `./bin/download-api.sh`
- Run `./bin/generate-api.sh` to generate any new API files

3. Deployment

After those, Mintlify handles the deployment automatically.
````

### `protocols\javascript\modules\ikev2.IKEMessage.md`

````markdown
# Class: IKEMessage

[ikev2](/templates/protocols/javascript/modules/ikev2).IKEMessage

IKEMessage is the IKEv2 message
IKEv2 implements a limited subset of IKEv2 Protocol, specifically
the IKE_NOTIFY and IKE_NONCE payloads and the IKE_SA_INIT exchange.

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/ikev2.IKEMessage#constructor)

### Properties

- [ExchangeType](/templates/protocols/javascript/modules/ikev2.IKEMessage#exchangetype)
- [Flags](/templates/protocols/javascript/modules/ikev2.IKEMessage#flags)
- [InitiatorSPI](/templates/protocols/javascript/modules/ikev2.IKEMessage#initiatorspi)
- [Version](/templates/protocols/javascript/modules/ikev2.IKEMessage#version)

### Methods

- [AppendPayload](/templates/protocols/javascript/modules/ikev2.IKEMessage#appendpayload)
- [Encode](/templates/protocols/javascript/modules/ikev2.IKEMessage#encode)

## Constructors

### constructor

• **new IKEMessage**(): [`IKEMessage`](/templates/protocols/javascript/modules/ikev2.IKEMessage)

#### Returns

[`IKEMessage`](/templates/protocols/javascript/modules/ikev2.IKEMessage)

#### Defined in

ikev2.ts:52

## Properties

### ExchangeType

• `Optional` **ExchangeType**: `number`

#### Defined in

ikev2.ts:44

___

### Flags

• `Optional` **Flags**: `number`

#### Defined in

ikev2.ts:48

___

### InitiatorSPI

• `Optional` **InitiatorSPI**: `number`

#### Defined in

ikev2.ts:36

___

### Version

• `Optional` **Version**: `number`

#### Defined in

ikev2.ts:40

## Methods

### AppendPayload

▸ **AppendPayload**(`payload`): `void`

AppendPayload appends a payload to the IKE message
payload can be any of the payloads like IKENotification, IKENonce, etc.

#### Parameters

| Name | Type |
| :------ | :------ |
| `payload` | `any` |

#### Returns

`void`

**`Example`**

```javascript
const ikev2 = require('nuclei/ikev2');
const message = new ikev2.IKEMessage();
const nonce = new ikev2.IKENonce();
nonce.NonceData = [1, 2, 3];
message.AppendPayload(nonce);
```

#### Defined in

ikev2.ts:65

___

### Encode

▸ **Encode**(): `Uint8Array`

Encode encodes the final IKE message

#### Returns

`Uint8Array`

**`Example`**

```javascript
const ikev2 = require('nuclei/ikev2');
const message = new ikev2.IKEMessage();
const nonce = new ikev2.IKENonce();
nonce.NonceData = [1, 2, 3];
message.AppendPayload(nonce);
log(message.Encode());
```

#### Defined in

ikev2.ts:82
````

### `protocols\javascript\modules\ikev2.IKENonce.md`

````markdown
# Interface: IKENonce

[ikev2](/templates/protocols/javascript/modules/ikev2).IKENonce

IKENonce is the IKEv2 Nonce payload
this implements the IKEPayload interface

**`Example`**

```javascript
const ikev2 = require('nuclei/ikev2');
const nonce = new ikev2.IKENonce();
nonce.NonceData = [1, 2, 3];
```

## Table of contents

### Properties

- [NonceData](/templates/protocols/javascript/modules/ikev2.IKENonce#noncedata)

## Properties

### NonceData

• `Optional` **NonceData**: `Uint8Array`

#### Defined in

ikev2.ts:103
````

### `protocols\javascript\modules\ikev2.IKENotification.md`

````markdown
# Interface: IKENotification

[ikev2](/templates/protocols/javascript/modules/ikev2).IKENotification

IKEv2Notify is the IKEv2 Notification payload
this implements the IKEPayload interface

**`Example`**

```javascript
const ikev2 = require('nuclei/ikev2');
const notify = new ikev2.IKENotification();
notify.NotifyMessageType = ikev2.IKE_NOTIFY_NO_PROPOSAL_CHOSEN;
notify.NotificationData = [1, 2, 3];
```

## Table of contents

### Properties

- [NotificationData](/templates/protocols/javascript/modules/ikev2.IKENotification#notificationdata)
- [NotifyMessageType](/templates/protocols/javascript/modules/ikev2.IKENotification#notifymessagetype)

## Properties

### NotificationData

• `Optional` **NotificationData**: `Uint8Array`

#### Defined in

ikev2.ts:123

___

### NotifyMessageType

• `Optional` **NotifyMessageType**: `number`

#### Defined in

ikev2.ts:121
````

### `protocols\javascript\modules\ikev2.md`

````markdown
# Namespace: ikev2

## Table of contents

### Classes

- [IKEMessage](/templates/protocols/javascript/modules/ikev2.IKEMessage)

### Interfaces

- [IKENonce](/templates/protocols/javascript/modules/ikev2.IKENonce)
- [IKENotification](/templates/protocols/javascript/modules/ikev2.IKENotification)

### Variables

- [IKE\_EXCHANGE\_AUTH](/templates/protocols/javascript/modules/ikev2#ike_exchange_auth)
- [IKE\_EXCHANGE\_CREATE\_CHILD\_SA](/templates/protocols/javascript/modules/ikev2#ike_exchange_create_child_sa)
- [IKE\_EXCHANGE\_INFORMATIONAL](/templates/protocols/javascript/modules/ikev2#ike_exchange_informational)
- [IKE\_EXCHANGE\_SA\_INIT](/templates/protocols/javascript/modules/ikev2#ike_exchange_sa_init)
- [IKE\_FLAGS\_InitiatorBitCheck](/templates/protocols/javascript/modules/ikev2#ike_flags_initiatorbitcheck)
- [IKE\_NOTIFY\_NO\_PROPOSAL\_CHOSEN](/templates/protocols/javascript/modules/ikev2#ike_notify_no_proposal_chosen)
- [IKE\_NOTIFY\_USE\_TRANSPORT\_MODE](/templates/protocols/javascript/modules/ikev2#ike_notify_use_transport_mode)
- [IKE\_VERSION\_2](/templates/protocols/javascript/modules/ikev2#ike_version_2)

## Variables

### IKE\_EXCHANGE\_AUTH

• `Const` **IKE\_EXCHANGE\_AUTH**: ``35``

#### Defined in

ikev2.ts:4

___

### IKE\_EXCHANGE\_CREATE\_CHILD\_SA

• `Const` **IKE\_EXCHANGE\_CREATE\_CHILD\_SA**: ``36``

#### Defined in

ikev2.ts:7

___

### IKE\_EXCHANGE\_INFORMATIONAL

• `Const` **IKE\_EXCHANGE\_INFORMATIONAL**: ``37``

#### Defined in

ikev2.ts:10

___

### IKE\_EXCHANGE\_SA\_INIT

• `Const` **IKE\_EXCHANGE\_SA\_INIT**: ``34``

#### Defined in

ikev2.ts:13

___

### IKE\_FLAGS\_InitiatorBitCheck

• `Const` **IKE\_FLAGS\_InitiatorBitCheck**: ``8``

#### Defined in

ikev2.ts:16

___

### IKE\_NOTIFY\_NO\_PROPOSAL\_CHOSEN

• `Const` **IKE\_NOTIFY\_NO\_PROPOSAL\_CHOSEN**: ``14``

#### Defined in

ikev2.ts:19

___

### IKE\_NOTIFY\_USE\_TRANSPORT\_MODE

• `Const` **IKE\_NOTIFY\_USE\_TRANSPORT\_MODE**: ``16391``

#### Defined in

ikev2.ts:22

___

### IKE\_VERSION\_2

• `Const` **IKE\_VERSION\_2**: ``32``

#### Defined in

ikev2.ts:25
````

### `protocols\javascript\modules\kerberos.AuthorizationDataEntry.md`

````markdown
# Interface: AuthorizationDataEntry

[kerberos](/templates/protocols/javascript/modules/kerberos).AuthorizationDataEntry

AuthorizationDataEntry Interface

## Table of contents

### Properties

- [ADData](/templates/protocols/javascript/modules/kerberos.AuthorizationDataEntry#addata)
- [ADType](/templates/protocols/javascript/modules/kerberos.AuthorizationDataEntry#adtype)

## Properties

### ADData

• `Optional` **ADData**: `Uint8Array`

#### Defined in

kerberos.ts:193

___

### ADType

• `Optional` **ADType**: `number`

#### Defined in

kerberos.ts:191
````

### `protocols\javascript\modules\kerberos.BitString.md`

````markdown
# Interface: BitString

[kerberos](/templates/protocols/javascript/modules/kerberos).BitString

BitString Interface

## Table of contents

### Properties

- [BitLength](/templates/protocols/javascript/modules/kerberos.BitString#bitlength)
- [Bytes](/templates/protocols/javascript/modules/kerberos.BitString#bytes)

## Properties

### BitLength

• `Optional` **BitLength**: `number`

#### Defined in

kerberos.ts:205

kerberos.ts:217

___

### Bytes

• `Optional` **Bytes**: `Uint8Array`

#### Defined in

kerberos.ts:203

kerberos.ts:215
````

### `protocols\javascript\modules\kerberos.Client.md`

````markdown
# Class: Client

[kerberos](/templates/protocols/javascript/modules/kerberos).Client

Known Issues:
Hardcoded timeout in gokrb5 library
TGT / Session Handling not exposed
Client is kerberos client

**`Example`**

```javascript
const kerberos = require('nuclei/kerberos');
// if controller is empty a dns lookup for default kdc server will be performed
const client = new kerberos.Client('acme.com', 'kdc.acme.com');
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/kerberos.Client#constructor)

### Properties

- [Krb5Config](/templates/protocols/javascript/modules/kerberos.Client#krb5config)
- [Realm](/templates/protocols/javascript/modules/kerberos.Client#realm)
- [controller](/templates/protocols/javascript/modules/kerberos.Client#controller)
- [domain](/templates/protocols/javascript/modules/kerberos.Client#domain)

### Methods

- [EnumerateUser](/templates/protocols/javascript/modules/kerberos.Client#enumerateuser)
- [GetServiceTicket](/templates/protocols/javascript/modules/kerberos.Client#getserviceticket)
- [SetConfig](/templates/protocols/javascript/modules/kerberos.Client#setconfig)

## Constructors

### constructor

• **new Client**(`domain`, `controller?`): [`Client`](/templates/protocols/javascript/modules/kerberos.Client)

#### Parameters

| Name | Type |
| :------ | :------ |
| `domain` | `string` |
| `controller?` | `string` |

#### Returns

[`Client`](/templates/protocols/javascript/modules/kerberos.Client)

#### Defined in

kerberos.ts:90

## Properties

### Krb5Config

• `Optional` **Krb5Config**: [`Config`](/templates/protocols/javascript/modules/kerberos.Config)

#### Defined in

kerberos.ts:82

___

### Realm

• `Optional` **Realm**: `string`

#### Defined in

kerberos.ts:86

___

### controller

• `Optional` **controller**: `string`

#### Defined in

kerberos.ts:90

___

### domain

• **domain**: `string`

#### Defined in

kerberos.ts:90

## Methods

### EnumerateUser

▸ **EnumerateUser**(`username`): [`EnumerateUserResponse`](/templates/protocols/javascript/modules/kerberos.EnumerateUserResponse)

EnumerateUser and attempt to get AS-REP hash by disabling PA-FX-FAST

#### Parameters

| Name | Type |
| :------ | :------ |
| `username` | `string` |

#### Returns

[`EnumerateUserResponse`](/templates/protocols/javascript/modules/kerberos.EnumerateUserResponse)

**`Example`**

```javascript
const kerberos = require('nuclei/kerberos');
const client = new kerberos.Client('acme.com', 'kdc.acme.com');
const resp = client.EnumerateUser('pdtm');
log(resp);
```

#### Defined in

kerberos.ts:122

___

### GetServiceTicket

▸ **GetServiceTicket**(`User`): [`TGS`](/templates/protocols/javascript/modules/kerberos.TGS)

GetServiceTicket returns a TGS for a given user, password and SPN

#### Parameters

| Name | Type |
| :------ | :------ |
| `User` | `string` |

#### Returns

[`TGS`](/templates/protocols/javascript/modules/kerberos.TGS)

**`Example`**

```javascript
const kerberos = require('nuclei/kerberos');
const client = new kerberos.Client('acme.com', 'kdc.acme.com');
const resp = client.GetServiceTicket('pdtm', 'password', 'HOST/CLIENT1');
log(resp);
```

#### Defined in

kerberos.ts:137

___

### SetConfig

▸ **SetConfig**(`cfg`): `void`

SetConfig sets additional config for the kerberos client
Note: as of now ip and timeout overrides are only supported
in EnumerateUser due to fastdialer but can be extended to other methods currently

#### Parameters

| Name | Type |
| :------ | :------ |
| `cfg` | [`Config`](/templates/protocols/javascript/modules/kerberos.Config) |

#### Returns

`void`

**`Example`**

```javascript
const kerberos = require('nuclei/kerberos');
const client = new kerberos.Client('acme.com', 'kdc.acme.com');
const cfg = new kerberos.Config();
cfg.SetIPAddress('192.168.100.22');
cfg.SetTimeout(5);
client.SetConfig(cfg);
```

#### Defined in

kerberos.ts:107
````

### `protocols\javascript\modules\kerberos.Config.md`

````markdown
# Class: Config

[kerberos](/templates/protocols/javascript/modules/kerberos).Config

Config is extra configuration for the kerberos client

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/kerberos.Config#constructor)

### Properties

- [LibDefaults](/templates/protocols/javascript/modules/kerberos.Config#libdefaults)
- [Realms](/templates/protocols/javascript/modules/kerberos.Config#realms)

### Methods

- [SetIPAddress](/templates/protocols/javascript/modules/kerberos.Config#setipaddress)
- [SetTimeout](/templates/protocols/javascript/modules/kerberos.Config#settimeout)

## Constructors

### constructor

• **new Config**(): [`Config`](/templates/protocols/javascript/modules/kerberos.Config)

#### Returns

[`Config`](/templates/protocols/javascript/modules/kerberos.Config)

#### Defined in

kerberos.ts:153

## Properties

### LibDefaults

• `Optional` **LibDefaults**: [`LibDefaults`](/templates/protocols/javascript/modules/kerberos.LibDefaults)

#### Defined in

kerberos.ts:227

___

### Realms

• `Optional` **Realms**: [`Realm`](/templates/protocols/javascript/modules/kerberos.Realm)

#### Defined in

kerberos.ts:229

## Methods

### SetIPAddress

▸ **SetIPAddress**(`ip`): [`Config`](/templates/protocols/javascript/modules/kerberos.Config)

SetIPAddress sets the IP address for the kerberos client

#### Parameters

| Name | Type |
| :------ | :------ |
| `ip` | `string` |

#### Returns

[`Config`](/templates/protocols/javascript/modules/kerberos.Config)

**`Example`**

```javascript
const kerberos = require('nuclei/kerberos');
const cfg = new kerberos.Config();
cfg.SetIPAddress('10.10.10.1');
```

#### Defined in

kerberos.ts:163

___

### SetTimeout

▸ **SetTimeout**(`timeout`): [`Config`](/templates/protocols/javascript/modules/kerberos.Config)

SetTimeout sets the RW timeout for the kerberos client

#### Parameters

| Name | Type |
| :------ | :------ |
| `timeout` | `number` |

#### Returns

[`Config`](/templates/protocols/javascript/modules/kerberos.Config)

**`Example`**

```javascript
const kerberos = require('nuclei/kerberos');
const cfg = new kerberos.Config();
cfg.SetTimeout(5);
```

#### Defined in

kerberos.ts:177
````

### `protocols\javascript\modules\kerberos.EncryptedData.md`

````markdown
# Interface: EncryptedData

[kerberos](/templates/protocols/javascript/modules/kerberos).EncryptedData

EncryptedData Interface

## Table of contents

### Properties

- [Cipher](/templates/protocols/javascript/modules/kerberos.EncryptedData#cipher)
- [EType](/templates/protocols/javascript/modules/kerberos.EncryptedData#etype)
- [KVNO](/templates/protocols/javascript/modules/kerberos.EncryptedData#kvno)

### Cipher

• `Optional` **Cipher**: `Uint8Array`

#### Defined in

kerberos.ts:273

___

### EType

• `Optional` **EType**: `number`

#### Defined in

kerberos.ts:269

___

### KVNO

• `Optional` **KVNO**: `number`

#### Defined in

kerberos.ts:271
````

### `protocols\javascript\modules\kerberos.EncryptionKey.md`

````markdown
# Interface: EncryptionKey

[kerberos](/templates/protocols/javascript/modules/kerberos).EncryptionKey

EncryptionKey Interface

## Table of contents

### Properties

- [KeyType](/templates/protocols/javascript/modules/kerberos.EncryptionKey#keytype)
- [KeyValue](/templates/protocols/javascript/modules/kerberos.EncryptionKey#keyvalue)

## Properties

### KeyType

• `Optional` **KeyType**: `number`

#### Defined in

kerberos.ts:283

___

### KeyValue

• `Optional` **KeyValue**: `Uint8Array`

#### Defined in

kerberos.ts:285
````

### `protocols\javascript\modules\kerberos.EncTicketPart.md`

````markdown
# Interface: EncTicketPart

[kerberos](/templates/protocols/javascript/modules/kerberos).EncTicketPart

EncTicketPart Interface

## Table of contents

### Properties

- [AuthTime](/templates/protocols/javascript/modules/kerberos.EncTicketPart#authtime)
- [AuthorizationData](/templates/protocols/javascript/modules/kerberos.EncTicketPart#authorizationdata)
- [CAddr](/templates/protocols/javascript/modules/kerberos.EncTicketPart#caddr)
- [CName](/templates/protocols/javascript/modules/kerberos.EncTicketPart#cname)
- [CRealm](/templates/protocols/javascript/modules/kerberos.EncTicketPart#crealm)
- [EndTime](/templates/protocols/javascript/modules/kerberos.EncTicketPart#endtime)
- [Flags](/templates/protocols/javascript/modules/kerberos.EncTicketPart#flags)
- [Key](/templates/protocols/javascript/modules/kerberos.EncTicketPart#key)
- [RenewTill](/templates/protocols/javascript/modules/kerberos.EncTicketPart#renewtill)
- [StartTime](/templates/protocols/javascript/modules/kerberos.EncTicketPart#starttime)
- [Transited](/templates/protocols/javascript/modules/kerberos.EncTicketPart#transited)

## Properties

### AuthTime

• `Optional` **AuthTime**: `Date`

#### Defined in

kerberos.ts:247

___

### AuthorizationData

• `Optional` **AuthorizationData**: [`AuthorizationDataEntry`](/templates/protocols/javascript/modules/kerberos.AuthorizationDataEntry)

#### Defined in

kerberos.ts:249

___

### CAddr

• `Optional` **CAddr**: [`HostAddress`](/templates/protocols/javascript/modules/kerberos.HostAddress)

#### Defined in

kerberos.ts:259

___

### CName

• `Optional` **CName**: [`PrincipalName`](/templates/protocols/javascript/modules/kerberos.PrincipalName)

#### Defined in

kerberos.ts:255

___

### CRealm

• `Optional` **CRealm**: `string`

#### Defined in

kerberos.ts:245

___

### EndTime

• `Optional` **EndTime**: `Date`

#### Defined in

kerberos.ts:241

___

### Flags

• `Optional` **Flags**: [`BitString`](/templates/protocols/javascript/modules/kerberos.BitString)

#### Defined in

kerberos.ts:251

___

### Key

• `Optional` **Key**: [`EncryptionKey`](/templates/protocols/javascript/modules/kerberos.EncryptionKey)

#### Defined in

kerberos.ts:253

___

### RenewTill

• `Optional` **RenewTill**: `Date`

#### Defined in

kerberos.ts:243

___

### StartTime

• `Optional` **StartTime**: `Date`

#### Defined in

kerberos.ts:239

___

### Transited

• `Optional` **Transited**: [`TransitedEncoding`](/templates/protocols/javascript/modules/kerberos.TransitedEncoding)

#### Defined in

kerberos.ts:257
````

### `protocols\javascript\modules\kerberos.EnumerateUserResponse.md`

````markdown
# Interface: EnumerateUserResponse

[kerberos](/templates/protocols/javascript/modules/kerberos).EnumerateUserResponse

EnumerateUserResponse is the response from EnumerateUser

## Table of contents

### Properties

- [ASREPHash](/templates/protocols/javascript/modules/kerberos.EnumerateUserResponse#asrephash)
- [Error](/templates/protocols/javascript/modules/kerberos.EnumerateUserResponse#error)
- [Valid](/templates/protocols/javascript/modules/kerberos.EnumerateUserResponse#valid)

## Properties

### ASREPHash

• `Optional` **ASREPHash**: `string`

#### Defined in

kerberos.ts:297

___

### Error

• `Optional` **Error**: `string`

#### Defined in

kerberos.ts:299

___

### Valid

• `Optional` **Valid**: `boolean`

#### Defined in

kerberos.ts:295
````

### `protocols\javascript\modules\kerberos.HostAddress.md`

````markdown
# Interface: HostAddress

[kerberos](/templates/protocols/javascript/modules/kerberos).HostAddress

HostAddress Interface

## Table of contents

### Properties

- [AddrType](/templates/protocols/javascript/modules/kerberos.HostAddress#addrtype)
- [Address](/templates/protocols/javascript/modules/kerberos.HostAddress#address)

## Properties

### AddrType

• `Optional` **AddrType**: `number`

#### Defined in

kerberos.ts:309

___

### Address

• `Optional` **Address**: `Uint8Array`

#### Defined in

kerberos.ts:311
````

### `protocols\javascript\modules\kerberos.LibDefaults.md`

````markdown
# Interface: LibDefaults

[kerberos](/templates/protocols/javascript/modules/kerberos).LibDefaults

LibDefaults Interface

## Table of contents

### Properties

- [AllowWeakCrypto](/templates/protocols/javascript/modules/kerberos.LibDefaults#allowweakcrypto)
- [CCacheType](/templates/protocols/javascript/modules/kerberos.LibDefaults#ccachetype)
- [Canonicalize](/templates/protocols/javascript/modules/kerberos.LibDefaults#canonicalize)
- [Clockskew](/templates/protocols/javascript/modules/kerberos.LibDefaults#clockskew)
- [DNSCanonicalizeHostname](/templates/protocols/javascript/modules/kerberos.LibDefaults#dnscanonicalizehostname)
- [DNSLookupKDC](/templates/protocols/javascript/modules/kerberos.LibDefaults#dnslookupkdc)
- [DNSLookupRealm](/templates/protocols/javascript/modules/kerberos.LibDefaults#dnslookuprealm)
- [DefaultClientKeytabName](/templates/protocols/javascript/modules/kerberos.LibDefaults#defaultclientkeytabname)
- [DefaultKeytabName](/templates/protocols/javascript/modules/kerberos.LibDefaults#defaultkeytabname)
- [DefaultRealm](/templates/protocols/javascript/modules/kerberos.LibDefaults#defaultrealm)
- [DefaultTGSEnctypeIDs](/templates/protocols/javascript/modules/kerberos.LibDefaults#defaulttgsenctypeids)
- [DefaultTGSEnctypes](/templates/protocols/javascript/modules/kerberos.LibDefaults#defaulttgsenctypes)
- [DefaultTktEnctypeIDs](/templates/protocols/javascript/modules/kerberos.LibDefaults#defaulttktenctypeids)
- [DefaultTktEnctypes](/templates/protocols/javascript/modules/kerberos.LibDefaults#defaulttktenctypes)
- [ExtraAddresses](/templates/protocols/javascript/modules/kerberos.LibDefaults#extraaddresses)
- [Forwardable](/templates/protocols/javascript/modules/kerberos.LibDefaults#forwardable)
- [IgnoreAcceptorHostname](/templates/protocols/javascript/modules/kerberos.LibDefaults#ignoreacceptorhostname)
- [K5LoginAuthoritative](/templates/protocols/javascript/modules/kerberos.LibDefaults#k5loginauthoritative)
- [K5LoginDirectory](/templates/protocols/javascript/modules/kerberos.LibDefaults#k5logindirectory)
- [KDCDefaultOptions](/templates/protocols/javascript/modules/kerberos.LibDefaults#kdcdefaultoptions)
- [KDCTimeSync](/templates/protocols/javascript/modules/kerberos.LibDefaults#kdctimesync)
- [NoAddresses](/templates/protocols/javascript/modules/kerberos.LibDefaults#noaddresses)
- [PermittedEnctypeIDs](/templates/protocols/javascript/modules/kerberos.LibDefaults#permittedenctypeids)
- [PermittedEnctypes](/templates/protocols/javascript/modules/kerberos.LibDefaults#permittedenctypes)
- [PreferredPreauthTypes](/templates/protocols/javascript/modules/kerberos.LibDefaults#preferredpreauthtypes)
- [Proxiable](/templates/protocols/javascript/modules/kerberos.LibDefaults#proxiable)
- [RDNS](/templates/protocols/javascript/modules/kerberos.LibDefaults#rdns)
- [RealmTryDomains](/templates/protocols/javascript/modules/kerberos.LibDefaults#realmtrydomains)
- [RenewLifetime](/templates/protocols/javascript/modules/kerberos.LibDefaults#renewlifetime)
- [SafeChecksumType](/templates/protocols/javascript/modules/kerberos.LibDefaults#safechecksumtype)
- [TicketLifetime](/templates/protocols/javascript/modules/kerberos.LibDefaults#ticketlifetime)
- [UDPPreferenceLimit](/templates/protocols/javascript/modules/kerberos.LibDefaults#udppreferencelimit)
- [VerifyAPReqNofail](/templates/protocols/javascript/modules/kerberos.LibDefaults#verifyapreqnofail)

## Properties

### AllowWeakCrypto

• `Optional` **AllowWeakCrypto**: `boolean`

#### Defined in

kerberos.ts:391

___

### CCacheType

• `Optional` **CCacheType**: `number`

#### Defined in

kerberos.ts:373

___

### Canonicalize

• `Optional` **Canonicalize**: `boolean`

#### Defined in

kerberos.ts:393

___

### Clockskew

• `Optional` **Clockskew**: `number`

time in nanoseconds

#### Defined in

kerberos.ts:331

___

### DNSCanonicalizeHostname

• `Optional` **DNSCanonicalizeHostname**: `boolean`

#### Defined in

kerberos.ts:333

___

### DNSLookupKDC

• `Optional` **DNSLookupKDC**: `boolean`

#### Defined in

kerberos.ts:367

___

### DNSLookupRealm

• `Optional` **DNSLookupRealm**: `boolean`

#### Defined in

kerberos.ts:363

___

### DefaultClientKeytabName

• `Optional` **DefaultClientKeytabName**: `string`

#### Defined in

kerberos.ts:359

___

### DefaultKeytabName

• `Optional` **DefaultKeytabName**: `string`

#### Defined in

kerberos.ts:321

___

### DefaultRealm

• `Optional` **DefaultRealm**: `string`

#### Defined in

kerberos.ts:339

___

### DefaultTGSEnctypeIDs

• `Optional` **DefaultTGSEnctypeIDs**: `number`[]

#### Defined in

kerberos.ts:361

___

### DefaultTGSEnctypes

• `Optional` **DefaultTGSEnctypes**: `string`[]

#### Defined in

kerberos.ts:365

___

### DefaultTktEnctypeIDs

• `Optional` **DefaultTktEnctypeIDs**: `number`[]

#### Defined in

kerberos.ts:323

___

### DefaultTktEnctypes

• `Optional` **DefaultTktEnctypes**: `string`[]

#### Defined in

kerberos.ts:375

___

### ExtraAddresses

• `Optional` **ExtraAddresses**: `Uint8Array`

#### Defined in

kerberos.ts:353

___

### Forwardable

• `Optional` **Forwardable**: `boolean`

#### Defined in

kerberos.ts:355

___

### IgnoreAcceptorHostname

• `Optional` **IgnoreAcceptorHostname**: `boolean`

#### Defined in

kerberos.ts:357

___

### K5LoginAuthoritative

• `Optional` **K5LoginAuthoritative**: `boolean`

#### Defined in

kerberos.ts:377

___

### K5LoginDirectory

• `Optional` **K5LoginDirectory**: `string`

#### Defined in

kerberos.ts:395

___

### KDCDefaultOptions

• `Optional` **KDCDefaultOptions**: [`BitString`](/templates/protocols/javascript/modules/kerberos.BitString)

#### Defined in

kerberos.ts:397

___

### KDCTimeSync

• `Optional` **KDCTimeSync**: `number`

#### Defined in

kerberos.ts:379

___

### NoAddresses

• `Optional` **NoAddresses**: `boolean`

#### Defined in

kerberos.ts:335

___

### PermittedEnctypeIDs

• `Optional` **PermittedEnctypeIDs**: `number`[]

#### Defined in

kerberos.ts:325

___

### PermittedEnctypes

• `Optional` **PermittedEnctypes**: `string`[]

#### Defined in

kerberos.ts:341

___

### PreferredPreauthTypes

• `Optional` **PreferredPreauthTypes**: `number`[]

#### Defined in

kerberos.ts:381

___

### Proxiable

• `Optional` **Proxiable**: `boolean`

#### Defined in

kerberos.ts:343

___

### RDNS

• `Optional` **RDNS**: `boolean`

#### Defined in

kerberos.ts:369

___

### RealmTryDomains

• `Optional` **RealmTryDomains**: `number`

#### Defined in

kerberos.ts:371

___

### RenewLifetime

• `Optional` **RenewLifetime**: `number`

time in nanoseconds

#### Defined in

kerberos.ts:349

___

### SafeChecksumType

• `Optional` **SafeChecksumType**: `number`

#### Defined in

kerberos.ts:383

___

### TicketLifetime

• `Optional` **TicketLifetime**: `number`

time in nanoseconds

#### Defined in

kerberos.ts:389

___

### UDPPreferenceLimit

• `Optional` **UDPPreferenceLimit**: `number`

#### Defined in

kerberos.ts:337

___

### VerifyAPReqNofail

• `Optional` **VerifyAPReqNofail**: `boolean`

#### Defined in

kerberos.ts:351
````

### `protocols\javascript\modules\kerberos.md`

````markdown
# Namespace: kerberos

## Table of contents

### Classes

- [Client](/templates/protocols/javascript/modules/kerberos.Client)
- [Config](/templates/protocols/javascript/modules/kerberos.Config)

### Interfaces

- [AuthorizationDataEntry](/templates/protocols/javascript/modules/kerberos.AuthorizationDataEntry)
- [BitString](/templates/protocols/javascript/modules/kerberos.BitString)
- [EncTicketPart](/templates/protocols/javascript/modules/kerberos.EncTicketPart)
- [EncryptedData](/templates/protocols/javascript/modules/kerberos.EncryptedData)
- [EncryptionKey](/templates/protocols/javascript/modules/kerberos.EncryptionKey)
- [EnumerateUserResponse](/templates/protocols/javascript/modules/kerberos.EnumerateUserResponse)
- [HostAddress](/templates/protocols/javascript/modules/kerberos.HostAddress)
- [LibDefaults](/templates/protocols/javascript/modules/kerberos.LibDefaults)
- [PrincipalName](/templates/protocols/javascript/modules/kerberos.PrincipalName)
- [Realm](/templates/protocols/javascript/modules/kerberos.Realm)
- [TGS](/templates/protocols/javascript/modules/kerberos.TGS)
- [Ticket](/templates/protocols/javascript/modules/kerberos.Ticket)
- [TransitedEncoding](/templates/protocols/javascript/modules/kerberos.TransitedEncoding)

### Functions

- [ASRepToHashcat](/templates/protocols/javascript/modules/kerberos#asreptohashcat)
- [CheckKrbError](/templates/protocols/javascript/modules/kerberos#checkkrberror)
- [NewKerberosClientFromString](/templates/protocols/javascript/modules/kerberos#newkerberosclientfromstring)
- [SendToKDC](/templates/protocols/javascript/modules/kerberos#sendtokdc)
- [TGStoHashcat](/templates/protocols/javascript/modules/kerberos#tgstohashcat)

## Functions

### ASRepToHashcat

▸ **ASRepToHashcat**(`asrep`): `string` \| ``null``

ASRepToHashcat converts an AS-REP message to a hashcat format

#### Parameters

| Name | Type |
| :------ | :------ |
| `asrep` | `any` |

#### Returns

`string` \| ``null``

#### Defined in

kerberos.ts:6

___

### CheckKrbError

▸ **CheckKrbError**(`b`): `Uint8Array` \| ``null``

CheckKrbError checks if the response bytes from the KDC are a KRBError.

#### Parameters

| Name | Type |
| :------ | :------ |
| `b` | `Uint8Array` |

#### Returns

`Uint8Array` \| ``null``

#### Defined in

kerberos.ts:15

___

### NewKerberosClientFromString

▸ **NewKerberosClientFromString**(`cfg`): [`Client`](/templates/protocols/javascript/modules/kerberos.Client) \| ``null``

NewKerberosClientFromString creates a new kerberos client from a string
by parsing krb5.conf

#### Parameters

| Name | Type |
| :------ | :------ |
| `cfg` | `string` |

#### Returns

[`Client`](/templates/protocols/javascript/modules/kerberos.Client) \| ``null``

**`Example`**

```javascript
const kerberos = require('nuclei/kerberos');
const client = kerberos.NewKerberosClientFromString(`
[libdefaults]
default_realm = ACME.COM
dns_lookup_kdc = true
`);
```

#### Defined in

kerberos.ts:34

___

### SendToKDC

▸ **SendToKDC**(`kclient`, `msg`): `string` \| ``null``

sendtokdc.go deals with actual sending and receiving responses from KDC
SendToKDC sends a message to the KDC and returns the response.
It first tries to send the message over TCP, and if that fails, it falls back to UDP.(and vice versa)

#### Parameters

| Name | Type |
| :------ | :------ |
| `kclient` | [`Client`](/templates/protocols/javascript/modules/kerberos.Client) |
| `msg` | `string` |

#### Returns

`string` \| ``null``

**`Example`**

```javascript
const kerberos = require('nuclei/kerberos');
const client = new kerberos.Client('acme.com');
const response = kerberos.SendToKDC(client, 'message');
```

#### Defined in

kerberos.ts:51

___

### TGStoHashcat

▸ **TGStoHashcat**(`tgs`, `username`): `string` \| ``null``

TGStoHashcat converts a TGS to a hashcat format.

#### Parameters

| Name | Type |
| :------ | :------ |
| `tgs` | `any` |
| `username` | `string` |

#### Returns

`string` \| ``null``

#### Defined in

kerberos.ts:60
````

### `protocols\javascript\modules\kerberos.PrincipalName.md`

````markdown
# Interface: PrincipalName

[kerberos](/templates/protocols/javascript/modules/kerberos).PrincipalName

PrincipalName Interface

## Table of contents

### Properties

- [NameString](/templates/protocols/javascript/modules/kerberos.PrincipalName#namestring)
- [NameType](/templates/protocols/javascript/modules/kerberos.PrincipalName#nametype)

## Properties

### NameString

• `Optional` **NameString**: `string`[]

#### Defined in

kerberos.ts:409

___

### NameType

• `Optional` **NameType**: `number`

#### Defined in

kerberos.ts:407
````

### `protocols\javascript\modules\kerberos.Realm.md`

````markdown
# Interface: Realm

[kerberos](/templates/protocols/javascript/modules/kerberos).Realm

Realm Interface

## Table of contents

### Properties

- [AdminServer](/templates/protocols/javascript/modules/kerberos.Realm#adminserver)
- [DefaultDomain](/templates/protocols/javascript/modules/kerberos.Realm#defaultdomain)
- [KDC](/templates/protocols/javascript/modules/kerberos.Realm#kdc)
- [KPasswdServer](/templates/protocols/javascript/modules/kerberos.Realm#kpasswdserver)
- [MasterKDC](/templates/protocols/javascript/modules/kerberos.Realm#masterkdc)
- [Realm](/templates/protocols/javascript/modules/kerberos.Realm#realm)

## Properties

### AdminServer

• `Optional` **AdminServer**: `string`[]

#### Defined in

kerberos.ts:421

___

### DefaultDomain

• `Optional` **DefaultDomain**: `string`

#### Defined in

kerberos.ts:423

___

### KDC

• `Optional` **KDC**: `string`[]

#### Defined in

kerberos.ts:425

___

### KPasswdServer

• `Optional` **KPasswdServer**: `string`[]

#### Defined in

kerberos.ts:427

___

### MasterKDC

• `Optional` **MasterKDC**: `string`[]

#### Defined in

kerberos.ts:429

___

### Realm

• `Optional` **Realm**: `string`

#### Defined in

kerberos.ts:419
````

### `protocols\javascript\modules\kerberos.TGS.md`

````markdown
# Interface: TGS

[kerberos](/templates/protocols/javascript/modules/kerberos).TGS

TGS is the response from GetServiceTicket

## Table of contents

### Properties

- [ErrMsg](/templates/protocols/javascript/modules/kerberos.TGS#errmsg)
- [Hash](/templates/protocols/javascript/modules/kerberos.TGS#hash)
- [Ticket](/templates/protocols/javascript/modules/kerberos.TGS#ticket)

## Properties

### ErrMsg

• `Optional` **ErrMsg**: `string`

#### Defined in

kerberos.ts:443

___

### Hash

• `Optional` **Hash**: `string`

#### Defined in

kerberos.ts:441

___

### Ticket

• `Optional` **Ticket**: [`Ticket`](/templates/protocols/javascript/modules/kerberos.Ticket)

#### Defined in

kerberos.ts:439
````

### `protocols\javascript\modules\kerberos.Ticket.md`

````markdown
# Interface: Ticket

[kerberos](/templates/protocols/javascript/modules/kerberos).Ticket

Ticket Interface

## Table of contents

### Properties

- [DecryptedEncPart](/templates/protocols/javascript/modules/kerberos.Ticket#decryptedencpart)
- [EncPart](/templates/protocols/javascript/modules/kerberos.Ticket#encpart)
- [Realm](/templates/protocols/javascript/modules/kerberos.Ticket#realm)
- [SName](/templates/protocols/javascript/modules/kerberos.Ticket#sname)
- [TktVNO](/templates/protocols/javascript/modules/kerberos.Ticket#tktvno)

## Properties

### DecryptedEncPart

• `Optional` **DecryptedEncPart**: [`EncTicketPart`](/templates/protocols/javascript/modules/kerberos.EncTicketPart)

#### Defined in

kerberos.ts:461

___

### EncPart

• `Optional` **EncPart**: [`EncryptedData`](/templates/protocols/javascript/modules/kerberos.EncryptedData)

#### Defined in

kerberos.ts:459

___

### Realm

• `Optional` **Realm**: `string`

#### Defined in

kerberos.ts:455

___

### SName

• `Optional` **SName**: [`PrincipalName`](/templates/protocols/javascript/modules/kerberos.PrincipalName)

#### Defined in

kerberos.ts:457

___

### TktVNO

• `Optional` **TktVNO**: `number`

#### Defined in

kerberos.ts:453
````

### `protocols\javascript\modules\kerberos.TransitedEncoding.md`

````markdown
# Interface: TransitedEncoding

[kerberos](/templates/protocols/javascript/modules/kerberos).TransitedEncoding

TransitedEncoding Interface

## Table of contents

### Properties

- [Contents](/templates/protocols/javascript/modules/kerberos.TransitedEncoding#contents)
- [TRType](/templates/protocols/javascript/modules/kerberos.TransitedEncoding#trtype)

## Properties

### Contents

• `Optional` **Contents**: `Uint8Array`

#### Defined in

kerberos.ts:473

___

### TRType

• `Optional` **TRType**: `number`

#### Defined in

kerberos.ts:471
````

### `protocols\javascript\modules\ldap.ADObject.md`

````markdown
# Interface: ADObject

[ldap](/templates/protocols/javascript/modules/ldap).ADObject

ADObject represents an Active Directory object

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const users = client.GetADUsers();
log(to_json(users));
```

## Table of contents

### Properties

- [DistinguishedName](/templates/protocols/javascript/modules/ldap.ADObject#distinguishedname)
- [LastLogon](/templates/protocols/javascript/modules/ldap.ADObject#lastlogon)
- [MemberOf](/templates/protocols/javascript/modules/ldap.ADObject#memberof)
- [PWDLastSet](/templates/protocols/javascript/modules/ldap.ADObject#pwdlastset)
- [SAMAccountName](/templates/protocols/javascript/modules/ldap.ADObject#samaccountname)
- [ServicePrincipalName](/templates/protocols/javascript/modules/ldap.ADObject#serviceprincipalname)

## Properties

### DistinguishedName

• `Optional` **DistinguishedName**: `string`

#### Defined in

ldap.ts:496

___

### LastLogon

• `Optional` **LastLogon**: `string`

#### Defined in

ldap.ts:502

___

### MemberOf

• `Optional` **MemberOf**: `string`[]

#### Defined in

ldap.ts:504

___

### PWDLastSet

• `Optional` **PWDLastSet**: `string`

#### Defined in

ldap.ts:500

___

### SAMAccountName

• `Optional` **SAMAccountName**: `string`

#### Defined in

ldap.ts:498

___

### ServicePrincipalName

• `Optional` **ServicePrincipalName**: `string`[]

#### Defined in

ldap.ts:506
````

### `protocols\javascript\modules\ldap.Client.md`

````markdown
# Class: Client

[ldap](/templates/protocols/javascript/modules/ldap).Client

Client is a client for ldap protocol in nuclei

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
// here ldap.example.com is the ldap server and acme.com is the realm
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
```

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const cfg = new ldap.Config();
cfg.Timeout = 10;
cfg.ServerName = 'ldap.internal.acme.com';
// optional config can be passed as third argument
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com', cfg);
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/ldap.Client#constructor)

### Properties

- [BaseDN](/templates/protocols/javascript/modules/ldap.Client#basedn)
- [Host](/templates/protocols/javascript/modules/ldap.Client#host)
- [Port](/templates/protocols/javascript/modules/ldap.Client#port)
- [Realm](/templates/protocols/javascript/modules/ldap.Client#realm)
- [config](/templates/protocols/javascript/modules/ldap.Client#config)
- [ldapUrl](/templates/protocols/javascript/modules/ldap.Client#ldapurl)
- [realm](/templates/protocols/javascript/modules/ldap.Client#realm-1)

### Methods

- [AdvancedSearch](/templates/protocols/javascript/modules/ldap.Client#advancedsearch)
- [Authenticate](/templates/protocols/javascript/modules/ldap.Client#authenticate)
- [AuthenticateWithNTLMHash](/templates/protocols/javascript/modules/ldap.Client#authenticatewithntlmhash)
- [Close](/templates/protocols/javascript/modules/ldap.Client#close)
- [CollectMetadata](/templates/protocols/javascript/modules/ldap.Client#collectmetadata)
- [FindADObjects](/templates/protocols/javascript/modules/ldap.Client#findadobjects)
- [GetADActiveUsers](/templates/protocols/javascript/modules/ldap.Client#getadactiveusers)
- [GetADAdmins](/templates/protocols/javascript/modules/ldap.Client#getadadmins)
- [GetADDCList](/templates/protocols/javascript/modules/ldap.Client#getaddclist)
- [GetADDomainSID](/templates/protocols/javascript/modules/ldap.Client#getaddomainsid)
- [GetADGroups](/templates/protocols/javascript/modules/ldap.Client#getadgroups)
- [GetADUserAsRepRoastable](/templates/protocols/javascript/modules/ldap.Client#getaduserasreproastable)
- [GetADUserKerberoastable](/templates/protocols/javascript/modules/ldap.Client#getaduserkerberoastable)
- [GetADUserTrustedForDelegation](/templates/protocols/javascript/modules/ldap.Client#getadusertrustedfordelegation)
- [GetADUserWithNeverExpiringPasswords](/templates/protocols/javascript/modules/ldap.Client#getaduserwithneverexpiringpasswords)
- [GetADUserWithPasswordNotRequired](/templates/protocols/javascript/modules/ldap.Client#getaduserwithpasswordnotrequired)
- [GetADUsers](/templates/protocols/javascript/modules/ldap.Client#getadusers)
- [Search](/templates/protocols/javascript/modules/ldap.Client#search)

## Constructors

### constructor

• **new Client**(`ldapUrl`, `realm`, `config?`): [`Client`](/templates/protocols/javascript/modules/ldap.Client)

#### Parameters

| Name | Type |
| :------ | :------ |
| `ldapUrl` | `string` |
| `realm` | `string` |
| `config?` | [`Config`](/templates/protocols/javascript/modules/ldap.Config) |

#### Returns

[`Client`](/templates/protocols/javascript/modules/ldap.Client)

#### Defined in

ldap.ts:198

## Properties

### BaseDN

• `Optional` **BaseDN**: `string`

#### Defined in

ldap.ts:194

___

### Host

• `Optional` **Host**: `string`

#### Defined in

ldap.ts:182

___

### Port

• `Optional` **Port**: `number`

#### Defined in

ldap.ts:186

___

### Realm

• `Optional` **Realm**: `string`

#### Defined in

ldap.ts:190

___

### config

• `Optional` **config**: [`Config`](/templates/protocols/javascript/modules/ldap.Config)

#### Defined in

ldap.ts:198

___

### ldapUrl

• **ldapUrl**: `string`

#### Defined in

ldap.ts:198

___

### realm

• **realm**: `string`

#### Defined in

ldap.ts:198

## Methods

### AdvancedSearch

▸ **AdvancedSearch**(`Scope`, `TypesOnly`, `Filter`, `Attributes`, `Controls`): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

AdvancedSearch accepts all values of search request type and return Ldap Entry
its up to user to handle the response

#### Parameters

| Name | Type |
| :------ | :------ |
| `Scope` | `number` |
| `TypesOnly` | `boolean` |
| `Filter` | `string` |
| `Attributes` | `string`[] |
| `Controls` | `any` |

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const results = client.AdvancedSearch(ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, '(objectClass=*)', ['cn', 'mail'], []);
```

#### Defined in

ldap.ts:446

___

### Authenticate

▸ **Authenticate**(`username`): `void`

Authenticate authenticates with the ldap server using the given username and password
performs NTLMBind first and then Bind/UnauthenticatedBind if NTLMBind fails

#### Parameters

| Name | Type |
| :------ | :------ |
| `username` | `string` |

#### Returns

`void`

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
client.Authenticate('user', 'password');
```

#### Defined in

ldap.ts:402

___

### AuthenticateWithNTLMHash

▸ **AuthenticateWithNTLMHash**(`username`): `void`

AuthenticateWithNTLMHash authenticates with the ldap server using the given username and NTLM hash

#### Parameters

| Name | Type |
| :------ | :------ |
| `username` | `string` |

#### Returns

`void`

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
client.AuthenticateWithNTLMHash('pdtm', 'hash');
```

#### Defined in

ldap.ts:416

___

### Close

▸ **Close**(): `void`

close the ldap connection

#### Returns

`void`

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
client.Close();
```

#### Defined in

ldap.ts:475

___

### CollectMetadata

▸ **CollectMetadata**(): [`Metadata`](/templates/protocols/javascript/modules/ldap.Metadata)

CollectLdapMetadata collects metadata from ldap server.

#### Returns

[`Metadata`](/templates/protocols/javascript/modules/ldap.Metadata)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const metadata = client.CollectMetadata();
log(to_json(metadata));
```

#### Defined in

ldap.ts:461

___

### FindADObjects

▸ **FindADObjects**(`filter`): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

FindADObjects finds AD objects based on a filter
and returns them as a list of ADObject

#### Parameters

| Name | Type |
| :------ | :------ |
| `filter` | `string` |

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const users = client.FindADObjects(ldap.FilterIsPerson);
log(to_json(users));
```

#### Defined in

ldap.ts:212

___

### GetADActiveUsers

▸ **GetADActiveUsers**(): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

GetADActiveUsers returns all AD users
using FilterIsPerson and FilterAccountEnabled filter query

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const users = client.GetADActiveUsers();
log(to_json(users));
```

#### Defined in

ldap.ts:244

___

### GetADAdmins

▸ **GetADAdmins**(): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

GetADAdmins returns all AD admins
using FilterIsPerson, FilterAccountEnabled and FilterIsAdmin filter query

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const admins = client.GetADAdmins();
log(to_json(admins));
```

#### Defined in

ldap.ts:340

___

### GetADDCList

▸ **GetADDCList**(): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

GetADDCList returns all AD domain controllers
using FilterIsComputer, FilterAccountEnabled and FilterServerTrustAccount filter query

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const dcs = client.GetADDCList();
log(to_json(dcs));
```

#### Defined in

ldap.ts:324

___

### GetADDomainSID

▸ **GetADDomainSID**(): `string`

GetADDomainSID returns the SID of the AD domain

#### Returns

`string`

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const domainSID = client.GetADDomainSID();
log(domainSID);
```

#### Defined in

ldap.ts:387

___

### GetADGroups

▸ **GetADGroups**(): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

GetADGroups returns all AD groups
using FilterIsGroup filter query

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const groups = client.GetADGroups();
log(to_json(groups));
```

#### Defined in

ldap.ts:308

___

### GetADUserAsRepRoastable

▸ **GetADUserAsRepRoastable**(): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

GetADUserAsRepRoastable returns all AD users that are AsRepRoastable
using FilterIsPerson, and FilterDontRequirePreauth filter query

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const AsRepRoastable = client.GetADUserAsRepRoastable();
log(to_json(AsRepRoastable));
```

#### Defined in

ldap.ts:372

___

### GetADUserKerberoastable

▸ **GetADUserKerberoastable**(): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

GetADUserKerberoastable returns all AD users that are kerberoastable
using FilterIsPerson, FilterAccountEnabled and FilterHasServicePrincipalName filter query

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const kerberoastable = client.GetADUserKerberoastable();
log(to_json(kerberoastable));
```

#### Defined in

ldap.ts:356

___

### GetADUserTrustedForDelegation

▸ **GetADUserTrustedForDelegation**(): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

GetADUserTrustedForDelegation returns all AD users that are trusted for delegation
using FilterIsPerson and FilterTrustedForDelegation filter query

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const users = client.GetADUserTrustedForDelegation();
log(to_json(users));
```

#### Defined in

ldap.ts:276

___

### GetADUserWithNeverExpiringPasswords

▸ **GetADUserWithNeverExpiringPasswords**(): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

GetAdUserWithNeverExpiringPasswords returns all AD users
using FilterIsPerson and FilterDontExpirePassword filter query

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const users = client.GetADUserWithNeverExpiringPasswords();
log(to_json(users));
```

#### Defined in

ldap.ts:260

___

### GetADUserWithPasswordNotRequired

▸ **GetADUserWithPasswordNotRequired**(): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

GetADUserWithPasswordNotRequired returns all AD users that do not require a password
using FilterIsPerson and FilterPasswordNotRequired filter query

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const users = client.GetADUserWithPasswordNotRequired();
log(to_json(users));
```

#### Defined in

ldap.ts:292

___

### GetADUsers

▸ **GetADUsers**(): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

GetADUsers returns all AD users
using FilterIsPerson filter query

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const users = client.GetADUsers();
log(to_json(users));
```

#### Defined in

ldap.ts:228

___

### Search

▸ **Search**(`filter`, `attributes`): [`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

Search accepts whatever filter and returns a list of maps having provided attributes
as keys and associated values mirroring the ones returned by ldap

#### Parameters

| Name | Type |
| :------ | :------ |
| `filter` | `string` |
| `attributes` | `any` |

#### Returns

[`SearchResult`](/templates/protocols/javascript/modules/ldap.SearchResult)

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const results = client.Search('(objectClass=*)', 'cn', 'mail');
```

#### Defined in

ldap.ts:431
````

### `protocols\javascript\modules\ldap.Config.md`

````markdown
# Interface: Config

[ldap](/templates/protocols/javascript/modules/ldap).Config

Config is extra configuration for the ldap client

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const cfg = new ldap.Config();
cfg.Timeout = 10;
cfg.ServerName = 'ldap.internal.acme.com';
cfg.Upgrade = true; // upgrade to tls
```

## Table of contents

### Properties

- [ServerName](/templates/protocols/javascript/modules/ldap.Config#servername)
- [Timeout](/templates/protocols/javascript/modules/ldap.Config#timeout)
- [Upgrade](/templates/protocols/javascript/modules/ldap.Config#upgrade)

## Properties

### ServerName

• `Optional` **ServerName**: `string`

#### Defined in

ldap.ts:503

___

### Timeout

• `Optional` **Timeout**: `number`

Timeout is the timeout for the ldap client in seconds

#### Defined in

ldap.ts:501

___

### Upgrade

• `Optional` **Upgrade**: `boolean`

#### Defined in

ldap.ts:505
````

### `protocols\javascript\modules\ldap.Entry.md`

````markdown
# Interface: Entry

[ldap](/templates/protocols/javascript/modules/ldap).Entry

Entry Interface

## Table of contents

### Properties

- [Attributes](/templates/protocols/javascript/modules/ldap.Entry#attributes)
- [DN](/templates/protocols/javascript/modules/ldap.Entry#dn)

## Properties

### Attributes

• `Optional` **Attributes**: [`EntryAttribute`](/templates/protocols/javascript/modules/ldap.EntryAttribute)

#### Defined in

ldap.ts:544

___

### DN

• `Optional` **DN**: `string`

#### Defined in

ldap.ts:542
````

### `protocols\javascript\modules\ldap.EntryAttribute.md`

````markdown
# Interface: EntryAttribute

[ldap](/templates/protocols/javascript/modules/ldap).EntryAttribute

EntryAttribute Interface

## Table of contents

### Properties

- [ByteValues](/templates/protocols/javascript/modules/ldap.EntryAttribute#bytevalues)
- [Name](/templates/protocols/javascript/modules/ldap.EntryAttribute#name)
- [Values](/templates/protocols/javascript/modules/ldap.EntryAttribute#values)

## Properties

### ByteValues

• `Optional` **ByteValues**: `Uint8Array`

#### Defined in

ldap.ts:554

___

### Name

• `Optional` **Name**: `string`

#### Defined in

ldap.ts:556

___

### Values

• `Optional` **Values**: `string`[]

#### Defined in

ldap.ts:558
````

### `protocols\javascript\modules\ldap.md`

````markdown
# Namespace: ldap

## Table of contents

### Classes

- [Client](/templates/protocols/javascript/modules/ldap.Client)

### Interfaces

- [Config](/templates/protocols/javascript/modules/ldap.Config)
- [LdapAttributes](/templates/protocols/javascript/modules/ldap.LdapAttributes)
- [LdapEntry](/templates/protocols/javascript/modules/ldap.LdapEntry)
- [Metadata](/templates/protocols/javascript/modules/ldap.Metadata)
- [SearchResult](/templates/protocols/javascript/modules/ldap.SearchResult)

### Variables

- [FilterAccountDisabled](/templates/protocols/javascript/modules/ldap#filteraccountdisabled)
- [FilterAccountEnabled](/templates/protocols/javascript/modules/ldap#filteraccountenabled)
- [FilterCanSendEncryptedPassword](/templates/protocols/javascript/modules/ldap#filtercansendencryptedpassword)
- [FilterDontExpirePassword](/templates/protocols/javascript/modules/ldap#filterdontexpirepassword)
- [FilterDontRequirePreauth](/templates/protocols/javascript/modules/ldap#filterdontrequirepreauth)
- [FilterHasServicePrincipalName](/templates/protocols/javascript/modules/ldap#filterhasserviceprincipalname)
- [FilterHomedirRequired](/templates/protocols/javascript/modules/ldap#filterhomedirrequired)
- [FilterInterdomainTrustAccount](/templates/protocols/javascript/modules/ldap#filterinterdomaintrustaccount)
- [FilterIsAdmin](/templates/protocols/javascript/modules/ldap#filterisadmin)
- [FilterIsComputer](/templates/protocols/javascript/modules/ldap#filteriscomputer)
- [FilterIsDuplicateAccount](/templates/protocols/javascript/modules/ldap#filterisduplicateaccount)
- [FilterIsGroup](/templates/protocols/javascript/modules/ldap#filterisgroup)
- [FilterIsNormalAccount](/templates/protocols/javascript/modules/ldap#filterisnormalaccount)
- [FilterIsPerson](/templates/protocols/javascript/modules/ldap#filterisperson)
- [FilterLockout](/templates/protocols/javascript/modules/ldap#filterlockout)
- [FilterLogonScript](/templates/protocols/javascript/modules/ldap#filterlogonscript)
- [FilterMnsLogonAccount](/templates/protocols/javascript/modules/ldap#filtermnslogonaccount)
- [FilterNotDelegated](/templates/protocols/javascript/modules/ldap#filternotdelegated)
- [FilterPartialSecretsAccount](/templates/protocols/javascript/modules/ldap#filterpartialsecretsaccount)
- [FilterPasswordCantChange](/templates/protocols/javascript/modules/ldap#filterpasswordcantchange)
- [FilterPasswordExpired](/templates/protocols/javascript/modules/ldap#filterpasswordexpired)
- [FilterPasswordNotRequired](/templates/protocols/javascript/modules/ldap#filterpasswordnotrequired)
- [FilterServerTrustAccount](/templates/protocols/javascript/modules/ldap#filterservertrustaccount)
- [FilterSmartCardRequired](/templates/protocols/javascript/modules/ldap#filtersmartcardrequired)
- [FilterTrustedForDelegation](/templates/protocols/javascript/modules/ldap#filtertrustedfordelegation)
- [FilterTrustedToAuthForDelegation](/templates/protocols/javascript/modules/ldap#filtertrustedtoauthfordelegation)
- [FilterUseDesKeyOnly](/templates/protocols/javascript/modules/ldap#filterusedeskeyonly)
- [FilterWorkstationTrustAccount](/templates/protocols/javascript/modules/ldap#filterworkstationtrustaccount)

### Functions

- [DecodeADTimestamp](/templates/protocols/javascript/modules/ldap#decodeadtimestamp)
- [DecodeSID](/templates/protocols/javascript/modules/ldap#decodesid)
- [DecodeZuluTimestamp](/templates/protocols/javascript/modules/ldap#decodezulutimestamp)
- [JoinFilters](/templates/protocols/javascript/modules/ldap#joinfilters)
- [NegativeFilter](/templates/protocols/javascript/modules/ldap#negativefilter)

## Variables

### FilterAccountDisabled

• `Const` **FilterAccountDisabled**: ``"(userAccountControl:1.2.840.113556.1.4.803:=2)"``

The user account is disabled.

#### Defined in

ldap.ts:4

___

### FilterAccountEnabled

• `Const` **FilterAccountEnabled**: ``"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"``

The user account is enabled.

#### Defined in

ldap.ts:7

___

### FilterCanSendEncryptedPassword

• `Const` **FilterCanSendEncryptedPassword**: ``"(userAccountControl:1.2.840.113556.1.4.803:=128)"``

The user can send an encrypted password.

#### Defined in

ldap.ts:10

___

### FilterDontExpirePassword

• `Const` **FilterDontExpirePassword**: ``"(userAccountControl:1.2.840.113556.1.4.803:=65536)"``

Represents the password, which should never expire on the account.

#### Defined in

ldap.ts:13

___

### FilterDontRequirePreauth

• `Const` **FilterDontRequirePreauth**: ``"(userAccountControl:1.2.840.113556.1.4.803:=4194304)"``

This account doesn't require Kerberos pre-authentication for logging on.

#### Defined in

ldap.ts:16

___

### FilterHasServicePrincipalName

• `Const` **FilterHasServicePrincipalName**: ``"(servicePrincipalName=*)"``

The object has a service principal name.

#### Defined in

ldap.ts:19

___

### FilterHomedirRequired

• `Const` **FilterHomedirRequired**: ``"(userAccountControl:1.2.840.113556.1.4.803:=8)"``

The home folder is required.

#### Defined in

ldap.ts:22

___

### FilterInterdomainTrustAccount

• `Const` **FilterInterdomainTrustAccount**: ``"(userAccountControl:1.2.840.113556.1.4.803:=2048)"``

It's a permit to trust an account for a system domain that trusts other domains.

#### Defined in

ldap.ts:25

___

### FilterIsAdmin

• `Const` **FilterIsAdmin**: ``"(adminCount=1)"``

The object is an admin.

#### Defined in

ldap.ts:28

___

### FilterIsComputer

• `Const` **FilterIsComputer**: ``"(objectCategory=computer)"``

The object is a computer.

#### Defined in

ldap.ts:31

___

### FilterIsDuplicateAccount

• `Const` **FilterIsDuplicateAccount**: ``"(userAccountControl:1.2.840.113556.1.4.803:=256)"``

It's an account for users whose primary account is in another domain.

#### Defined in

ldap.ts:34

___

### FilterIsGroup

• `Const` **FilterIsGroup**: ``"(objectCategory=group)"``

The object is a group.

#### Defined in

ldap.ts:37

___

### FilterIsNormalAccount

• `Const` **FilterIsNormalAccount**: ``"(userAccountControl:1.2.840.113556.1.4.803:=512)"``

It's a default account type that represents a typical user.

#### Defined in

ldap.ts:40

___

### FilterIsPerson

• `Const` **FilterIsPerson**: ``"(objectCategory=person)"``

The object is a person.

#### Defined in

ldap.ts:43

___

### FilterLockout

• `Const` **FilterLockout**: ``"(userAccountControl:1.2.840.113556.1.4.803:=16)"``

The user is locked out.

#### Defined in

ldap.ts:46

___

### FilterLogonScript

• `Const` **FilterLogonScript**: ``"(userAccountControl:1.2.840.113556.1.4.803:=1)"``

The logon script will be run.

#### Defined in

ldap.ts:49

___

### FilterMnsLogonAccount

• `Const` **FilterMnsLogonAccount**: ``"(userAccountControl:1.2.840.113556.1.4.803:=131072)"``

It's an MNS logon account.

#### Defined in

ldap.ts:52

___

### FilterNotDelegated

• `Const` **FilterNotDelegated**: ``"(userAccountControl:1.2.840.113556.1.4.803:=1048576)"``

When this flag is set, the security context of the user isn't delegated to a service even if the service account is set as trusted for Kerberos delegation.

#### Defined in

ldap.ts:55

___

### FilterPartialSecretsAccount

• `Const` **FilterPartialSecretsAccount**: ``"(userAccountControl:1.2.840.113556.1.4.803:=67108864)"``

The account is a read-only domain controller (RODC).

#### Defined in

ldap.ts:58

___

### FilterPasswordCantChange

• `Const` **FilterPasswordCantChange**: ``"(userAccountControl:1.2.840.113556.1.4.803:=64)"``

The user can't change the password.

#### Defined in

ldap.ts:61

___

### FilterPasswordExpired

• `Const` **FilterPasswordExpired**: ``"(userAccountControl:1.2.840.113556.1.4.803:=8388608)"``

The user's password has expired.

#### Defined in

ldap.ts:64

___

### FilterPasswordNotRequired

• `Const` **FilterPasswordNotRequired**: ``"(userAccountControl:1.2.840.113556.1.4.803:=32)"``

No password is required.

#### Defined in

ldap.ts:67

___

### FilterServerTrustAccount

• `Const` **FilterServerTrustAccount**: ``"(userAccountControl:1.2.840.113556.1.4.803:=8192)"``

It's a computer account for a domain controller that is a member of this domain.

#### Defined in

ldap.ts:70

___

### FilterSmartCardRequired

• `Const` **FilterSmartCardRequired**: ``"(userAccountControl:1.2.840.113556.1.4.803:=262144)"``

When this flag is set, it forces the user to log on by using a smart card.

#### Defined in

ldap.ts:73

___

### FilterTrustedForDelegation

• `Const` **FilterTrustedForDelegation**: ``"(userAccountControl:1.2.840.113556.1.4.803:=524288)"``

When this flag is set, the service account (the user or computer account) under which a service runs is trusted for Kerberos delegation.

#### Defined in

ldap.ts:76

___

### FilterTrustedToAuthForDelegation

• `Const` **FilterTrustedToAuthForDelegation**: ``"(userAccountControl:1.2.840.113556.1.4.803:=16777216)"``

The account is enabled for delegation.

#### Defined in

ldap.ts:79

___

### FilterUseDesKeyOnly

• `Const` **FilterUseDesKeyOnly**: ``"(userAccountControl:1.2.840.113556.1.4.803:=2097152)"``

Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.

#### Defined in

ldap.ts:82

___

### FilterWorkstationTrustAccount

• `Const` **FilterWorkstationTrustAccount**: ``"(userAccountControl:1.2.840.113556.1.4.803:=4096)"``

It's a computer account for a computer that is running old Windows builds.

#### Defined in

ldap.ts:85

## Functions

### DecodeADTimestamp

▸ **DecodeADTimestamp**(`timestamp`): `string`

DecodeADTimestamp decodes an Active Directory timestamp

#### Parameters

| Name | Type |
| :------ | :------ |
| `timestamp` | `string` |

#### Returns

`string`

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const timestamp = ldap.DecodeADTimestamp('132036744000000000');
log(timestamp);
```

#### Defined in

ldap.ts:96

___

### DecodeSID

▸ **DecodeSID**(`s`): `string`

DecodeSID decodes a SID string

#### Parameters

| Name | Type |
| :------ | :------ |
| `s` | `string` |

#### Returns

`string`

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const sid = ldap.DecodeSID('S-1-5-21-3623811015-3361044348-30300820-1013');
log(sid);
```

#### Defined in

ldap.ts:111

___

### DecodeZuluTimestamp

▸ **DecodeZuluTimestamp**(`timestamp`): `string`

DecodeZuluTimestamp decodes a Zulu timestamp

#### Parameters

| Name | Type |
| :------ | :------ |
| `timestamp` | `string` |

#### Returns

`string`

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const timestamp = ldap.DecodeZuluTimestamp('2021-08-25T10:00:00Z');
log(timestamp);
```

#### Defined in

ldap.ts:126

___

### JoinFilters

▸ **JoinFilters**(`filters`): `string`

JoinFilters joins multiple filters into a single filter

#### Parameters

| Name | Type |
| :------ | :------ |
| `filters` | `any` |

#### Returns

`string`

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const filter = ldap.JoinFilters(ldap.FilterIsPerson, ldap.FilterAccountEnabled);
```

#### Defined in

ldap.ts:140

___

### NegativeFilter

▸ **NegativeFilter**(`filter`): `string`

NegativeFilter returns a negative filter for a given filter

#### Parameters

| Name | Type |
| :------ | :------ |
| `filter` | `string` |

#### Returns

`string`

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const filter = ldap.NegativeFilter(ldap.FilterIsPerson);
```

#### Defined in

ldap.ts:154
````

### `protocols\javascript\modules\ldap.Metadata.md`

````markdown
# Interface: Metadata

[ldap](/templates/protocols/javascript/modules/ldap).Metadata

Metadata is the metadata for ldap server.
this is returned by CollectMetadata method

## Table of contents

### Properties

- [BaseDN](/templates/protocols/javascript/modules/ldap.Metadata#basedn)
- [DefaultNamingContext](/templates/protocols/javascript/modules/ldap.Metadata#defaultnamingcontext)
- [DnsHostName](/templates/protocols/javascript/modules/ldap.Metadata#dnshostname)
- [Domain](/templates/protocols/javascript/modules/ldap.Metadata#domain)
- [DomainControllerFunctionality](/templates/protocols/javascript/modules/ldap.Metadata#domaincontrollerfunctionality)
- [DomainFunctionality](/templates/protocols/javascript/modules/ldap.Metadata#domainfunctionality)
- [ForestFunctionality](/templates/protocols/javascript/modules/ldap.Metadata#forestfunctionality)

## Properties

### BaseDN

• `Optional` **BaseDN**: `string`

#### Defined in

ldap.ts:701

___

### DefaultNamingContext

• `Optional` **DefaultNamingContext**: `string`

#### Defined in

ldap.ts:705

___

### DnsHostName

• `Optional` **DnsHostName**: `string`

#### Defined in

ldap.ts:713

___

### Domain

• `Optional` **Domain**: `string`

#### Defined in

ldap.ts:703

___

### DomainControllerFunctionality

• `Optional` **DomainControllerFunctionality**: `string`

#### Defined in

ldap.ts:711

___

### DomainFunctionality

• `Optional` **DomainFunctionality**: `string`

#### Defined in

ldap.ts:707

___

### ForestFunctionality

• `Optional` **ForestFunctionality**: `string`

#### Defined in

ldap.ts:709
````

### `protocols\javascript\modules\ldap.SearchResult.md`

````markdown
# Interface: SearchResult

[ldap](/templates/protocols/javascript/modules/ldap).SearchResult

SearchResult contains search result of any / all ldap search request

**`Example`**

```javascript
const ldap = require('nuclei/ldap');
const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
const results = client.Search('(objectinterface=*)', 'cn', 'mail');
```

## Table of contents

### Properties

- [Controls](/templates/protocols/javascript/modules/ldap.SearchResult#controls)
- [Entries](/templates/protocols/javascript/modules/ldap.SearchResult#entries)
- [Referrals](/templates/protocols/javascript/modules/ldap.SearchResult#referrals)

## Properties

### Controls

• `Optional` **Controls**: `string`[]

Controls contains list of controls

#### Defined in

ldap.ts:739

___

### Entries

• `Optional` **Entries**: [`LdapEntry`](/templates/protocols/javascript/modules/ldap.LdapEntry)[]

Entries contains list of entries

#### Defined in

ldap.ts:745

___

### Referrals

• `Optional` **Referrals**: `string`[]

Referrals contains list of referrals

#### Defined in

ldap.ts:733
````

### `protocols\javascript\modules\mssql.md`

````markdown
# Namespace: mssql

## Table of contents

### Classes

- [MSSQLClient](/templates/protocols/javascript/modules/mssql.MSSQLClient)
````

### `protocols\javascript\modules\mssql.MSSQLClient.md`

````markdown
# Class: MSSQLClient

[mssql](/templates/protocols/javascript/modules/mssql).MSSQLClient

Client is a client for MS SQL database.
Internally client uses microsoft/go-mssqldb driver.

**`Example`**

```javascript
const mssql = require('nuclei/mssql');
const client = new mssql.MSSQLClient;
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/mssql.MSSQLClient#constructor)

### Methods

- [Connect](/templates/protocols/javascript/modules/mssql.MSSQLClient#connect)
- [ConnectWithDB](/templates/protocols/javascript/modules/mssql.MSSQLClient#connectwithdb)
- [IsMssql](/templates/protocols/javascript/modules/mssql.MSSQLClient#ismssql)

## Constructors

### constructor

• **new MSSQLClient**(): [`MSSQLClient`](/templates/protocols/javascript/modules/mssql.MSSQLClient)

#### Returns

[`MSSQLClient`](/templates/protocols/javascript/modules/mssql.MSSQLClient)

#### Defined in

mssql.ts:16

## Methods

### Connect

▸ **Connect**(`host`, `port`, `username`): `boolean`

Connect connects to MS SQL database using given credentials.
If connection is successful, it returns true.
If connection is unsuccessful, it returns false and error.
The connection is closed after the function returns.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `username` | `string` |

#### Returns

`boolean`

**`Example`**

```javascript
const mssql = require('nuclei/mssql');
const client = new mssql.MSSQLClient;
const connected = client.Connect('acme.com', 1433, 'username', 'password');
```

#### Defined in

mssql.ts:29

___

### ConnectWithDB

▸ **ConnectWithDB**(`host`, `port`, `username`): `boolean`

ConnectWithDB connects to MS SQL database using given credentials and database name.
If connection is successful, it returns true.
If connection is unsuccessful, it returns false and error.
The connection is closed after the function returns.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `username` | `string` |

#### Returns

`boolean`

**`Example`**

```javascript
const mssql = require('nuclei/mssql');
const client = new mssql.MSSQLClient;
const connected = client.ConnectWithDB('acme.com', 1433, 'username', 'password', 'master');
```

#### Defined in

mssql.ts:46

___

### IsMssql

▸ **IsMssql**(`host`, `port`): `boolean`

IsMssql checks if the given host is running MS SQL database.
If the host is running MS SQL database, it returns true.
If the host is not running MS SQL database, it returns false.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

`boolean`

**`Example`**

```javascript
const mssql = require('nuclei/mssql');
const isMssql = mssql.IsMssql('acme.com', 1433);
```

#### Defined in

mssql.ts:61
````

### `protocols\javascript\modules\mysql.md`

````markdown
# Namespace: mysql

## Table of contents

### Classes

- [MySQLClient](/templates/protocols/javascript/modules/mysql.MySQLClient)

### Interfaces

- [MySQLInfo](/templates/protocols/javascript/modules/mysql.MySQLInfo)
- [MySQLOptions](/templates/protocols/javascript/modules/mysql.MySQLOptions)
- [SQLResult](/templates/protocols/javascript/modules/mysql.SQLResult)
- [ServiceMySQL](/templates/protocols/javascript/modules/mysql.ServiceMySQL)

### Functions

- [BuildDSN](/templates/protocols/javascript/modules/mysql#builddsn)

## Functions

### BuildDSN

▸ **BuildDSN**(`opts`): `string` \| ``null``

BuildDSN builds a MySQL data source name (DSN) from the given options.

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | [`MySQLOptions`](/templates/protocols/javascript/modules/mysql.MySQLOptions) |

#### Returns

`string` \| ``null``

**`Example`**

```javascript
const mysql = require('nuclei/mysql');
const options = new mysql.MySQLOptions();
options.Host = 'acme.com';
options.Port = 3306;
const dsn = mysql.BuildDSN(options);
```

#### Defined in

mysql.ts:14
````

### `protocols\javascript\modules\mysql.MySQLClient.md`

````markdown
# Class: MySQLClient

[mysql](/templates/protocols/javascript/modules/mysql).MySQLClient

MySQLClient is a client for MySQL database.
Internally client uses go-sql-driver/mysql driver.

**`Example`**

```javascript
const mysql = require('nuclei/mysql');
const client = new mysql.MySQLClient;
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/mysql.MySQLClient#constructor)

### Methods

- [Connect](/templates/protocols/javascript/modules/mysql.MySQLClient#connect)
- [ConnectWithDSN](/templates/protocols/javascript/modules/mysql.MySQLClient#connectwithdsn)
- [ExecuteQuery](/templates/protocols/javascript/modules/mysql.MySQLClient#executequery)
- [ExecuteQueryOnDB](/templates/protocols/javascript/modules/mysql.MySQLClient#executequeryondb)
- [ExecuteQueryWithOpts](/templates/protocols/javascript/modules/mysql.MySQLClient#executequerywithopts)
- [FingerprintMySQL](/templates/protocols/javascript/modules/mysql.MySQLClient#fingerprintmysql)
- [IsMySQL](/templates/protocols/javascript/modules/mysql.MySQLClient#ismysql)

## Constructors

### constructor

• **new MySQLClient**(): [`MySQLClient`](/templates/protocols/javascript/modules/mysql.MySQLClient)

#### Returns

[`MySQLClient`](/templates/protocols/javascript/modules/mysql.MySQLClient)

#### Defined in

mysql.ts:33

## Methods

### Connect

▸ **Connect**(`host`, `port`, `username`): `boolean`

Connect connects to MySQL database using given credentials.
If connection is successful, it returns true.
If connection is unsuccessful, it returns false and error.
The connection is closed after the function returns.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `username` | `string` |

#### Returns

`boolean`

**`Example`**

```javascript
const mysql = require('nuclei/mysql');
const client = new mysql.MySQLClient;
const connected = client.Connect('acme.com', 3306, 'username', 'password');
```

#### Defined in

mysql.ts:61

___

### ConnectWithDSN

▸ **ConnectWithDSN**(`dsn`): `boolean`

ConnectWithDSN connects to MySQL database using given DSN.
we override mysql dialer with fastdialer so it respects network policy
If connection is successful, it returns true.

#### Parameters

| Name | Type |
| :------ | :------ |
| `dsn` | `string` |

#### Returns

`boolean`

**`Example`**

```javascript
const mysql = require('nuclei/mysql');
const client = new mysql.MySQLClient;
const connected = client.ConnectWithDSN('username:password@tcp(acme.com:3306)/');
```

#### Defined in

mysql.ts:91

___

### ExecuteQuery

▸ **ExecuteQuery**(`host`, `port`, `username`): [`SQLResult`](/templates/protocols/javascript/modules/mysql.SQLResult)

ExecuteQuery connects to Mysql database using given credentials
and executes a query on the db.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `username` | `string` |

#### Returns

[`SQLResult`](/templates/protocols/javascript/modules/mysql.SQLResult)

**`Example`**

```javascript
const mysql = require('nuclei/mysql');
const result = mysql.ExecuteQuery('acme.com', 3306, 'username', 'password', 'SELECT * FROM users');
log(to_json(result));
```

#### Defined in

mysql.ts:124

___

### ExecuteQueryOnDB

▸ **ExecuteQueryOnDB**(`host`, `port`, `username`): [`SQLResult`](/templates/protocols/javascript/modules/mysql.SQLResult)

ExecuteQuery connects to Mysql database using given credentials
and executes a query on the db.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `username` | `string` |

#### Returns

[`SQLResult`](/templates/protocols/javascript/modules/mysql.SQLResult)

**`Example`**

```javascript
const mysql = require('nuclei/mysql');
const result = mysql.ExecuteQueryOnDB('acme.com', 3306, 'username', 'password', 'dbname', 'SELECT * FROM users');
log(to_json(result));
```

#### Defined in

mysql.ts:139

___

### ExecuteQueryWithOpts

▸ **ExecuteQueryWithOpts**(`opts`, `query`): [`SQLResult`](/templates/protocols/javascript/modules/mysql.SQLResult)

ExecuteQueryWithOpts connects to Mysql database using given credentials
and executes a query on the db.

#### Parameters

| Name | Type |
| :------ | :------ |
| `opts` | [`MySQLOptions`](/templates/protocols/javascript/modules/mysql.MySQLOptions) |
| `query` | `string` |

#### Returns

[`SQLResult`](/templates/protocols/javascript/modules/mysql.SQLResult)

**`Example`**

```javascript
const mysql = require('nuclei/mysql');
const options = new mysql.MySQLOptions();
options.Host = 'acme.com';
options.Port = 3306;
const result = mysql.ExecuteQueryWithOpts(options, 'SELECT * FROM users');
log(to_json(result));
```

#### Defined in

mysql.ts:109

___

### FingerprintMySQL

▸ **FingerprintMySQL**(`host`, `port`): [`MySQLInfo`](/templates/protocols/javascript/modules/mysql.MySQLInfo)

returns MySQLInfo when fingerpint is successful

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`MySQLInfo`](/templates/protocols/javascript/modules/mysql.MySQLInfo)

**`Example`**

```javascript
const mysql = require('nuclei/mysql');
const info = mysql.FingerprintMySQL('acme.com', 3306);
log(to_json(info));
```

#### Defined in

mysql.ts:75

___

### IsMySQL

▸ **IsMySQL**(`host`, `port`): `boolean`

IsMySQL checks if the given host is running MySQL database.
If the host is running MySQL database, it returns true.
If the host is not running MySQL database, it returns false.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

`boolean`

**`Example`**

```javascript
const mysql = require('nuclei/mysql');
const isMySQL = mysql.IsMySQL('acme.com', 3306);
```

#### Defined in

mysql.ts:44
````

### `protocols\javascript\modules\mysql.MySQLInfo.md`

````markdown
# Interface: MySQLInfo

[mysql](/templates/protocols/javascript/modules/mysql).MySQLInfo

MySQLInfo contains information about MySQL server.
this is returned when fingerprint is successful

## Table of contents

### Properties

- [Debug](/templates/protocols/javascript/modules/mysql.MySQLInfo#debug)
- [Host](/templates/protocols/javascript/modules/mysql.MySQLInfo#host)
- [IP](/templates/protocols/javascript/modules/mysql.MySQLInfo#ip)
- [Port](/templates/protocols/javascript/modules/mysql.MySQLInfo#port)
- [Protocol](/templates/protocols/javascript/modules/mysql.MySQLInfo#protocol)
- [Raw](/templates/protocols/javascript/modules/mysql.MySQLInfo#raw)
- [TLS](/templates/protocols/javascript/modules/mysql.MySQLInfo#tls)
- [Transport](/templates/protocols/javascript/modules/mysql.MySQLInfo#transport)
- [Version](/templates/protocols/javascript/modules/mysql.MySQLInfo#version)

## Properties

### Debug

• `Optional` **Debug**: [`ServiceMySQL`](/templates/protocols/javascript/modules/mysql.ServiceMySQL)

#### Defined in

mysql.ts:168

___

### Host

• `Optional` **Host**: `string`

#### Defined in

mysql.ts:154

___

### IP

• `Optional` **IP**: `string`

#### Defined in

mysql.ts:156

___

### Port

• `Optional` **Port**: `number`

#### Defined in

mysql.ts:158

___

### Protocol

• `Optional` **Protocol**: `string`

#### Defined in

mysql.ts:160

___

### Raw

• `Optional` **Raw**: `string`

#### Defined in

mysql.ts:170

___

### TLS

• `Optional` **TLS**: `boolean`

#### Defined in

mysql.ts:162

___

### Transport

• `Optional` **Transport**: `string`

#### Defined in

mysql.ts:164

___

### Version

• `Optional` **Version**: `string`

#### Defined in

mysql.ts:166
````

### `protocols\javascript\modules\mysql.MySQLOptions.md`

````markdown
# Interface: MySQLOptions

[mysql](/templates/protocols/javascript/modules/mysql).MySQLOptions

MySQLOptions defines the data source name (DSN) options required to connect to a MySQL database.
along with other options like Timeout etc

**`Example`**

```javascript
const mysql = require('nuclei/mysql');
const options = new mysql.MySQLOptions();
options.Host = 'acme.com';
options.Port = 3306;
```

## Table of contents

### Properties

- [DbName](/templates/protocols/javascript/modules/mysql.MySQLOptions#dbname)
- [Host](/templates/protocols/javascript/modules/mysql.MySQLOptions#host)
- [Password](/templates/protocols/javascript/modules/mysql.MySQLOptions#password)
- [Port](/templates/protocols/javascript/modules/mysql.MySQLOptions#port)
- [Protocol](/templates/protocols/javascript/modules/mysql.MySQLOptions#protocol)
- [RawQuery](/templates/protocols/javascript/modules/mysql.MySQLOptions#rawquery)
- [Timeout](/templates/protocols/javascript/modules/mysql.MySQLOptions#timeout)
- [Username](/templates/protocols/javascript/modules/mysql.MySQLOptions#username)

## Properties

### DbName

• `Optional` **DbName**: `string`

#### Defined in

mysql.ts:198

___

### Host

• `Optional` **Host**: `string`

#### Defined in

mysql.ts:188

___

### Password

• `Optional` **Password**: `string`

#### Defined in

mysql.ts:196

___

### Port

• `Optional` **Port**: `number`

#### Defined in

mysql.ts:190

___

### Protocol

• `Optional` **Protocol**: `string`

#### Defined in

mysql.ts:192

___

### RawQuery

• `Optional` **RawQuery**: `string`

#### Defined in

mysql.ts:200

___

### Timeout

• `Optional` **Timeout**: `number`

#### Defined in

mysql.ts:202

___

### Username

• `Optional` **Username**: `string`

#### Defined in

mysql.ts:194
````

### `protocols\javascript\modules\mysql.ServiceMySQL.md`

````markdown
# Interface: ServiceMySQL

[mysql](/templates/protocols/javascript/modules/mysql).ServiceMySQL

ServiceMySQL Interface

## Table of contents

### Properties

- [ErrorCode](/templates/protocols/javascript/modules/mysql.ServiceMySQL#errorcode)
- [ErrorMessage](/templates/protocols/javascript/modules/mysql.ServiceMySQL#errormessage)
- [PacketType](/templates/protocols/javascript/modules/mysql.ServiceMySQL#packettype)

## Properties

### ErrorCode

• `Optional` **ErrorCode**: `number`

#### Defined in

mysql.ts:228

___

### ErrorMessage

• `Optional` **ErrorMessage**: `string`

#### Defined in

mysql.ts:226

___

### PacketType

• `Optional` **PacketType**: `string`

#### Defined in

mysql.ts:224
````

### `protocols\javascript\modules\mysql.SQLResult.md`

````markdown
# Interface: SQLResult

[mysql](/templates/protocols/javascript/modules/mysql).SQLResult

SQLResult Interface

## Table of contents

### Properties

- [Columns](/templates/protocols/javascript/modules/mysql.SQLResult#columns)
- [Count](/templates/protocols/javascript/modules/mysql.SQLResult#count)

## Properties

### Columns

• `Optional` **Columns**: `string`[]

#### Defined in

mysql.ts:214

___

### Count

• `Optional` **Count**: `number`

#### Defined in

mysql.ts:212
````

### `protocols\javascript\modules\net.md`

````markdown
# Namespace: net

## Table of contents

### Classes

- [NetConn](/templates/protocols/javascript/modules/net.NetConn)

### Functions

- [Open](/templates/protocols/javascript/modules/net#open)
- [OpenTLS](/templates/protocols/javascript/modules/net#opentls)

## Functions

### Open

▸ **Open**(`protocol`): [`NetConn`](/templates/protocols/javascript/modules/net.NetConn) \| ``null``

Open opens a new connection to the address with a timeout.
supported protocols: tcp, udp

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | `string` |

#### Returns

[`NetConn`](/templates/protocols/javascript/modules/net.NetConn) \| ``null``

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
```

#### Defined in

net.ts:12

___

### OpenTLS

▸ **OpenTLS**(`protocol`): [`NetConn`](/templates/protocols/javascript/modules/net.NetConn) \| ``null``

Open opens a new connection to the address with a timeout.
supported protocols: tcp, udp

#### Parameters

| Name | Type |
| :------ | :------ |
| `protocol` | `string` |

#### Returns

[`NetConn`](/templates/protocols/javascript/modules/net.NetConn) \| ``null``

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.OpenTLS('tcp', 'acme.com:443');
```

#### Defined in

net.ts:27
````

### `protocols\javascript\modules\net.NetConn.md`

````markdown
# Class: NetConn

[net](/templates/protocols/javascript/modules/net).NetConn

NetConn is a connection to a remote host.
this is returned/create by Open and OpenTLS functions.

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/net.NetConn#constructor)

### Methods

- [Close](/templates/protocols/javascript/modules/net.NetConn#close)
- [Recv](/templates/protocols/javascript/modules/net.NetConn#recv)
- [RecvFull](/templates/protocols/javascript/modules/net.NetConn#recvfull)
- [RecvFullHex](/templates/protocols/javascript/modules/net.NetConn#recvfullhex)
- [RecvFullString](/templates/protocols/javascript/modules/net.NetConn#recvfullstring)
- [RecvHex](/templates/protocols/javascript/modules/net.NetConn#recvhex)
- [RecvString](/templates/protocols/javascript/modules/net.NetConn#recvstring)
- [Send](/templates/protocols/javascript/modules/net.NetConn#send)
- [SendArray](/templates/protocols/javascript/modules/net.NetConn#sendarray)
- [SendHex](/templates/protocols/javascript/modules/net.NetConn#sendhex)
- [SetTimeout](/templates/protocols/javascript/modules/net.NetConn#settimeout)

## Constructors

### constructor

• **new NetConn**(): [`NetConn`](/templates/protocols/javascript/modules/net.NetConn)

#### Returns

[`NetConn`](/templates/protocols/javascript/modules/net.NetConn)

#### Defined in

net.ts:46

## Methods

### Close

▸ **Close**(): `void`

Close closes the connection.

#### Returns

`void`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
conn.Close();
```

#### Defined in

net.ts:56

___

### Recv

▸ **Recv**(`N`): `Uint8Array`

Recv is similar to RecvFull but does not guarantee full read instead
it creates a buffer of N bytes and returns whatever is returned by the connection
for reading headers or initial bytes from the server this is usually used.
for reading a fixed number of already known bytes (ex: body based on content-length) use RecvFull.

#### Parameters

| Name | Type |
| :------ | :------ |
| `N` | `number` |

#### Returns

`Uint8Array`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
const data = conn.Recv(1024);
log(`Received ${data.length} bytes from the server`)
```

#### Defined in

net.ts:146

___

### RecvFull

▸ **RecvFull**(`N`): `Uint8Array`

RecvFull receives data from the connection with a timeout.
If N is 0, it will read all data sent by the server with 8MB limit.
it tries to read until N bytes or timeout is reached.

#### Parameters

| Name | Type |
| :------ | :------ |
| `N` | `number` |

#### Returns

`Uint8Array`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
const data = conn.RecvFull(1024);
```

#### Defined in

net.ts:128

___

### RecvFullHex

▸ **RecvFullHex**(`N`): `string`

RecvFullHex receives data from the connection with a timeout
in hex format.
If N is 0,it will read all data sent by the server with 8MB limit.
until N bytes or timeout is reached.

#### Parameters

| Name | Type |
| :------ | :------ |
| `N` | `number` |

#### Returns

`string`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
const data = conn.RecvFullHex(1024);
```

#### Defined in

net.ts:196

___

### RecvFullString

▸ **RecvFullString**(`N`): `string`

RecvFullString receives data from the connection with a timeout
output is returned as a string.
If N is 0, it will read all data sent by the server with 8MB limit.

#### Parameters

| Name | Type |
| :------ | :------ |
| `N` | `number` |

#### Returns

`string`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
const data = conn.RecvFullString(1024);
```

#### Defined in

net.ts:162

___

### RecvHex

▸ **RecvHex**(`N`): `string`

RecvHex is similar to RecvFullHex but does not guarantee full read instead
it creates a buffer of N bytes and returns whatever is returned by the connection
for reading headers or initial bytes from the server this is usually used.
for reading a fixed number of already known bytes (ex: body based on content-length) use RecvFull.

#### Parameters

| Name | Type |
| :------ | :------ |
| `N` | `number` |

#### Returns

`string`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
const data = conn.RecvHex(1024);
```

#### Defined in

net.ts:213

___

### RecvString

▸ **RecvString**(`N`): `string`

RecvString is similar to RecvFullString but does not guarantee full read, instead
it creates a buffer of N bytes and returns whatever is returned by the connection
for reading headers or initial bytes from the server this is usually used.
for reading a fixed number of already known bytes (ex: body based on content-length) use RecvFullString.

#### Parameters

| Name | Type |
| :------ | :------ |
| `N` | `number` |

#### Returns

`string`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
const data = conn.RecvString(1024);
```

#### Defined in

net.ts:179

___

### Send

▸ **Send**(`data`): `void`

Send sends data to the connection with a timeout.

#### Parameters

| Name | Type |
| :------ | :------ |
| `data` | `string` |

#### Returns

`void`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
conn.Send('hello');
```

#### Defined in

net.ts:112

___

### SendArray

▸ **SendArray**(`data`): `void`

SendArray sends array data to connection

#### Parameters

| Name | Type |
| :------ | :------ |
| `data` | `any` |

#### Returns

`void`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
conn.SendArray(['hello', 'world']);
```

#### Defined in

net.ts:84

___

### SendHex

▸ **SendHex**(`data`): `void`

SendHex sends hex data to connection

#### Parameters

| Name | Type |
| :------ | :------ |
| `data` | `string` |

#### Returns

`void`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
conn.SendHex('68656c6c6f');
```

#### Defined in

net.ts:98

___

### SetTimeout

▸ **SetTimeout**(`value`): `void`

SetTimeout sets read/write timeout for the connection (in seconds).

#### Parameters

| Name | Type |
| :------ | :------ |
| `value` | `number` |

#### Returns

`void`

**`Example`**

```javascript
const net = require('nuclei/net');
const conn = net.Open('tcp', 'acme.com:80');
conn.SetTimeout(10);
```

#### Defined in

net.ts:70
````

### `protocols\javascript\modules\oracle.IsOracleResponse.md`

````markdown
# Interface: IsOracleResponse

[oracle](/templates/protocols/javascript/modules/oracle).IsOracleResponse

IsOracleResponse is the response from the IsOracle function.
this is returned by IsOracle function.

**`Example`**

```javascript
const oracle = require('nuclei/oracle');
const isOracle = oracle.IsOracle('acme.com', 1521);
```

## Table of contents

### Properties

- [Banner](/templates/protocols/javascript/modules/oracle.IsOracleResponse#banner)
- [IsOracle](/templates/protocols/javascript/modules/oracle.IsOracleResponse#isoracle)

## Properties

### Banner

• `Optional` **Banner**: `string`

#### Defined in

oracle.ts:31

___

### IsOracle

• `Optional` **IsOracle**: `boolean`

#### Defined in

oracle.ts:29
````

### `protocols\javascript\modules\oracle.md`

````markdown
# Namespace: oracle

## Table of contents

### Interfaces

- [IsOracleResponse](/templates/protocols/javascript/modules/oracle.IsOracleResponse)

### Functions

- [IsOracle](/templates/protocols/javascript/modules/oracle#isoracle)

## Functions

### IsOracle

▸ **IsOracle**(`host`, `port`): [`IsOracleResponse`](/templates/protocols/javascript/modules/oracle.IsOracleResponse) \| ``null``

IsOracle checks if a host is running an Oracle server

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsOracleResponse`](/templates/protocols/javascript/modules/oracle.IsOracleResponse) \| ``null``

**`Example`**

```javascript
const oracle = require('nuclei/oracle');
const isOracle = oracle.IsOracle('acme.com', 1521);
log(toJSON(isOracle));
```

#### Defined in

oracle.ts:12
````

### `protocols\javascript\modules\oracle.OracleClient.md`

````markdown
# Class: OracleClient

[oracle](/templates/protocols/javascript/modules/oracle).OracleClient

OracleClient is a minimal Oracle client for nuclei scripts.

**`Example`**

```javascript
const oracle = require('nuclei/oracle');
const client = new oracle.Client();
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/oracle.OracleClient#constructor)

### Methods

- [IsOracle](/templates/protocols/javascript/modules/oracle.OracleClient#isoracle)

## Constructors

### constructor

• **new OracleClient**(): [`OracleClient`](/templates/protocols/javascript/modules/oracle.OracleClient)

#### Returns

[`OracleClient`](/templates/protocols/javascript/modules/oracle.OracleClient)

#### Defined in

oracle.ts:15

## Methods

### IsOracle

▸ **IsOracle**(`host`, `port`): [`IsOracleResponse`](/templates/protocols/javascript/modules/oracle.IsOracleResponse)

IsOracle checks if a host is running an Oracle server

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsOracleResponse`](/templates/protocols/javascript/modules/oracle.IsOracleResponse)

**`Example`**

```javascript
const oracle = require('nuclei/oracle');
const isOracle = oracle.IsOracle('acme.com', 1521);
log(toJSON(isOracle));
```

#### Defined in

oracle.ts:25
````

### `protocols\javascript\modules\pop3.IsPOP3Response.md`

````markdown
# Interface: IsPOP3Response

[pop3](/templates/protocols/javascript/modules/pop3).IsPOP3Response

IsPOP3Response is the response from the IsPOP3 function.
this is returned by IsPOP3 function.

**`Example`**

```javascript
const pop3 = require('nuclei/pop3');
const isPOP3 = pop3.IsPOP3('acme.com', 110);
log(toJSON(isPOP3));
```

## Table of contents

### Properties

- [Banner](/templates/protocols/javascript/modules/pop3.IsPOP3Response#banner)
- [IsPOP3](/templates/protocols/javascript/modules/pop3.IsPOP3Response#ispop3)

## Properties

### Banner

• `Optional` **Banner**: `string`

#### Defined in

pop3.ts:32

___

### IsPOP3

• `Optional` **IsPOP3**: `boolean`

#### Defined in

pop3.ts:30
````

### `protocols\javascript\modules\pop3.md`

````markdown
# Namespace: pop3

## Table of contents

### Interfaces

- [IsPOP3Response](/templates/protocols/javascript/modules/pop3.IsPOP3Response)

### Functions

- [IsPOP3](/templates/protocols/javascript/modules/pop3#ispop3)

## Functions

### IsPOP3

▸ **IsPOP3**(`host`, `port`): [`IsPOP3Response`](/templates/protocols/javascript/modules/pop3.IsPOP3Response) \| ``null``

IsPOP3 checks if a host is running a POP3 server.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsPOP3Response`](/templates/protocols/javascript/modules/pop3.IsPOP3Response) \| ``null``

**`Example`**

```javascript
const pop3 = require('nuclei/pop3');
const isPOP3 = pop3.IsPOP3('acme.com', 110);
log(toJSON(isPOP3));
```

#### Defined in

pop3.ts:12
````

### `protocols\javascript\modules\pop3.Pop3Client.md`

````markdown
# Class: Pop3Client

[pop3](/templates/protocols/javascript/modules/pop3).Pop3Client

Pop3Client is a minimal POP3 client for nuclei scripts.

**`Example`**

```javascript
const pop3 = require('nuclei/pop3');
const client = new pop3.Client();
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/pop3.Pop3Client#constructor)

### Methods

- [IsPOP3](/templates/protocols/javascript/modules/pop3.Pop3Client#ispop3)

## Constructors

### constructor

• **new Pop3Client**(): [`Pop3Client`](/templates/protocols/javascript/modules/pop3.Pop3Client)

#### Returns

[`Pop3Client`](/templates/protocols/javascript/modules/pop3.Pop3Client)

#### Defined in

pop3.ts:15

## Methods

### IsPOP3

▸ **IsPOP3**(`host`, `port`): [`IsPOP3Response`](/templates/protocols/javascript/modules/pop3.IsPOP3Response)

IsPOP3 checks if a host is running a POP3 server.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsPOP3Response`](/templates/protocols/javascript/modules/pop3.IsPOP3Response)

**`Example`**

```javascript
const pop3 = require('nuclei/pop3');
const isPOP3 = pop3.IsPOP3('acme.com', 110);
log(toJSON(isPOP3));
```

#### Defined in

pop3.ts:25
````

### `protocols\javascript\modules\postgres.md`

````markdown
# Namespace: postgres

## Table of contents

### Classes

- [PGClient](/templates/protocols/javascript/modules/postgres.PGClient)

### Interfaces

- [SQLResult](/templates/protocols/javascript/modules/postgres.SQLResult)
````

### `protocols\javascript\modules\postgres.PGClient.md`

````markdown
# Class: PGClient

[postgres](/templates/protocols/javascript/modules/postgres).PGClient

PGClient is a client for Postgres database.
Internally client uses go-pg/pg driver.

**`Example`**

```javascript
const postgres = require('nuclei/postgres');
const client = new postgres.PGClient;
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/postgres.PGClient#constructor)

### Methods

- [Connect](/templates/protocols/javascript/modules/postgres.PGClient#connect)
- [ConnectWithDB](/templates/protocols/javascript/modules/postgres.PGClient#connectwithdb)
- [ExecuteQuery](/templates/protocols/javascript/modules/postgres.PGClient#executequery)
- [IsPostgres](/templates/protocols/javascript/modules/postgres.PGClient#ispostgres)

## Constructors

### constructor

• **new PGClient**(): [`PGClient`](/templates/protocols/javascript/modules/postgres.PGClient)

#### Returns

[`PGClient`](/templates/protocols/javascript/modules/postgres.PGClient)

#### Defined in

postgres.ts:16

## Methods

### Connect

▸ **Connect**(`host`, `port`, `username`): `boolean`

Connect connects to Postgres database using given credentials.
If connection is successful, it returns true.
If connection is unsuccessful, it returns false and error.
The connection is closed after the function returns.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `username` | `string` |

#### Returns

`boolean`

**`Example`**

```javascript
const postgres = require('nuclei/postgres');
const client = new postgres.PGClient;
const connected = client.Connect('acme.com', 5432, 'username', 'password');
```

#### Defined in

postgres.ts:44

___

### ConnectWithDB

▸ **ConnectWithDB**(`host`, `port`, `username`): `boolean`

ConnectWithDB connects to Postgres database using given credentials and database name.
If connection is successful, it returns true.
If connection is unsuccessful, it returns false and error.
The connection is closed after the function returns.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `username` | `string` |

#### Returns

`boolean`

**`Example`**

```javascript
const postgres = require('nuclei/postgres');
const client = new postgres.PGClient;
const connected = client.ConnectWithDB('acme.com', 5432, 'username', 'password', 'dbname');
```

#### Defined in

postgres.ts:78

___

### ExecuteQuery

▸ **ExecuteQuery**(`host`, `port`, `username`): [`SQLResult`](/templates/protocols/javascript/modules/postgres.SQLResult)

ExecuteQuery connects to Postgres database using given credentials and database name.
and executes a query on the db.
If connection is successful, it returns the result of the query.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `username` | `string` |

#### Returns

[`SQLResult`](/templates/protocols/javascript/modules/postgres.SQLResult)

**`Example`**

```javascript
const postgres = require('nuclei/postgres');
const client = new postgres.PGClient;
const result = client.ExecuteQuery('acme.com', 5432, 'username', 'password', 'dbname', 'select * from users');
log(to_json(result));
```

#### Defined in

postgres.ts:61

___

### IsPostgres

▸ **IsPostgres**(`host`, `port`): `boolean`

IsPostgres checks if the given host and port are running Postgres database.
If connection is successful, it returns true.
If connection is unsuccessful, it returns false and error.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

`boolean`

**`Example`**

```javascript
const postgres = require('nuclei/postgres');
const isPostgres = postgres.IsPostgres('acme.com', 5432);
```

#### Defined in

postgres.ts:27
````

### `protocols\javascript\modules\postgres.SQLResult.md`

````markdown
# Interface: SQLResult

[postgres](/templates/protocols/javascript/modules/postgres).SQLResult

SQLResult Interface

## Table of contents

### Properties

- [Columns](/templates/protocols/javascript/modules/postgres.SQLResult#columns)
- [Count](/templates/protocols/javascript/modules/postgres.SQLResult#count)

## Properties

### Columns

• `Optional` **Columns**: `string`[]

#### Defined in

postgres.ts:94

___

### Count

• `Optional` **Count**: `number`

#### Defined in

postgres.ts:92
````

### `protocols\javascript\modules\rdp.CheckRDPAuthResponse.md`

````markdown
# Interface: CheckRDPAuthResponse

[rdp](/templates/protocols/javascript/modules/rdp).CheckRDPAuthResponse

CheckRDPAuthResponse is the response from the CheckRDPAuth function.
this is returned by CheckRDPAuth function.

**`Example`**

```javascript
const rdp = require('nuclei/rdp');
const checkRDPAuth = rdp.CheckRDPAuth('acme.com', 3389);
log(toJSON(checkRDPAuth));
```

## Table of contents

### Properties

- [Auth](/templates/protocols/javascript/modules/rdp.CheckRDPAuthResponse#auth)
- [PluginInfo](/templates/protocols/javascript/modules/rdp.CheckRDPAuthResponse#plugininfo)

## Properties

### Auth

• `Optional` **Auth**: `boolean`

#### Defined in

rdp.ts:52

___

### PluginInfo

• `Optional` **PluginInfo**: [`ServiceRDP`](/templates/protocols/javascript/modules/rdp.ServiceRDP)

#### Defined in

rdp.ts:50
````

### `protocols\javascript\modules\rdp.IsRDPResponse.md`

````markdown
# Interface: IsRDPResponse

[rdp](/templates/protocols/javascript/modules/rdp).IsRDPResponse

IsRDPResponse is the response from the IsRDP function.
this is returned by IsRDP function.

**`Example`**

```javascript
const rdp = require('nuclei/rdp');
const isRDP = rdp.IsRDP('acme.com', 3389);
log(toJSON(isRDP));
```

## Table of contents

### Properties

- [IsRDP](/templates/protocols/javascript/modules/rdp.IsRDPResponse#isrdp)
- [OS](/templates/protocols/javascript/modules/rdp.IsRDPResponse#os)

## Properties

### IsRDP

• `Optional` **IsRDP**: `boolean`

#### Defined in

rdp.ts:69

___

### OS

• `Optional` **OS**: `string`

#### Defined in

rdp.ts:71
````

### `protocols\javascript\modules\rdp.md`

````markdown
# Namespace: rdp

## Table of contents

### Interfaces

- [CheckRDPAuthResponse](/templates/protocols/javascript/modules/rdp.CheckRDPAuthResponse)
- [IsRDPResponse](/templates/protocols/javascript/modules/rdp.IsRDPResponse)
- [ServiceRDP](/templates/protocols/javascript/modules/rdp.ServiceRDP)

### Functions

- [CheckRDPAuth](/templates/protocols/javascript/modules/rdp#checkrdpauth)
- [IsRDP](/templates/protocols/javascript/modules/rdp#isrdp)

## Functions

### CheckRDPAuth

▸ **CheckRDPAuth**(`host`, `port`): [`CheckRDPAuthResponse`](/templates/protocols/javascript/modules/rdp.CheckRDPAuthResponse) \| ``null``

CheckRDPAuth checks if the given host and port are running rdp server
with authentication and returns their metadata.
If connection is successful, it returns true.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`CheckRDPAuthResponse`](/templates/protocols/javascript/modules/rdp.CheckRDPAuthResponse) \| ``null``

**`Example`**

```javascript
const rdp = require('nuclei/rdp');
const checkRDPAuth = rdp.CheckRDPAuth('acme.com', 3389);
log(toJSON(checkRDPAuth));
```

#### Defined in

rdp.ts:14

___

### IsRDP

▸ **IsRDP**(`host`, `port`): [`IsRDPResponse`](/templates/protocols/javascript/modules/rdp.IsRDPResponse) \| ``null``

IsRDP checks if the given host and port are running rdp server.
If connection is successful, it returns true.
If connection is unsuccessful, it returns false and error.
The Name of the OS is also returned if the connection is successful.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsRDPResponse`](/templates/protocols/javascript/modules/rdp.IsRDPResponse) \| ``null``

**`Example`**

```javascript
const rdp = require('nuclei/rdp');
const isRDP = rdp.IsRDP('acme.com', 3389);
log(toJSON(isRDP));
```

#### Defined in

rdp.ts:32
````

### `protocols\javascript\modules\rdp.RDPClient.md`

````markdown
# Class: RDPClient

[rdp](/templates/protocols/javascript/modules/rdp).RDPClient

RDPClient is a minimal RDP client for nuclei scripts.

**`Example`**

```javascript
const rdp = require('nuclei/rdp');
const client = new rdp.Client();
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/rdp.RDPClient#constructor)

### Methods

- [CheckRDPAuth](/templates/protocols/javascript/modules/rdp.RDPClient#checkrdpauth)
- [IsRDP](/templates/protocols/javascript/modules/rdp.RDPClient#isrdp)

## Constructors

### constructor

• **new RDPClient**(): [`RDPClient`](/templates/protocols/javascript/modules/rdp.RDPClient)

#### Returns

[`RDPClient`](/templates/protocols/javascript/modules/rdp.RDPClient)

#### Defined in

rdp.ts:15

## Methods

### CheckRDPAuth

▸ **CheckRDPAuth**(`host`, `port`): [`CheckRDPAuthResponse`](/templates/protocols/javascript/modules/rdp.CheckRDPAuthResponse)

CheckRDPAuth checks if the given host and port are running rdp server
with authentication and returns their metadata.
If connection is successful, it returns true.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`CheckRDPAuthResponse`](/templates/protocols/javascript/modules/rdp.CheckRDPAuthResponse)

**`Example`**

```javascript
const rdp = require('nuclei/rdp');
const checkRDPAuth = rdp.CheckRDPAuth('acme.com', 3389);
log(toJSON(checkRDPAuth));
```

#### Defined in

rdp.ts:44

___

### IsRDP

▸ **IsRDP**(`host`, `port`): [`IsRDPResponse`](/templates/protocols/javascript/modules/rdp.IsRDPResponse)

IsRDP checks if the given host and port are running rdp server.
If connection is successful, it returns true.
If connection is unsuccessful, it returns false and error.
The Name of the OS is also returned if the connection is successful.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsRDPResponse`](/templates/protocols/javascript/modules/rdp.IsRDPResponse)

**`Example`**

```javascript
const rdp = require('nuclei/rdp');
const isRDP = rdp.IsRDP('acme.com', 3389);
log(toJSON(isRDP));
```

#### Defined in

rdp.ts:28
````

### `protocols\javascript\modules\rdp.ServiceRDP.md`

````markdown
# Interface: ServiceRDP

[rdp](/templates/protocols/javascript/modules/rdp).ServiceRDP

ServiceRDP Interface

## Table of contents

### Properties

- [DNSComputerName](/templates/protocols/javascript/modules/rdp.ServiceRDP#dnscomputername)
- [DNSDomainName](/templates/protocols/javascript/modules/rdp.ServiceRDP#dnsdomainname)
- [ForestName](/templates/protocols/javascript/modules/rdp.ServiceRDP#forestname)
- [NetBIOSComputerName](/templates/protocols/javascript/modules/rdp.ServiceRDP#netbioscomputername)
- [NetBIOSDomainName](/templates/protocols/javascript/modules/rdp.ServiceRDP#netbiosdomainname)
- [OSFingerprint](/templates/protocols/javascript/modules/rdp.ServiceRDP#osfingerprint)
- [OSVersion](/templates/protocols/javascript/modules/rdp.ServiceRDP#osversion)
- [TargetName](/templates/protocols/javascript/modules/rdp.ServiceRDP#targetname)

## Properties

### DNSComputerName

• `Optional` **DNSComputerName**: `string`

#### Defined in

rdp.ts:95

___

### DNSDomainName

• `Optional` **DNSDomainName**: `string`

#### Defined in

rdp.ts:81

___

### ForestName

• `Optional` **ForestName**: `string`

#### Defined in

rdp.ts:83

___

### NetBIOSComputerName

• `Optional` **NetBIOSComputerName**: `string`

#### Defined in

rdp.ts:91

___

### NetBIOSDomainName

• `Optional` **NetBIOSDomainName**: `string`

#### Defined in

rdp.ts:93

___

### OSFingerprint

• `Optional` **OSFingerprint**: `string`

#### Defined in

rdp.ts:85

___

### OSVersion

• `Optional` **OSVersion**: `string`

#### Defined in

rdp.ts:87

___

### TargetName

• `Optional` **TargetName**: `string`

#### Defined in

rdp.ts:89
````

### `protocols\javascript\modules\redis.md`

````markdown
# Namespace: redis

## Table of contents

### Functions

- [Connect](/templates/protocols/javascript/modules/redis#connect)
- [GetServerInfo](/templates/protocols/javascript/modules/redis#getserverinfo)
- [GetServerInfoAuth](/templates/protocols/javascript/modules/redis#getserverinfoauth)
- [IsAuthenticated](/templates/protocols/javascript/modules/redis#isauthenticated)
- [RunLuaScript](/templates/protocols/javascript/modules/redis#runluascript)

## Functions

### Connect

▸ **Connect**(`host`, `port`, `password`): `boolean` \| ``null``

Connect tries to connect redis server with password

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `password` | `string` |

#### Returns

`boolean` \| ``null``

**`Example`**

```javascript
const redis = require('nuclei/redis');
const connected = redis.Connect('acme.com', 6379, 'password');
```

#### Defined in

redis.ts:11

___

### GetServerInfo

▸ **GetServerInfo**(`host`, `port`): `string` \| ``null``

GetServerInfo returns the server info for a redis server

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

`string` \| ``null``

**`Example`**

```javascript
const redis = require('nuclei/redis');
const info = redis.GetServerInfo('acme.com', 6379);
```

#### Defined in

redis.ts:25

___

### GetServerInfoAuth

▸ **GetServerInfoAuth**(`host`, `port`, `password`): `string` \| ``null``

GetServerInfoAuth returns the server info for a redis server

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `password` | `string` |

#### Returns

`string` \| ``null``

**`Example`**

```javascript
const redis = require('nuclei/redis');
const info = redis.GetServerInfoAuth('acme.com', 6379, 'password');
```

#### Defined in

redis.ts:39

___

### IsAuthenticated

▸ **IsAuthenticated**(`host`, `port`): `boolean` \| ``null``

IsAuthenticated checks if the redis server requires authentication

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

`boolean` \| ``null``

**`Example`**

```javascript
const redis = require('nuclei/redis');
const isAuthenticated = redis.IsAuthenticated('acme.com', 6379);
```

#### Defined in

redis.ts:53

___

### RunLuaScript

▸ **RunLuaScript**(`host`, `port`, `password`, `script`): `any` \| ``null``

RunLuaScript runs a lua script on the redis server

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `password` | `string` |
| `script` | `string` |

#### Returns

`any` \| ``null``

**`Example`**

```javascript
const redis = require('nuclei/redis');
const result = redis.RunLuaScript('acme.com', 6379, 'password', 'return redis.call("get", KEYS[1])');
```

#### Defined in

redis.ts:67
````

### `protocols\javascript\modules\rsync.IsRsyncResponse.md`

````markdown
# Interface: IsRsyncResponse

[rsync](/templates/protocols/javascript/modules/rsync).IsRsyncResponse

IsRsyncResponse is the response from the IsRsync function.
this is returned by IsRsync function.

**`Example`**

```javascript
const rsync = require('nuclei/rsync');
const isRsync = rsync.IsRsync('acme.com', 873);
log(toJSON(isRsync));
```

## Table of contents

### Properties

- [Banner](/templates/protocols/javascript/modules/rsync.IsRsyncResponse#banner)
- [IsRsync](/templates/protocols/javascript/modules/rsync.IsRsyncResponse#isrsync)

## Properties

### Banner

• `Optional` **Banner**: `string`

#### Defined in

rsync.ts:32

___

### IsRsync

• `Optional` **IsRsync**: `boolean`

#### Defined in

rsync.ts:30
````

### `protocols\javascript\modules\rsync.md`

````markdown
# Namespace: rsync

## Table of contents

### Interfaces

- [IsRsyncResponse](/templates/protocols/javascript/modules/rsync.IsRsyncResponse)

### Functions

- [IsRsync](/templates/protocols/javascript/modules/rsync#isrsync)

## Functions

### IsRsync

▸ **IsRsync**(`host`, `port`): [`IsRsyncResponse`](/templates/protocols/javascript/modules/rsync.IsRsyncResponse) \| ``null``

IsRsync checks if a host is running a Rsync server.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsRsyncResponse`](/templates/protocols/javascript/modules/rsync.IsRsyncResponse) \| ``null``

**`Example`**

```javascript
const rsync = require('nuclei/rsync');
const isRsync = rsync.IsRsync('acme.com', 873);
log(toJSON(isRsync));
```

#### Defined in

rsync.ts:12
````

### `protocols\javascript\modules\rsync.RsyncClient.md`

````markdown
# Class: RsyncClient

[rsync](/templates/protocols/javascript/modules/rsync).RsyncClient

RsyncClient is a minimal Rsync client for nuclei scripts.

**`Example`**

```javascript
const rsync = require('nuclei/rsync');
const client = new rsync.Client();
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/rsync.RsyncClient#constructor)

### Methods

- [IsRsync](/templates/protocols/javascript/modules/rsync.RsyncClient#isrsync)

## Constructors

### constructor

• **new RsyncClient**(): [`RsyncClient`](/templates/protocols/javascript/modules/rsync.RsyncClient)

#### Returns

[`RsyncClient`](/templates/protocols/javascript/modules/rsync.RsyncClient)

#### Defined in

rsync.ts:15

## Methods

### IsRsync

▸ **IsRsync**(`host`, `port`): [`IsRsyncResponse`](/templates/protocols/javascript/modules/rsync.IsRsyncResponse)

IsRsync checks if a host is running a Rsync server.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsRsyncResponse`](/templates/protocols/javascript/modules/rsync.IsRsyncResponse)

**`Example`**

```javascript
const rsync = require('nuclei/rsync');
const isRsync = rsync.IsRsync('acme.com', 873);
log(toJSON(isRsync));
```

#### Defined in

rsync.ts:25
````

### `protocols\javascript\modules\smb.HeaderLog.md`

````markdown
# Interface: HeaderLog

[smb](/templates/protocols/javascript/modules/smb).HeaderLog

HeaderLog Interface

## Table of contents

### Properties

- [Command](/templates/protocols/javascript/modules/smb.HeaderLog#command)
- [Credits](/templates/protocols/javascript/modules/smb.HeaderLog#credits)
- [Flags](/templates/protocols/javascript/modules/smb.HeaderLog#flags)
- [ProtocolID](/templates/protocols/javascript/modules/smb.HeaderLog#protocolid)
- [Status](/templates/protocols/javascript/modules/smb.HeaderLog#status)

## Properties

### Command

• `Optional` **Command**: `number`

#### Defined in

smb.ts:100

___

### Credits

• `Optional` **Credits**: `number`

#### Defined in

smb.ts:102

___

### Flags

• `Optional` **Flags**: `number`

#### Defined in

smb.ts:104

___

### ProtocolID

• `Optional` **ProtocolID**: `Uint8Array`

#### Defined in

smb.ts:106

___

### Status

• `Optional` **Status**: `number`

#### Defined in

smb.ts:98
````

### `protocols\javascript\modules\smb.md`

````markdown
# Namespace: smb

## Table of contents

### Classes

- [SMBClient](/templates/protocols/javascript/modules/smb.SMBClient)

### Interfaces

- [HeaderLog](/templates/protocols/javascript/modules/smb.HeaderLog)
- [NegotiationLog](/templates/protocols/javascript/modules/smb.NegotiationLog)
- [SMBCapabilities](/templates/protocols/javascript/modules/smb.SMBCapabilities)
- [SMBLog](/templates/protocols/javascript/modules/smb.SMBLog)
- [SMBVersions](/templates/protocols/javascript/modules/smb.SMBVersions)
- [ServiceSMB](/templates/protocols/javascript/modules/smb.ServiceSMB)
- [SessionSetupLog](/templates/protocols/javascript/modules/smb.SessionSetupLog)
````

### `protocols\javascript\modules\smb.NegotiationLog.md`

````markdown
# Interface: NegotiationLog

[smb](/templates/protocols/javascript/modules/smb).NegotiationLog

NegotiationLog Interface

## Table of contents

### Properties

- [AuthenticationTypes](/templates/protocols/javascript/modules/smb.NegotiationLog#authenticationtypes)
- [Capabilities](/templates/protocols/javascript/modules/smb.NegotiationLog#capabilities)
- [DialectRevision](/templates/protocols/javascript/modules/smb.NegotiationLog#dialectrevision)
- [HeaderLog](/templates/protocols/javascript/modules/smb.NegotiationLog#headerlog)
- [SecurityMode](/templates/protocols/javascript/modules/smb.NegotiationLog#securitymode)
- [ServerGuid](/templates/protocols/javascript/modules/smb.NegotiationLog#serverguid)
- [ServerStartTime](/templates/protocols/javascript/modules/smb.NegotiationLog#serverstarttime)
- [SystemTime](/templates/protocols/javascript/modules/smb.NegotiationLog#systemtime)

## Properties

### AuthenticationTypes

• `Optional` **AuthenticationTypes**: `string`[]

#### Defined in

smb.ts:116

___

### Capabilities

• `Optional` **Capabilities**: `number`

#### Defined in

smb.ts:124

___

### DialectRevision

• `Optional` **DialectRevision**: `number`

#### Defined in

smb.ts:120

___

### HeaderLog

• `Optional` **HeaderLog**: [`HeaderLog`](/templates/protocols/javascript/modules/smb.HeaderLog)

#### Defined in

smb.ts:130

___

### SecurityMode

• `Optional` **SecurityMode**: `number`

#### Defined in

smb.ts:118

___

### ServerGuid

• `Optional` **ServerGuid**: `Uint8Array`

#### Defined in

smb.ts:122

___

### ServerStartTime

• `Optional` **ServerStartTime**: `number`

#### Defined in

smb.ts:128

___

### SystemTime

• `Optional` **SystemTime**: `number`

#### Defined in

smb.ts:126
````

### `protocols\javascript\modules\smb.ServiceSMB.md`

````markdown
# Interface: ServiceSMB

[smb](/templates/protocols/javascript/modules/smb).ServiceSMB

ServiceSMB Interface

## Table of contents

### Properties

- [DNSComputerName](/templates/protocols/javascript/modules/smb.ServiceSMB#dnscomputername)
- [DNSDomainName](/templates/protocols/javascript/modules/smb.ServiceSMB#dnsdomainname)
- [ForestName](/templates/protocols/javascript/modules/smb.ServiceSMB#forestname)
- [NetBIOSComputerName](/templates/protocols/javascript/modules/smb.ServiceSMB#netbioscomputername)
- [NetBIOSDomainName](/templates/protocols/javascript/modules/smb.ServiceSMB#netbiosdomainname)
- [OSVersion](/templates/protocols/javascript/modules/smb.ServiceSMB#osversion)
- [SigningEnabled](/templates/protocols/javascript/modules/smb.ServiceSMB#signingenabled)
- [SigningRequired](/templates/protocols/javascript/modules/smb.ServiceSMB#signingrequired)

## Properties

### DNSComputerName

• `Optional` **DNSComputerName**: `string`

#### Defined in

smb.ts:204

___

### DNSDomainName

• `Optional` **DNSDomainName**: `string`

#### Defined in

smb.ts:206

___

### ForestName

• `Optional` **ForestName**: `string`

#### Defined in

smb.ts:208

___

### NetBIOSComputerName

• `Optional` **NetBIOSComputerName**: `string`

#### Defined in

smb.ts:216

___

### NetBIOSDomainName

• `Optional` **NetBIOSDomainName**: `string`

#### Defined in

smb.ts:218

___

### OSVersion

• `Optional` **OSVersion**: `string`

#### Defined in

smb.ts:214

___

### SigningEnabled

• `Optional` **SigningEnabled**: `boolean`

#### Defined in

smb.ts:210

___

### SigningRequired

• `Optional` **SigningRequired**: `boolean`

#### Defined in

smb.ts:212
````

### `protocols\javascript\modules\smb.SessionSetupLog.md`

````markdown
# Interface: SessionSetupLog

[smb](/templates/protocols/javascript/modules/smb).SessionSetupLog

SessionSetupLog Interface

## Table of contents

### Properties

- [HeaderLog](/templates/protocols/javascript/modules/smb.SessionSetupLog#headerlog)
- [NegotiateFlags](/templates/protocols/javascript/modules/smb.SessionSetupLog#negotiateflags)
- [SetupFlags](/templates/protocols/javascript/modules/smb.SessionSetupLog#setupflags)
- [TargetName](/templates/protocols/javascript/modules/smb.SessionSetupLog#targetname)

## Properties

### HeaderLog

• `Optional` **HeaderLog**: [`HeaderLog`](/templates/protocols/javascript/modules/smb.HeaderLog)

#### Defined in

smb.ts:234

___

### NegotiateFlags

• `Optional` **NegotiateFlags**: `number`

#### Defined in

smb.ts:228

___

### SetupFlags

• `Optional` **SetupFlags**: `number`

#### Defined in

smb.ts:230

___

### TargetName

• `Optional` **TargetName**: `string`

#### Defined in

smb.ts:232
````

### `protocols\javascript\modules\smb.SMBCapabilities.md`

````markdown
# Interface: SMBCapabilities

[smb](/templates/protocols/javascript/modules/smb).SMBCapabilities

SMBCapabilities Interface

## Table of contents

### Properties

- [DFSSupport](/templates/protocols/javascript/modules/smb.SMBCapabilities#dfssupport)
- [DirLeasing](/templates/protocols/javascript/modules/smb.SMBCapabilities#dirleasing)
- [Encryption](/templates/protocols/javascript/modules/smb.SMBCapabilities#encryption)
- [LargeMTU](/templates/protocols/javascript/modules/smb.SMBCapabilities#largemtu)
- [Leasing](/templates/protocols/javascript/modules/smb.SMBCapabilities#leasing)
- [MultiChan](/templates/protocols/javascript/modules/smb.SMBCapabilities#multichan)
- [Persist](/templates/protocols/javascript/modules/smb.SMBCapabilities#persist)

## Properties

### DFSSupport

• `Optional` **DFSSupport**: `boolean`

#### Defined in

smb.ts:144

___

### DirLeasing

• `Optional` **DirLeasing**: `boolean`

#### Defined in

smb.ts:140

___

### Encryption

• `Optional` **Encryption**: `boolean`

#### Defined in

smb.ts:142

___

### LargeMTU

• `Optional` **LargeMTU**: `boolean`

#### Defined in

smb.ts:148

___

### Leasing

• `Optional` **Leasing**: `boolean`

#### Defined in

smb.ts:146

___

### MultiChan

• `Optional` **MultiChan**: `boolean`

#### Defined in

smb.ts:150

___

### Persist

• `Optional` **Persist**: `boolean`

#### Defined in

smb.ts:152
````

### `protocols\javascript\modules\smb.SMBClient.md`

````markdown
# Class: SMBClient

[smb](/templates/protocols/javascript/modules/smb).SMBClient

SMBClient is a client for SMB servers.
Internally client uses github.com/zmap/zgrab2/lib/smb/smb driver.
github.com/projectdiscovery/go-smb2 driver

**`Example`**

```javascript
const smb = require('nuclei/smb');
const client = new smb.SMBClient();
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/smb.SMBClient#constructor)

### Methods

- [ConnectSMBInfoMode](/templates/protocols/javascript/modules/smb.SMBClient#connectsmbinfomode)
- [DetectSMBGhost](/templates/protocols/javascript/modules/smb.SMBClient#detectsmbghost)
- [ListSMBv2Metadata](/templates/protocols/javascript/modules/smb.SMBClient#listsmbv2metadata)
- [ListShares](/templates/protocols/javascript/modules/smb.SMBClient#listshares)

## Constructors

### constructor

• **new SMBClient**(): [`SMBClient`](/templates/protocols/javascript/modules/smb.SMBClient)

#### Returns

[`SMBClient`](/templates/protocols/javascript/modules/smb.SMBClient)

#### Defined in

smb.ts:17

## Methods

### ConnectSMBInfoMode

▸ **ConnectSMBInfoMode**(`host`, `port`): [`SMBLog`](/templates/protocols/javascript/modules/smb.SMBLog)

ConnectSMBInfoMode tries to connect to provided host and port
and discovery SMB information
Returns handshake log and error. If error is not nil,
state will be false

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`SMBLog`](/templates/protocols/javascript/modules/smb.SMBLog)

**`Example`**

```javascript
const smb = require('nuclei/smb');
const client = new smb.SMBClient();
const info = client.ConnectSMBInfoMode('acme.com', 445);
log(to_json(info));
```

#### Defined in

smb.ts:31

___

### DetectSMBGhost

▸ **DetectSMBGhost**(`host`, `port`): `boolean`

DetectSMBGhost tries to detect SMBGhost vulnerability
by using SMBv3 compression feature.
If the host is vulnerable, it returns true.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

`boolean`

**`Example`**

```javascript
const smb = require('nuclei/smb');
const isSMBGhost = smb.DetectSMBGhost('acme.com', 445);
```

#### Defined in

smb.ts:84

___

### ListSMBv2Metadata

▸ **ListSMBv2Metadata**(`host`, `port`): [`ServiceSMB`](/templates/protocols/javascript/modules/smb.ServiceSMB)

ListSMBv2Metadata tries to connect to provided host and port
and list SMBv2 metadata.
Returns metadata and error. If error is not nil,
state will be false

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`ServiceSMB`](/templates/protocols/javascript/modules/smb.ServiceSMB)

**`Example`**

```javascript
const smb = require('nuclei/smb');
const client = new smb.SMBClient();
const metadata = client.ListSMBv2Metadata('acme.com', 445);
log(to_json(metadata));
```

#### Defined in

smb.ts:49

___

### ListShares

▸ **ListShares**(`host`, `port`, `user`): `string`[]

ListShares tries to connect to provided host and port
and list shares by using given credentials.
Credentials cannot be blank. guest or anonymous credentials
can be used by providing empty password.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `user` | `string` |

#### Returns

`string`[]

**`Example`**

```javascript
const smb = require('nuclei/smb');
const client = new smb.SMBClient();
const shares = client.ListShares('acme.com', 445, 'username', 'password');
	for (const share of shares) {
		  log(share);
	}
```

#### Defined in

smb.ts:69
````

### `protocols\javascript\modules\smb.SMBLog.md`

````markdown
# Interface: SMBLog

[smb](/templates/protocols/javascript/modules/smb).SMBLog

SMBLog Interface

## Table of contents

### Properties

- [Capabilities](/templates/protocols/javascript/modules/smb.SMBLog#capabilities)
- [GroupName](/templates/protocols/javascript/modules/smb.SMBLog#groupname)
- [HasNTLM](/templates/protocols/javascript/modules/smb.SMBLog#hasntlm)
- [NTLM](/templates/protocols/javascript/modules/smb.SMBLog#ntlm)
- [NativeOs](/templates/protocols/javascript/modules/smb.SMBLog#nativeos)
- [NegotiationLog](/templates/protocols/javascript/modules/smb.SMBLog#negotiationlog)
- [SessionSetupLog](/templates/protocols/javascript/modules/smb.SMBLog#sessionsetuplog)
- [SupportV1](/templates/protocols/javascript/modules/smb.SMBLog#supportv1)
- [Version](/templates/protocols/javascript/modules/smb.SMBLog#version)

## Properties

### Capabilities

• `Optional` **Capabilities**: [`SMBCapabilities`](/templates/protocols/javascript/modules/smb.SMBCapabilities)

#### Defined in

smb.ts:174

___

### GroupName

• `Optional` **GroupName**: `string`

#### Defined in

smb.ts:166

___

### HasNTLM

• `Optional` **HasNTLM**: `boolean`

#### Defined in

smb.ts:168

___

### NTLM

• `Optional` **NTLM**: `string`

#### Defined in

smb.ts:164

___

### NativeOs

• `Optional` **NativeOs**: `string`

#### Defined in

smb.ts:162

___

### NegotiationLog

• `Optional` **NegotiationLog**: [`NegotiationLog`](/templates/protocols/javascript/modules/smb.NegotiationLog)

#### Defined in

smb.ts:176

___

### SessionSetupLog

• `Optional` **SessionSetupLog**: [`SessionSetupLog`](/templates/protocols/javascript/modules/smb.SessionSetupLog)

#### Defined in

smb.ts:178

___

### SupportV1

• `Optional` **SupportV1**: `boolean`

#### Defined in

smb.ts:170

___

### Version

• `Optional` **Version**: [`SMBVersions`](/templates/protocols/javascript/modules/smb.SMBVersions)

#### Defined in

smb.ts:172
````

### `protocols\javascript\modules\smb.SMBVersions.md`

````markdown
# Interface: SMBVersions

[smb](/templates/protocols/javascript/modules/smb).SMBVersions

SMBVersions Interface

## Table of contents

### Properties

- [Major](/templates/protocols/javascript/modules/smb.SMBVersions#major)
- [Minor](/templates/protocols/javascript/modules/smb.SMBVersions#minor)
- [Revision](/templates/protocols/javascript/modules/smb.SMBVersions#revision)
- [VerString](/templates/protocols/javascript/modules/smb.SMBVersions#verstring)

## Properties

### Major

• `Optional` **Major**: `number`

#### Defined in

smb.ts:188

___

### Minor

• `Optional` **Minor**: `number`

#### Defined in

smb.ts:190

___

### Revision

• `Optional` **Revision**: `number`

#### Defined in

smb.ts:192

___

### VerString

• `Optional` **VerString**: `string`

#### Defined in

smb.ts:194
````

### `protocols\javascript\modules\smtp.Client.md`

````markdown
# Class: Client

[smtp](/templates/protocols/javascript/modules/smtp).Client

Client is a minimal SMTP client for nuclei scripts.

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const client = new smtp.Client('acme.com', 25);
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/smtp.Client#constructor)

### Properties

- [host](/templates/protocols/javascript/modules/smtp.Client#host)
- [port](/templates/protocols/javascript/modules/smtp.Client#port)

### Methods

- [IsOpenRelay](/templates/protocols/javascript/modules/smtp.Client#isopenrelay)
- [IsSMTP](/templates/protocols/javascript/modules/smtp.Client#issmtp)
- [SendMail](/templates/protocols/javascript/modules/smtp.Client#sendmail)

## Constructors

### constructor

• **new Client**(`host`, `port`): [`Client`](/templates/protocols/javascript/modules/smtp.Client)

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `string` |

#### Returns

[`Client`](/templates/protocols/javascript/modules/smtp.Client)

#### Defined in

smtp.ts:15

## Properties

### host

• **host**: `string`

#### Defined in

smtp.ts:15

___

### port

• **port**: `string`

#### Defined in

smtp.ts:15

## Methods

### IsOpenRelay

▸ **IsOpenRelay**(`msg`): `boolean`

IsOpenRelay checks if a host is an open relay.

#### Parameters

| Name | Type |
| :------ | :------ |
| `msg` | [`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage) |

#### Returns

`boolean`

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.From('xyz@projectdiscovery.io');
message.To('xyz2@projectdiscoveyr.io');
message.Subject('hello');
message.Body('hello');
const client = new smtp.Client('acme.com', 25);
const isRelay = client.IsOpenRelay(message);
```

#### Defined in

smtp.ts:47

___

### IsSMTP

▸ **IsSMTP**(): [`SMTPResponse`](/templates/protocols/javascript/modules/smtp.SMTPResponse)

IsSMTP checks if a host is running a SMTP server.

#### Returns

[`SMTPResponse`](/templates/protocols/javascript/modules/smtp.SMTPResponse)

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const client = new smtp.Client('acme.com', 25);
const isSMTP = client.IsSMTP();
log(isSMTP)
```

#### Defined in

smtp.ts:28

___

### SendMail

▸ **SendMail**(`msg`): `boolean`

SendMail sends an email using the SMTP protocol.

#### Parameters

| Name | Type |
| :------ | :------ |
| `msg` | [`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage) |

#### Returns

`boolean`

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.From('xyz@projectdiscovery.io');
message.To('xyz2@projectdiscoveyr.io');
message.Subject('hello');
message.Body('hello');
const client = new smtp.Client('acme.com', 25);
const isSent = client.SendMail(message);
log(isSent)
```

#### Defined in

smtp.ts:67
````

### `protocols\javascript\modules\smtp.IsSMTPResponse.md`

````markdown
# Interface: IsSMTPResponse

[smtp](/templates/protocols/javascript/modules/smtp).IsSMTPResponse

IsSMTPResponse is the response from the IsSMTP function.

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const isSMTP = smtp.IsSMTP('acme.com', 25);
log(toJSON(isSMTP));
```

## Table of contents

### Properties

- [Banner](/templates/protocols/javascript/modules/smtp.IsSMTPResponse#banner)
- [IsSMTP](/templates/protocols/javascript/modules/smtp.IsSMTPResponse#issmtp)

## Properties

### Banner

• `Optional` **Banner**: `string`

#### Defined in

smtp.ts:189

___

### IsSMTP

• `Optional` **IsSMTP**: `boolean`

#### Defined in

smtp.ts:187
````

### `protocols\javascript\modules\smtp.md`

````markdown
# Namespace: smtp

## Table of contents

### Classes

- [Client](/templates/protocols/javascript/modules/smtp.Client)
- [SMTPMessage](/templates/protocols/javascript/modules/smtp.SMTPMessage)

### Interfaces

- [SMTPResponse](/templates/protocols/javascript/modules/smtp.SMTPResponse)
````

### `protocols\javascript\modules\smtp.SMTPClient.md`

````markdown
# Class: SMTPClient

[smtp](/templates/protocols/javascript/modules/smtp).SMTPClient

SMTPClient is a minimal SMTP client for nuclei scripts.

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const client = new smtp.Client();
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/smtp.SMTPClient#constructor)

### Methods

- [IsOpenRelay](/templates/protocols/javascript/modules/smtp.SMTPClient#isopenrelay)
- [IsSMTP](/templates/protocols/javascript/modules/smtp.SMTPClient#issmtp)
- [SendMail](/templates/protocols/javascript/modules/smtp.SMTPClient#sendmail)

## Constructors

### constructor

• **new SMTPClient**(): [`SMTPClient`](/templates/protocols/javascript/modules/smtp.SMTPClient)

#### Returns

[`SMTPClient`](/templates/protocols/javascript/modules/smtp.SMTPClient)

#### Defined in

smtp.ts:15

## Methods

### IsOpenRelay

▸ **IsOpenRelay**(`host`, `port`, `msg`): `boolean`

IsOpenRelay checks if a host is an open relay.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `msg` | [`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage) |

#### Returns

`boolean`

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.From('xyz@projectdiscovery.io');
message.To('xyz2@projectdiscoveyr.io');
message.Subject('hello');
message.Body('hello');
const isRelay = smtp.IsOpenRelay('acme.com', 25, message);
```

#### Defined in

smtp.ts:43

___

### IsSMTP

▸ **IsSMTP**(`host`, `port`): [`IsSMTPResponse`](/templates/protocols/javascript/modules/smtp.IsSMTPResponse)

IsSMTP checks if a host is running a SMTP server.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsSMTPResponse`](/templates/protocols/javascript/modules/smtp.IsSMTPResponse)

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const isSMTP = smtp.IsSMTP('acme.com', 25);
log(toJSON(isSMTP));
```

#### Defined in

smtp.ts:25

___

### SendMail

▸ **SendMail**(`host`, `port`, `msg`): `boolean`

SendMail sends an email using the SMTP protocol.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `string` |
| `msg` | [`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage) |

#### Returns

`boolean`

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.From('xyz@projectdiscovery.io');
message.To('xyz2@projectdiscoveyr.io');
message.Subject('hello');
message.Body('hello');
const isSent = smtp.SendMail('acme.com', 25, message);
```

#### Defined in

smtp.ts:61
````

### `protocols\javascript\modules\smtp.SMTPMessage.md`

````markdown
# Class: SMTPMessage

[smtp](/templates/protocols/javascript/modules/smtp).SMTPMessage

SMTPMessage is a message to be sent over SMTP

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.From('xyz@projectdiscovery.io');
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/smtp.SMTPMessage#constructor)

### Methods

- [Auth](/templates/protocols/javascript/modules/smtp.SMTPMessage#auth)
- [Body](/templates/protocols/javascript/modules/smtp.SMTPMessage#body)
- [From](/templates/protocols/javascript/modules/smtp.SMTPMessage#from)
- [String](/templates/protocols/javascript/modules/smtp.SMTPMessage#string)
- [Subject](/templates/protocols/javascript/modules/smtp.SMTPMessage#subject)
- [To](/templates/protocols/javascript/modules/smtp.SMTPMessage#to)

## Constructors

### constructor

• **new SMTPMessage**(): [`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

#### Returns

[`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

#### Defined in

smtp.ts:89

## Methods

### Auth

▸ **Auth**(`username`): [`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

Auth when called authenticates using username and password before sending the message

#### Parameters

| Name | Type |
| :------ | :------ |
| `username` | `string` |

#### Returns

[`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.Auth('username', 'password');
```

#### Defined in

smtp.ts:155

___

### Body

▸ **Body**(`msg`): [`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

Body adds the message body to the message

#### Parameters

| Name | Type |
| :------ | :------ |
| `msg` | `Uint8Array` |

#### Returns

[`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.Body('hello');
```

#### Defined in

smtp.ts:141

___

### From

▸ **From**(`email`): [`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

From adds the from field to the message

#### Parameters

| Name | Type |
| :------ | :------ |
| `email` | `string` |

#### Returns

[`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.From('xyz@projectdiscovery.io');
```

#### Defined in

smtp.ts:99

___

### String

▸ **String**(): `string`

String returns the string representation of the message

#### Returns

`string`

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.From('xyz@projectdiscovery.io');
message.To('xyz2@projectdiscoveyr.io');
message.Subject('hello');
message.Body('hello');
log(message.String());
```

#### Defined in

smtp.ts:173

___

### Subject

▸ **Subject**(`sub`): [`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

Subject adds the subject field to the message

#### Parameters

| Name | Type |
| :------ | :------ |
| `sub` | `string` |

#### Returns

[`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.Subject('hello');
```

#### Defined in

smtp.ts:127

___

### To

▸ **To**(`email`): [`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

To adds the to field to the message

#### Parameters

| Name | Type |
| :------ | :------ |
| `email` | `string` |

#### Returns

[`SMTPMessage`](/templates/protocols/javascript/modules/smtp.SMTPMessage)

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const message = new smtp.SMTPMessage();
message.To('xyz@projectdiscovery.io');
```

#### Defined in

smtp.ts:113
````

### `protocols\javascript\modules\smtp.SMTPResponse.md`

````markdown
# Interface: SMTPResponse

[smtp](/templates/protocols/javascript/modules/smtp).SMTPResponse

SMTPResponse is the response from the IsSMTP function.

**`Example`**

```javascript
const smtp = require('nuclei/smtp');
const client = new smtp.Client('acme.com', 25);
const isSMTP = client.IsSMTP();
log(isSMTP)
```

## Table of contents

### Properties

- [Banner](/templates/protocols/javascript/modules/smtp.SMTPResponse#banner)
- [IsSMTP](/templates/protocols/javascript/modules/smtp.SMTPResponse#issmtp)

## Properties

### Banner

• `Optional` **Banner**: `string`

#### Defined in

smtp.ts:196

___

### IsSMTP

• `Optional` **IsSMTP**: `boolean`

#### Defined in

smtp.ts:194
````

### `protocols\javascript\modules\ssh.Algorithms.md`

````markdown
# Interface: Algorithms

[ssh](/templates/protocols/javascript/modules/ssh).Algorithms

Algorithms Interface

## Table of contents

### Properties

- [HostKey](/templates/protocols/javascript/modules/ssh.Algorithms#hostkey)
- [Kex](/templates/protocols/javascript/modules/ssh.Algorithms#kex)
- [R](/templates/protocols/javascript/modules/ssh.Algorithms#r)
- [W](/templates/protocols/javascript/modules/ssh.Algorithms#w)

## Properties

### HostKey

• `Optional` **HostKey**: `string`

#### Defined in

ssh.ts:134

___

### Kex

• `Optional` **Kex**: `string`

#### Defined in

ssh.ts:132

___

### R

• `Optional` **R**: [`DirectionAlgorithms`](/templates/protocols/javascript/modules/ssh.DirectionAlgorithms)

#### Defined in

ssh.ts:138

___

### W

• `Optional` **W**: [`DirectionAlgorithms`](/templates/protocols/javascript/modules/ssh.DirectionAlgorithms)

#### Defined in

ssh.ts:136
````

### `protocols\javascript\modules\ssh.DirectionAlgorithms.md`

````markdown
# Interface: DirectionAlgorithms

[ssh](/templates/protocols/javascript/modules/ssh).DirectionAlgorithms

DirectionAlgorithms Interface

## Table of contents

### Properties

- [Cipher](/templates/protocols/javascript/modules/ssh.DirectionAlgorithms#cipher)
- [Compression](/templates/protocols/javascript/modules/ssh.DirectionAlgorithms#compression)
- [MAC](/templates/protocols/javascript/modules/ssh.DirectionAlgorithms#mac)

## Properties

### Cipher

• `Optional` **Cipher**: `string`

#### Defined in

ssh.ts:148

___

### Compression

• `Optional` **Compression**: `string`

#### Defined in

ssh.ts:152

___

### MAC

• `Optional` **MAC**: `string`

#### Defined in

ssh.ts:150
````

### `protocols\javascript\modules\ssh.EndpointId.md`

````markdown
# Interface: EndpointId

[ssh](/templates/protocols/javascript/modules/ssh).EndpointId

EndpointId Interface

## Table of contents

### Properties

- [Comment](/templates/protocols/javascript/modules/ssh.EndpointId#comment)
- [ProtoVersion](/templates/protocols/javascript/modules/ssh.EndpointId#protoversion)
- [Raw](/templates/protocols/javascript/modules/ssh.EndpointId#raw)
- [SoftwareVersion](/templates/protocols/javascript/modules/ssh.EndpointId#softwareversion)

## Properties

### Comment

• `Optional` **Comment**: `string`

#### Defined in

ssh.ts:168

___

### ProtoVersion

• `Optional` **ProtoVersion**: `string`

#### Defined in

ssh.ts:164

___

### Raw

• `Optional` **Raw**: `string`

#### Defined in

ssh.ts:162

___

### SoftwareVersion

• `Optional` **SoftwareVersion**: `string`

#### Defined in

ssh.ts:166
````

### `protocols\javascript\modules\ssh.HandshakeLog.md`

````markdown
# Interface: HandshakeLog

[ssh](/templates/protocols/javascript/modules/ssh).HandshakeLog

HandshakeLog Interface

## Table of contents

### Properties

- [AlgorithmSelection](/templates/protocols/javascript/modules/ssh.HandshakeLog#algorithmselection)
- [Banner](/templates/protocols/javascript/modules/ssh.HandshakeLog#banner)
- [ClientID](/templates/protocols/javascript/modules/ssh.HandshakeLog#clientid)
- [ClientKex](/templates/protocols/javascript/modules/ssh.HandshakeLog#clientkex)
- [ServerID](/templates/protocols/javascript/modules/ssh.HandshakeLog#serverid)
- [ServerKex](/templates/protocols/javascript/modules/ssh.HandshakeLog#serverkex)
- [UserAuth](/templates/protocols/javascript/modules/ssh.HandshakeLog#userauth)

## Properties

### AlgorithmSelection

• `Optional` **AlgorithmSelection**: [`Algorithms`](/templates/protocols/javascript/modules/ssh.Algorithms)

#### Defined in

ssh.ts:184

___

### Banner

• `Optional` **Banner**: `string`

#### Defined in

ssh.ts:178

___

### ClientID

• `Optional` **ClientID**: [`EndpointId`](/templates/protocols/javascript/modules/ssh.EndpointId)

#### Defined in

ssh.ts:188

___

### ClientKex

• `Optional` **ClientKex**: [`KexInitMsg`](/templates/protocols/javascript/modules/ssh.KexInitMsg)

#### Defined in

ssh.ts:182

___

### ServerID

• `Optional` **ServerID**: [`EndpointId`](/templates/protocols/javascript/modules/ssh.EndpointId)

#### Defined in

ssh.ts:186

___

### ServerKex

• `Optional` **ServerKex**: [`KexInitMsg`](/templates/protocols/javascript/modules/ssh.KexInitMsg)

#### Defined in

ssh.ts:190

___

### UserAuth

• `Optional` **UserAuth**: `string`[]

#### Defined in

ssh.ts:180
````

### `protocols\javascript\modules\ssh.KexInitMsg.md`

````markdown
# Interface: KexInitMsg

[ssh](/templates/protocols/javascript/modules/ssh).KexInitMsg

KexInitMsg Interface

## Table of contents

### Properties

- [CiphersClientServer](/templates/protocols/javascript/modules/ssh.KexInitMsg#ciphersclientserver)
- [CiphersServerClient](/templates/protocols/javascript/modules/ssh.KexInitMsg#ciphersserverclient)
- [CompressionClientServer](/templates/protocols/javascript/modules/ssh.KexInitMsg#compressionclientserver)
- [CompressionServerClient](/templates/protocols/javascript/modules/ssh.KexInitMsg#compressionserverclient)
- [Cookie](/templates/protocols/javascript/modules/ssh.KexInitMsg#cookie)
- [FirstKexFollows](/templates/protocols/javascript/modules/ssh.KexInitMsg#firstkexfollows)
- [KexAlgos](/templates/protocols/javascript/modules/ssh.KexInitMsg#kexalgos)
- [LanguagesClientServer](/templates/protocols/javascript/modules/ssh.KexInitMsg#languagesclientserver)
- [LanguagesServerClient](/templates/protocols/javascript/modules/ssh.KexInitMsg#languagesserverclient)
- [MACsClientServer](/templates/protocols/javascript/modules/ssh.KexInitMsg#macsclientserver)
- [MACsServerClient](/templates/protocols/javascript/modules/ssh.KexInitMsg#macsserverclient)
- [Reserved](/templates/protocols/javascript/modules/ssh.KexInitMsg#reserved)
- [ServerHostKeyAlgos](/templates/protocols/javascript/modules/ssh.KexInitMsg#serverhostkeyalgos)

## Properties

### CiphersClientServer

• `Optional` **CiphersClientServer**: `string`[]

#### Defined in

ssh.ts:228

___

### CiphersServerClient

• `Optional` **CiphersServerClient**: `string`[]

#### Defined in

ssh.ts:208

___

### CompressionClientServer

• `Optional` **CompressionClientServer**: `string`[]

#### Defined in

ssh.ts:214

___

### CompressionServerClient

• `Optional` **CompressionServerClient**: `string`[]

#### Defined in

ssh.ts:210

___

### Cookie

• `Optional` **Cookie**: `Uint8Array`

fixed size array of length: [16]

#### Defined in

ssh.ts:204

___

### FirstKexFollows

• `Optional` **FirstKexFollows**: `boolean`

#### Defined in

ssh.ts:222

___

### KexAlgos

• `Optional` **KexAlgos**: `string`[]

#### Defined in

ssh.ts:226

___

### LanguagesClientServer

• `Optional` **LanguagesClientServer**: `string`[]

#### Defined in

ssh.ts:218

___

### LanguagesServerClient

• `Optional` **LanguagesServerClient**: `string`[]

#### Defined in

ssh.ts:220

___

### MACsClientServer

• `Optional` **MACsClientServer**: `string`[]

#### Defined in

ssh.ts:212

___

### MACsServerClient

• `Optional` **MACsServerClient**: `string`[]

#### Defined in

ssh.ts:216

___

### Reserved

• `Optional` **Reserved**: `number`

#### Defined in

ssh.ts:224

___

### ServerHostKeyAlgos

• `Optional` **ServerHostKeyAlgos**: `string`[]

#### Defined in

ssh.ts:206
````

### `protocols\javascript\modules\ssh.md`

````markdown
# Namespace: ssh

## Table of contents

### Classes

- [SSHClient](/templates/protocols/javascript/modules/ssh.SSHClient)

### Interfaces

- [Algorithms](/templates/protocols/javascript/modules/ssh.Algorithms)
- [DirectionAlgorithms](/templates/protocols/javascript/modules/ssh.DirectionAlgorithms)
- [EndpointId](/templates/protocols/javascript/modules/ssh.EndpointId)
- [HandshakeLog](/templates/protocols/javascript/modules/ssh.HandshakeLog)
- [KexInitMsg](/templates/protocols/javascript/modules/ssh.KexInitMsg)
````

### `protocols\javascript\modules\ssh.SSHClient.md`

````markdown
# Class: SSHClient

[ssh](/templates/protocols/javascript/modules/ssh).SSHClient

SSHClient is a client for SSH servers.
Internally client uses github.com/zmap/zgrab2/lib/ssh driver.

**`Example`**

```javascript
const ssh = require('nuclei/ssh');
const client = new ssh.SSHClient();
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/ssh.SSHClient#constructor)

### Methods

- [Close](/templates/protocols/javascript/modules/ssh.SSHClient#close)
- [Connect](/templates/protocols/javascript/modules/ssh.SSHClient#connect)
- [ConnectSSHInfoMode](/templates/protocols/javascript/modules/ssh.SSHClient#connectsshinfomode)
- [ConnectWithKey](/templates/protocols/javascript/modules/ssh.SSHClient#connectwithkey)
- [Run](/templates/protocols/javascript/modules/ssh.SSHClient#run)
- [SetTimeout](/templates/protocols/javascript/modules/ssh.SSHClient#settimeout)

## Constructors

### constructor

• **new SSHClient**(): [`SSHClient`](/templates/protocols/javascript/modules/ssh.SSHClient)

#### Returns

[`SSHClient`](/templates/protocols/javascript/modules/ssh.SSHClient)

#### Defined in

ssh.ts:16

## Methods

### Close

▸ **Close**(): `boolean`

Close closes the SSH connection and destroys the client
Returns the success state and error. If error is not nil,
state will be false

#### Returns

`boolean`

**`Example`**

```javascript
const ssh = require('nuclei/ssh');
const client = new ssh.SSHClient();
client.Connect('acme.com', 22, 'username', 'password');
const closed = client.Close();
```

#### Defined in

ssh.ts:118

___

### Connect

▸ **Connect**(`host`, `port`, `username`): `boolean`

Connect tries to connect to provided host and port
with provided username and password with ssh.
Returns state of connection and error. If error is not nil,
state will be false

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `username` | `string` |

#### Returns

`boolean`

**`Example`**

```javascript
const ssh = require('nuclei/ssh');
const client = new ssh.SSHClient();
const connected = client.Connect('acme.com', 22, 'username', 'password');
```

#### Defined in

ssh.ts:43

___

### ConnectSSHInfoMode

▸ **ConnectSSHInfoMode**(`host`, `port`): [`HandshakeLog`](/templates/protocols/javascript/modules/ssh.HandshakeLog)

ConnectSSHInfoMode tries to connect to provided host and port
with provided host and port
Returns HandshakeLog and error. If error is not nil,
state will be false
HandshakeLog is a struct that contains information about the
ssh connection

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`HandshakeLog`](/templates/protocols/javascript/modules/ssh.HandshakeLog)

**`Example`**

```javascript
const ssh = require('nuclei/ssh');
const client = new ssh.SSHClient();
const info = client.ConnectSSHInfoMode('acme.com', 22);
log(to_json(info));
```

#### Defined in

ssh.ts:81

___

### ConnectWithKey

▸ **ConnectWithKey**(`host`, `port`, `username`): `boolean`

ConnectWithKey tries to connect to provided host and port
with provided username and private_key.
Returns state of connection and error. If error is not nil,
state will be false

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |
| `username` | `string` |

#### Returns

`boolean`

**`Example`**

```javascript
const ssh = require('nuclei/ssh');
const client = new ssh.SSHClient();
const privateKey = `-----BEGIN RSA PRIVATE KEY----- ...`;
const connected = client.ConnectWithKey('acme.com', 22, 'username', privateKey);
```

#### Defined in

ssh.ts:61

___

### Run

▸ **Run**(`cmd`): `string`

Run tries to open a new SSH session, then tries to execute
the provided command in said session
Returns string and error. If error is not nil,
state will be false
The string contains the command output

#### Parameters

| Name | Type |
| :------ | :------ |
| `cmd` | `string` |

#### Returns

`string`

**`Example`**

```javascript
const ssh = require('nuclei/ssh');
const client = new ssh.SSHClient();
client.Connect('acme.com', 22, 'username', 'password');
const output = client.Run('id');
log(output);
```

#### Defined in

ssh.ts:101

___

### SetTimeout

▸ **SetTimeout**(`sec`): `void`

SetTimeout sets the timeout for the SSH connection in seconds

#### Parameters

| Name | Type |
| :------ | :------ |
| `sec` | `number` |

#### Returns

`void`

**`Example`**

```javascript
const ssh = require('nuclei/ssh');
const client = new ssh.SSHClient();
client.SetTimeout(10);
```

#### Defined in

ssh.ts:26
````

### `protocols\javascript\modules\structs.md`

````markdown
# Namespace: structs

## Table of contents

### Functions

- [Pack](/templates/protocols/javascript/modules/structs#pack)
- [StructsCalcSize](/templates/protocols/javascript/modules/structs#structscalcsize)
- [Unpack](/templates/protocols/javascript/modules/structs#unpack)

## Functions

### Pack

▸ **Pack**(`formatStr`, `msg`): `Uint8Array` \| ``null``

StructsPack returns a byte slice containing the values of msg slice packed according to the given format.
The items of msg slice must match the values required by the format exactly.
Ex: structs.pack("H", 0)

#### Parameters

| Name | Type |
| :------ | :------ |
| `formatStr` | `string` |
| `msg` | `any` |

#### Returns

`Uint8Array` \| ``null``

**`Example`**

```javascript
const structs = require('nuclei/structs');
const packed = structs.Pack('H', [0]);
```

#### Defined in

structs.ts:13

___

### StructsCalcSize

▸ **StructsCalcSize**(`format`): `number` \| ``null``

StructsCalcSize returns the number of bytes needed to pack the values according to the given format.
Ex: structs.CalcSize("H")

#### Parameters

| Name | Type |
| :------ | :------ |
| `format` | `string` |

#### Returns

`number` \| ``null``

**`Example`**

```javascript
const structs = require('nuclei/structs');
const size = structs.CalcSize('H');
```

#### Defined in

structs.ts:28

___

### Unpack

▸ **Unpack**(`format`, `msg`): `any` \| ``null``

StructsUnpack the byte slice (presumably packed by Pack(format, msg)) according to the given format.
The result is a []interface{} slice even if it contains exactly one item.
The byte slice must contain not less the amount of data required by the format
(len(msg) must more or equal CalcSize(format)).
Ex: structs.Unpack(">I", buff[:nb])

#### Parameters

| Name | Type |
| :------ | :------ |
| `format` | `string` |
| `msg` | `Uint8Array` |

#### Returns

`any` \| ``null``

**`Example`**

```javascript
const structs = require('nuclei/structs');
const result = structs.Unpack('H', [0]);
```

#### Defined in

structs.ts:46
````

### `protocols\javascript\modules\telnet.IsTelnetResponse.md`

````markdown
# Interface: IsTelnetResponse

[telnet](/templates/protocols/javascript/modules/telnet).IsTelnetResponse

IsTelnetResponse is the response from the IsTelnet function.
this is returned by IsTelnet function.

**`Example`**

```javascript
const telnet = require('nuclei/telnet');
const isTelnet = telnet.IsTelnet('acme.com', 23);
log(toJSON(isTelnet));
```

## Table of contents

### Properties

- [Banner](/templates/protocols/javascript/modules/telnet.IsTelnetResponse#banner)
- [IsTelnet](/templates/protocols/javascript/modules/telnet.IsTelnetResponse#istelnet)

## Properties

### Banner

• `Optional` **Banner**: `string`

#### Defined in

telnet.ts:32

___

### IsTelnet

• `Optional` **IsTelnet**: `boolean`

#### Defined in

telnet.ts:30
````

### `protocols\javascript\modules\telnet.md`

````markdown
# Namespace: telnet

## Table of contents

### Interfaces

- [IsTelnetResponse](/templates/protocols/javascript/modules/telnet.IsTelnetResponse)

### Functions

- [IsTelnet](/templates/protocols/javascript/modules/telnet#istelnet)

## Functions

### IsTelnet

▸ **IsTelnet**(`host`, `port`): [`IsTelnetResponse`](/templates/protocols/javascript/modules/telnet.IsTelnetResponse) \| ``null``

IsTelnet checks if a host is running a Telnet server.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsTelnetResponse`](/templates/protocols/javascript/modules/telnet.IsTelnetResponse) \| ``null``

**`Example`**

```javascript
const telnet = require('nuclei/telnet');
const isTelnet = telnet.IsTelnet('acme.com', 23);
log(toJSON(isTelnet));
```

#### Defined in

telnet.ts:12
````

### `protocols\javascript\modules\telnet.TelnetClient.md`

````markdown
# Class: TelnetClient

[telnet](/templates/protocols/javascript/modules/telnet).TelnetClient

TelnetClient is a minimal Telnet client for nuclei scripts.

**`Example`**

```javascript
const telnet = require('nuclei/telnet');
const client = new telnet.Client();
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/telnet.TelnetClient#constructor)

### Methods

- [IsTelnet](/templates/protocols/javascript/modules/telnet.TelnetClient#istelnet)

## Constructors

### constructor

• **new TelnetClient**(): [`TelnetClient`](/templates/protocols/javascript/modules/telnet.TelnetClient)

#### Returns

[`TelnetClient`](/templates/protocols/javascript/modules/telnet.TelnetClient)

#### Defined in

telnet.ts:15

## Methods

### IsTelnet

▸ **IsTelnet**(`host`, `port`): [`IsTelnetResponse`](/templates/protocols/javascript/modules/telnet.IsTelnetResponse)

IsTelnet checks if a host is running a Telnet server.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsTelnetResponse`](/templates/protocols/javascript/modules/telnet.IsTelnetResponse)

**`Example`**

```javascript
const telnet = require('nuclei/telnet');
const isTelnet = telnet.IsTelnet('acme.com', 23);
log(toJSON(isTelnet));
```

#### Defined in

telnet.ts:25
````

### `protocols\javascript\modules\vnc.IsVNCResponse.md`

````markdown
# Interface: IsVNCResponse

[vnc](/templates/protocols/javascript/modules/vnc).IsVNCResponse

IsVNCResponse is the response from the IsVNC function.

**`Example`**

```javascript
const vnc = require('nuclei/vnc');
const isVNC = vnc.IsVNC('acme.com', 5900);
log(toJSON(isVNC));
```

## Table of contents

### Properties

- [Banner](/templates/protocols/javascript/modules/vnc.IsVNCResponse#banner)
- [IsVNC](/templates/protocols/javascript/modules/vnc.IsVNCResponse#isvnc)

## Properties

### Banner

• `Optional` **Banner**: `string`

#### Defined in

vnc.ts:33

___

### IsVNC

• `Optional` **IsVNC**: `boolean`

#### Defined in

vnc.ts:31
````

### `protocols\javascript\modules\vnc.md`

````markdown
# Namespace: vnc

## Table of contents

### Interfaces

- [IsVNCResponse](/templates/protocols/javascript/modules/vnc.IsVNCResponse)

### Functions

- [IsVNC](/templates/protocols/javascript/modules/vnc#isvnc)

## Functions

### IsVNC

▸ **IsVNC**(`host`, `port`): [`IsVNCResponse`](/templates/protocols/javascript/modules/vnc.IsVNCResponse) \| ``null``

IsVNC checks if a host is running a VNC server.
It returns a boolean indicating if the host is running a VNC server
and the banner of the VNC server.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsVNCResponse`](/templates/protocols/javascript/modules/vnc.IsVNCResponse) \| ``null``

**`Example`**

```javascript
const vnc = require('nuclei/vnc');
const isVNC = vnc.IsVNC('acme.com', 5900);
log(toJSON(isVNC));
```

#### Defined in

vnc.ts:14
````

### `protocols\javascript\modules\vnc.VNCClient.md`

````markdown
# Class: VNCClient

[vnc](/templates/protocols/javascript/modules/vnc).VNCClient

VNCClient is a minimal VNC client for nuclei scripts.

**`Example`**

```javascript
const vnc = require('nuclei/vnc');
const client = new vnc.Client();
```

## Table of contents

### Constructors

- [constructor](/templates/protocols/javascript/modules/vnc.VNCClient#constructor)

### Methods

- [IsVNC](/templates/protocols/javascript/modules/vnc.VNCClient#isvnc)

## Constructors

### constructor

• **new VNCClient**(): [`VNCClient`](/templates/protocols/javascript/modules/vnc.VNCClient)

#### Returns

[`VNCClient`](/templates/protocols/javascript/modules/vnc.VNCClient)

#### Defined in

vnc.ts:15

## Methods

### IsVNC

▸ **IsVNC**(`host`, `port`): [`IsVNCResponse`](/templates/protocols/javascript/modules/vnc.IsVNCResponse)

IsVNC checks if a host is running a VNC server.
It returns a boolean indicating if the host is running a VNC server
and the banner of the VNC server.

#### Parameters

| Name | Type |
| :------ | :------ |
| `host` | `string` |
| `port` | `number` |

#### Returns

[`IsVNCResponse`](/templates/protocols/javascript/modules/vnc.IsVNCResponse)

**`Example`**

```javascript
const vnc = require('nuclei/vnc');
const isVNC = vnc.IsVNC('acme.com', 5900);
log(toJSON(isVNC));
```

#### Defined in

vnc.ts:27
````

### `protocols\javascript\modules\_Sidebar.md`

````markdown
## nuclei

- [Home](../wiki/Home)
- [Exports](../wiki/Exports)

### Namespaces

- [bytes](../wiki/bytes)
- [fs](../wiki/fs)
- [goconsole](../wiki/goconsole)
- [ikev2](../wiki/ikev2)
- [kerberos](../wiki/kerberos)
- [ldap](../wiki/ldap)
- [mssql](../wiki/mssql)
- [mysql](../wiki/mysql)
- [net](../wiki/net)
- [oracle](../wiki/oracle)
- [pop3](../wiki/pop3)
- [postgres](../wiki/postgres)
- [rdp](../wiki/rdp)
- [redis](../wiki/redis)
- [rsync](../wiki/rsync)
- [smb](../wiki/smb)
- [smtp](../wiki/smtp)
- [ssh](../wiki/ssh)
- [structs](../wiki/structs)
- [telnet](../wiki/telnet)
- [vnc](../wiki/vnc)
````

### `reference\extractors.md`

````markdown
---
title: "Extractors"
description: "Review details on extractors for Nuclei"
icon: "arrow-down-to-line"
iconType: "duotone"
---

Extractors can be used to extract and display in results a match from the response returned by a module.

### Types

Multiple extractors can be specified in a request. As of now we support five type of extractors.

1. **regex** - Extract data from response based on a Regular Expression.
2. **kval** - Extract `key: value`/`key=value` formatted data from Response Header/Cookie
3. **json** - Extract data from JSON based response in JQ like syntax.
4. **xpath** - Extract xpath based data from HTML Response
5. **dsl** - Extract data from the response based on a DSL expressions.

### Regex Extractor

Example extractor for HTTP Response body using **regex** -

```yaml
extractors:
  - type: regex # type of the extractor
    part: body  # part of the response (header,body,all)
    regex:
      - "(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"  # regex to use for extraction.
```

### Kval Extractor

A **kval** extractor example to extract `content-type` header from HTTP Response.

```yaml
extractors:
  - type: kval # type of the extractor
    kval:
      - content_type # header/cookie value to extract from response
```

Note that `content-type` has been replaced with `content_type` because **kval** extractor does not accept dash (`-`) as input and must be substituted with underscore (`_`).

### JSON Extractor

A **json** extractor example to extract value of `id` object from JSON block.

```yaml
      - type: json # type of the extractor
        part: body
        name: user
        json:
          - '.[] | .id'  # JQ like syntax for extraction
```

For more details about JQ - <https://github.com/stedolan/jq>

### Xpath Extractor

A **xpath** extractor example to extract value of `href` attribute from HTML response.

```yaml
extractors:
  - type: xpath # type of the extractor
    attribute: href # attribute value to extract (optional)
    xpath:
      - '/html/body/div/p[2]/a' # xpath value for extraction
```

With a simple [copy paste in browser](https://www.scientecheasy.com/2020/07/find-xpath-chrome.html/), we can get the **xpath** value form any web page content.

### DSL Extractor

A **dsl** extractor example to extract the effective `body` length through the `len` helper function from HTTP Response.

```yaml
extractors:
  - type: dsl  # type of the extractor
    dsl:
      - len(body) # dsl expression value to extract from response
```

### Dynamic Extractor

Extractors can be used to capture Dynamic Values on runtime while writing Multi-Request templates. CSRF Tokens, Session Headers, etc. can be extracted and used in requests. This feature is only available in RAW request format.

Example of defining a dynamic extractor with name `api` which will capture a regex based pattern from the request.

```yaml
    extractors:
      - type: regex
        name: api
        part: body
        internal: true # Required for using dynamic variables
        regex:
          - "(?m)[0-9]{3,10}\\.[0-9]+"
```

The extracted value is stored in the variable **api**, which can be utilized in any section of the subsequent requests.

If you want to use extractor as a dynamic variable, you must use `internal: true` to avoid printing extracted values in the terminal.

An optional regex **match-group** can also be specified for the regex for more complex matches.

```yaml
extractors:
  - type: regex  # type of extractor
    name: csrf_token # defining the variable name
    part: body # part of response to look for
    # group defines the matching group being used.
    # In GO the "match" is the full array of all matches and submatches
    # match[0] is the full match
    # match[n] is the submatches. Most often we'd want match[1] as depicted below
    group: 1
    regex:
      - '<input\sname="csrf_token"\stype="hidden"\svalue="([[:alnum:]]{16})"\s/>'
```

The above extractor with name `csrf_token` will hold the value extracted by `([[:alnum:]]{16})` as `abcdefgh12345678`.

If no group option is provided with this regex, the above extractor with name `csrf_token` will hold the full match (by `<input name="csrf_token"\stype="hidden"\svalue="([[:alnum:]]{16})" />`) as `<input name="csrf_token" type="hidden" value="abcdefgh12345678" />`.

### Reusable Dynamic Extractors

With Nuclei v3.1.4 you can now reuse dynamic extracted value (ex: csrf_token in above example) immediately in next extractors and is by default available in subsequent requests

Example:

```yml
id: basic-raw-example

info:
  name: Test RAW Template
  author: pdteam
  severity: info


http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}

    extractors:
      - type: regex
        name: title
        group: 1
        regex:
          - '<title>(.*)<\/title>'
        internal: true

      - type: dsl
        dsl:
          - '"Title is " + title'
```
````

### `reference\helper-functions-examples.md`

````markdown
---
title: "Helper Functions Examples"
description: "Examples of the helper functions used in Nuclei Templates"
---

Nuclei has a number of helper functions that may be used to conduct various run-time operations on the request block. Here's an example template that shows how to use all the available helper functions.

```yaml
id: helper-functions-examples

info:
  name: RAW Template with Helper Functions
  author: pdteam
  severity: info

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        1: {{base64("Hello")}}
        2: {{base64(1234)}}
        3: {{base64_decode("SGVsbG8=")}}
        4: {{base64_py("Hello")}}
        5: {{compare_versions('v1.0.0', '>v0.0.1', '<v1.0.1')}}
        6: {{concat("Hello", "world")}}
        7: {{contains("Hello", "lo")}}
        8: {{contains_all("Hello everyone", "lo", "every")}}
        9: {{contains_any("Hello everyone", "abc", "llo")}}
        10: {{date_time("%Y-%M-%D")}}
        11: {{date_time("%Y-%M-%D", unix_time())}}
        12: {{date_time("%H-%m")}}
        13: {{date_time("02-01-2006 15:04")}}
        14: {{date_time("02-01-2006 15:04", unix_time())}}
        15: {{dec_to_hex(11111)}}
        16: {{generate_java_gadget("commons-collections3.1", "wget http://{{interactsh-url}}", "base64")}}
        17: {{gzip("Hello")}}
        18: {{gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))}}
        19: {{hex_decode("6161")}}
        20: {{hex_encode("aa")}}
        21: {{hmac("sha1", "test", "scrt")}}
        22: {{hmac("sha256", "test", "scrt")}}
        23: {{html_escape("<body>test</body>")}}
        24: {{html_unescape("&lt;body&gt;test&lt;/body&gt;")}}
        25: {{join("_", "hello", "world")}}
        26: {{len("Hello")}}
        27: {{len(5555)}}
        28: {{md5("Hello")}}
        29: {{md5(1234)}}
        30: {{mmh3("Hello")}}
        31: {{print_debug(1+2, "Hello")}}
        32: {{rand_base(5, "abc")}}
        33: {{rand_base(5, "")}}
        34: {{rand_base(5)}}
        35: {{rand_char("abc")}}
        36: {{rand_char("")}}
        37: {{rand_char()}}
        38: {{rand_int(1, 10)}}
        39: {{rand_int(10)}}
        40: {{rand_int()}}
        41: {{rand_ip("192.168.0.0/24")}}
        42: {{rand_ip("2002:c0a8::/24")}}
        43: {{rand_ip("192.168.0.0/24","10.0.100.0/24")}}
        44: {{rand_text_alpha(10, "abc")}}
        45: {{rand_text_alpha(10, "")}}
        46: {{rand_text_alpha(10)}}
        47: {{rand_text_alphanumeric(10, "ab12")}}
        48: {{rand_text_alphanumeric(10)}}
        49: {{rand_text_numeric(10, 123)}}
        50: {{rand_text_numeric(10)}}
        51: {{regex("H([a-z]+)o", "Hello")}}
        52: {{remove_bad_chars("abcd", "bc")}}
        53: {{repeat("a", 5)}}
        54: {{replace("Hello", "He", "Ha")}}
        55: {{replace_regex("He123llo", "(\\d+)", "")}}
        56: {{reverse("abc")}}
        57: {{sha1("Hello")}}
        58: {{sha256("Hello")}}
        59: {{to_lower("HELLO")}}
        60: {{to_upper("hello")}}
        61: {{trim("aaaHelloddd", "ad")}}
        62: {{trim_left("aaaHelloddd", "ad")}}
        63: {{trim_prefix("aaHelloaa", "aa")}}
        64: {{trim_right("aaaHelloddd", "ad")}}
        65: {{trim_space("  Hello  ")}}
        66: {{trim_suffix("aaHelloaa", "aa")}}
        67: {{unix_time(10)}}
        68: {{url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1")}}
        69: {{url_encode("https://projectdiscovery.io/test?a=1")}}
        70: {{wait_for(1)}}
        71: {{zlib("Hello")}}
        72: {{zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"))}}
        73: {{hex_encode(aes_gcm("AES256Key-32Characters1234567890", "exampleplaintext"))}}
        74: {{starts_with("Hello", "He")}}
        75: {{ends_with("Hello", "lo")}}
        76: {{line_starts_with("Hi\nHello", "He")}}
        77: {{line_ends_with("Hello\nHi", "lo")}}
        78: {{ip_format("169.254.169.254", 4)}}
```
````

### `reference\helper-functions.md`

````markdown
---
title: "Helper Functions"
description: "Review details on helper functions for Nuclei"
icon: "function"
iconType: "solid"
---

Here is the list of all supported helper functions can be used in the RAW requests / Network requests.

| Helper function                                                       | Description                                                                                                                                                                                                                           | Example                                                                                                                                                  | Output                                                                                                                                                                                                                                                                                                                                                                                     |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| aes_gcm(key, plaintext interface{}) []byte                            | AES GCM encrypts a string with key                                                                                                                                                                                                    | `{{hex_encode(aes_gcm("AES256Key-32Characters1234567890", "exampleplaintext"))}}`                                                                        | `ec183a153b8e8ae7925beed74728534b57a60920c0b009eaa7608a34e06325804c096d7eebccddea3e5ed6c4`                                                                                                                                                                                                                                                                                                 |
| base64(src interface{}) string                                        | Base64 encodes a string                                                                                                                                                                                                               | `base64("Hello")`                                                                                                                                        | `SGVsbG8=`                                                                                                                                                                                                                                                                                                                                                                                 |
| base64_decode(src interface{}) []byte                                 | Base64 decodes a string                                                                                                                                                                                                               | `base64_decode("SGVsbG8=")`                                                                                                                              | `Hello`                                                                                                                                                                                                                                                                                                                                                                                    |
| base64_py(src interface{}) string                                     | Encodes string to base64 like python (with new lines)                                                                                                                                                                                 | `base64_py("Hello")`                                                                                                                                     | `SGVsbG8=\n`                                                                                                                                                                                                                                                                                                                                                                               |
| bin_to_dec(binaryNumber number &#124; string) float64                 | Transforms the input binary number into a decimal format                                                                                                                                                                              | `bin_to_dec("0b1010")`<br />`bin_to_dec(1010)`                                                                                                            | `10`                                                                                                                                                                                                                                                                                                                                                                                       |
| compare_versions(versionToCheck string, constraints ...string) bool   | Compares the first version argument with the provided constraints                                                                                                                                                                     | `compare_versions('v1.0.0', '\>v0.0.1', '\<v1.0.1')`                                                                                                     | `true`                                                                                                                                                                                                                                                                                                                                                                                     |
| concat(arguments ...interface{}) string                               | Concatenates the given number of arguments to form a string                                                                                                                                                                           | `concat("Hello", 123, "world)`                                                                                                                           | `Hello123world`                                                                                                                                                                                                                                                                                                                                                                            |
| contains(input, substring interface{}) bool                           | Verifies if a string contains a substring                                                                                                                                                                                             | `contains("Hello", "lo")`                                                                                                                                | `true`                                                                                                                                                                                                                                                                                                                                                                                     |
| contains_all(input interface{}, substrings ...string) bool            | Verifies if any input contains all of the substrings                                                                                                                                                                                  | `contains("Hello everyone", "lo", "every")`                                                                                                              | `true`                                                                                                                                                                                                                                                                                                                                                                                     |
| contains_any(input interface{}, substrings ...string) bool            | Verifies if an input contains any of substrings                                                                                                                                                                                       | `contains("Hello everyone", "abc", "llo")`                                                                                                               | `true`                                                                                                                                                                                                                                                                                                                                                                                     |
| date_time(dateTimeFormat string, optionalUnixTime interface{}) string | Returns the formatted date time using simplified or `go` style layout for the current or the given unix time                                                                                                                          | `date_time("%Y-%M-%D %H:%m")`<br />`date_time("%Y-%M-%D %H:%m", 1654870680)`<br />`date_time("2006-01-02 15:04", unix_time())`                           | `2022-06-10 14:18`                                                                                                                                                                                                                                                                                                                                                                         |
| dec_to_hex(number number &#124; string) string                        | Transforms the input number into hexadecimal format                                                                                                                                                                                   | `dec_to_hex(7001)"`                                                                                                                                      | `1b59`                                                                                                                                                                                                                                                                                                                                                                                     |
| ends_with(str string, suffix ...string) bool                          | Checks if the string ends with any of the provided substrings                                                                                                                                                                         | `ends_with("Hello", "lo")`                                                                                                                               | `true`                                                                                                                                                                                                                                                                                                                                                                                     |
| generate_java_gadget(gadget, cmd, encoding interface{}) string        | Generates a Java Deserialization Gadget                                                                                                                                                                                               | `generate_java_gadget("dns", "{{interactsh-url}}", "base64")`                                                                                            | `rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAAHQAAHEAfgAFdAAFcHh0ACpjYWhnMmZiaW41NjRvMGJ0MHRzMDhycDdlZXBwYjkxNDUub2FzdC5mdW54` |
| generate_jwt(json, algorithm, signature, unixMaxAge) []byte           | Generates a JSON Web Token (JWT) using the claims provided in a JSON string, the signature, and the specified algorithm                                                                                                               | `generate_jwt("{\"name\":\"John Doe\",\"foo\":\"bar\"}", "HS256", "hello-world")`                                                                        | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYW1lIjoiSm9obiBEb2UifQ.EsrL8lIcYJR_Ns-JuhF3VCllCP7xwbpMCCfHin_WT6U`                                                                                                                                                                                                                                                              |
| gzip(input string) string                                             | Compresses the input using GZip                                                                                                                                                                                                       | `base64(gzip("Hello"))`                                                                                                                                  | `+H4sIAAAAAAAA//JIzcnJBwQAAP//gonR9wUAAAA=`                                                                                                                                                                                                                                                                                                                                                |
| gzip_decode(input string) string                                      | Decompresses the input using GZip                                                                                                                                                                                                     | `gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))`                                                                  | `Hello`                                                                                                                                                                                                                                                                                                                                                                                    |
| hex_decode(input interface{}) []byte                                  | Hex decodes the given input                                                                                                                                                                                                           | `hex_decode("6161")`                                                                                                                                     | `aa`                                                                                                                                                                                                                                                                                                                                                                                       |
| hex_encode(input interface{}) string                                  | Hex encodes the given input                                                                                                                                                                                                           | `hex_encode("aa")`                                                                                                                                       | `6161`                                                                                                                                                                                                                                                                                                                                                                                     |
| hex_to_dec(hexNumber number &#124; string) float64                    | Transforms the input hexadecimal number into decimal format                                                                                                                                                                           | `hex_to_dec("ff")`<br />`hex_to_dec("0xff")`                                                                                                             | `255`                                                                                                                                                                                                                                                                                                                                                                                      |
| hmac(algorithm, data, secret) string                                  | hmac function that accepts a hashing function type with data and secret                                                                                                                                                               | `hmac("sha1", "test", "scrt")`                                                                                                                           | `8856b111056d946d5c6c92a21b43c233596623c6`                                                                                                                                                                                                                                                                                                                                                 |
| html_escape(input interface{}) string                                 | HTML escapes the given input                                                                                                                                                                                                          | `html_escape("\<body\>test\</body\>")`                                                                                                                   | `&lt;body&gt;test&lt;/body&gt;`                                                                                                                                                                                                                                                                                                                                                            |
| html_unescape(input interface{}) string                               | HTML un-escapes the given input                                                                                                                                                                                                       | `html_unescape("&lt;body&gt;test&lt;/body&gt;")`                                                                                                         | `\<body\>test\</body\>`                                                                                                                                                                                                                                                                                                                                                                    |
| join(separator string, elements ...interface{}) string                | Joins the given elements using the specified separator                                                                                                                                                                                | `join("_", 123, "hello", "world")`                                                                                                                       | `123_hello_world`                                                                                                                                                                                                                                                                                                                                                                          |
| json_minify(json) string                                              | Minifies a JSON string by removing unnecessary whitespace                                                                                                                                                                             | `json_minify("{ \"name\": \"John Doe\", \"foo\": \"bar\" }")`                                                                                            | `{"foo":"bar","name":"John Doe"}`                                                                                                                                                                                                                                                                                                                                                          |
| json_prettify(json) string                                            | Prettifies a JSON string by adding indentation                                                                                                                                                                                        | `json_prettify("{\"foo\":\"bar\",\"name\":\"John Doe\"}")`                                                                                               | `{\n \"foo\": \"bar\",\n \"name\": \"John Doe\"\n}`                                                                                                                                                                                                                                                                                                                                        |
| len(arg interface{}) int                                              | Returns the length of the input                                                                                                                                                                                                       | `len("Hello")`                                                                                                                                           | `5`                                                                                                                                                                                                                                                                                                                                                                                        |
| line_ends_with(str string, suffix ...string) bool                     | Checks if any line of the string ends with any of the provided substrings                                                                                                                                                             | `line_ends_with("Hello\nHi", "lo")`                                                                                                                      | `true`                                                                                                                                                                                                                                                                                                                                                                                     |
| line_starts_with(str string, prefix ...string) bool                   | Checks if any line of the string starts with any of the provided substrings                                                                                                                                                           | `line_starts_with("Hi\nHello", "He")`                                                                                                                    | `true`                                                                                                                                                                                                                                                                                                                                                                                     |
| md5(input interface{}) string                                         | Calculates the MD5 (Message Digest) hash of the input                                                                                                                                                                                 | `md5("Hello")`                                                                                                                                           | `8b1a9953c4611296a827abf8c47804d7`                                                                                                                                                                                                                                                                                                                                                         |
| mmh3(input interface{}) string                                        | Calculates the MMH3 (MurmurHash3) hash of an input                                                                                                                                                                                    | `mmh3("Hello")`                                                                                                                                          | `316307400`                                                                                                                                                                                                                                                                                                                                                                                |
| oct_to_dec(octalNumber number &#124; string) float64                  | Transforms the input octal number into a decimal format                                                                                                                                                                               | `oct_to_dec("0o1234567")`<br />`oct_to_dec(1234567)`                                                                                                     | `342391`                                                                                                                                                                                                                                                                                                                                                                                   |
| print_debug(args ...interface{})                                      | Prints the value of a given input or expression. Used for debugging.                                                                                                                                                                  | `print_debug(1+2, "Hello")`                                                                                                                              | `3 Hello`                                                                                                                                                                                                                                                                                                                                                                                  |
| rand_base(length uint, optionalCharSet string) string                 | Generates a random sequence of given length string from an optional charset (defaults to letters and numbers)                                                                                                                         | `rand_base(5, "abc")`                                                                                                                                    | `caccb`                                                                                                                                                                                                                                                                                                                                                                                    |
| rand_char(optionalCharSet string) string                              | Generates a random character from an optional character set (defaults to letters and numbers)                                                                                                                                         | `rand_char("abc")`                                                                                                                                       | `a`                                                                                                                                                                                                                                                                                                                                                                                        |
| rand_int(optionalMin, optionalMax uint) int                           | Generates a random integer between the given optional limits (defaults to 0 - MaxInt32)                                                                                                                                               | `rand_int(1, 10)`                                                                                                                                        | `6`                                                                                                                                                                                                                                                                                                                                                                                        |
| rand_text_alpha(length uint, optionalBadChars string) string          | Generates a random string of letters, of given length, excluding the optional cutset characters                                                                                                                                       | `rand_text_alpha(10, "abc")`                                                                                                                             | `WKozhjJWlJ`                                                                                                                                                                                                                                                                                                                                                                               |
| rand_text_alphanumeric(length uint, optionalBadChars string) string   | Generates a random alphanumeric string, of given length without the optional cutset characters                                                                                                                                        | `rand_text_alphanumeric(10, "ab12")`                                                                                                                     | `NthI0IiY8r`                                                                                                                                                                                                                                                                                                                                                                               |
| rand_ip(cidr ...string) string                                        | Generates a random IP address                                                                                                                                                                                                         | `rand_ip("192.168.0.0/24")`                                                                                                                              | `192.168.0.171`                                                                                                                                                                                                                                                                                                                                                                            |
| rand_text_numeric(length uint, optionalBadNumbers string) string      | Generates a random numeric string of given length without the optional set of undesired numbers                                                                                                                                       | `rand_text_numeric(10, 123)`                                                                                                                             | `0654087985`                                                                                                                                                                                                                                                                                                                                                                               |
| regex(pattern, input string) bool                                     | Tests the given regular expression against the input string                                                                                                                                                                           | `regex("H([a-z]+)o", "Hello")`                                                                                                                           | `true`                                                                                                                                                                                                                                                                                                                                                                                     |
| remove_bad_chars(input, cutset interface{}) string                    | Removes the desired characters from the input                                                                                                                                                                                         | `remove_bad_chars("abcd", "bc")`                                                                                                                         | `ad`                                                                                                                                                                                                                                                                                                                                                                                       |
| repeat(str string, count uint) string                                 | Repeats the input string the given amount of times                                                                                                                                                                                    | `repeat("../", 5)`                                                                                                                                       | `../../../../../`                                                                                                                                                                                                                                                                                                                                                                          |
| replace(str, old, new string) string                                  | Replaces a given substring in the given input                                                                                                                                                                                         | `replace("Hello", "He", "Ha")`                                                                                                                           | `Hallo`                                                                                                                                                                                                                                                                                                                                                                                    |
| replace_regex(source, regex, replacement string) string               | Replaces substrings matching the given regular expression in the input                                                                                                                                                                | `replace_regex("He123llo", "(\\d+)", "")`                                                                                                                | `Hello`                                                                                                                                                                                                                                                                                                                                                                                    |
| reverse(input string) string                                          | Reverses the given input                                                                                                                                                                                                              | `reverse("abc")`                                                                                                                                         | `cba`                                                                                                                                                                                                                                                                                                                                                                                      |
| sha1(input interface{}) string                                        | Calculates the SHA1 (Secure Hash 1) hash of the input                                                                                                                                                                                 | `sha1("Hello")`                                                                                                                                          | `f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0`                                                                                                                                                                                                                                                                                                                                                 |
| sha256(input interface{}) string                                      | Calculates the SHA256 (Secure Hash 256) hash of the input                                                                                                                                                                             | `sha256("Hello")`                                                                                                                                        | `185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969`                                                                                                                                                                                                                                                                                                                         |
| starts_with(str string, prefix ...string) bool                        | Checks if the string starts with any of the provided substrings                                                                                                                                                                       | `starts_with("Hello", "He")`                                                                                                                             | `true`                                                                                                                                                                                                                                                                                                                                                                                     |
| to_lower(input string) string                                         | Transforms the input into lowercase characters                                                                                                                                                                                        | `to_lower("HELLO")`                                                                                                                                      | `hello`                                                                                                                                                                                                                                                                                                                                                                                    |
| to_unix_time(input string, layout string) int                         | Parses a string date time using default or user given layouts, then returns its Unix timestamp                                                                                                                                        | `to_unix_time("2022-01-13T16:30:10+00:00")`<br />`to_unix_time("2022-01-13 16:30:10")`<br />`to_unix_time("13-01-2022 16:30:10", "02-01-2006 15:04:05")` | `1642091410`                                                                                                                                                                                                                                                                                                                                                                               |
| to_upper(input string) string                                         | Transforms the input into uppercase characters                                                                                                                                                                                        | `to_upper("hello")`                                                                                                                                      | `HELLO`                                                                                                                                                                                                                                                                                                                                                                                    |
| trim(input, cutset string) string                                     | Returns a slice of the input with all leading and trailing Unicode code points contained in cutset removed                                                                                                                            | `trim("aaaHelloddd", "ad")`                                                                                                                              | `Hello`                                                                                                                                                                                                                                                                                                                                                                                    |
| trim_left(input, cutset string) string                                | Returns a slice of the input with all leading Unicode code points contained in cutset removed                                                                                                                                         | `trim_left("aaaHelloddd", "ad")`                                                                                                                         | `Helloddd`                                                                                                                                                                                                                                                                                                                                                                                 |
| trim_prefix(input, prefix string) string                              | Returns the input without the provided leading prefix string                                                                                                                                                                          | `trim_prefix("aaHelloaa", "aa")`                                                                                                                         | `Helloaa`                                                                                                                                                                                                                                                                                                                                                                                  |
| trim_right(input, cutset string) string                               | Returns a string, with all trailing Unicode code points contained in cutset removed                                                                                                                                                   | `trim_right("aaaHelloddd", "ad")`                                                                                                                        | `aaaHello`                                                                                                                                                                                                                                                                                                                                                                                 |
| trim_space(input string) string                                       | Returns a string, with all leading and trailing white space removed, as defined by Unicode                                                                                                                                            | `trim_space("  Hello  ")`                                                                                                                                | `"Hello"`                                                                                                                                                                                                                                                                                                                                                                                  |
| trim_suffix(input, suffix string) string                              | Returns input without the provided trailing suffix string                                                                                                                                                                             | `trim_suffix("aaHelloaa", "aa")`                                                                                                                         | `aaHello`                                                                                                                                                                                                                                                                                                                                                                                  |
| unix_time(optionalSeconds uint) float64                               | Returns the current Unix time (number of seconds elapsed since January 1, 1970 UTC) with the added optional seconds                                                                                                                   | `unix_time(10)`                                                                                                                                          | `1639568278`                                                                                                                                                                                                                                                                                                                                                                               |
| url_decode(input string) string                                       | URL decodes the input string                                                                                                                                                                                                          | `url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1")`                                                                                                 | `https://projectdiscovery.io?test=1`                                                                                                                                                                                                                                                                                                                                                       |
| url_encode(input string) string                                       | URL encodes the input string                                                                                                                                                                                                          | `url_encode("https://projectdiscovery.io/test?a=1")`                                                                                                     | `https%3A%2F%2Fprojectdiscovery.io%2Ftest%3Fa%3D1`                                                                                                                                                                                                                                                                                                                                         |
| wait_for(seconds uint)                                                | Pauses the execution for the given amount of seconds                                                                                                                                                                                  | `wait_for(10)`                                                                                                                                           | `true`                                                                                                                                                                                                                                                                                                                                                                                     |
| zlib(input string) string                                             | Compresses the input using Zlib                                                                                                                                                                                                       | `base64(zlib("Hello"))`                                                                                                                                  | `eJzySM3JyQcEAAD//wWMAfU=`                                                                                                                                                                                                                                                                                                                                                                 |
| zlib_decode(input string) string                                      | Decompresses the input using Zlib                                                                                                                                                                                                     | `zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"))`                                                                                          | `Hello`                                                                                                                                                                                                                                                                                                                                                                                    |
| resolve(host string, format string) string                            | Resolves a host using a dns type that you define                                                                                                                                                                                      | `resolve("localhost",4)`                                                                                                                                 | `127.0.0.1`                                                                                                                                                                                                                                                                                                                                                                                |
| ip_format(ip string, format string) string                            | It takes an input ip and converts it to another format according to this [legend](https://github.com/projectdiscovery/mapcidr/wiki/IP-Format-Index), the second parameter indicates the conversion index and must be between 1 and 11 | `ip_format("127.0.0.1", 3)`                                                                                                                              | `0177.0.0.01`                                                                                                                                                                                                                                                                                                                                                                              |

## Deserialization helper functions

Nuclei allows payload generation for a few common gadget from [ysoserial](https://github.com/frohoff/ysoserial).

**Supported Payload:**

- `dns` (URLDNS)
- `commons-collections3.1`
- `commons-collections4.0`
- `jdk7u21`
- `jdk8u20`
- `groovy1`

**Supported encodings:**

- `base64` (default)
- `gzip-base64`
- `gzip`
- `hex`
- `raw`

**Deserialization helper function format:**

```yaml
{ { generate_java_gadget(payload, cmd, encoding } }
```

**Deserialization helper function example:**

```yaml
{{generate_java_gadget("commons-collections3.1", "wget http://{{interactsh-url}}", "base64")}}
```

## JSON helper functions

Nuclei allows manipulate JSON strings in different ways, here is a list of its functions:

- `generate_jwt`, to generates a JSON Web Token (JWT) using the claims provided in a JSON string, the signature, and the specified algorithm.
- `json_minify`, to minifies a JSON string by removing unnecessary whitespace.
- `json_prettify`, to prettifies a JSON string by adding indentation.

**Examples**

**`generate_jwt`**

To generate a JSON Web Token (JWT), you have to supply the JSON that you want to sign, _at least_.

Here is a list of supported algorithms for generating JWTs with `generate_jwt` function _(case-insensitive)_:

- `HS256`
- `HS384`
- `HS512`
- `RS256`
- `RS384`
- `RS512`
- `PS256`
- `PS384`
- `PS512`
- `ES256`
- `ES384`
- `ES512`
- `EdDSA`
- `NONE`

Empty string ("") also means `NONE`.

Format:

```yaml
{ { generate_jwt(json, algorithm, signature, maxAgeUnix) } }
```

> Arguments other than `json` are optional.

Example:

```yaml
variables:
  json: | # required
    {
      "foo": "bar",
      "name": "John Doe"
    }
  alg: "HS256" # optional
  sig: "this_is_secret" # optional
  age: '{{to_unix_time("2032-12-30T16:30:10+00:00")}}' # optional
  jwt: '{{generate_jwt(json, "{{alg}}", "{{sig}}", "{{age}}")}}'
```

> The `maxAgeUnix` argument is to set the expiration `"exp"` JWT standard claim, as well as the `"iat"` claim when you call the function.

**`json_minify`**

Format:

```yaml
{ { json_minify(json) } }
```

Example:

```yaml
variables:
  json: |
    {
      "foo": "bar",
      "name": "John Doe"
    }
  minify: "{{json_minify(json}}"
```

`minify` variable output:

```json
{ "foo": "bar", "name": "John Doe" }
```

**`json_prettify`**

Format:

```yaml
{ { json_prettify(json) } }
```

Example:

```yaml
variables:
  json: '{"foo":"bar","name":"John Doe"}'
  pretty: "{{json_prettify(json}}"
```

`pretty` variable output:

```json
{
  "foo": "bar",
  "name": "John Doe"
}
```

**`resolve`**

Format:

```yaml
{ { resolve(host, format) } }
```

Here is a list of formats available for dns type:

- `4` or `a`
- `6` or `aaaa`
- `cname`
- `ns`
- `txt`
- `srv`
- `ptr`
- `mx`
- `soa`
- `caa`

## Examples

<Tip>
For more examples, see the [helper function examples](/templates/reference/helper-functions-examples)
</Tip>
````

### `reference\js-helper-functions.md`

````markdown
---
title: "Javascript Helper Functions"
description: "Available JS Helper Functions that can be used in global js runtime & protocol specific helpers."
icon: "function"
iconType: "solid"
---


## Javascript Runtime

| Name           | Description                                                                                                    | Signatures                                                    |
| -------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| atob           | Base64 decodes a given string                                                                                  | `atob(string) string`                                         |
| btoa           | Base64 encodes a given string                                                                                  | `bota(string) string`                                         |
| to_json        | Converts a given object to JSON                                                                                | `to_json(any) object`                                         |
| dump_json      | Prints a given object as JSON in console                                                                       | `dump_json(any)`                                              |
| to_array       | Sets/Updates objects prototype to array to enable Array.XXX functions                                          | `to_array(any) array`                                         |
| hex_to_ascii   | Converts a given hex string to ascii                                                                           | `hex_to_ascii(string) string`                                 |
| Rand           | Rand returns a random byte slice of length n                                                                   | `Rand(n int) []byte`                                          |
| RandInt        | RandInt returns a random int                                                                                   | `RandInt() int`                                               |
| log            | log prints given input to stdout with [JS] prefix for debugging purposes                                       | `log(msg string)`, `log(msg map[string]interface{})`          |
| getNetworkPort | getNetworkPort registers defaultPort and returns defaultPort if it is a colliding port with other protocols    | `getNetworkPort(port string, defaultPort string) string`      |
| isPortOpen     | isPortOpen checks if given TCP port is open on host. timeout is optional and defaults to 5 seconds             | `isPortOpen(host string, port string, [timeout int]) bool`    |
| isUDPPortOpen  | isUDPPortOpen checks if the given UDP port is open on the host. Timeout is optional and defaults to 5 seconds. | `isUDPPortOpen(host string, port string, [timeout int]) bool` |
| ToBytes        | ToBytes converts given input to byte slice                                                                     | `ToBytes(...interface{}) []byte`                              |
| ToString       | ToString converts given input to string                                                                        | `ToString(...interface{}) string`                             |
| Export         | Converts a given value to a string and is appended to output of script                                         | `Export(value any)`                                           |
| ExportAs       | Exports given value with specified key and makes it available in DSL and response                              | `ExportAs(key string,value any)`                              |

## Template Flow

| Name    | Description                                                                                                                                                                                                                                           | Signatures              |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| log     | Logs a given object/message to stdout (only for debugging purposes)                                                                                                                                                                                   | `log(obj any) any`      |
| iterate | Normalizes and Iterates over all arguments (can be a string,array,null etc) and returns an array of objects\nNote: If the object type is unknown(i.e could be a string or array) iterate should be used and it will always return an array of strings | `iterate(...any) []any` |
| Dedupe  | De-duplicates given values and returns a new array of unique values                                                                                                                                                                                   | `new Dedupe()`          |

## Code Protocol

| Name      | Description                                         | Signatures         |
| --------- | --------------------------------------------------- | ------------------ |
| OS        | OS returns the current OS                           | `OS() string`      |
| IsLinux   | IsLinux checks if the current OS is Linux           | `IsLinux() bool`   |
| IsWindows | IsWindows checks if the current OS is Windows       | `IsWindows() bool` |
| IsOSX     | IsOSX checks if the current OS is OSX               | `IsOSX() bool`     |
| IsAndroid | IsAndroid checks if the current OS is Android       | `IsAndroid() bool` |
| IsIOS     | IsIOS checks if the current OS is IOS               | `IsIOS() bool`     |
| IsJS      | IsJS checks if the current OS is JS                 | `IsJS() bool`      |
| IsFreeBSD | IsFreeBSD checks if the current OS is FreeBSD       | `IsFreeBSD() bool` |
| IsOpenBSD | IsOpenBSD checks if the current OS is OpenBSD       | `IsOpenBSD() bool` |
| IsSolaris | IsSolaris checks if the current OS is Solaris       | `IsSolaris() bool` |
| Arch      | Arch returns the current architecture               | `Arch() string`    |
| Is386     | Is386 checks if the current architecture is 386     | `Is386() bool`     |
| IsAmd64   | IsAmd64 checks if the current architecture is Amd64 | `IsAmd64() bool`   |
| IsARM     | IsArm checks if the current architecture is Arm     | `IsARM() bool`     |
| IsARM64   | IsArm64 checks if the current architecture is Arm64 | `IsARM64() bool`   |
| IsWasm    | IsWasm checks if the current architecture is Wasm   | `IsWasm() bool`    |

## JavaScript Protocol

| Name          | Description                                                                                    | Signatures                           |
| ------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------ |
| set           | set variable from init code. this function is available in init code block only                | `set(string, interface{})`           |
| updatePayload | update/override any payload from init code. this function is available in init code block only | `updatePayload(string, interface{})` |
````

### `reference\matchers.md`

````markdown
---
title: "Matchers"
description: "Review details on matchers for Nuclei"
icon: "spell-check"
iconType: "duotone"
---

Matchers allow different type of flexible comparisons on protocol responses. They are what makes nuclei so powerful, checks are very simple to write and multiple checks can be added as per need for very effective scanning.

### Types

Multiple matchers can be specified in a request. There are basically 7 types of matchers:

| Matcher Type | Part Matched                |
|--------------|-----------------------------|
| status       | Integer Comparisons of Part |
| size         | Content Length of Part      |
| word         | Part for a protocol         |
| regex        | Part for a protocol         |
| binary       | Part for a protocol         |
| dsl          | Part for a protocol         |
| xpath        | Part for a protocol         |

To match status codes for responses, you can use the following syntax.

```yaml
matchers:
  # Match the status codes
  - type: status
    # Some status codes we want to match
    status:
      - 200
      - 302
```

To match binary for hexadecimal responses, you can use the following syntax.

```yaml
matchers:
  - type: binary
    binary:
      - "504B0304" # zip archive
      - "526172211A070100" # RAR archive version 5.0
      - "FD377A585A0000" # xz tar.xz archive
    condition: or
    part: body
```

Matchers also support hex encoded data which will be decoded and matched.

```yaml
matchers:
  - type: word
    encoding: hex
    words:
      - "50494e47"
    part: body
```

**Word** and **Regex** matchers can be further configured depending on the needs of the users.

**XPath** matchers use XPath queries to match XML and HTML responses. If the XPath query returns any results, it's considered a match.

```yaml
matchers:
  - type: xpath
    part: body
    xpath:
      - "/html/head/title[contains(text(), 'Example Domain')]"
```

Complex matchers of type **dsl** allows building more elaborate expressions with helper functions. These function allow access to Protocol Response which contains variety of data based on each protocol. See protocol specific documentation to learn about different returned results.

```yaml
matchers:
  - type: dsl
    dsl:
      - "len(body)<1024 && status_code==200" # Body length less than 1024 and 200 status code
      - "contains(toupper(body), md5(cookie))" # Check if the MD5 sum of cookies is contained in the uppercase body
```

Every part of a Protocol response can be matched with DSL matcher. Some examples -

| Response Part  | Description                                     | Example                |
|----------------|-------------------------------------------------|------------------------|
| content_length | Content-Length Header                           | content_length >= 1024 |
| status_code    | Response Status Code                            | status_code==200       |
| all_headers    | Unique string containing all headers            | len(all_headers)       |
| body           | Body as string                                  | len(body)              |
| header_name    | Lowercase header name with `-` converted to `_` | len(user_agent)        |
| raw            | Headers + Response                              | len(raw)               |

### Conditions

Multiple words and regexes can be specified in a single matcher and can be configured with different conditions like **AND** and **OR**.

1. **AND** - Using AND conditions allows matching of all the words from the list of words for the matcher. Only then will the request be marked as successful when all the words have been matched.
2. **OR** - Using OR conditions allows matching of a single word from the list of matcher. The request will be marked as successful when even one of the word is matched for the matcher.

### Matched Parts

Multiple parts of the response can also be matched for the request, default matched part is `body` if not defined.

Example matchers for HTTP response body using the AND condition:

```yaml
matchers:
  # Match the body word
  - type: word
   # Some words we want to match
   words:
     - "[core]"
     - "[config]"
   # Both words must be found in the response body
   condition: and
   #  We want to match request body (default)
   part: body
```

Similarly, matchers can be written to match anything that you want to find in the response body allowing unlimited creativity and extensibility.

### Negative Matchers

All types of matchers also support negative conditions, mostly useful when you look for a match with an exclusions. This can be used by adding `negative: true` in the **matchers** block.

Here is an example syntax using `negative` condition, this will return all the URLs not having `PHPSESSID` in the response header.

```yaml
matchers:
  - type: word
    words:
      - "PHPSESSID"
    part: header
    negative: true
```

### Multiple Matchers

Multiple matchers can be used in a single template to fingerprint multiple conditions with a single request.

Here is an example of syntax for multiple matchers.

```yaml
matchers:
  - type: word
    name: php
    words:
      - "X-Powered-By: PHP"
      - "PHPSESSID"
    part: header
  - type: word
    name: node
    words:
      - "Server: NodeJS"
      - "X-Powered-By: nodejs"
    condition: or
    part: header
  - type: word
    name: python
    words:
      - "Python/2."
      - "Python/3."
    condition: or
    part: header
```

### Matchers Condition

While using multiple matchers the default condition is to follow OR operation in between all the matchers, AND operation can be used to make sure return the result if all matchers returns true.

```yaml
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "X-Powered-By: PHP"
          - "PHPSESSID"
        condition: or
        part: header

      - type: word
        words:
          - "PHP"
        part: body
```

### Internal Matchers

When writing multi-protocol or `flow` based templates, there might be a case where we need to validate/match first request then proceed to next request and a good example of this is [`CVE-2023-6553`](https://github.com/projectdiscovery/nuclei-templates/blob/c5be73e328ebd9a0c122ea0324f60bbdd7eb940d/http/cves/2023/CVE-2023-6553.yaml#L21)

In this template, we are first checking if target is actual using `Backup Migration` plugin using matchers and if true then proceed to next request with help of `flow`

But this will print two results, one for each request match since we are using the first request matchers as a pre-condition to proceed to next request we can mark it as internal using `internal: true` in the matchers block.

```yaml
id: CVE-2023-6553

info:
  name: Worpress Backup Migration <= 1.3.7 - Unauthenticated Remote Code Execution
  author: FLX
  severity: critical

flow: http(1) && http(2)

http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/backup-backup/readme.txt"

    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          - 'contains(body, "Backup Migration")'
        condition: and
        internal: true  # <- updated logic (this will skip printing this event/result)

  - method: POST
    path:
      - "{{BaseURL}}/wp-content/plugins/backup-backup/includes/backup-heart.php"
    headers:
      Content-Dir: "{{rand_text_alpha(10)}}"

    matchers:
      - type: dsl
        dsl:
          - 'len(body) == 0'
          - 'status_code == 200'
          - '!contains(body, "Incorrect parameters")'
        condition: and
```
````

### `reference\oob-testing.md`

````markdown
---
title: "OOB Testing"
description: "Understanding OOB testing with Nuclei Templates"
icon: "flask-vial"
iconType: "solid"
---

Since release of [Nuclei v2.3.6](https://github.com/projectdiscovery/nuclei/releases/tag/v2.3.6), Nuclei supports using the [interactsh](https://github.com/projectdiscovery/interactsh) API to achieve OOB based vulnerability scanning with automatic Request correlation built in. It's as easy as writing `{{interactsh-url}}`  anywhere in the request, and adding a matcher for `interact_protocol`. Nuclei will handle correlation of the interaction to the template & the request it was generated from allowing effortless OOB scanning.

## Interactsh Placeholder

`{{interactsh-url}}` placeholder is supported in **http** and **network** requests.

An example of nuclei request with `{{interactsh-url}}` placeholders is provided below. These are replaced on runtime with unique interactsh URLs.

```yaml
  - raw:
      - |
        GET /plugins/servlet/oauth/users/icon-uri?consumerUri=https://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}
```

## Interactsh Matchers

Interactsh interactions can be used with `word`, `regex` or `dsl` matcher/extractor using following parts.

| part                |
|---------------------|
| interactsh_protocol |
| interactsh_request  |
| interactsh_response |

<Note>
**interactsh_protocol**

Value can be dns, http or smtp. This is the standard matcher for every interactsh based template with DNS often as the common value as it is very non-intrusive in nature.
</Note>

<Note>
**interactsh_request**

The request that the interactsh server received.
</Note>

<Note>
**interactsh_response**

The response that the interactsh server sent to the client.
</Note>

Example of Interactsh DNS Interaction matcher:

```yaml
    matchers:
      - type: word
        part: interactsh_protocol # Confirms the DNS Interaction
        words:
          - "dns"
```

Example of HTTP Interaction matcher + word matcher on Interaction content

```yaml
matchers-condition: and
matchers:
    - type: word
      part: interactsh_protocol # Confirms the HTTP Interaction
      words:
        - "http"

    - type: regex
      part: interactsh_request # Confirms the retrieval of /etc/passwd file
      regex:
        - "root:[x*]:0:0:"
```
````

### `reference\preprocessors.md`

````markdown
---
title: "Preprocessors"
description: "Review details on pre-processors for Nuclei"
icon: "microchip"
iconType: "solid"
---

Certain pre-processors can be specified globally anywhere in the template that run as soon as the template is loaded to achieve things like random ids generated for each template run.

### randstr

<Note>
Generates a [random ID](https://github.com/rs/xid) for a template on each nuclei run. This can be used anywhere in the template and will always contain the same value. `randstr` can be suffixed by a number, and new random ids will be created for those names too. Ex. `{{randstr_1}}` which  will remain same across the template.

`randstr` is also supported within matchers and can be used to match the inputs.
</Note>

For example:-

```yaml
http:
  - method: POST
    path:
      - "{{BaseURL}}/level1/application/"
    headers:
      cmd: echo '{{randstr}}'

    matchers:
      - type: word
        words:
          - '{{randstr}}'
```
````

### `reference\template-signing.md`

````markdown
---
title: "Template Signing"
description: "Review details on template signing for Nuclei"
icon: "signature"
iconType: "solid"
---

Template signing via the private-public key mechanism is a crucial aspect of ensuring the integrity, authenticity, and security of templates. This mechanism involves the use of asymmetric cryptography, specifically the Elliptic Curve Digital Signature Algorithm (ECDSA), to create a secure and verifiable signature.

In this process, a template author generates a private key that remains confidential and securely stored. The corresponding public key is then shared with the template consumers. When a template is created or modified, the author signs it using their private key, generating a unique signature that is attached to the template.

Template consumers can verify the authenticity and integrity of a signed template by using the author's public key. By applying the appropriate cryptographic algorithm (ECDSA), they can validate the signature and ensure that the template has not been tampered with since it was signed. This provides a level of trust, as any modifications or unauthorized changes to the template would result in a failed verification process.

By employing the private-public key mechanism, template signing adds an additional layer of security and trust to the template ecosystem. It helps establish the identity of the template author and ensures that the templates used in various systems are genuine and have not been altered maliciously.

**What does signing a template mean?**

Template signing is a mechanism to ensure the integrity and authenticity of templates. The primary goal is to provide template writers and consumers a way to trust crowdsourced or custom templates ensuring that they are not tampered with.

All [official Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) include a digital signature and are verified by Nuclei while loading templates using ProjectDiscovery's public key (shipped with the Nuclei binary).

Individuals or organizations running Nuclei in their work environment can generate their own key-pair with `nuclei` and sign their custom templates with their private key, thus ensuring that only authorized templates are being used in their environment.

This also allows entities to fully utilize the power of new protocols like `code` without worrying about malicious custom templates being used in their environment.

**NOTE:**

- **Template signing is optional for all protocols except `code`**.
- **Unsigned code templates are disabled and can not be executed using Nuclei**.
- **Only signed code templates by the author (yourself) or ProjectDiscovery can be executed.**
- **Template signing is primarily introduced to ensure security of template to run code on host machine.**
- Code file references (for example: `source: protocols/code/pyfile.py`) are allowed and content of these files is included in the template digest.
- Payload file references (for example: `payloads: protocols/http/params.txt`) are not included in the template digest as it is treated as a payload/helper and not actual code that is being executed.
- Template signing is deterministic while both signing and verifying a template i.e. if a code file is referenced in a template that is present outside of templates directory with `-lfa` flag then verification will fail if same template is used without `-lfa` flag. (Note this only applies to `-lfa` i.e. local file access flag only)

### Signing Custom Template

The simplest and recommended way to generate key-pair and signing/verifying templates is to use `nuclei` itself.

When signing a template if key-pair does not exist then Nuclei will prompt user to generate a new key-pair with options.

```console
$ ./nuclei -t templates.yaml -sign
[INF] Generating new key-pair for signing templates
[*] Enter User/Organization Name (exit to abort) : acme
[*] Enter passphrase (exit to abort):
[*] Enter same passphrase again:
[INF] Successfully generated new key-pair for signing templates
```

> **Note:** Passphrase is optional and can be left blank when used private key is encrypted with passphrase using PEMCipherAES256 Algo

Once a key-pair is generated, you can sign any custom template using `-sign` flag as shown below.

```console
$ ./nuclei -t templates.yaml -sign
[INF] All templates signatures were elaborated success=1 failed=0
```

> **Note:** Every time you make any change in your code template, you need to re-sign it to run with Nuclei.

### Template Digest and Signing Keys

When a template is signed, a digest is generated and added to the template. This digest is a hash of the template content and is used to verify the integrity of the template. If the template is modified after signing, the digest will change, and the signature verification will fail during template loading.

```yaml
# digest: 4a0a00473045022100eb01da6b97893e7868c584f330a0cd52df9bddac005860bb8595ba5b8aed58c9022050043feac68d69045cf320cba9298a2eb2e792ea4720d045d01e803de1943e7d:4a3eb6b4988d95847d4203be25ed1d46
```

The digest is in the format of `signature:fragment`, where the signature is the digital signature of the template used to verify its integrity, and the fragment is metadata generated by MD5 hashing the public key to disable re-signing of code templates not written by you.

The key-pair generated by Nuclei is stored in two files in the `$CONFIG/nuclei/keys directory`, where `$CONFIG` is the system-specific config directory. The private key is stored in nuclei-user-private-key.pem, which is encrypted with a passphrase if provided. The public key is stored in nuclei-user.crt, which includes the public key and identifier (e.g., user/org name) in a self-signed certificate.

```bash
$ la ~/.config/nuclei/keys
total 16
-rw-------  1 tarun  staff   251B Oct  4 21:45 nuclei-user-private-key.pem # encrypted private key with passphrase
-rw-------  1 tarun  staff   572B Oct  4 21:45 nuclei-user.crt # self signed certificate which includes public key and identifier (i.e user/org name)
```

To use the public key for verification, you can either copy it to the `$CONFIG/nuclei/keys` directory on another user's machine, or set the `NUCLEI_USER_CERTIFICATE` environment variable to the path or content of the public key.

To use the private key, you can copy it to the `$CONFIG/nuclei/keys` directory on another user's machine, or set the `NUCLEI_USER_PRIVATE_KEY` environment variable to the path or content of the private key.

```console
export NUCLEI_USER_CERTIFICATE=$(cat path/to/nuclei-user.crt)
export NUCLEI_USER_PRIVATE_KEY=$(cat path/to/nuclei-user-private-key.pem)
```

It's important to note that you are responsible for securing and managing the private key, and Nuclei has no accountability for any loss of the private key.

By default, Nuclei loads the user certificate (public key) from the default locations mentioned above and uses it to verify templates. When running Nuclei, it will execute signed templates and warn about executing unsigned custom templates and block unsigned code templates. You can disable this warning by setting the `HIDE_TEMPLATE_SIG_WARNING` environment variable to `true`.

## FAQ

**Found X unsigned or tampered code template?**

```bash
./nuclei -u scanme.sh -t simple-code.yaml

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.0.0-dev

    projectdiscovery.io

[WRN] Found 1 unsigned or tampered code template (carefully examine before using it & use -sign flag to sign them)
[INF] Current nuclei version: v3.0.0-dev (development)
[INF] Current nuclei-templates version: v9.6.4 (latest)
[WRN] Executing 1 unsigned templates. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] No results found. Better luck next time!
[FTL] Could not run nuclei: no templates provided for scan
```

Here `simple-code.yaml` is a code protocol template which is not signed or content of template has been modified after signing which indicates loss of integrity of template.
If you are template writer then you can go ahead and sign the template using `-sign` flag and if you are template consumer then you should carefully examine the template before signing it.

**Re-signing code templates are not allowed for security reasons?**

```bash
nuclei -u scanme.sh -t simple-code.yaml -sign

[ERR] could not sign 'simple-code.yaml': [signer:RUNTIME] re-signing code templates are not allowed for security reasons.
[INF] All templates signatures were elaborated success=0 failed=1
```

The error message `re-signing code templates are not allowed for security reasons` comes from the Nuclei engine. This error indicates that a code template initially signed by another user and someone is trying to re-sign it.

This measure was implemented to prevent running untrusted templates unknowingly, which might lead to potential security issues.
When you encounter this error, it suggests that you're dealing with a template that has been signed by another user Likely, the original signer is not you or the team from projectdiscovery.

By default, Nuclei disallows executing code templates that are signed by anyone other than you or from the public templates provided by projectdiscovery/nuclei-templates.

This is done to prevent potential security abuse using code templates.

To resolve this error:

  1. Open and thoroughly examine the code template for any modifications.
  2. Manually remove the existing digest signature from the template.
  3. Sign the template again.

This way, you can ensure that only templates verified and trusted by you (or projectdiscovery) are run, thus maintaining a secure environment.
````

### `reference\variables.md`

````markdown
---
title: "Variables"
description: "Review details on variables for Nuclei"
icon: "brackets-curly"
iconType: "solid"
---

Variables can be used to declare some values which remain constant throughout the template. The value of the variable once calculated does not change. Variables can be either simple strings or DSL helper functions. If the variable is a helper function, it is enclosed in double-curly brackets `{{<expression>}}`. Variables are declared at template level.

Example variables

```yaml
variables:
  a1: "test" # A string variable
  a2: "{{to_lower(rand_base(5))}}" # A DSL function variable
```

Currently, `dns`, `http`, `headless` and `network` protocols support variables.

Example of templates with variables

```yaml
# Variable example using HTTP requests
id: variables-example

info:
  name: Variables Example
  author: pdteam
  severity: info

variables:
  a1: "value"
  a2: "{{base64('hello')}}"

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{FQDN}}
        Test: {{a1}}
        Another: {{a2}}
    stop-at-first-match: true
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "value"
          - "aGVsbG8="
```

```yaml
# Variable example for network requests
id: variables-example

info:
  name: Variables Example
  author: pdteam
  severity: info

variables:
  a1: "PING"
  a2: "{{base64('hello')}}"

tcp:
  - host:
      - "{{Hostname}}"
    inputs:
      - data: "{{a1}}"
    read-size: 8
    matchers:
      - type: word
        part: data
        words:
          - "{{a2}}"
```
````

### `workflows\examples.md`

````markdown
---
title: "Workflow Examples"
description: "Review some template workflow examples for Nuclei"
sidebarTitle: "Examples"
icon: "list-timeline"
---

## Generic workflows

A generic workflow that runs two templates, one to detect Jira and another to detect Confluence.

```yaml
id: workflow-example
info:
  name: Test Workflow Template
  author: pdteam

workflows:
  - template: technologies/jira-detect.yaml
  - template: technologies/confluence-detect.yaml
```

## Basic conditional workflows

A condition based workflow, which first tries to detect if springboot is running on a target. If springboot is found, a list of exploits executed against it.

```yaml
id: springboot-workflow

info:
  name: Springboot Security Checks
  author: dwisiswant0

workflows:
  - template: security-misconfiguration/springboot-detect.yaml
    subtemplates:
      - template: cves/CVE-2018-1271.yaml
      - template: cves/CVE-2018-1271.yaml
      - template: cves/CVE-2020-5410.yaml
      - template: vulnerabilities/springboot-actuators-jolokia-xxe.yaml
      - template: vulnerabilities/springboot-h2-db-rce.yaml
```

## Multi condition workflows

This template demonstrates nested workflows with nuclei, where there's multiple levels of chaining of templates.

```yaml
id: springboot-workflow

info:
  name: Springboot Security Checks
  author: dwisiswant0

workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: lotus-domino
        subtemplates:
          - template: technologies/lotus-domino-version.yaml
            subtemplates:
              - template: cves/xx-yy-zz.yaml
                subtemplates:
                  - template: cves/xx-xx-xx.yaml
```

## Conditional workflows with matcher

This template detects if WordPress is running on an input host, and if found a set of targeted exploits and CVEs are executed against it.

```yaml
id: workflow-example
info:
  name: Test Workflow Template
  author: pdteam

workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: wordpress
        subtemplates:
          - template: cves/CVE-2019-6715.yaml
          - template: cves/CVE-2019-9978.yaml
          - template: files/wordpress-db-backup.yaml
          - template: files/wordpress-debug-log.yaml
          - template: files/wordpress-directory-listing.yaml
          - template: files/wordpress-emergency-script.yaml
          - template: files/wordpress-installer-log.yaml
          - template: files/wordpress-tmm-db-migrate.yaml
          - template: files/wordpress-user-enumeration.yaml
          - template: security-misconfiguration/wordpress-accessible-wpconfig.yaml
          - template: vulnerabilities/sassy-social-share.yaml
          - template: vulnerabilities/w3c-total-cache-ssrf.yaml
          - template: vulnerabilities/wordpress-duplicator-path-traversal.yaml
          - template: vulnerabilities/wordpress-social-metrics-tracker.yaml
          - template: vulnerabilities/wordpress-wordfence-xss.yaml
          - template: vulnerabilities/wordpress-wpcourses-info-disclosure.yaml
```

## Multiple Matcher workflow

Very similar to the last example, with multiple matcher names.

```yaml
id: workflow-multiple-matcher
info:
  name: Test Workflow Template
  author: pdteam

workflows:
  - template: technologies/tech-detect.yaml
    matchers:
      - name: vbulletin
        subtemplates:
          - tags: vbulletin

      - name: jboss
        subtemplates:
          - tags: jboss

```
````

### `workflows\overview.md`

````markdown
---
title: "Template Workflows Overview"
description: "Learn about template workflows in Nuclei"
sidebarTitle: "Template Workflows"
icon: "list-tree"
iconType: "regular"
---

Workflows enable users to orchestrate a series of actions by setting a defined execution order for various templates. These templates are activated upon predetermined conditions, establishing a streamlined method to leverage the capabilities of nuclei tailored to the user's specific requirements. Consequently, you can craft workflows that are contingent on particular technologies or targets—such as those exclusive to WordPress or Jira—triggering these sequences only when the relevant technology is identified.

Within a workflow, all templates share a unified execution environment, which means that any named extractor from one template can be seamlessly accessed in another by simply referencing its designated name.

<Tip>
For those with prior knowledge of the technology stack in use, we advise constructing personalized workflows for your scans. This strategic approach not only substantially reduces the duration of scans but also enhances the quality and precision of the outcomes.
</Tip>

Workflows can be defined with `workflows` attribute, following the `template` / `subtemplates` and `tags` to execute.

```yaml
workflows:
  - template: http/technologies/template-to-execute.yaml
```

**Type of workflows**

1. [Generic workflows](#generic-workflows)
2. [Conditional workflows](#conditional-workflows)

## Generic Workflows

In generic workflow one can define single or multiple template to be executed from a single workflow file. It supports both files and directories as input.

A workflow that runs all config related templates on the list of give URLs.

```yaml
workflows:
  - template: http/exposures/configs/git-config.yaml
  - template: http/exposures/configs/exposed-svn.yaml
  - template: http/vulnerabilities/generic/generic-env.yaml
  - template: http/exposures/backups/zip-backup-files.yaml
  - tags: xss,ssrf,cve,lfi
```

A workflow that runs specific list of checks defined for your project.

```yaml
workflows:
  - template: http/cves/
  - template: http/exposures/
  - tags: exposures
```
## Conditional Workflows

You can also create conditional templates which execute after matching the condition from a previous template. This is mostly useful for vulnerability detection and exploitation as well as tech based detection and exploitation. Use-cases for this kind of workflows are vast and varied.

**Templates based condition check**

A workflow that executes subtemplates when base template gets matched.

```yaml
workflows:
  - template: http/technologies/jira-detect.yaml
    subtemplates:
      - tags: jira
      - template: exploits/jira/
```

**Matcher Name based condition check**

A workflow that executes subtemplates when a matcher of base template is found in result.

```yaml
workflows:
  - template: http/technologies/tech-detect.yaml
    matchers:
      - name: vbulletin
        subtemplates:
          - template: exploits/vbulletin-exp1.yaml
          - template: exploits/vbulletin-exp2.yaml
      - name: jboss
        subtemplates:
          - template: exploits/jboss-exp1.yaml
          - template: exploits/jboss-exp2.yaml
```

In similar manner, one can create as many and as nested checks for workflows as needed.

**Subtemplate and matcher name based multi level conditional check**

A workflow showcasing chain of template executions that run only if the previous templates get matched.


```yaml
workflows:
  - template: http/technologies/tech-detect.yaml
    matchers:
      - name: lotus-domino
        subtemplates:
          - template: http/technologies/lotus-domino-version.yaml
            subtemplates:
              - template: http/cves/2020/xx-yy-zz.yaml
                subtemplates:
                  - template: http/cves/2020/xx-xx-xx.yaml
```

Conditional workflows are great examples of performing checks and vulnerability detection in most efficient manner instead of spraying all the templates on all the targets and generally come with good ROI on your time and is gentle for the targets as well.

## Shared Execution Context

Nuclei engine supports transparent workflow cookiejar and key-value sharing across templates parts of a same workflow. Here follow an example of a workflow that extract a value from the first template and use it in the second conditional one:

```yaml
id: key-value-sharing-example
info:
  name: Key Value Sharing Example
  author: pdteam
  severity: info

workflows:
  - template: template-with-named-extractor.yaml
    subtemplates:
      - template: template-using-named-extractor.yaml
```

For example, the following templates extract `href` links from a target web page body and make the value available under the `extracted` key:

```yaml
# template-with-named-extractor.yaml

id: value-sharing-template1

info:
  name: value-sharing-template1
  author: pdteam
  severity: info

http:
  - path:
      - "{{BaseURL}}/path1"
    extractors:
      - type: regex
        part: body
        name: extracted
        regex:
          - 'href="(.*)"'
        group: 1
```

Finally the second template in the workflow will use the obtained value by referencing the extractor name (`extracted`):

```yaml
# template-using-named-extractor.yaml

id: value-sharing-template2

info:
  name: value-sharing-template2
  author: pdteam
  severity: info

http:
  - raw:
      - |
        GET /path2 HTTP/1.1
        Host: {{Hostname}}

        {{extracted}}
```
````

Important Matcher Rules:

- Try adding at least 2 matchers in a template it can be a response header or status code for the web templates.
- Make sure the template have enough matchers to validate the issue properly. The matcher should be unique and also try not to add very strict matcher which may result in False negatives.
- Just like the XSS templates SSRF template also results in False Positives so make sure to add additional matcher from the response to the template. We have seen honeypots sending request to any URL they may receive in GET/POST data which will result in FP if we are just using the HTTP/DNS interactsh matcher.
- For Time-based SQL Injection templates, if we must have to add duration dsl for the detection, make sure to add additional string from the vulnerable endpoint to avoid any FP that can be due to network error.

Make sure there are no yaml errors in a valid nuclei templates like the following

- trailing spaces
- wrong indentation errors like: expected 10 but found 9
- no new line character at the end of file
- found unknown escape character
- mapping values are not allowed in this context
- found character that cannot start any token
- did not find expected key
- did not find expected alphabetic or numeric character
- did not find expected \'-\' indicator- network: is deprecated, use tcp: instead
- requests: is deprecated, use http: instead
- unknown escape sequence
- all_headers is deprecated, use header instead
- at line
- bad indentation of a mapping entry
- bad indentation of a sequence entry
- can not read a block mapping entry;
- duplicated mapping key
- is not allowed to have the additional
- is not one of enum values
- the stream contains non-printable characters
- unexpected end of the stream within a
- unidentified alias \"/*\"
- unknown escape sequence. You can also remove unnecessary headers from requests if they are not required for the vulnerability.

"""

END CONTEXT

## OUTPUT INSTRUCTIONS

- Output only the correct yaml nuclei template like the EXAMPLES above
- Keep the matcher in the nuclei template with proper indentation.
- The templates id should be the cve id or the product-vulnerability-name.
- The matcher should be indented inside the corresponding requests block.
- Your answer should be strictly based on the above example templates
- Do not output warnings or notes—just the requested sections.

## INPUT

INPUT:
