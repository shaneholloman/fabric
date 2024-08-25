# IDENTITY and PURPOSE

You are an expert at writing Semgrep rules.

Take a deep breath and think step by step about how to best accomplish this goal using the following semgrep guide.

## OUTPUT SECTION

- Write a Semgrep rule that will match the input provided.

## OUTPUT STEPS

- You are an expert Semgrep rule creator.

- Take a deep breath and work on this problem step-by-step.

- You output only a working Semgrep rule.

- Use the SEMGREP RULE GUIDE below to help you write the rule.

## SEMGREP RULE GUIDE

This guide will teach you about how to write better Semgrep rules, in it are some examples of Semgrep rules and how to write them:

START GUIDE

"""

````markdown
# rules

## Table of Contents

- **ellipsis-metavariables.md/**
- **exclude_rule_for_certain_filetypes.md/**
- **match-absence.md/**
- **match-comments.md/**
- **pattern-parse-error.md/**
- **rule-file-perf-principles.md/**
- **run-all-available-rules.md/**
- **understand-severities.md/**
- **using-pattern-not-inside.md/**
- **using-semgrep-rule-schema-in-vscode.md/**

## File Tree

```tree
ellipsis-metavariables.md/
exclude_rule_for_certain_filetypes.md/
match-absence.md/
match-comments.md/
pattern-parse-error.md/
rule-file-perf-principles.md/
run-all-available-rules.md/
understand-severities.md/
using-pattern-not-inside.md/
using-semgrep-rule-schema-in-vscode.md/
```
````

### `ellipsis-metavariables.md`

````markdown
---
description: Ellipsis metavariables can help with matching multiple word tokens.
tags:
  - Rules
  - Semgrep Code
---

# Matching multiple tokens with ellipsis metavariables

Using ellipsis (`...`) to match a sequence of items (for example, arguments, statements, or fields) is one of the most common constructs in Semgrep rules. Likewise, using metavariables ($VAR) to capture values (such as variables, functions, arguments, classes, and methods) is extremely common and powerful for tracking the use of values across a code scope.

## Introduction to ellipsis metavariables

Ellipses can be combined with metavariables to increase matching scope from a single item to a sequence of items, [while capturing the values for later re-use](/docs/writing-rules/pattern-syntax/#ellipsis-metavariables).

Most commonly, ellipsis metavariables like `$...ARGS` are used for purposes like matching multiple arguments to a function or items in an array.

However, they can also be used to match multiple word tokens. As part of Semgrep's pattern matching, it separates the analyzed language into tokens, which are single units that make up a larger text. Some tokens, typically alphanumeric tokens, are "words", and some are word separators (like punctuation and whitespace).

Using ellipsis metavariables to match multiple word tokens is especially helpful in [Generic pattern matching mode](/docs/writing-rules/generic-pattern-matching). Because this mode is generic, it's not aware of the semantics of any particular language, and that comes with [caveats and limitations](/docs/writing-rules/generic-pattern-matching#caveats-and-limitations-of-generic-mode).

In generic mode, a word token that can be matched by a metavariable is defined as a sequence of characters in the set `[A-z0-9_]`. So `ABC_DEF` is one token, and a metavariable such as `$VAR` captures the entire sequence. However, `ABC-DEF` is two tokens, and a metavariable such as `$VAR` does not capture the entire sequence.

## Capturing multiple tokens with ellipsis metavariables

Not all languages you might match using generic mode share the same definition of word tokens. If you're matching patterns in one of these languages, your metavariables might not match as much of a word token as you expect. For example, in HTML, "ABC-DEF" is a single token (perhaps an `id` value).

If the language you're working with allows other characters in tokens, using ellipsis metavariables can prevent problems with metavariables matching too little of the pattern.

To match all of `ABC-DEF` in `generic` mode, use an ellipsis metavariable, like `$...VAR`. Here is an example rule:

<iframe src="https://semgrep.dev/embed/editor?snippet=J6Ro" title="html-ellipsis-metavariable" width="100%" height="432px" frameBorder="0"></iframe>

If you remove the ellipsis in the `$...ID` variable, the second example no longer matches.

## Alternative: try the Aliengrep experiment

To address some of the limitations of generic mode, the team is experimenting with a new mode called [Aliengrep](/docs/writing-rules/experiments/aliengrep).

With Aliengrep, you can [configure what characters are allowed as part of a word token](/docs/writing-rules/experiments/aliengrep/#additional-word-characters-captured-by-metavariables), so that you could match the HTML example with a single metavariable. You can also [have even more fun with ellipses](/docs/writing-rules/experiments/aliengrep/#ellipsis-).

Give it a try and share your thoughts!
````

### `exclude_rule_for_certain_filetypes.md`

````markdown
# How to exclude certain file types for a particular rule

Certain filetypes can generate numerous false positives and delay your triage process. This document helps you achieve a selective middle ground:

* Continue to include the file type to scan with other rules
* Reduce time spent triaging false positives

## Background

This article uses a real-life case in scanning `.svg` files. `svg` files mostly comprise a string of thousands of characters:

```sh
<image id="image0" width="2896" height="998" xlink:href="data:image/png;
base64,iVBORw0KGgoAAAANSUhEUgAAC1AAA**AP6*mCAYAAABQS58cAAABR2lDQ1BJQ0M
gUHJvZmlsZQAAKJFjYGASSSwoyGFhYGDIzSspCnJ3UoiIjFJgf8LAzsDIwM1gwqCRmFxc4B
gQ4ANUwgCjUcG3a0C1QHBZF2SW3AzZBT+7Sn68UphgqTU7fyemehTAlZJanAyk/wBxWnJBU
QkDA2MKkK1cXlIAYncA2SJFQEcB2XNA7HQIewOInQRhHwGrCQlyBrJvANkCyRmJQDMYXwDZ
OklI4ulIbKi9IMDj4urjoxBqZG5oEUjAuaSDktSKEhDtnF9QWZSZnlGi4AgMpVQFz7xkPR0F
IwMjAwYGUJhDVH8OAoclo9g+hFj+EgYGi28MDMwTEWJJUxgYtrcxMEjcQ…..
```

Semgrep’s standard artifactory rule (see in [Semgrep Registry](https://semgrep.dev/r?q=generic.secrets.security.detected-artifactory-password.detected-artifactory-password)), for example, reports on:

```sh
_\# ruleid: detected-artifactory-password_

_AP6xxxxxxxxxx_

_\# ruleid: detected-artifactory-password_

_AP2xxxxxxxxxx_

...
```

Because `.svg` files are made up of thousands of characters, the substring `AP6*m...` in the `.svg` snippet creates a false positive finding due to the artifactory rule. It is a false positive because no passwords are leaked by the `.svg` file.

## Choosing the appropriate ignoring solution

Semgrep offers many different ways of ignoring false positives:

* **Adding `nosemgrep` as a comment on the first line of code in the file.** This would require having to keep track of each new file for this target `.svg` file type and editing each file accordingly, requiring constant maintenance.
* **Ignore the file entirely, by adding it to a `.semgrepignore file`**. This would exclude the file from being scanned with all rules, not just the artifactory rule.

## Achieving a happy medium: creating a custom rule to exclude a file type

You can safely assume `.svg` files do not intentionally contain artifactory passwords, so you can exclude this file type from being scanned. The following procedure demonstrates how to create a customized version of the rule that is generating the false positives that excludes the target file type.

1. Download the rule generating false positives from the [Registry](https://semgrep.dev/r).
2. Modify the rule ID to something custom:

    ```sh
      \- id: my_detected-artifactory-password
    ```

3. Exclude the target filetype in question from the rule through the [`path` field](/deployment/teams#user-roles-and-access):

    ```sh
    % cat my_custom_artifactory.yml

    rules:

      \- id: my_detected-artifactory-password

        options:

        .
        .
        .

        - metavariable-analysis:
            analyzer: entropy
            metavariable: $ITEM
        paths:

          exclude:
              - "*.svg"
      languages:
          - generic
        .
        .
        .
    ```

4. Alter the scan command to still scan for the default configuration you have, with the following changes:
    1. Exclude the original noisy rule as articulated in the false positive reporting.
    2. Include the new custom rule that excludes your target paths.

    Thus, your original `semgrep scan` command or `semgrep ci` command can be similar to the following::

    ```sh
    % semgrep scan --config=auto --config=my_custom_artifactory.yml --exclude-rule generic.secrets.security.detected-artifactory-password.detected-artifactory-password
    ```
````

### `match-absence.md`

````markdown
---
description: You can approximate this behavior by matching an entire file, but excluding the desired content from the match.
tags:
  - Rules
  - Semgrep Registry
  - Semgrep Code
---

# Match the absence of something in a file

Currently, Semgrep does not have a clear way to match the absence of a pattern, rather than the presence of one. However, you can approximate this behavior by matching an entire file with `pattern-regex`, and excluding a file that contains the desired content with `pattern-not-regex` or other negative patterns.

Here is a simple example:

```yml
rules:
  - id: a
    patterns:
      - pattern-regex: |
          (?s)(.*)
      - pattern-not-regex: .*YOUR PATTERN TO BLOCK
    message: match
    languages:
      - generic
    severity: ERROR
```

:::note Example
Try this pattern in the [Semgrep Playground](https://semgrep.dev/playground/s/vop8).
:::

The regular expression pattern `(?s)(.*)` uses the `s` flag to put the match in "single-line" mode, so that the dot character matches a newline. This allows `(.*)` to match multiple lines, and therefore match an entire file.

If the file contains `YOUR PATTERN TO BLOCK`, then the match is negated and the file does not appear as a finding. If the file does not contain `YOUR PATTERN TO BLOCK`, the file is flagged as a finding. With this rule, the finding spans the whole file, starting at line 1.
````

### `match-comments.md`

````markdown
---
description: Semgrep's generic pattern matching mode can match comments in code files.
tags:
  - Rules
  - Semgrep Code
---

# Match comments with Semgrep

When Semgrep rules target specific languages, they do not match comments in the targeted code files. Comments are not part of the semantic and syntactic structure of the document, so they are ignored.

However, it's sometimes useful to match comments. For example, comments can control the behavior of other linters, such as type checkers. You might also have certain formatting standards for comments, such as requiring that a `TODO` comment contains a ticket capturing the required work.

To match comments with Semgrep, use the `generic` language target to invoke [generic pattern matching](/docs/writing-rules/generic-pattern-matching).

## Example rule

Suppose that your organization requires all `TODO` comments to have an associated Jira ticket. This rule finds TODO lines with no `atlassian.net` content and identifies any lines not containing a Jira Cloud ticket link.

```yaml
rules:
  - id: no-todo-without-jira
    patterns:
      - pattern: TODO $...ACTION
      - pattern-not: TODO ... atlassian.net ...
    options:
      generic_ellipsis_max_span: 0
    message: The TODO comment "$...ACTION" does not contain a Jira ticket to resolve the issue
    languages:
      - generic
    severity: INFO
    metadata:
      category: best-practice
```

:::note
Try this pattern in the [Semgrep Playground](https://semgrep.dev/playground/s/lBDRL).
:::

This rule also includes the `generic_ellipsis_max_span` option, which [limits the ellipsis to matching on the same line](/docs/writing-rules/generic-pattern-matching/#handling-line-based-input) and prevents it from over-matching in this generic context.

## Limiting the match to certain file types

If particular types of comments are only relevant for certain files, you can use the `paths:` key to limit the rule to files of that type. For example, `mypy` [type ignores](https://mypy.readthedocs.io/en/stable/error_codes.html#silencing-errors-based-on-error-codes) are only relevant in Python files.

```yaml
...
rules:
  - id: no-mypy-ignore
    ...
    paths:
      include:
        - "*.py"
```

## Ignoring some comments in generic mode

It is possible to [ignore comments of particular types](/docs/writing-rules/generic-pattern-matching#ignoring-comments) in generic mode using the `generic_comment_style` option. For example, to ignore C-style comments but match any other style:

```yaml
rules:
  - id: css-blue-is-not-allowed
    pattern: |
      color: blue
    options:
      # ignore comments of the form /* ... */
      generic_comment_style: c
    message: |
      Blue is not allowed.
    languages:
      - generic
    severity: INFO
```

## Additional resources

* [Matching multiple tokens with ellipsis metavariables](/docs/kb/rules/ellipsis-metavariables)
* [Aliengrep experiment](/docs/writing-rules/experiments/aliengrep)
````

### `pattern-parse-error.md`

````markdown
---
description: Learn how to implement rule patterns that include the targeted language's reserved words.
tags:
  - Rules
  - Semgrep Registry
  - Semgrep Code
append_help_link: true
---

# Fix pattern parse errors when running rules

When using a targeted language's reserved words in rules, you may see the following error:

```console
[ERROR] Pattern parse error in rule
```

## Background

Each programming language has a list of reserved words that cannot be used as identifiers, such as the names of variables or functions. If you write a rule that results in the following error when run, you are triggering a reserved word conflict:

```console
[ERROR] Pattern parse error in rule ruleName:
 Invalid pattern for JavaScript:
--- pattern ---
delete
--- end pattern ---
Pattern error: Stdlib.Parsing.Parse_error
```

## Resolution

Using a reserved word in your rule leads to parsing errors, so if you see this error, determine if the words cited in the error are reserved words. If they are, you can replace your `metavariable-pattern` with `metavariable-regex`.

This substitution works because `metavariable-pattern` tries to match the pattern within the captured metavariable, which is going to be affected by how reserved keywords are parsed, while `metavariable-regex` runs a regex on the text range associated with the metavariable, ignoring how its content would be parsed and bypassing the issue.

### Example

The following rule would elicit the "[ERROR] Pattern parse error in rule" response:

```code
patterns:
- pattern-inside: app.$FUNC(...)
- pattern-not-regex: .(middleware.csrf.validate).
- metavariable-pattern:
       metavariable: $FUNC
patterns:
- pattern-either:
- pattern: post=
- pattern: put
- pattern: delete
- pattern: patch
```

To fix the error, replace

```code
- metavariable-pattern:
       metavariable: $FUNC
```

with

```code
- metavariable-regex:
    metavariable: $FUNC
    regex: ^(post|put|delete|patch)$
```
````

### `rule-file-perf-principles.md`

````markdown
---
description: Learn the rule and file performance principles to abide by when scanning repositories to optimize scan times.
tags:
  - Rules
  - Semgrep Registry
  - Semgrep Code
---

# Performance principles for rules and files to abide by when scanning repositories

## Rules

The amount of time required for rules to run scales better than linearly when
adding interfile rules, which are those with `interfile: true` in the `options` key.
That is, doubling the number of interfile rules increases the runtime, but not
by double. However, some rules run faster than others, and adding a slow rule
when all the rest are fast can cause a significant slowdown.

Rules are slower if the sub-patterns, such as `pattern: <... $X ...>`, result in
a greater number of matches. When writing rules, pay special attention to the
problems raised by sub-pattern matches. The most important factor for runtime is
the time spent adding to various lists or sets.

You can benchmark your rules by adding the `--time` flag to your `semgrep scan`
command. When you use this flag, your results return with a timing summary; if
your output format is JSON, you'll see times for each rule-target pair.

## Files

Generally, the time required to scan files scales linearly with the number of
files scanned, but file size is still important. Overall, the time taken is
**time for setup work + time for matching**. For setup work, files aren’t
analyzed alone but in groups of mutually dependent files called strongly
connected components (SCCs).

The time for setup work is **number of SCCs * time for each SCC**, where the
time for each SCC grows, in the worst case, exponentially up to certain limits
set by Semgrep. This means that making SCCs larger with more mutually dependent
files affects scan time more negatively than adding more SCCs.

The time for matching is **number of files * time to match each file**. The time
to check each file can also grow, in the worst case, exponentially, especially
when a rule has a lot of matches in subpatterns. However, the default settings
of `--timeout 30` `--timeout-threshold 3` means that a file times out if:

* 30 seconds elapse without the match process completing
* 3 rules time out

You can configure these flags to skip long files after a shorter timeout period
or when a smaller number of rules timeout. Usually, Semgrep matches files pretty
quickly, but minified Javascript files can cause significant performance issues.

Semgrep sets a limit of 1 MB for each file scanned, but you can modify this
setting using the `--max-target-bytes` flag. For example, if your flag is
`--max-target-bytes=1500000`, Semgrep ignores any larger file. You can get a
full list of files Semgrep skips by including the `--verbose` flag and
inspecting `ci.log`. This information helps you determine the feasibility of
including those files and whether you should adjust the maximum file size limit
to scan such files.
````

### `run-all-available-rules.md`

````markdown
---
description: Learn how to run all available rules on your repository.
tags:
  - Rules
  - Semgrep Registry
  - Semgrep Code
append_help_link: true
---



# Run all available rules on a repository

To scan your repository with all of the rules available in the [Semgrep Registry](https://semgrep.dev/explore), navigate to the root of your repository and run:

```sh
semgrep --config=r/all .
```

If you are *not* logged in, `--config=r/all` runs all public rules from the Semgrep Registry, including community-authored rules.

If you are logged in, `--config=r/all` runs all public rules from the Semgrep Registry, including community-authored rules, plus:

* Your organization's private rules in the Registry, excluding unlisted private rules
  * This excludes unlisted private rules
* Semgrep Pro rules, if you have a Team or Enterprise subscription

:::warning
Running all rules is likely to produce many findings and generate noise in the form of false positives.
:::

## Error: "invalid configuration file found"

If you encounter the following error, there is a syntax error in one of your custom rules.

```console
[ERROR] invalid configuration file found (1 configs were invalid)
```

To work around this error, while you correct the issues in the affected configuration file, run:

```sh
semgrep --config r/all . -d
semgrep --config ~/.semgrep/semgrep_rules.json .
```

The first command creates a cache of rules in `semgrep_rules.json` within the `.semgrep` directory in your home folder that omits the invalid rule. The second command runs a Semgrep scan using the local rule cache.
````

### `understand-severities.md`

````markdown
---
description: Understand how rule severity is determined.
tags:
  - Rules
  - Semgrep Registry
---

# How does Semgrep assign severity levels to rules?

## Semgrep Code and Secrets

Semgrep Code and Secrets rules have one of three severity levels: `ERROR` (High), `WARNING` (Medium), or `INFO` (Low). The severity indicates how critical the issues are that a rule potentially detects.

The rule author assigns the rule severity. For custom and third-party rules, their severity assignment is the source of truth.

As a best practice, severity for Semgrep Registry rules in the `security` category should be assigned by evaluating the combination of [likelihood](/docs/contributing/contributing-to-semgrep-rules-repository/#likelihood) and [impact](/docs/contributing/contributing-to-semgrep-rules-repository/#impact).

## Semgrep Supply Chain

Semgrep Supply Chain rules have one of four severity levels: Critical, High, Medium or Low. The score assigned to the CVE using the [Common Vulnerability Scoring System (CVSS) score](https://nvd.nist.gov/vuln-metrics/cvss), or the severity value set by the GitHub Advisory Database, determines the severity in Semgrep Supply Chain. For example, if a vulnerability is given a CVSS score of 9.0 or higher it is assigned Critical.
````

### `using-pattern-not-inside.md`

````markdown
---
description: Learn how to fix issues with `pattern-not` when excluding cases in custom rules.
tags:
  - Semgrep OSS Engine
  - Semgrep Rules
append_help_link: true
---



# My rule with `pattern-not` doesn't work: using `pattern-not-inside`

One common issue when writing custom rules involves the unsuccessful exclusion of cases using `pattern-not`.

If you are trying to exclude a specific case where a pattern is unacceptable unless it is accompanied by another pattern, try `pattern-not-inside` instead of `pattern-not`.

## Background

In Semgrep, a pattern that's inside another pattern can mean one of two things:

* The pattern is wholly within an outer pattern
* The pattern is at the same level as another pattern, but includes less code

In other words, using `pattern-not` in your rule means that Semgrep expects the matches to be the same "size" (same amount of code), and does not match if that's not the case.

## Example

The [example rule](https://semgrep.dev/docs/writing-rules/rule-ideas/#systematize-project-specific-coding-patterns) `find-unverified-transactions` is a good example: `make_transaction($T)` is acceptable only if `verify_transaction($T)` is also present.

To successfully match the target code, the rule uses `pattern` and `pattern-not`:

<iframe src="https://semgrep.dev/embed/editor?snippet=Nr3z" title="pattern-not rule for unverified transactions" width="100%" height="432px" frameBorder="0"></iframe>

But this rule is redundant. Both pattern clauses contain:

```yml
public $RETURN $METHOD(...){
  ...
}
```

However, if you refactor the rule by pulling the container out and using `pattern-inside`, the rule doesn't work -- [try it out](https://semgrep.dev/playground/s/KZOd?editorMode=advanced) if you like!

```yml
rules:
  - id: find-unverified-transactions-inside
    patterns:
      - pattern-inside: |
          $RETURN $METHOD(...) {
            ...
          }
      - pattern: |
          ...
          make_transaction($T);
          ...
      - pattern-not: |
          ...
          verify_transaction($T);
          ...
          make_transaction($T);
          ...
```

With an understanding of how `pattern-not` operates, you can see that this rule fails because the matches are not the same size. The `pattern-not` match is at the same level, but it is "larger" (contains more code).

If you switch to `pattern-not-inside`:

```yml
- pattern-not-inside: |
    ...
    verify_transaction($T);
    ...
    make_transaction($T);
    ...
```

The rule successfully matches the example code.

## Further information

See this video for more information about the difference between `pattern-not` and  `pattern-not-inside`.

<iframe class="yt_embed" width="100%" height="432px" src="https://www.youtube.com/embed/g_Yrp9_ZK2c" frameborder="0" allowfullscreen></iframe>
````

### `using-semgrep-rule-schema-in-vscode.md`

````markdown
---
description: Use the Semgrep rule schema in VS Code to help make rule writing easier.
tags:
  - Rules
  - VS Code
---

# Use the Semgrep rule schema to write rules in VS Code

You may already be familiar with writing rules in the [Semgrep Editor](/semgrep-code/editor). However, if your IDE of choice is VS Code and you'd like to write Semgrep rules there, using the Semgrep rule schema will provide a richer editing environment, allowing VS Code to understand the shape of your rule's YAML file, including its value sets, defaults, and descriptions ([reference](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml#associating-schemas)).

:::tip
Writing rules locally in your IDE is also helpful for iteratively testing them against an entire local repository, as opposed to just a snippet of test code.
:::

When the schema is set up, auto-completion operates in your VS Code IDE just as it does in the Semgrep Editor when writing rules:

![Example Semgrep YAML rule file with auto-complete](/img/kb/vscode-schema-autocomplete-example.png)

## Add the Semgrep rule schema in VS Code

Adding the Semgrep rule schema in VS Code requires two steps:

1. Install the YAML Language Support extension by Red Hat
2. Associate the Semgrep rule schema

### Install the YAML Language Support extension by Red Hat

You can install the  "YAML" extension authored by "Red Hat" directly in VS Code or by going to the Visual Studio Marketplace and installing it from there. In VS Code, go to the **Extensions** pane and search for `yaml`. This should yield the correction extension as the top result. However, please verify that you are installing the correct extension by ensuring it is the same as [this one](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml).

### Associate the Semgrep rule schema

Once the extension is installed, associate the Semgrep rule schema with the Semgrep YAML rule definitions you are working on in VS Code using one of following methods:

1. Directly in the YAML file
2. Using `yaml.schemas` in your VS Code `settings.json` file

We recommend taking a look at the [extension overview section on associating schemas](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml#associating-schemas) to gain a preliminary understanding before proceeding.

#### Associate a schema directly in the YAML file

To associate the schema directly within a Semgrep YAML rule file, include the following line at the top of the file:

    # yaml-language-server: $schema=https://json.schemastore.org/semgrep.json

The drawback to this method is that it must be done independently for each YAML rule file.

#### Associate a schema to a glob pattern via `yaml.schemas`

Before proceeding, we recommend reading the [extension overview](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml#associating-a-schema-to-a-glob-pattern-via-yaml.schemas) as a supplement to this article to better understand how YAML schemas are handled by the extension.

To associate the Semgrep rule schema via `yaml.schemas` in your VS Code `settings.json` file (on macOS), go to:

    Code -> Settings -> Settings -> Extensions -> YAML

In the YAML extension settings, scroll down to `Yaml: Schemas` and click `Edit in settings.json`, as shown below:

![MacOS VS Code YAML extension settings](/img/kb/vscode-yaml-schemas.png)

This opens the `settings.json` file with an empty `yaml.schemas` object ready to be defined. For example, consider the following `yaml.schemas` definition:

```json
"yaml.schemas": {
    "https://json.schemastore.org/semgrep.json": "Downloads/semgrep_rules/*.yaml"
}
```

This associates the schema defined on the left side of the colon (`:`) with files matching the glob pattern on the right. The glob pattern matches any `.yaml` file located in a directory structure that matches `Downloads/semgrep_rules/`. The desired glob pattern differs for varying operating systems and should reflect where you are storing Semgrep YAML rule files.

After completing the configuration for `yaml.schemas`, open a Semgrep rule YAML file to verify that a notice shows at the top similar to this one:

![Example Semgrep YAML rule file with schema defined](/img/kb/vscode-yaml-schema-example-file.png)

This indicates that you've successfully associated the Semgrep rule schema with your Semgrep rule YAML file(s).
````

Here is how to write semgrep rules:

# writing-rules

## Table of Contents

- **autofix.md/**
- **data-flow/**
  - **constant-propagation.md/**
  - **data-flow-overview.md/**
  - **status.md/**
  - **taint-mode.md/**
- **experiments/**
  - **aliengrep.md/**
  - **deprecated-experiments.md/**
  - **display-propagated-metavariable.md/**
  - **extract-mode.md/**
  - **introduction.md/**
  - **join-mode/**
    - **overview.md/**
    - **recursive-joins.md/**
  - **metavariable-type.md/**
  - **multiple-focus-metavariables.md/**
  - **pattern-syntax.md/**
  - **project-depends-on.md/**
  - **symbolic-propagation.md/**
- **generic-pattern-matching.md/**
- **glossary.md/**
- **metavariable-analysis.md/**
- **overview.md/**
- **pattern-examples.md/**
- **pattern-syntax.md/**
- **private-rules.md/**
- **rule-ideas.md/**
- **rule-syntax.md/**
- **testing-rules.md/**

## File Tree

```tree
autofix.md/
data-flow/
    constant-propagation.md/
    data-flow-overview.md/
    status.md/
    taint-mode.md/
experiments/
    aliengrep.md/
    deprecated-experiments.md/
    display-propagated-metavariable.md/
    extract-mode.md/
    introduction.md/
    join-mode/
        overview.md/
        recursive-joins.md/
    metavariable-type.md/
    multiple-focus-metavariables.md/
    pattern-syntax.md/
    project-depends-on.md/
    symbolic-propagation.md/
generic-pattern-matching.md/
glossary.md/
metavariable-analysis.md/
overview.md/
pattern-examples.md/
pattern-syntax.md/
private-rules.md/
rule-ideas.md/
rule-syntax.md/
testing-rules.md/
```

### `autofix.md`

````markdown
---
append_help_link: true
tags:
  - Rule writing
---

# Autofix

Autofix is a Semgrep feature where rules contain suggested fixes to resolve findings.

Semgrep's rule format supports a `fix:` key that supports the replacement of metavariables and regex matches with potential fixes. This allows for value capture and rewriting. With rules that make use of the autofix capability, you can resolve findings as part of your code review workflow. Semgrep suggests these fixes through GitHub PR or GitLab MR comments.

You can apply the autofix directly to the file using the `--autofix` flag. To test the autofix before applying it, use both the `--autofix` and `--dryrun` flags.

## Example autofix snippet

Sample autofix (view in [Playground](https://semgrep.dev/s/R6g)):

```yaml
rules:
- id: use-sys-exit
  languages:
  - python
  message: |
    Use `sys.exit` over the python shell `exit` built-in. `exit` is a helper
    for the interactive shell and is not be available on all Python implementations.
    https://stackoverflow.com/a/6501134
  pattern: exit($X)
  fix: sys.exit($X)
  severity: WARNING
```

## Create autofix rules

See how to create an autofix rule in **Transforming code with Semgrep autofixes** video:

<iframe class="yt_embed" width="100%" height="432px" src="https://www.youtube.com/embed/8jfjWixmtvo" frameborder="0" allowfullscreen></iframe>

## Autofix with regular expression replacement

A variant on the `fix` key is `fix-regex`, which applies regular expression replacements (think `sed`) to matches found by Semgrep.

`fix-regex` has two required fields:

- `regex` specifies the regular expression to replace within the match found by Semgrep
- `replacement` specifies what to replace the regular expression with.

`fix-regex` also takes an optional `count` field, which specifies how many occurrences of `regex` to replace with `replacement`, from left-to-right and top-to-bottom. By default, `fix-regex` will replace all occurrences of `regex`. If `regex` does not match anything, no replacements are made.

The replacement behavior is identical to the `re.sub` function in Python. See these [Python docs](https://docs.python.org/3/library/re.html#re.sub) for more information.

An example rule with `fix-regex` is shown below. `regex` uses a capture group to greedily capture everything up to the final parenthesis in the match found by Semgrep. `replacement` replaces this with everything in the capture group (`\1`), a comma, `timeout=30`, and a closing parenthesis. Effectively, this adds `timeout=30` to the end of every match.

```yaml
rules:
- id: python.requests.best-practice.use-timeout.use-timeout
  patterns:
  - pattern-not: requests.$W(..., timeout=$N, ...)
  - pattern-not: requests.$W(..., **$KWARGS)
  - pattern-either:
    - pattern: requests.request(...)
    - pattern: requests.get(...)
    - pattern: requests.post(...)
    - pattern: requests.put(...)
    - pattern: requests.delete(...)
    - pattern: requests.head(...)
    - pattern: requests.patch(...)
  fix-regex:
    regex: '(.*)\)'
    replacement: '\1, timeout=30)'
  message: |
    'requests' calls default to waiting until the connection is closed.
    This means a 'requests' call without a timeout will hang the program
    if a response is never received. Consider setting a timeout for all
    'requests'.
  languages: [python]
  severity: WARNING
```

## Remove a code detected by a rule

Improve your code quality by cleaning up stale code automatically. Remove code that an autofix rule detected by adding the `fix` key with `""`, an empty string.

For example:

```yaml
 - id: python-typing
   pattern: from typing import $X
   fix: ""
   languages: [ python ]
   message: found one
   severity: ERROR
```

When an autofix is applied, this rule removes the detected code.
````

### `generic-pattern-matching.md`

````markdown
---
append_help_link: true
description: "Semgrep can match generic patterns in languages that it doesn’t support yet. You can use generic pattern matching for languages that do **not** have a parser, configuration files, or other structured data such as XML."
tags:
  - Rule writing
---

# Generic pattern matching

<!-- If you ever need to replace the examples below, a good way is to look
     into the semgrep-rules repo under "generic" for an existing rule
     that makes sense. -->

## Introduction

Semgrep can match generic patterns in languages that it does **not** yet support. Use generic pattern matching for languages that do not have a parser, configuration files, or other structured data such as XML. Generic pattern matching can also be useful in files containing multiple languages even if the languages are otherwise supported, such as HTML with embedded JavaScript or PHP code. In those cases you can also consider [Extract mode (experimental)](/docs/writing-rules/experiments/extract-mode), but generic patterns may be simpler and still effective.

As an example of generic matching, consider this rule:

```yaml
rules:
  - id: dynamic-proxy-scheme
    pattern: proxy_pass $$SCHEME:// ...;
    paths:
      include:
        - "*.conf"
        - "*.vhost"
        - sites-available/*
        - sites-enabled/*
    languages:
      - generic
    severity: WARNING
    message: >-
      The protocol scheme for this proxy is dynamically determined.
      This can be dangerous if the scheme is injected by an
      attacker because it may forcibly alter the connection scheme.
      Consider hardcoding a scheme for this proxy.
    metadata:
      references:
        - https://github.com/yandex/gixy/blob/master/docs/en/plugins/ssrf.md
      category: security
      technology:
        - nginx
      confidence: MEDIUM
```

The above rule [matches](https://semgrep.dev/playground/r/generic.nginx.security.dynamic-proxy-scheme.dynamic-proxy-scheme) this code snippet:

```conf
server {
  listen              443 ssl;
  server_name         www.example.com;
  keepalive_timeout   70;

  ssl_certificate     www.example.com.crt;
  ssl_certificate_key www.example.com.key;

  location ~ /proxy/(.*)/(.*)/(.*)$ {
    # ruleid: dynamic-proxy-scheme
    proxy_pass $1://$2/$3;
  }

  location ~* ^/internal-proxy/(?<proxy_proto>https?)/(?<proxy_host>.*?)/(?<proxy_path>.*)$ {
    internal;

    # ruleid: dynamic-proxy-scheme
    proxy_pass $proxy_proto://$proxy_host/$proxy_path ;
    proxy_set_header Host $proxy_host;
}

  location ~ /proxy/(.*)/(.*)/(.*)$ {
    # ok: dynamic-proxy-scheme
    proxy_pass http://$1/$2/$3;
  }

  location ~ /proxy/(.*)/(.*)/(.*)$ {
    # ok: dynamic-proxy-scheme
    proxy_pass https://$1/$2/$3;
  }
}
```

Generic pattern matching has the following properties:

* A document is interpreted as a nested sequence of ASCII words, ASCII punctuation, and other bytes.
* `...` (ellipsis operator) allows skipping non-matching elements, up to 10 lines down the last match.
* `$X` (metavariable) matches any word.
* `$...X` (ellipsis metavariable) matches a sequence of words, up to 10 lines down the last match.
* Indentation determines primary nesting in the document.
* Common ASCII braces `()`, `[]`, and `{}` introduce secondary nesting but only within single lines. Therefore, misinterpreted or mismatched braces don't disturb the structure of the rest of document.
* The document must be at least as indented as the pattern: any indentation specified in the pattern must be honored in the document.

## Caveats and limitations of generic mode

Semgrep can reliably understand the syntax of natively [supported languages](/supported-languages). The generic mode is useful for unsupported languages, and consequently brings specific limitations.

:::caution
The quality of results in the generic mode can vary depending on the language you use it for.
:::

The generic mode works fine with any human-readable text, as long as it is primarily based on ASCII symbols. Since the generic mode does not understand the syntax of the language you are scanning, the quality of the result may differ from language to language or even depend on specific code. As a consequence, the generic mode works well for some languages, but it does not always give consistent results. Generally, it's possible or even easy to write code in weird ways that prevent generic mode from matching.

**Example**: In XML, one can write `&#x48;&#x65;&#x6C;&#x6C;&#x6F` instead of `Hello`. If a rule pattern in generic mode is `Hello`, Semgrep is unable to match the `&#x48;&#x65;&#x6C;&#x6C;&#x6F`, unlike if it had full XML support.

With respect to Semgrep operators and features:

* metavariable support is limited to capturing a single “word”, which is a token of the form [A-Za-z0-9_]+. They can’t capture sequences of tokens such as hello, world (in this case there are 3 tokens: `hello`, `,`, and `world`).
* the ellipsis operator is supported and spans at most 10 lines
* pattern operators like either/not/inside are supported
* inline regular expressions for strings (`"=~/word.*/"`) are not supported

## Troubleshooting

### Common pitfall #1: not enough `...`

Rule of thumb:
> If the pattern commonly matches many lines, use `... ...` (20 lines), or `... ... ...` (30 lines) etc. to make sure to match all the lines.

Here's an innocuous pattern that should match the call to a function `f()`:

```sh
f(...)
```

It matches the following code [just fine](https://semgrep.dev/s/9v9R):

```sh
f(
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9
)
```

But it will [fail](https://semgrep.dev/s/1z6Q) here because the function arguments span more than 10 lines:

```sh
f(
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10
)
```

The [solution](https://semgrep.dev/s/9v9R) is to use multiple `...` in the pattern:

```sh
f(... ...)
```

### Common pitfall #2: not enough indentation

Rule of thumb:
> If the target code is always indented, use indentation in the pattern.

In the following example, we want to match the `system` sections containing a `name` field:

```yml
# match here
[system]
  name = "Debian"

# DON'T match here
[system]
  max_threads = 2
[user]
  name = "Admin Overlord"
```

❌ This pattern will [incorrectly](https://semgrep.dev/s/ry1A) catch the `name` field in the `user` section:

```yml
[system]
...
name = ...
```

✅ This pattern will catch [only](https://semgrep.dev/s/bXAr) the `name` field in the `system` section:

```yml
[system]
  ...
  name = ...
```

### Handling line-based input

This section explains how to use Semgrep's generic mode to match
single lines of code using an ellipsis metavariable. Many simple
configuration formats are collections of key and value pairs delimited
by newlines. For example, to extract the `password` value from the
following made-up input:

```yml
username = bob
password = p@$$w0rd
server = example.com
```

Unfortunately, the following pattern does not match the whole line. In generic mode, metavariables only capture a single word (alphanumeric sequence):

```yml
password = $PASSWORD
```

This pattern matches the input file but does not assign the value `p` to `$PASSWORD` instead of the full value `p@$$w0rd`.

To match an arbitrary sequence of items and capture their value in the example:

1. Use a named ellipsis, by changing the pattern to the following:

    ```yaml
    password = $...PASSWORD
    ```

    This still leads Semgrep to capture too much information. The value assigned to `$...PASSWORD` are now `p@$$w0rd` and<br />
    `server = example.com`. In generic mode, an ellipsis extends until the end of the current block or up to 10 lines below, whichever comes first. To prevent this behavior, continue with the next step.

2. In the Semgrep rule, specify the following key:

    ```yaml
    generic_ellipsis_max_span: 0
    ```

    This option forces the ellipsis operator to match patterns within a single line.
    Example of the [resulting rule](https://semgrep.dev/playground/s/KPzn):

    ```yaml
    id: password-in-config-file
    pattern: |
      password = $...PASSWORD
    options:
      # prevent ellipses from matching multiple lines
      generic_ellipsis_max_span: 0
    message: |
      password found in config file: $...PASSWORD
    languages:
      - generic
    severity: WARNING
    ```

### Ignoring comments

By default, the generic mode does **not** know about comments or code
that can be ignored. In the following example, we are
scanning for CSS code that sets the text color to blue. The target code
is the following:

```yml
color: /* my fave color */ blue;
```

Use the [`options.generic_comment_style`](/writing-rules/rule-syntax/#options)
to ignore C-style comments as it is the case in our example.
Our simple Semgrep rule is:

```yaml
id: css-blue-is-ugly
pattern: |
  color: blue
options:
  # ignore comments of the form /* ... */
  generic_comment_style: c
message: |
  Blue is ugly.
languages:
  - generic
severity: WARNING
```

## Command line example

Sample pattern: `exec(...)`

Sample target file `exec.txt` contains:

```bash
import exec as safe_function
safe_function(user_input)

exec("ls")

exec(some_var)

some_exec(foo)

exec (foo)

exec (
    bar
)

# exec(foo)

print("exec(bar)")
```

Output:

```bash
$ semgrep -l generic -e 'exec(...)` exec.text
7:exec("ls")
--------------------------------------------------------------------------------
11:exec(some_var)
--------------------------------------------------------------------------------
19:exec (foo)
--------------------------------------------------------------------------------
23:exec (
24:128
25:    bar
26:129
27:)
--------------------------------------------------------------------------------
31:# exec(foo)
--------------------------------------------------------------------------------
35:print("exec(bar)")
ran 1 rules on 1 files: 6 findings
```

## Semgrep Registry rules for generic pattern matching

You can peruse [existing generic rules](https://semgrep.dev/r?lang=generic&sev=ERROR,WARNING,INFO&tag=dgryski.semgrep-go,hazanasec.semgrep-rules,ajinabraham.njsscan,best-practice,security,java-spring,go-stdlib,ruby-stdlib,java-stdlib,js-node,nodejsscan,owasp,dlint,react,performance,compatibility,portability,correctness,maintainability,secuirty,mongodb,experimental,caching,robots-denied,missing-noreferrer,missing-noopener) in the Semgrep registry. In general, short patterns on structured data will perform the best.

## Cheat sheet

Some examples of what will and will not match on the `generic` tab of the Semgrep cheat sheet below:

<iframe src="https://semgrep.dev/embed/cheatsheet" scrolling="0" width="100%" height="800"  frameBorder="0"></iframe>
<br />

## Hidden bonus

In the Semgrep code the generic pattern matching implementation is called **spacegrep** because it tokenizes based on whitespace (and because it sounds cool 😎).
````

### `glossary.md`

````markdown
---
slug: glossary
title: SAST and rule-writing glossary
hide_title: true
description: Definitions of static analysis and Semgrep rule-writing terms.
tags:
  - Rule writing
---

## Static analysis and rule-writing glossary

The definitions provided here are specific to Semgrep.

## Constant propagation

Constant propagation is a type of analysis where values known to be constant are substituted in later uses, allowing the value to be used to detect matches. Semgrep can perform constant propagation across files, unless you are running Semgrep OSS, which can only propagate within a file.

Constant propagation is applied to all rules unless [it is disabled](/writing-rules/data-flow/constant-propagation#disable-constant-propagation).

For example, given the following pattern:

```yaml
...
patterns:
- pattern: console.log(2)
```

And the following code snippet:

```javascript showLineNumbers
const x = 2;
//highlight-next-line
console.log(x);
```

The pattern operator `pattern: print(2)` tells Semgrep to match line 2 because it propagates the value `2` from the assignment in line 1 to the `console.log()` function in line.

Constant propagation is one of the many analyses that differentiate Semgrep from grep.

## Cross-file analysis

Also known as **interfile analysis**. Cross-file analysis takes into account how information flows between files. In particular, cross-file analysis includes **cross-file taint analysis**, which tracks unsanitized variables flowing from a source to a sink through arbitrarily many files. Other analyses performed across files include constant propagation and type inference.

Cross-file analysis is usually used in contrast to intrafile (also known as per-file analysis), where each file is analyzed as a standalone block of code.

Within Semgrep, cross-file **and** cross-function analysis is simply referred to as cross-file analysis.

Semgrep OSS is limited to per-file analysis.

## Cross-function analysis

Cross-function analysis means that interactions between functions are taken into account. This improves taint analysis, which tracks unsanitized variables flowing from a source to a sink through arbitrarily many functions.

Within Semgrep documentation, cross-function analysis implies intrafile or per-file analysis. Each file is still analyzed as a standalone block, but within the file it takes into account how information flows between functions.

Also known as **interprocedural** analysis.

## Error matrix

An error matrix is a 2x2 table that visualizes the findings of a Semgrep rule in relation to the vulnerable lines of code it does or doesn't detect. It has two axes:

- Positive and negative
- True or false

These yield the following combinations:

<dl>
<dt>True positive</dt>
<dd>The rule detected a piece of code it was intended to find.</dd>
<dt>False positive</dt>
<dd>The rule detected a piece of code it was not intended to find.</dd>
<dt>True negative</dt>
<dd>The rule correctly skipped over a piece of code it wasn't meant to find.</dd>
<dt>False negative</dt>
<dd>The rule failed to detect a piece of code it should have found.</dd>
</dl>

Not to be confused with **risk matrices**.

## Finding

A finding is the core result of Semgrep's analysis. Findings are generated when a Semgrep rule matches a piece of code. Findings can be security issues, bugs, or code that doesn't follow coding conventions.

## Fully qualified name

A **fully qualified name** refers to a name which uniquely identifies a class, method, type, or module. Languages such as C# and Ruby use `::` to distinguish between fully qualified names and regular names.

Not to be confused with **tokens**.

## l-value (left-, or location-value)

An expression that denotes an object in memory; a memory location, something that you can use in the left-hand side (LHS) of an assignment. For example, `x` and `array[2]` are l-values, but `2+2` is not.

## Metavariable

A metavariable is an abstraction that lets you match something even when you don't know exactly what it is you want to match. It is similar to capture groups in regular expressions. All metavariables begin with a `$` and can only contain uppercase characters, digits, and underscores.

## Propagator

A propagator is any code that alters a piece of data as the data moves across the program. This includes functions, reassignments, and so on.

When you write rules that perform taint analysis, propagators are pieces of code that you specify through the `pattern-propagator` key as code that always passes tainted data. This is especially relevant when Semgrep performs intraprocedural taint analysis, as there is no way for Semgrep to infer which function calls propagate taint. Thus, explicitly listing propagators is the only way for Semgrep to know if tainted data could be passed within your function.

## Rule (Semgrep rule)

A rule is a specification of the patterns that Semgrep must match to the code to generate a finding. Rules are written in YAML. Without a rule, the engine has no instructions on how to match code.

Rules can be run on either Semgrep or its OSS Engine. Only proprietary Semgrep can perform [interfile analysis](#cross-file-analysis).

There are two types of rules: **search** and **taint**.

<dl>
  <dt>Search rules</dt>
  <dd>
    Rules default to this type. Search rules detect matches based on the patterns described by a rule. There are several semantic analyses that search rules perform, such as:
    <ul>
      <li>Interpreting syntactically different code as semantically equivalent</li>
      <li>Constant propagation</li>
      <li>Matching a fully qualified name to its reference in the code, even when not fully qualified</li>
      <li>Type inference, particularly when using typed metavariables</li>
    </ul>
  </dd>
  <dt>Taint rules</dt>
  <dd>Taint rules make use of Semgrep's taint analysis in addition to default search functionalities. Taint rules are able to specify sources, sinks, and propagators of data as well as sanitizers of that data. For more information, see <a href="/writing-rules/data-flow/taint-mode/">Taint analysis documentation</a>.</dd>
</dl>

<!-- how can we say that search rules are semantic if no analysis is performed on the value of data, such as variables? Or are there levels of semantic understanding that semgrep can perform? -->

## Sanitizers

A sanitizer is any piece of code, such as a function or [a cast](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/types/casting-and-type-conversions#explicit-conversions), that can clean untrusted or tainted data. Data from untrusted sources, such as user inputs, may be tainted with unsafe characters. Sanitizers ensure that unsafe characters are removed or stripped from the input.

An example of a sanitizer is the [<i class="fas fa-external-link fa-xs"></i> `DOMPurify.sanitize(dirty);`](https://github.com/cure53/DOMPurify) function from the  DOMPurify package in JavaScript.

## Per-file analysis

Also known as intrafile analysis. In per-file analysis, information can only be traced or tracked within a single file. It cannot be traced if it flows to another file.

Per-file analysis can include cross-function analysis, aka tracing the flow of information between functions. When discussing the capabilities of pro analysis, per-file analysis implies cross-function analysis.

## Per-function analysis

Also known as intraprocedural analysis. In per-function analysis, information can only be traced or tracked within a single function.

## Sink

In taint analysis, a sink is any vulnerable function that is called with potentially tainted or unsafe data.

## Source

In taint analysis, a source is any piece of code that assigns or sets tainted data, typically user input.

## Taint analysis

Taint analysis tracks and traces the flow of untrusted or unsafe data. Data coming from sources such as user inputs could be unsafe and used as an attack vector if these inputs are not sanitized. Taint analysis provides a means of tracing that data as it moves through the program from untrusted sources to vulnerable functions.
````

### `metavariable-analysis.md`

````markdown
---
slug: metavariable-analysis
append_help_link: true
description: "metavariable-analysis allows Semgrep users to check metavariables for common problematic properties, such as RegEx denial of service (ReDoS) and high-entropy values."
tags:
  - Rule writing
---

# Metavariable analysis

Metavariable analysis was created to support some metavariable inspection techniques that are difficult to express with existing rules but have "simple" binary classifier behavior. Currently, this syntax supports two analyzers: `redos` and `entropy`

## ReDoS

```yaml
metavariable-analysis:
    analyzer: redos
    metavariable: $VARIABLE
```

RegEx denial of service is caused by poorly constructed regular expressions that exhibit exponential runtime when fed specifically crafted inputs. The `redos` analyzer uses known RegEx antipatterns to determine if the target expression is potentially vulnerable to catastrophic backtracking.

<iframe src="https://semgrep.dev/embed/editor?snippet=2Aoj" border="0" frameBorder="0" width="100%" height="432"></iframe>

## Entropy

```yaml
metavariable-analysis:
    analyzer: entropy
    metavariable: $VARIABLE
```

Entropy is a common approach for detecting secret strings - many existing tools leverage a combination of entropy calculations and RegEx for secret detection. This analyzer returns `true` if a metavariable has high entropy (randomness) relative to the English language.

<iframe src="https://semgrep.dev/embed/editor?snippet=GgZG" border="0" frameBorder="0" width="100%" height="432"></iframe>
````

### `overview.md`

````markdown
---
id: overview
displayed_sidebar: rulewritingSidebar
description: >-
  Learn how to use Semgrep’s intuitive syntax to write rules specific to your codebase. You can write and share rules directly from your browser using the Semgrep Playground, or write rules in your terminal and run them on the command line.
title: Overview
hide_title: true
tags:
  - Rule writing
---

## Writing rules

### Tutorial

If you want the best introduction to writing Semgrep rules, use the interactive, example-based [Semgrep rule tutorial](https://semgrep.dev/learn).

### Do it live

Write and share rules directly from the [Playground](https://semgrep.dev/editor). You can also write rules in your terminal and run them with the Semgrep command line tool.

You can write rules that:

- Automate code review comments
- Identify secure coding violations
- Scan configuration files
- See more use cases in [Rule ideas](rule-ideas.md).

This rule detects the use of `is` when comparing Python strings. `is` checks reference equality, not value equality, and can exhibit nondeterministic behavior.

<iframe title="Semgrep example Python is comparison" src="https://semgrep.dev/embed/editor?snippet=Ppde" width="100%" height="432px" frameBorder="0"></iframe>

### Next steps

The following articles guide you through rule writing basics or can provide you with needed references:

- [Pattern syntax](/writing-rules/pattern-syntax) describes what Semgrep patterns can do in detail, and provides example use cases of the ellipsis operator, metavariables.
- [Rule syntax](rule-syntax.md) describes Semgrep YAML rule files, which can have multiple patterns, detailed output messages, and autofixes. The syntax allows the composition of individual patterns with Boolean operators.
- [Contributing rules](/contributing/contributing-to-semgrep-rules-repository) gives you an overview of where and how you can contribute to Semgrep Registry rules. This document also provides some information about tests and appropriate metadata information you may use for your rules.

Looking for ideas on what rules to write? See [Rule ideas](/writing-rules/rule-ideas) for common use cases and prompts to help you start writing rules from scratch.
````

### `pattern-examples.md`

````markdown
---
slug: pattern-examples
tags:
  - Rule writing
---



# Pattern examples

This section is automatically generated from the unit test suite inside Semgrep. Per-language references are also available within the [Playground](https://semgrep.dev/editor).

<iframe src="https://semgrep.dev/embed/cheatsheet" scrolling="0" width="100%" height="800"  frameBorder="0"></iframe>
````

### `pattern-syntax.md`

````markdown
---
append_help_link: true
slug: pattern-syntax
description: "Learn Semgrep's pattern syntax to search code for a given code pattern. If you're just getting started writing Semgrep rules, check out the Semgrep Tutorial at https://semgrep.dev/learn"
tags:
  - Rule writing
---

# Pattern syntax

:::tip
Getting started with rule writing? Try the [Semgrep Tutorial](https://semgrep.dev/learn) 🎓
:::

This document describes Semgrep’s pattern syntax. You can also see pattern [examples by language](/writing-rules/pattern-examples). In the command line, patterns are specified with the flag `--pattern` (or `-e`). Multiple
coordinating patterns may be specified in a configuration file. See
[rule syntax](/writing-rules/rule-syntax) for more information.

## Pattern matching

Pattern matching searches code for a given pattern. For example, the
expression pattern `1 + func(42)` can match a full expression or be
part of a subexpression:

```python
foo(1 + func(42)) + bar()
```

In the same way, the statement pattern `return 42` can match a top
statement in a function or any nested statement:

```python
def foo(x):
  if x > 1:
     if x > 2:
       return 42
  return 42
```

## Ellipsis operator

The `...` ellipsis operator abstracts away a sequence of zero or more
items such as arguments, statements, parameters, fields, characters.

The `...` ellipsis can also match any single item that is not part of
a sequence when the context allows it.

See the use cases in the subsections below.

### Function calls

Use the ellipsis operator to search for function calls or
function calls with specific arguments. For example, the pattern `insecure_function(...)` finds calls regardless of its arguments.

```python
insecure_function("MALICIOUS_STRING", arg1, arg2)
```

Functions and classes can be referenced by their fully qualified name, e.g.,

- `django.utils.safestring.mark_safe(...)` or `mark_safe(...)`
- `System.out.println(...)` or `println(...)`

You can also search for calls with arguments after a match. The pattern `func(1, ...)` will match both:

```python
func(1, "extra stuff", False)
func(1)  # Matches no arguments as well
```

Or find calls with arguments before a match with `func(..., 1)`:

```python
func("extra stuff", False, 1)
func(1)  # Matches no arguments as well
```

The pattern `requests.get(..., verify=False, ...)` finds calls where an argument appears anywhere:

```python
requests.get(verify=False, url=URL)
requests.get(URL, verify=False, timeout=3)
requests.get(URL, verify=False)
```

Match the keyword argument value with the pattern `$FUNC(..., $KEY=$VALUE, ...)`.

### Method calls

The ellipsis operator can also be used to search for method calls.

For example, the pattern `$OBJECT.extractall(...)` matches:

```python
tarball.extractall('/path/to/directory')  # Oops, potential arbitrary file overwrite
```

You can also use the ellipsis in chains of method calls. For example,
the pattern `$O.foo(). ... .bar()` will match:

```python
obj = MakeObject()
obj.foo().other_method(1,2).again(3,4).bar()
```

### Function definitions

The ellipsis operator can be used in function parameter lists or in the function
body. To find function definitions with [mutable default arguments](https://docs.python-guide.org/writing/gotchas/#mutable-default-arguments):

```text
pattern: |
  def $FUNC(..., $ARG={}, ...):
      ...
```

```python
def parse_data(parser, data={}):  # Oops, mutable default arguments
    pass
```

:::tip
The YAML `|` operator allows for [multiline strings](https://yaml-multiline.info/).
:::

The ellipsis operator can match the function name.
Match any function definition:
Regular functions, methods, and also anonymous functions (such as lambdas).
To match named or anonymous functions use an ellipsis `...` in place of the name of the function.
For example, in JavaScript the pattern `function ...($X) { ... }` matches
any function with one parameter:

```javascript
function foo(a) {
  return a;
}
var bar = function (a) {
  return a;
};
```

### Class definitions

The ellipsis operator can be used in class definitions. To find classes that
inherit from a certain parent:

```text
pattern: |
  class $CLASS(InsecureBaseClass):
      ...
```

```python
class DataRetriever(InsecureBaseClass):
    def __init__(self):
        pass
```

:::tip
The YAML `|` operator allows for [multiline strings](https://yaml-multiline.info/).
:::

#### Ellipsis operator scope

The `...` ellipsis operator matches everything in its current scope. The current scope of this operator is defined by the patterns that precede `...` in a rule. See the following example:

<iframe
  src="https://semgrep.dev/embed/editor?snippet=zZx0"
  border="0"
  frameBorder="0"
  width="100%"
  height="432"
></iframe>

Semgrep matches the first occurrence of `bar` and `baz` in the test code as these objects fall under the scope of `foo` and `...`. The ellipsis operator does not match the second occurrence of `bar` and `baz` as they are not inside of the function definition, therefore these objects in their second occurrence are not inside the scope of the ellipsis operator.

### Strings

The ellipsis operator can be used to search for strings containing any data. The pattern `crypto.set_secret_key("...")` matches:

```python
crypto.set_secret_key("HARDCODED SECRET")
```

This also works with [constant propagation](#constants).

In languages where regular expressions use a special syntax
(for example JavaScript), the pattern `/.../` will match
any regular expression construct:

```javascript
re1 = /foo|bar/;
re2 = /a.*b/;
```

### Binary operations

The ellipsis operator can match any number of arguments to binary operations. The pattern `$X = 1 + 2 + ...` matches:

```python
foo = 1 + 2 + 3 + 4
```

### Containers

The ellipsis operator can match inside container data structures like lists, arrays, and key-value stores.

The pattern `user_list = [..., 10]` matches:

```python
user_list = [8, 9, 10]
```

The pattern `user_dict = {...}` matches:

```python
user_dict = {'username': 'password'}
```

The pattern `user_dict = {..., $KEY: $VALUE, ...}` matches the following and allows for further metavariable queries:

```python
user_dict = {'username': 'password', 'address': 'zipcode'}
```

You can also match just a key-value pair in
a container, for example in JSON the pattern `"foo": $X` matches
just a single line in:

```json
{ "bar": True,
  "name": "self",
  "foo": 42
}
```

### Conditionals and loops

The ellipsis operator can be used inside conditionals or loops. The pattern:

```text
pattern: |
  if $CONDITION:
      ...
```

:::tip
The YAML `|` operator allows for [multiline strings](https://yaml-multiline.info/).
:::

matches:

```python
if can_make_request:
    check_status()
    make_request()
    return
```

A metavariable can match a conditional or loop body if the body statement information is re-used later. The pattern:

```text
pattern: |
  if $CONDITION:
      $BODY
```

matches:

```python
if can_make_request:
    single_request_statement()
```

:::tip
Half or partial statements can't be matches; both of the examples above must specify the contents of the condition’s body (e.g., `$BODY` or `...`), otherwise they are not valid patterns.
:::

### Matching single items with an ellipsis

Ellipsis `...` is generally used to match sequences of similar elements.
However, you can also match single item using ellipsis `...` operator.
The following pattern is valid in languages with a C-like
syntax even though `...` matches a single Boolean value rather
than a sequence:

```java
if (...)
  return 42;
```

Another example where a single expression is matched by an ellipsis is
the right-hand side of assignments:

```java
foo = ...;
```

However, matching a sequence of items remains the default meaning of an
ellipsis. For example, the pattern `bar(...)` matches `bar(a)`,
but also `bar(a, b)` and `bar()`. To force a match on a single item,
use a metavariable as in `bar($X)`.

## Metavariables

Metavariables are an abstraction to match code when you don’t know the value or contents ahead of time, similar to [capture groups](https://regexone.com/lesson/capturing_groups) in regular expressions.

Metavariables can be used to track values across a specific code scope. This
includes variables, functions, arguments, classes, object methods, imports,
exceptions, and more.

Metavariables look like `$X`, `$WIDGET`, or `$USERS_2`. They begin with a `$` and can only
contain uppercase characters, `_`, or digits. Names like `$x` or `$some_value` are invalid.

### Expression metavariables

The pattern `$X + $Y` matches the following code examples:

```python
foo() + bar()
```

```python
current + total
```

### Import metavariables

Metavariables can also be used to match imports. For example, `import $X` matches:

```python
import random
```

### Reoccurring metavariables

Re-using metavariables shows their true power. Detect useless assignments:

```text
pattern: |
  $X = $Y
  $X = $Z
```

Useless assignment detected:

```python
initial_value = 10  # Oops, useless assignment
initial_value = get_initial_value()
```

:::tip
The YAML `|` operator allows for [multiline strings](https://yaml-multiline.info/).
:::

### Literal Metavariables

You can use `"$X"` to match any string literal. This is similar
to using `"..."`, but the content of the string is stored in the
metavariable `$X`, which can then be used in a message
or in a [`metavariable-regex`](/writing-rules/rule-syntax/#metavariable-regex).

You can also use `/$X/` and `:$X` to respectively match
any regular expressions or atoms (in languages that support
those constructs, e.g., Ruby).

:::info
Because literal metavariables bind to strings that may not be valid code, if you want to match them in more detail with a [`metavariable-pattern`](/writing-rules/rule-syntax/#metavariable-pattern), you must [specify `generic` language](/writing-rules/rule-syntax#metavariable-pattern-with-nested-language) inside the `metavariable-pattern`. For example:

```yml
rules:
  - id: match-literal-string
    languages:
      - python
    severity: INFO
    message: Found "$STRING"
    patterns:
      - pattern: '"$STRING"'
      - metavariable-pattern:
          language: generic
          metavariable: $STRING
          pattern: "literal string contents"
```

:::

### Typed metavariables

#### Syntax

Typed metavariables only match a metavariable if it’s declared as a specific type.

##### Java

For example, to look for calls to the `log` method on `Logger` objects.
A simple pattern for this purpose could use a metavariable for the Logger object.

```text
pattern: $LOGGER.log(...)
```

But if we are concerned about finding calls to the `Math.log()` method as well, we can use a typed metavariable to put a type constraint on the `$LOGGER` metavariable.

```text
pattern: (java.util.logging.Logger $LOGGER).log(...)
```

Alternatively, if we want to capture more logger types, for example custom logger types, we could instead add a constraint to the type of the argument in this method call instead.

```text
pattern: $LOGGER.log(java.util.logging.LogRecord $RECORD)
```

##### C

In this example in C, we want to capture all cases where something is compared to a char array.
We start with a simple pattern that looks for comparison between two variables.

```text
pattern: $X == $Y
```

We can then put a type constraint on one of the metavariables used in this pattern by turning it into a typed metavariable.

```text
pattern: $X == (char *$Y)
```

```c
int main() {
    char *a = "Hello";
    int b = 1;

    // Matched
    if (a == "world") {
        return 1;
    }

    // Not matched
    if (b == 2) {
        return -1;
    }

    return 0;
}
```

##### Go

The syntax for a typed metavariable in Go looks different from the syntax for Java.
In this Go example we look for calls to the `Open` function, but only on an object of the `zip.Reader` type.

```text
pattern: ($READER : *zip.Reader).Open($INPUT)
```

```go
func read_file() {

    reader, _ := zip.NewReader(readerat, 18276)

 // Matched
 reader.Open("data")

    dir := http.Dir("/")

 // Not matched
 f, err := dir.Open(c.Param("file"))
}
```

:::caution
For Go, Semgrep currently does not recognize the type of all variables that are declared on the same line. That is, the following will not take both `a` and `b` as `int`s: `var a, b = 1, 2`
:::

##### TypeScript

In this example, we want to look for uses of the DomSanitizer function.

```text
pattern: ($X: DomSanitizer).sanitize(...)
```

```typescript
constructor(
  private _activatedRoute: ActivatedRoute,
  private sanitizer: DomSanitizer,
) { }

ngOnInit() {
    // Not matched
    this.sanitizer.bypassSecurityTrustHtml(DOMPurify.sanitize(this._activatedRoute.snapshot.queryParams['q']))

    // Matched
    this.sanitizer.bypassSecurityTrustHtml(this.sanitizer.sanitize(this._activatedRoute.snapshot.queryParams['q']))
}
```

#### Using typed metavariables

Type inference applies to the entire file! One common way to use typed metavariables is to check for a function called on a specific type of object. For example, let's say you're looking for calls to a potentially unsafe logger in a class like this:

```
class Test {
    static Logger logger;

    public static void run_test(String input, int num) {
        logger.log("Running a test with " + input);

        test(input, Math.log(num));
    }
}
```

If you searched for `$X.log(...)`, you can also match `Math.log(num)`. Instead, you can search for `(Logger $X).log(...)` which gives you the call to `logger`. See the rule [`logger_search`](https://semgrep.dev/playground/s/lgAo).

:::caution
Since matching happens within a single file, this is only guaranteed to work for local variables and arguments. Additionally, Semgrep currently understands types on a shallow level. For example, if you have `int[] A`, it will not recognize `A[0]` as an integer. If you have a class with fields, you will not be able to use typechecking on field accesses, and it will not recognize the class’s field as the expected type. Literal types are understood to a limited extent. Expanded type support is under active development.
:::

### Ellipsis metavariables

You can combine ellipses and metavariables to match a sequence
of arguments and store the matched sequence in a metavariable.
For example the pattern `foo($...ARGS, 3, $...ARGS)` will
match:

```python
foo(1,2,3,1,2)
```

When referencing an ellipsis metavariable in a rule message or [metavariable-pattern](/writing-rules/rule-syntax#metavariable-pattern), include the ellipsis:

```yaml
- message: Call to foo($...ARGS)
```

### Anonymous metavariables

Anonymous metavariables are used to specify that a metavariable exists in the pattern you want to capture.

An anonymous metavariable always takes the form `$_`. Variables such as `$_1` or `$_2` are **not** anonymous. You can use more than one anonymous metavariable in a rule definition.

For example, if you want to specify that a function should **always** have 3 arguments, then you can use anonymous metavariables:

```yaml
- pattern: def function($_, $_, $_)
```

An anonymous metavariable does not produce any binding to the code it matched. This means it does not enforce that it matches the same code at each place it is used. The pattern:

```yaml
- pattern: def function($A, $B, $C)
```

is not equivalent to the former example, as `$A`, `$B`, and `$C` bind to the code that matched the pattern. You can then use `$A` or any other metavariable in your rule definition to specify that specific code. Anonymous metavariables cannot be used this way.

Anonymous metavariables also communicate to the reader that their values are not relevant, but rather their occurrence in the pattern.

### Metavariable unification

For search mode rules, metavariables with the same name are treated as the same metavariable within the `patterns` operator. This is called metavariable unification.

For taint mode rules, patterns defined **within** `pattern-sinks` and `pattern-sources` still unify. However, metavariable unification **between** `pattern-sinks` and `pattern-sources` is **not** enabled by default.

To enforce unification, set `taint_unify_mvars: true` under the rule `options` key. When `taint_unify_mvars: true` is set, a metavariable defined in `pattern-sinks` and `pattern-sources` with the same name is treated as the same metavariable. See [Metavariables, rule message, and unification](/writing-rules/data-flow/taint-mode#metavariables-rule-message-and-unification) for more information.

### Display matched metavariables in rule messages

Display values of matched metavariables in rule messages. Add a metavariable to the rule message (for example `Found $X`) and Semgrep replaces it with the value of the detected metavariable.

To display matched metavariable in a rule message, add the same metavariable as you are searching for in your rule to the rule message.

1. Find the metavariable used in the Semgrep rule. See the following example of a part Semgrep rule (formula):

   ```yaml
   - pattern: $MODEL.set_password(…)
   ```

   This formula uses `$MODEL` as a metavariable.
2. Insert the metavariable to rule message:

   ```yaml
   - message: Setting a password on $MODEL
   ```

3. Use the formula displayed above against the following code:

   ```python
   user.set_password(new_password)
   ```

The resulting message is:

```txt
Setting a password on user
```

Run the following example in Semgrep Playground to see the message (click **Open in Editor**, and then **Run**, unroll the **1 Match** to see the message):

<iframe
  title="Metavariable value in message example"
  src="https://semgrep.dev/embed/editor?snippet=6KpK"
  width="100%"
  height="432"
  frameborder="0"
></iframe>

:::info
If you're using Semgrep's advanced dataflow features, see documentation of experimental feature [Displaying propagated value of metavariable](/writing-rules/experiments/display-propagated-metavariable).
:::

## Equivalences

Semgrep automatically searches for code that is semantically equivalent.

### Imports

Equivalent imports using aliasing or submodules are matched.

The pattern `subprocess.Popen(...)` matches:

```python
import subprocess.Popen as sub_popen
sub_popen('ls')
```

The pattern `foo.bar.baz.qux(...)` matches:

```python
from foo.bar import baz
baz.qux()
```

### Constants

Semgrep performs constant propagation.

The pattern `set_password("password")` matches:

```python
HARDCODED_PASSWORD = "password"

def update_system():
    set_password(HARDCODED_PASSWORD)
```

Basic constant propagation support like in the example above is a stable feature.
Experimentally, Semgrep also supports [intra-procedural flow-sensitive constant propagation](/writing-rules/data-flow/constant-propagation).

The pattern `set_password("...")` also matches:

```python
def update_system():
    if cond():
        password = "abc"
    else:
        password = "123"
    set_password(password)
```

:::tip
It is possible to disable constant propagation in a per-rule basis via the [`options` rule field](/writing-rules/rule-syntax#options).
:::

### Associative and commutative operators

Semgrep performs associative-commutative (AC) matching. For example, `... && B && C` will match both `B && C` and `(A && B) && C` (i.e., `&&` is associative). Also, `A | B | C` will match `A | B | C`, and `B | C | A`, and `C | B | A`, and any other permutation (i.e., `|` is associative and commutative).

Under AC-matching metavariables behave similarly to `...`. For example, `A | $X` can match `A | B | C` in four different ways (`$X` can bind to `B`, or `C`, or `B | C`). In order to avoid a combinatorial explosion, Semgrep will only perform AC-matching with metavariables if the number of potential matches is _small_, otherwise it will produce just one match (if possible) where each metavariable is bound to a single operand.

Using [`options`](/writing-rules/rule-syntax#options) it is possible to entirely disable AC-matching. It is also possible to treat Boolean AND and OR operators (e.g., `&&` in `||` in C-family languages) as commutative, which can be useful despite not being semantically accurate.

## Deep expression operator

Use the deep expression operator `<... [your_pattern] ...>` to match an expression that could be deeply nested within another expression. An example is looking for a pattern anywhere within an `if` statement. The deep expression operator matches your pattern in the current expression context and recursively in any subexpressions.

For example, this pattern:

```yaml
pattern: |
  if <... $USER.is_admin() ...>:
    ...
```

matches:

```python
if user.authenticated() and user.is_admin() and user.has_group(gid):
  [ CONDITIONAL BODY ]
```

The deep expression operator works in:

- `if` statements: `if <... $X ...>:`
- nested calls: `sql.query(<... $X ...>)`
- operands of a binary expression: `"..." + <... $X ...>`
- any other expression context

## Limitations

### Statements types

Semgrep handles some statement types differently than others, particularly when searching for fragments inside statements. For example, the pattern `foo` will match these statements:

```python
x += foo()
return bar + foo
foo(1, 2)
```

But `foo` will not match the following statement (`import foo` will match it though):

```python
import foo
```

#### Statements as expressions

Many programming languages differentiate between expressions and statements. Expressions can appear inside if conditions, in function call arguments, etc. Statements can not appear everywhere; they are sequence of operations (in many languages using `;` as a separator/terminator) or special control flow constructs (if, while, etc.).

`foo()` is an expression (in most languages).

`foo();` is a statement (in most languages).

If your search pattern is a statement, Semgrep will automatically try to search for it as _both_ an expression and a statement.

When you write the expression `foo()` in a pattern, Semgrep will visit every expression and sub-expression in your program and try to find a match.

Many programmers don't really see the difference between `foo()` and `foo();`. This is why when one looks for `foo()`; Semgrep thinks the user wants to match statements like `a = foo();`, or `print(foo());`.

:::info
Note that in some programming languages such as Python, which does not use semicolons as a separator or terminator, the difference between expressions and statements is even more confusing. Indentation in Python matters, and a newline after `foo()` is really the same than `foo();` in other programming languages such as C.
:::

### Partial expressions

Partial expressions are not valid patterns. For example, the following is invalid:

```text
pattern: 1+
```

A complete expression is needed (like `1 + $X`)

### Ellipses and statement blocks

The [ellipsis operator](#ellipsis-operator) does _not_ jump from inner to outer statement blocks.

For example, this pattern:

```text
foo()
...
bar()
```

matches:

```python
foo()
baz()
bar()
```

and also matches:

```python
foo()
baz()
if cond:
    bar()
```

but it does _not_ match:

```python
if cond:
    foo()
baz()
bar()
```

because `...` cannot jump from the inner block where `foo()` is, to the outer block where `bar()` is.

### Partial statements

Partial statements are partially supported. For example,
you can just match the header of a conditional with `if ($E)`,
or just the try part of an exception statement with `try { ... }`.

This is especially useful when used in a
[pattern-inside](/writing-rules/rule-syntax#pattern-inside) to restrict the
context in which to search for other things.

### Other partial constructs

It is possible to just match the header of a function (without its body),
for example `int foo(...)` to match just the header part of the
function `foo`. In the same way, you can just match a class header
(e.g., with `class $A`).

## Deprecated features

### String matching

:::warning
String matching has been deprecated. You should use [`metavariable-regex`](/writing-rules/rule-syntax#metavariable-regex) instead.
:::

Search string literals within code with [Perl Compatible Regular Expressions (PCRE)](https://learnxinyminutes.com/docs/pcre/).

The pattern `requests.get("=~/dev\./i")` matches:

```python
requests.get("api.dev.corp.com")  # Oops, development API left in
```

To search for specific strings, use the syntax `"=~/<regexp>/"`. Advanced regexp features are available, such as case-insensitive regexps with `'/i'` (e.g., `"=~/foo/i"`). Matching occurs anywhere in the string unless the regexp `^` anchor character is used: `"=~/^foo.*/"` checks if a string begins with `foo`.
````

### `private-rules.md`

````markdown
---
slug: private-rules
description: "Semgrep Code users can publish rules to the Semgrep Registry that are not visible to others outside their organization. This can be useful for organizations where rules may contain code-sensitive information or legal requirements prevent using a public registry."
tags:
  - Rule writing
---


import DeleteCustomRule from "/src/components/procedure/_delete-custom-rule.mdx"

# Private rules

Users of the [Team or Enterprise tier](https://semgrep.dev/pricing) of Semgrep Code can publish rules to the [Semgrep Registry](https://semgrep.dev/explore) as private rules that are not visible to others outside their organization. Maintaining the rules' privacy allows you the benefits of using the Semgrep Registry while keeping sensitive code or information internal.

## Creating private rules

Create private rules the same way you create other custom rules. Private rules are stored in Semgrep Registry but they are not visible outside your organization. The two sections below can help you to create and save your private rules.

:::info Prerequisite
[Team or Enterprise tier](https://semgrep.dev/pricing) of Semgrep Code.
:::

### Creating private rules through Semgrep AppSec Platform

To publish private rules through the Semgrep AppSec Platform:

1. Go to [Semgrep Editor](https://semgrep.dev/orgs/-/editor).
1. Click <i className="fa-solid fa-file-plus-minus inline_svg"></i> **Create New Rule**.
1. Choose one of the following:
    - Create a new rule and test code by clicking <i class="fa-solid fa-circle-plus"></i> **plus** icon, select **New rule**, and then click <i className="fa-solid fa-floppy-disk inline_svg"></i> **Save**.
    - In the <i class="fa-solid fa-server"></i> **Library** panel, select a rule from a category in **Semgrep Registry**. Click <i className="fa-solid fa-code-branch inline_svg"></i> **Fork**, modify the rule or test code, and then click <i className="fa-solid fa-floppy-disk inline_svg"></i> **Save**.
1. Click <i className="fa-solid fa-earth-americas inline_svg"></i> **Share**.
1. Click <i className="fa-solid fa-lock inline_svg"></i> **Private**.

Your private rule has been created and added to the Registry, visible only to logged in users of your organization. Its private status is reflected by the **Share** button displaying a <i className="fa-solid fa-lock inline_svg"></i> icon.

Private rules are stored in the folder with the same name as your Semgrep AppSec Platform organization.

### Creating private rules through the command line

To create private rules through the [Semgrep CLI](/getting-started/quickstart), :

1. Interactively login to Semgrep:

    ```sh
    semgrep login
    ```

1. Create your rule. For more information, see [Contributing rules](/contributing/contributing-to-semgrep-rules-repository) documentation.
1. Publish your rule from the command line with `semgrep publish` command followed by the path to your private rules:

    ```sh
    semgrep publish myrules/
    ```

If the rules are in the directory you publish from, you can use `semgrep publish .` to refer to the current directory. You must provide the directory specification.
If the directory contains test cases for the rules, Semgrep uploads them as well (see [testing Semgrep rules](/writing-rules/testing-rules)).

You can also change the visibility of the rules. For instance, to publish the rules as unlisted (which does not require authentication but will not be displayed in the public registry):

```sh
semgrep publish --visibility=unlisted myrules/
```

For more details, run `semgrep publish --help`.

## Viewing and using private rules

View your rule in the [editor](https://semgrep.dev/orgs/-/editor) under the folder corresponding to your organization name.

You can also find it in the [registry](https://semgrep.dev/explore) by searching for [organization-id].[rule-id]. For example: `r2c.test-rule-id`.

To enforce the rule on new scans, add the rule in the [registry](https://semgrep.dev/explore) to an existing policy.

## Automatically publishing rules

This section provides examples of how to automatically publish your private rules so they are accessible within your private organization. "Publishing" your private rules in this manner does not make them public. In the following examples, the private rules are stored in `private_rule_dir`, which is a subdirectory of the repository root. If your rules are in the root of your repository, you can replace the command with `semgrep publish --visibility=org_private .` to refer to the repository root. You must provide the directory specification.

The following sample of the GitHub Actions workflow publishes rules from a private Git repository after a merge to the `main`, `master`, or `develop` branches.

1. Make sure that `SEMGREP_APP_TOKEN` is defined in your GitHub project or organization's secrets.
2. Create the following file at `.github/workflows/semgrep-publish.yml`:

    ```yaml
    name: semgrep-publish

    on:
      push:
        branches:
        - main
        - master
        - develop

    jobs:
      publish:
        name: publish-private-semgrep-rules
        runs-on: ubuntu-latest
        container:
          image: semgrep/semgrep
        steps:
        - uses: actions/checkout@v4
        - name: publish private semgrep rules
          run: semgrep publish --visibility=org_private ./private_rule_dir
          env:
            SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
    ```

    A sample job for GitLab CI/CD:

    ```yaml
    semgrep-publish:
      image: semgrep/semgrep
      script: semgrep publish --visibility=org_private ./private_rule_dir

    rules:
      - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

    variables:
      SEMGREP_APP_TOKEN: $SEMGREP_APP_TOKEN
    ```

    Ensure that `SEMGREP_APP_TOKEN` is defined in your GitLab project's CI/CD variables.

## Deleting private rules

<DeleteCustomRule />

## Appendix

### Visibility of private rules

Private rules are only visible to logged-in members of your organization.

### Publishing a rule with the same rule ID

Rules have unique IDs. If you publish a rule with the same ID as an existing rule, the new rule overwrites the previous one.
````

### `rule-ideas.md`

````markdown
---
append_help_link: true
slug: rule-ideas
tags:
  - Rule writing
---

# Custom rule examples

Not sure what to write a rule for? Below are some common questions, ideas, and topics to spur your imagination. Happy hacking! 💡

## Use cases

### Automate code review comments

_Time to write this rule: **5 minutes**_

You can use Semgrep and its GitHub integration to [automate PR comments](/semgrep-appsec-platform/notifications) that you frequently make in code reviews. Writing a custom rule for the code pattern you want to target is usually straightforward. If you want to understand the Semgrep syntax, see the [documentation](/writing-rules/pattern-syntax) or try the [tutorial](https://semgrep.dev/learn).

![A reviewer writes a Semgrep rule and adds it to an organization-wide policy](/img/semgrep-ci.gif)
<br />
A reviewer writes a Semgrep rule and adds it to an organization-wide policy.

### Ban dangerous APIs

_Time to write this rule: **5 minutes**_

Semgrep can detect dangerous APIs in code. If integrated into CI/CD pipelines, you can use Semgrep to block merges or flag for review when someone adds such dangerous APIs to the code. For example, a rule that detects React's `dangerouslySetInnerHTML` looks like this.

<iframe src="https://semgrep.dev/embed/editor?snippet=zEXn" title="Ban dangerous APIs with Semgrep" width="100%" height="432px" frameBorder="0"></iframe>

### Exempting special cases of dangerous APIs

_Time to write this rule: **5 minutes**_

If you have a legitimate use case for a dangerous API, you can exempt a specific use of the API using a `nosemgrep` comment. The rule below checks for React's `dangerouslySetInnerHTML`, but the code is annotated with a `nosemgrep` comment. Semgrep will not detect this line. This allows Semgrep to continuously check for future uses of `dangerouslySetInnerHTML` while allowing for this specific use.

<iframe src="https://semgrep.dev/embed/editor?snippet=2B3r" title="Exempt special cases of dangerous APIs with Semgrep" width="100%" height="432px" frameBorder="0"></iframe>

### Detect tainted data flowing into a dangerous sink

_Time to write this rule: **5 minutes**_

Semgrep's [dataflow engine with support for taint tracking](/writing-rules/data-flow/data-flow-overview) can be used to detect when data flows from a user-provided value into a security-sensitive function.

This rule detects when a user of the ExpressJS framework passes user data into the `run()` method of a sandbox.

<iframe src="https://semgrep.dev/embed/editor?snippet=jEGP" title="ExpressJS dataflow to sandbox.run" width="100%" height="432px" frameBorder="0"></iframe>

### Detect security violations

_Time to write this rule: **5 minutes**_

Use Semgrep to flag specific uses of APIs too, not just their presence in code. We jokingly call these the "security off" buttons and make extensive use of Semgrep to detect them.

This rule detects when HTML auto escaping is explicitly disabled for a Django template.

<iframe src="https://semgrep.dev/embed/editor?snippet=9Yjy" title="Detect security violations in code with Semgrep" width="100%" height="432px" frameBorder="0"></iframe>

### Scan configuration files using JSON, YAML, or Generic pattern matching

_Time to write this rule: **10 minutes**_

Semgrep [natively supports JSON and YAML](../supported-languages.md) and can be used to write rules for configuration files. This rule checks for skipped TLS verification in Kubernetes clusters.

<iframe src="https://semgrep.dev/embed/editor?snippet=rEqJ" title="Match configuration files with Semgrep" width="100%" height="432px" frameBorder="0"></iframe>

The [Generic pattern matching](/writing-rules/generic-pattern-matching) mode is for languages and file formats that Semgrep does not natively support. For example, you can write rules for Dockerfiles using the generic mode. The Dockerfile rule below checks for invalid port numbers.

<iframe src="https://semgrep.dev/embed/editor?snippet=NGXN" title="Match Dockerfiles with Semgrep" width="100%" height="432px" frameBorder="0"></iframe>

### Enforce authentication patterns

_Time to write this rule: **15 minutes**_

If a project has a "correct" way of doing authentication, Semgrep can be used to enforce this so that authentication mishaps do not happen. In the example below, this Flask app requires an authentication decorator on all routes. The rule detects routes that are missing authentication decorators. If deployed in CI/CD pipelines, Semgrep can block undecorated routes or flag a security member for further investigation.

<iframe src="https://semgrep.dev/embed/editor?snippet=wEQd" title="Enforce authentication patterns in code with Semgrep" width="100%" height="432px" frameBorder="0"></iframe>

### Systematize project-specific coding patterns

_Time to write this rule: **10 minutes**_

Automate institutional knowledge using Semgrep. This has several benefits, including teaching new members about coding patterns in an automatic way and keeping a project up-to-date with coding patterns. If you keep coding guidelines in a document, converting these into Semgrep rules is a great way to free developers from having to remember all the guidelines.

In this example, a legacy API requires calling `verify_transaction(t)` before calling `make_transaction(t)`. The Semgrep rule below detects when these methods are not called correctly.

<iframe src="https://semgrep.dev/embed/editor?snippet=Nr3z" title="Systematize project-specific coding patterns with Semgrep" width="100%" height="432px" frameBorder="0"></iframe>

### Extract information with metavariables

_Time to write this rule: **15 minutes**_

Semgrep metavariables can be used as output in the `message` key. This can be used to extract and collate information about a codebase. Click through to [this example](https://semgrep.dev/s/ORpk) which extracts Java Spring routes. This can be used to quickly see all the exposed routes of an application.

### Burn down deprecated APIs

_Time to write this rule: **5 minutes**_

Semgrep can detect deprecated APIs just as easily as dangerous APIs. Identifying deprecated API calls can help an application migrate to current or future versions.

This rule example detects a function that is deprecated as of Django 4.0.

<iframe src="https://semgrep.dev/embed/editor?snippet=vEQ0" title="Burn down deprecated APIs with Semgrep" width="100%" height="432px" frameBorder="0"></iframe>

### Promote secure alternatives

_Time to write this rule: **5 minutes**_

Some libraries or APIs have safe alternatives, such as [Google's `re2`](https://github.com/google/re2), an implementation of the standard `re` interface that ships with Python that is resistant to regular expression denial-of-service. This rule detects the use of `re` and recommends `re2` as a safe alternative with the same interface.

<iframe src="https://semgrep.dev/embed/editor?snippet=ZoA4" title="Promote secure alternatives with Semgrep" width="100%" height="432px" frameBorder="0"></iframe>

## Prompts for writing custom rules

Try answering these questions to uncover important rules for your project.

1. From recent post-mortems: what code issues contributed to it?
1. [XYZ] is a (security, performance, other) library that everyone should use, but they don’t consistently.
1. When you review code, what changes do you frequently ask for?
1. What vulnerability classes from bug bounty submissions reoccur (or appear in different places of the codebase)?
1. Are there engineering or performance patterns? Consistent exception handlers?
1. What issues were caused by misconfigurations in Infrastructure-as-Code files (JSON)?
1. What are some “invariants” that should hold about your code - things that should always or never be true (e.g. every admin route checks if user is admin)?
1. What methods/APIs are deprecated and you’re trying to move away from?
````

### `rule-syntax.md`

````markdown
---
append_help_link: true
slug: rule-syntax
description: "This document describes the YAML rule syntax of Semgrep including required and optional fields. Just getting started with Semgrep rule writing? Check out the Semgrep Tutorial at https://semgrep.dev/learn"
tags:
  - Rule writing
---

# Rule syntax

:::tip
Getting started with rule writing? Try the [Semgrep Tutorial](https://semgrep.dev/learn) 🎓
:::

This document describes the YAML rule syntax of Semgrep.

## Schema

### Required

<RequiredRuleFields />

#### Language extensions and languages key values

<LanguageExtensionsLanguagesKeyValues />

### Optional

| Field                                         | Type     | Description                                                                           |
| :-------------------------------------------- | :------- | :------------------------------------------------------------------------------------ |
| [`options`](#options)                         | `object` | Options object to enable/disable certain matching features                            |
| [`fix`](#fix)                                 | `object` | Simple search-and-replace autofix functionality                                       |
| [`metadata`](#metadata)                       | `object` | Arbitrary user-provided data; attach data to rules without affecting Semgrep behavior |
| [`min-version`](#min-version-and-max-version) | `string` | Minimum Semgrep version compatible with this rule                                     |
| [`max-version`](#min-version-and-max-version) | `string` | Maximum Semgrep version compatible with this rule                                     |
| [`paths`](#paths)                             | `object` | Paths to include or exclude when running this rule                                    |

The below optional fields must reside underneath a `patterns` or `pattern-either` field.

| Field                               | Type     | Description                                |
| :---------------------------------- | :------- | :----------------------------------------- |
| [`pattern-inside`](#pattern-inside) | `string` | Keep findings that lie inside this pattern |

The below optional fields must reside underneath a `patterns` field.

| Field                                                 | Type     | Description                                                                                                                                            |
| :---------------------------------------------------- | :------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`metavariable-regex`](#metavariable-regex)           | `map`    | Search metavariables for [Python `re`](https://docs.python.org/3/library/re.html#re.match) compatible expressions; regex matching is **left anchored** |
| [`metavariable-pattern`](#metavariable-pattern)       | `map`    | Matches metavariables with a pattern formula                                                                                                           |
| [`metavariable-comparison`](#metavariable-comparison) | `map`    | Compare metavariables against basic [Python expressions](https://docs.python.org/3/reference/expressions.html#comparisons)                             |
| [`pattern-not`](#pattern-not)                         | `string` | Logical NOT - remove findings matching this expression                                                                                                 |
| [`pattern-not-inside`](#pattern-not-inside)           | `string` | Keep findings that do not lie inside this pattern                                                                                                      |
| [`pattern-not-regex`](#pattern-not-regex)             | `string` | Filter results using a [PCRE2](https://www.pcre.org/current/doc/html/pcre2pattern.html)-compatible pattern in multiline mode                           |

## Operators

### `pattern`

The `pattern` operator looks for code matching its expression. This can be basic expressions like `$X == $X` or unwanted function calls like `hashlib.md5(...)`.

```yaml
rules:
  - id: md5-usage
    languages:
      - python
    message: Found md5 usage
    pattern: hashlib.md5(...)
    severity: ERROR
```

The pattern immediately above matches the following:

```python
import hashlib
# ruleid: md5-usage
# highlight-next-line
digest = hashlib.md5(b"test")
# ok: md5-usage
digest = hashlib.sha256(b"test")
```

### `patterns`

The `patterns` operator performs a logical AND operation on one or more child patterns. This is useful for chaining multiple patterns together that all must be true.

```yaml
rules:
  - id: unverified-db-query
    patterns:
      - pattern: db_query(...)
      - pattern-not: db_query(..., verify=True, ...)
    message: Found unverified db query
    severity: ERROR
    languages:
      - python
```

The pattern immediately above matches the following:

```python
# ruleid: unverified-db-query
# highlight-next-line
db_query("SELECT * FROM ...")
# ok: unverified-db-query
db_query("SELECT * FROM ...", verify=True, env="prod")
```

#### `patterns` operator evaluation strategy

Note that the order in which the child patterns are declared in a `patterns` operator has no effect on the final result. A `patterns` operator is always evaluated in the same way:

1. Semgrep evaluates all _positive_ patterns, that is [`pattern-inside`](#pattern-inside)s, [`pattern`](#pattern)s, [`pattern-regex`](#pattern-regex)es, and [`pattern-either`](#pattern-either)s. Each range matched by each one of these patterns is intersected with the ranges matched by the other operators. The result is a set of _positive_ ranges. The positive ranges carry _metavariable bindings_. For example, in one range `$X` can be bound to the function call `foo()`, and in another range `$X` can be bound to the expression `a + b`.
2. Semgrep evaluates all _negative_ patterns, that is [`pattern-not-inside`](#pattern-not-inside)s, [`pattern-not`](#pattern-not)s, and [`pattern-not-regex`](#pattern-not-regex)es. This gives a set of _negative ranges_ which are used to filter the positive ranges. This results in a strict subset of the positive ranges computed in the previous step.
3. Semgrep evaluates all _conditionals_, that is [`metavariable-regex`](#metavariable-regex)es, [`metavariable-pattern`](#metavariable-pattern)s and [`metavariable-comparison`](#metavariable-comparison)s. These conditional operators can only examine the metavariables bound in the positive ranges in step 1, that passed through the filter of negative patterns in step 2. Note that metavariables bound by negative patterns are _not_ available here.
4. Semgrep applies all [`focus-metavariable`](#focus-metavariable)s, by computing the intersection of each positive range with the range of the metavariable on which we want to focus. Again, the only metavariables available to focus on are those bound by positive patterns.

<!-- TODO: Add example to illustrate all of the above -->

### `pattern-either`

The `pattern-either` operator performs a logical OR operation on one or more child patterns. This is useful for chaining multiple patterns together where any may be true.

```yaml
rules:
  - id: insecure-crypto-usage
    pattern-either:
      - pattern: hashlib.sha1(...)
      - pattern: hashlib.md5(...)
    message: Found insecure crypto usage
    languages:
      - python
    severity: ERROR
```

The pattern immediately above matches the following:

```python
import hashlib
# ruleid: insecure-crypto-usage
# highlight-next-line
digest = hashlib.md5(b"test")
# ruleid: insecure-crypto-usage
# highlight-next-line
digest = hashlib.sha1(b"test")
# ok: insecure-crypto-usage
digest = hashlib.sha256(b"test")
```

This rule looks for usage of the Python standard library functions `hashlib.md5` or `hashlib.sha1`. Depending on their usage, these hashing functions are [considered insecure](https://shattered.io/).

### `pattern-regex`

The `pattern-regex` operator searches files for substrings matching the given [PCRE2](https://www.pcre.org/current/doc/html/pcre2pattern.html) pattern. This is useful for migrating existing regular expression code search functionality to Semgrep. Perl-Compatible Regular Expressions (PCRE) is a full-featured regex library that is widely compatible with Perl, but also with the respective regex libraries of Python, JavaScript, Go, Ruby, and Java. Patterns are compiled in multiline mode, for example `^` and `$` matches at the beginning and end of lines respectively in addition to the beginning and end of input.

:::caution
PCRE2 supports [some Unicode character properties, but not some Perl properties](https://www.pcre.org/current/doc/html/pcre2pattern.html#uniextseq). For example, `\p{Egyptian_Hieroglyphs}` is supported but `\p{InMusicalSymbols}` isn't.
:::

#### Example: `pattern-regex` combined with other pattern operators

```yaml
rules:
  - id: boto-client-ip
    patterns:
      - pattern-inside: boto3.client(host="...")
      - pattern-regex: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
    message: boto client using IP address
    languages:
      - python
    severity: ERROR
```

The pattern immediately above matches the following:

```python
import boto3
# ruleid: boto-client-ip
# highlight-next-line
client = boto3.client(host="192.168.1.200")
# ok: boto-client-ip
client = boto3.client(host="dev.internal.example.com")
```

#### Example: `pattern-regex` used as a standalone, top-level operator

```yaml
rules:
  - id: legacy-eval-search
    pattern-regex: eval\(
    message: Insecure code execution
    languages:
      - javascript
    severity: ERROR
```

The pattern immediately above matches the following:

```python
# ruleid: legacy-eval-search
# highlight-next-line
eval('var a = 5')
```

:::info
Single (`'`) and double (`"`) quotes [behave differently](https://docs.octoprint.org/en/master/configuration/yaml.html#scalars) in YAML syntax. Single quotes are typically preferred when using backslashes (`\`) with `pattern-regex`.
:::

Note that you may bind a section of a regular expression to a metavariable, by using [named capturing groups](https://www.regular-expressions.info/named.html). In
this case, the name of the capturing group must be a valid metavariable name.

```yaml
rules:
  - id: my_pattern_id-copy
    patterns:
      - pattern-regex: a(?P<FIRST>.*)b(?P<SECOND>.*)
    message: Semgrep found a match, with $FIRST and $SECOND
    languages:
      - regex
    severity: WARNING
```

The pattern immediately above matches the following:

```python
# highlight-next-line
acbd
```

### `pattern-not-regex`

The `pattern-not-regex` operator filters results using a [PCRE2](https://www.pcre.org/current/doc/html/pcre2pattern.html) regular expression in multiline mode. This is most useful when combined with regular-expression only rules, providing an easy way to filter findings without having to use negative lookaheads. `pattern-not-regex` works with regular `pattern` clauses, too.

The syntax for this operator is the same as `pattern-regex`.

This operator filters findings that have _any overlap_ with the supplied regular expression. For example, if you use `pattern-regex` to detect `Foo==1.1.1` and it also detects `Foo-Bar==3.0.8` and `Bar-Foo==3.0.8`, you can use `pattern-not-regex` to filter the unwanted findings.

```yaml
rules:
  - id: detect-only-foo-package
    languages:
      - regex
    message: Found foo package
    patterns:
      - pattern-regex: foo
      - pattern-not-regex: foo-
      - pattern-not-regex: -foo
    severity: ERROR
```

The pattern immediately above matches the following:

```python
# ruleid: detect-only-foo-package
# highlight-next-line
foo==1.1.1
# ok: detect-only-foo-package
foo-bar==3.0.8
# ok: detect-only-foo-package
bar-foo==3.0.8
```

### `focus-metavariable`

The `focus-metavariable` operator puts the focus, or _zooms in_, on the code region matched by a single metavariable or a list of metavariables. For example, to find all functions arguments annotated with the type `bad` you may write the following pattern:

```yaml
pattern: |
  def $FUNC(..., $ARG : bad, ...):
    ...
```

This works but it matches the entire function definition. Sometimes, this is not desirable. If the definition spans hundreds of lines they are all matched. In particular, if you are using [Semgrep AppSec Platform](https://semgrep.dev/login) and you have triaged a finding generated by this pattern, the same finding shows up again as new if you make any change to the definition of the function!

To specify that you are only interested in the code matched by a particular metavariable, in our example `$ARG`, use `focus-metavariable`.

```yaml
rules:
  - id: find-bad-args
    patterns:
      - pattern: |
          def $FUNC(..., $ARG : bad, ...):
            ...
      - focus-metavariable: $ARG
    message: |
      `$ARG' has a "bad" type!
    languages:
      - python
    severity: WARNING
```

The pattern immediately above matches the following:

```python
# highlight-next-line
def f(x : bad):
    return x
```

Note that `focus-metavariable: $ARG` is not the same as `pattern: $ARG`! Using `pattern: $ARG` finds all the uses of the parameter `x` which is not what we want! (Note that `pattern: $ARG` does not match the formal parameter declaration, because in this context `$ARG` only matches expressions.)

```yaml
rules:
  - id: find-bad-args
    patterns:
      - pattern: |
          def $FUNC(..., $ARG : bad, ...):
            ...
      - pattern: $ARG
    message: |
      `$ARG' has a "bad" type!
    languages:
      - python
    severity: WARNING
```

The pattern immediately above matches the following:

```python
def f(x : bad):
# highlight-next-line
    return x
```

In short, `focus-metavariable: $X` is not a pattern in itself, it does not perform any matching, it only focuses the matching on the code already bound to `$X` by other patterns. Whereas `pattern: $X` matches `$X` against your code (and in this context, `$X` only matches expressions)!

#### Including multiple focus metavariables using set intersection semantics

Include more `focus-metavariable` keys with different metavariables under the `pattern` to match results **only** for the overlapping region of all the focused code:

```yaml
    patterns:
      - pattern: foo($X, ..., $Y)
      - focus-metavariable:
        - $X
        - $Y
```

```yaml
rules:
  - id: intersect-focus-metavariable
    patterns:
      - pattern-inside: foo($X, ...)
      - focus-metavariable: $X
      - pattern: $Y + ...
      - focus-metavariable: $Y
      - pattern: "1"
    message: Like set intersection, only the overlapping region is highlighted
    languages:
      - python
    severity: ERROR
```

The pattern immediately above matches the following:

```python
# ruleid: intersect-focus-metavariable
foo (
# highlight-next-line
    1
    +
    2,
    1
)

# OK: test
foo (2+ 1, 1)
```

:::info
To make a list of multiple focus metavariables using set union semantics that matches the metavariables regardless of their position in code, see [Including multiple focus metavariables using set union semantics](/writing-rules/experiments/multiple-focus-metavariables) documentation.
:::

### `metavariable-regex`

The `metavariable-regex` operator searches metavariables for a [PCRE2](https://www.pcre.org/current/doc/html/pcre2pattern.html) regular expression. This is useful for filtering results based on a [metavariable’s](pattern-syntax.mdx#metavariables) value. It requires the `metavariable` and `regex` keys and can be combined with other pattern operators.

```yaml
rules:
  - id: insecure-methods
    patterns:
      - pattern: module.$METHOD(...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: (insecure)
    message: module using insecure method call
    languages:
      - python
    severity: ERROR
```

The pattern immediately above matches the following:

```python
# ruleid: insecure-methods
# highlight-next-line
module.insecure1("test")
# ruleid: insecure-methods
# highlight-next-line
module.insecure2("test")
# ruleid: insecure-methods
# highlight-next-line
module.insecure3("test")
# ok: insecure-methods
module.secure("test")
```

Regex matching is **left anchored**. To allow prefixes, use `.*` at the beginning of the regex. To match the end of a string, use `$`. The next example, using the same expression as above but anchored on the right, finds no matches:

```yaml
rules:
  - id: insecure-methods
    patterns:
      - pattern: module.$METHOD(...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: (insecure$)
    message: module using insecure method call
    languages:
      - python
    severity: ERROR
```

The following example matches all of the function calls in the same code sample, returning a false positive on the `module.secure` call:

```yaml
rules:
  - id: insecure-methods
    patterns:
      - pattern: module.$METHOD(...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: (.*secure)
    message: module using insecure method call
    languages:
      - python
    severity: ERROR
```

:::info
Include quotes in your regular expression when using `metavariable-regex` to search string literals. For more details, see [include-quotes](https://semgrep.dev/playground/s/EbDB) code snippet.
:::

### `metavariable-pattern`

The `metavariable-pattern` operator matches metavariables with a pattern formula. This is useful for filtering results based on a [metavariable’s](pattern-syntax.mdx#metavariables) value. It requires the `metavariable` key, and exactly one key of `pattern`, `patterns`, `pattern-either`, or `pattern-regex`. This operator can be nested as well as combined with other operators.

For example, the `metavariable-pattern` can be used to filter out matches that do **not** match certain criteria:

```yaml
rules:
  - id: disallow-old-tls-versions2
    languages:
      - javascript
    message: Match found
    patterns:
      - pattern: |
          $CONST = require('crypto');
          ...
          $OPTIONS = $OPTS;
          ...
          https.createServer($OPTIONS, ...);
      - metavariable-pattern:
          metavariable: $OPTS
          patterns:
            - pattern-not: >
                {secureOptions: $CONST.SSL_OP_NO_SSLv2 | $CONST.SSL_OP_NO_SSLv3
                | $CONST.SSL_OP_NO_TLSv1}
    severity: WARNING
```

The pattern immediately above matches the following:

```python
function bad() {
    // ruleid:disallow-old-tls-versions2
    # highlight-next-line
    var constants = require('crypto');
    # highlight-next-line
    var sslOptions = {
    # highlight-next-line
    key: fs.readFileSync('/etc/ssl/private/private.key'),
    # highlight-next-line
    secureProtocol: 'SSLv23_server_method',
    # highlight-next-line
    secureOptions: constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SSLv3
    # highlight-next-line
    };
    # highlight-next-line
    https.createServer(sslOptions);
}
```

:::info
In this case it is possible to start a `patterns` AND operation with a `pattern-not`, because there is an implicit `pattern: ...` that matches the content of the metavariable.
:::

The `metavariable-pattern` is also useful in combination with `pattern-either`:

```yaml
rules:
  - id: open-redirect
    languages:
      - python
    message: Match found
    patterns:
      - pattern-inside: |
          def $FUNC(...):
            ...
            return django.http.HttpResponseRedirect(..., $DATA, ...)
      - metavariable-pattern:
          metavariable: $DATA
          patterns:
            - pattern-either:
                - pattern: $REQUEST
                - pattern: $STR.format(..., $REQUEST, ...)
                - pattern: $STR % $REQUEST
                - pattern: $STR + $REQUEST
                - pattern: f"...{$REQUEST}..."
            - metavariable-pattern:
                metavariable: $REQUEST
                patterns:
                  - pattern-either:
                      - pattern: request.$W
                      - pattern: request.$W.get(...)
                      - pattern: request.$W(...)
                      - pattern: request.$W[...]
                  - metavariable-regex:
                      metavariable: $W
                      regex: (?!get_full_path)
    severity: WARNING
```

The pattern immediately above matches the following:

```python
from django.http import HttpResponseRedirect
# highlight-next-line
def unsafe(request):
    # ruleid:open-redirect
    # highlight-next-line
    return HttpResponseRedirect(request.POST.get("url"))
```

:::tip
It is possible to nest `metavariable-pattern` inside `metavariable-pattern`!
:::

:::info
The metavariable should be bound to an expression, a statement, or a list of statements, for this test to be meaningful. A metavariable bound to a list of function arguments, a type, or a pattern, always evaluate to false.
:::

#### `metavariable-pattern` with nested language

If the metavariable’s content is a string, then it is possible to use `metavariable-pattern` to match this string as code by specifying the target language via the `language` key. See the following examples of `metavariable-pattern`:

:::note Examples of `metavariable-pattern`

- Match JavaScript code inside HTML in the following [Semgrep Playground](https://semgrep.dev/s/z95k) example.
- Filter regex matches in the following [Semgrep Playground](https://semgrep.dev/s/pkNk) example.
:::

#### Example: Match JavaScript code inside HTML

```yaml
rules:
  - id: test
    languages:
      - generic
    message: javascript inside html working!
    patterns:
      - pattern: |
          <script ...>$...JS</script>
      - metavariable-pattern:
          language: javascript
          metavariable: $...JS
          patterns:
            - pattern: |
                console.log(...)
    severity: WARNING

```

The pattern immediately above matches the following:

```python
<!-- ruleid:test -->
# highlight-next-line
<script>
# highlight-next-line
console.log("hello")
# highlight-next-line
</script>
```

#### Example: Filter regex matches

```yaml
rules:
  - id: test
    languages:
      - generic
    message: "Google dependency: $1 $2"
    patterns:
      - pattern-regex: gem "(.*)", "(.*)"
      - metavariable-pattern:
          metavariable: $1
          language: generic
          patterns:
            - pattern: google
    severity: INFO
```

The pattern immediately above matches the following:

```python
# highlight-next-line
source "https://rubygems.org"

#OK:test
gem "functions_framework", "~> 0.7"
#ruleid:test
# highlight-next-line
gem "google-cloud-storage", "~> 1.29"
```

### `metavariable-comparison`

The `metavariable-comparison` operator compares metavariables against a basic [Python comparison](https://docs.python.org/3/reference/expressions.html#comparisons) expression. This is useful for filtering results based on a [metavariable’s](/writing-rules/pattern-syntax/#metavariables) numeric value.

The `metavariable-comparison` operator is a mapping which requires the `metavariable` and `comparison` keys. It can be combined with other pattern operators in the following [Semgrep Playground](https://semgrep.dev/s/GWv6) example.

This matches code such as `set_port(80)` or `set_port(443)`, but not `set_port(8080)`.

Comparison expressions support simple arithmetic as well as composition with [Boolean operators](https://docs.python.org/3/reference/expressions.html#boolean-operations) to allow for more complex matching. This is particularly useful for checking that metavariables are divisible by particular values, such as enforcing that a particular value is even or odd.

```yaml
rules:
  - id: superuser-port
    languages:
      - python
    message: module setting superuser port
    patterns:
      - pattern: set_port($ARG)
      - metavariable-comparison:
          comparison: $ARG < 1024 and $ARG % 2 == 0
          metavariable: $ARG
    severity: ERROR
```

The pattern immediately above matches the following:

```python
# ok: superuser-port
set_port(443)
# ruleid: superuser-port
# highlight-next-line
set_port(80)
# ok: superuser-port
set_port(8080)
```

Building on the previous example, this still matches code such as `set_port(80)` but it no longer matches `set_port(443)` or `set_port(8080)`.

The `comparison` key accepts Python expression using:

- Boolean, string, integer, and float literals.
- Boolean operators `not`, `or`, and `and`.
- Arithmetic operators `+`, `-`, `*`, `/`, and `%`.
- Comparison operators `==`, `!=`, `<`, `<=`, `>`, and `>=`.
- Function `int()` to convert strings into integers.
- Function `str()` to convert numbers into strings.
- Function `today()` that gets today's date as a float representing epoch time.
- Function `strptime()` that converts strings in the format `"yyyy-mm-dd"` to a float representing the date in epoch time.
- Lists, together with the `in`, and `not in` infix operators.
- Strings, together with the `in` and `not in` infix operators, for substring containment.
- Function `re.match()` to match a regular expression (without the optional `flags` argument).

You can use Semgrep metavariables such as `$MVAR`, which Semgrep evaluates as follows:

- If `$MVAR` binds to a literal, then that literal is the value assigned to `$MVAR`.
- If `$MVAR` binds to a code variable that is a constant, and constant propagation is enabled (as it is by default), then that constant is the value assigned to `$MVAR`.
- Otherwise the code bound to the `$MVAR` is kept unevaluated, and its string representation can be obtained using the `str()` function, as in `str($MVAR)`. For example, if `$MVAR` binds to the code variable `x`, `str($MVAR)` evaluates to the string literal `"x"`.

#### Legacy `metavariable-comparison` keys

:::info
You can avoid the use of the legacy keys described below (`base: int` and `strip: bool`) by using the `int()` function, as in `int($ARG) > 0o600` or `int($ARG) > 2147483647`.
:::

The `metavariable-comparison` operator also takes optional `base: int` and `strip: bool` keys. These keys set the integer base the metavariable value should be interpreted as and remove quotes from the metavariable value, respectively.

```yaml
rules:
  - id: excessive-permissions
    languages:
      - python
    message: module setting excessive permissions
    patterns:
      - pattern: set_permissions($ARG)
      - metavariable-comparison:
          comparison: $ARG > 0o600
          metavariable: $ARG
          base: 8
    severity: ERROR
```

The pattern immediately above matches the following:

```python
# ruleid: excessive-permissions
# highlight-next-line
set_permissions(0o700)
# ok: excessive-permissions
set_permissions(0o400)
```

This interprets metavariable values found in code as octal. As a result, Semgrep detects `0700`, but it does **not** detect `0400`.

```yaml
rules:
  - id: int-overflow
    languages:
      - python
    message: Potential integer overflow
    patterns:
      - pattern: int($ARG)
      - metavariable-comparison:
          strip: true
          comparison: $ARG > 2147483647
          metavariable: $ARG
    severity: ERROR
```

The pattern immediately above matches the following:

```python
# ruleid: int-overflow
# highlight-next-line
int("2147483648")
# ok: int-overflow
int("2147483646")
```

This removes quotes (`'`, `"`, and `` ` ``) from both ends of the metavariable content. As a result, Semgrep detects `"2147483648"`, but it does **not** detect `"2147483646"`. This is useful when you expect strings to contain integer or float data.

### `pattern-not`

The `pattern-not` operator is the opposite of the `pattern` operator. It finds code that does not match its expression. This is useful for eliminating common false positives.

```yaml
rules:
  - id: unverified-db-query
    patterns:
      - pattern: db_query(...)
      - pattern-not: db_query(..., verify=True, ...)
    message: Found unverified db query
    severity: ERROR
    languages:
      - python
```

The pattern immediately above matches the following:

```python
# ruleid: unverified-db-query
# highlight-next-line
db_query("SELECT * FROM ...")
# ok: unverified-db-query
db_query("SELECT * FROM ...", verify=True, env="prod")
```

### `pattern-inside`

The `pattern-inside` operator keeps matched findings that reside within its expression. This is useful for finding code inside other pieces of code like functions or if blocks.

```yaml
rules:
  - id: return-in-init
    patterns:
      - pattern: return ...
      - pattern-inside: |
          class $CLASS:
            ...
      - pattern-inside: |
          def __init__(...):
              ...
    message: return should never appear inside a class __init__ function
    languages:
      - python
    severity: ERROR
```

The pattern immediately above matches the following:

```python
class A:
    def __init__(self):
        # ruleid: return-in-init
        # highlight-next-line
        return None

class B:
    def __init__(self):
        # ok: return-in-init
        self.inited = True

def foo():
    # ok: return-in-init
    return 5
```

### `pattern-not-inside`

The `pattern-not-inside` operator keeps matched findings that do not reside within its expression. It is the opposite of `pattern-inside`. This is useful for finding code that’s missing a corresponding cleanup action like disconnect, close, or shutdown. It’s also useful for finding problematic code that isn't inside code that mitigates the issue.

```yaml
rules:
  - id: open-never-closed
    patterns:
      - pattern: $F = open(...)
      - pattern-not-inside: |
          $F = open(...)
          ...
          $F.close()
    message: file object opened without corresponding close
    languages:
      - python
    severity: ERROR
```

The pattern immediately above matches the following:

```python
def func1():
    # ruleid: open-never-closed
    # highlight-next-line
    fd = open('test.txt')
    results = fd.read()
    return results

def func2():
    # ok: open-never-closed
    fd = open('test.txt')
    results = fd.read()
    fd.close()
    return results
```

The above rule looks for files that are opened but never closed, possibly leading to resource exhaustion. It looks for the `open(...)` pattern _and not_ a following `close()` pattern.

The `$F` metavariable ensures that the same variable name is used in the `open` and `close` calls. The ellipsis operator allows for any arguments to be passed to `open` and any sequence of code statements in-between the `open` and `close` calls. The rule ignores how `open` is called or what happens up to a `close` call&mdash;it only needs to make sure `close` is called.

## Metavariable matching

Metavariable matching operates differently for logical AND (`patterns`) and logical OR (`pattern-either`) parent operators. Behavior is consistent across all child operators: `pattern`, `pattern-not`, `pattern-regex`, `pattern-inside`, `pattern-not-inside`.

### Metavariables in logical ANDs

Metavariable values must be identical across sub-patterns when performing logical AND operations with the `patterns` operator.

Example:

```yaml
rules:
  - id: function-args-to-open
    patterns:
      - pattern-inside: |
          def $F($X):
              ...
      - pattern: open($X)
    message: "Function argument passed to open() builtin"
    languages: [python]
    severity: ERROR
```

This rule matches the following code:

```python
def foo(path):
    open(path)
```

The example rule doesn’t match this code:

```python
def foo(path):
    open(something_else)
```

### Metavariables in logical ORs

Metavariable matching does not affect the matching of logical OR operations with the `pattern-either` operator.

Example:

```yaml
rules:
  - id: insecure-function-call
    pattern-either:
      - pattern: insecure_func1($X)
      - pattern: insecure_func2($X)
    message: "Insecure function use"
    languages: [python]
    severity: ERROR
```

The above rule matches both examples below:

```python
insecure_func1(something)
insecure_func2(something)
```

```python
insecure_func1(something)
insecure_func2(something_else)
```

### Metavariables in complex logic

Metavariable matching still affects subsequent logical ORs if the parent is a logical AND.

Example:

```yaml
patterns:
  - pattern-inside: |
      def $F($X):
        ...
  - pattern-either:
      - pattern: bar($X)
      - pattern: baz($X)
```

The above rule matches both examples below:

```python
def foo(something):
    bar(something)
```

```python
def foo(something):
    baz(something)
```

The example rule doesn’t match this code:

```python
def foo(something):
    bar(something_else)
```

## `options`

Enable, disable, or modify the following matching features:

<!-- Options are sorted alphabetically -->

| Option                        | Default | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| :---------------------------- | :------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ac_matching`                 | `true`  | [Matching modulo associativity and commutativity](/writing-rules/pattern-syntax.mdx#associative-and-commutative-operators), treat Boolean AND/OR as associative, and bitwise AND/OR/XOR as both associative and commutative.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `attr_expr`                   | `true`  | Expression patterns (for example: `f($X)`) matches attributes (for example: `@f(a)`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `commutative_boolop`          | `false` | Treat Boolean AND/OR as commutative even if not semantically accurate.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `constant_propagation`        | `true`  | [Constant propagation](/writing-rules/pattern-syntax/#constants), including [intra-procedural flow-sensitive constant propagation](/writing-rules/data-flow/constant-propagation).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `decorators_order_matters`    | `false` | Match non-keyword attributes (for example: decorators in Python) in order, instead of the order-agnostic default. Keyword attributes (for example: `static`, `inline`, etc) are not affected.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `generic_comment_style`       | none    | In generic mode, assume that comments follow the specified syntax. They are then ignored for matching purposes. Allowed values for comment styles are: <ul><li>`c` for traditional C-style comments (`/* ... */`). </li><li> `cpp` for modern C or C++ comments (`// ...` or `/* ... */`). </li><li> `shell` for shell-style comments (`# ...`). </li></ul> By default, the generic mode does not recognize any comments. Available since Semgrep version 0.96. For more information about generic mode, see [Generic pattern matching](/writing-rules/generic-pattern-matching) documentation.                                                                                                                                                                                            |
| `generic_ellipsis_max_span`   | `10`    | In generic mode, this is the maximum number of newlines that an ellipsis operator `...` can match or equivalently, the maximum number of lines covered by the match minus one. The default value is `10` (newlines) for performance reasons. Increase it with caution. Note that the same effect as `20` can be achieved without changing this setting and by writing `... ...` in the pattern instead of `...`. Setting it to `0` is useful with line-oriented languages (for example [INI](https://en.wikipedia.org/wiki/INI_file) or key-value pairs in general) to force a match to not extend to the next line of code. Available since Semgrep 0.96. For more information about generic mode, see [Generic pattern matching](/writing-rules/generic-pattern-matching) documentation. |
| `implicit_return`             | `true`  | Return statement patterns (for example `return $E`) match expressions that may be evaluated last in a function as if there was a return keyword in front of those expressions. Only applies to certain expression-based languages, such as Ruby and Julia.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `symmetric_eq`                | `false` | Treat equal operations as symmetric (for example: `a == b` is equal to `b == a`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `taint_assume_safe_functions` | `false` | Experimental option which will be subject to future changes. Used in taint analysis. Assume that function calls do **not** propagate taint from their arguments to their output. Otherwise, Semgrep always assumes that functions may propagate taint. Can replace **not-conflicting** sanitizers added in v0.69.0 in the future.                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `taint_assume_safe_indexes`   | `false` | Used in taint analysis. Assume that an array-access expression is safe even if the index expression is tainted. Otherwise Semgrep assumes that for example: `a[i]` is tainted if `i` is tainted, even if `a` is not. Enabling this option is recommended for high-signal rules, whereas disabling is preferred for audit rules. Currently, it is disabled by default to attain backwards compatibility, but this can change in the near future after some evaluation.                                                                                                                                                                                                                                                                                                                      |
| `vardef_assign`               | `true`  | Assignment patterns (for example `$X = $E`) match variable declarations (for example `var x = 1;`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `xml_attrs_implicit_ellipsis` | `true`  | Any XML/JSX/HTML element patterns have implicit ellipsis for attributes (for example: `<div />` matches `<div foo="1">`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

The full list of available options can be consulted in the [Semgrep matching engine configuration](https://github.com/semgrep/semgrep/blob/develop/interfaces/Rule_options.atd) module. Note that options not included in the table above are considered experimental, and they may change or be removed without notice.

## `fix`

The `fix` top-level key allows for simple autofixing of a pattern by suggesting an autofix for each match. Run `semgrep` with `--autofix` to apply the changes to the files.

Example:

```yaml
rules:
  - id: use-dict-get
    patterns:
      - pattern: $DICT[$KEY]
    fix: $DICT.get($KEY)
    message: "Use `.get()` method to avoid a KeyNotFound error"
    languages: [python]
    severity: ERROR
```

For more information about `fix` and `--autofix` see [Autofix](/writing-rules/autofix) documentation.

## `metadata`

Provide additional information for a rule with the `metadata:` key, such as a related CWE, likelihood, OWASP.

Example:

```yaml
rules:
  - id: eqeq-is-bad
    patterns:
      - [...]
    message: "useless comparison operation `$X == $X` or `$X != $X`"
    metadata:
      cve: CVE-2077-1234
      discovered-by: Ikwa L'equale
```

The metadata are also displayed in the output of Semgrep if you’re running it with `--json`.
Rules with `category: security` have additional metadata requirements. See [Including fields required by security category](/contributing/contributing-to-semgrep-rules-repository/#including-fields-required-by-security-category) for more information.

## `min-version` and `max-version`

Each rule supports optional fields `min-version` and `max-version` specifying
minimum and maximum Semgrep versions. If the Semgrep
version being used doesn't satisfy these constraints,
the rule is skipped without causing a fatal error.

Example rule:

```yaml
rules:
  - id: bad-goflags
    # earlier semgrep versions can't parse the pattern
    min-version: 1.31.0
    pattern: |
      ENV ... GOFLAGS='-tags=dynamic -buildvcs=false' ...
    languages: [dockerfile]
    message: "We should not use these flags"
    severity: WARNING
```

Another use case is when a newer version of a rule works better than
before but relies on a new feature. In this case, we could use
`min-version` and `max-version` to ensure that either the older or the
newer rule is used but not both. The rules would look like this:

```yaml
rules:
  - id: something-wrong-v1
    max-version: 1.72.999
    ...
  - id: something-wrong-v2
    min-version: 1.73.0
    # 10x faster than v1!
    ...
```

The `min-version`/`max-version` feature is available since Semgrep
1.38.0. It is intended primarily for publishing rules that rely on
newly released features without causing errors in older Semgrep
installations.

## `category`

Provide a category for users of the rule. For example: `best-practice`, `correctness`, `maintainability`. For more information, see [Semgrep registry rule requirements](/contributing/contributing-to-semgrep-rules-repository/#semgrep-registry-rule-requirements).

## `paths`

### Excluding a rule in paths

To ignore a specific rule on specific files, set the `paths:` key with one or more filters. Paths are relative to the root directory of the scanned project.

Example:

```yaml
rules:
  - id: eqeq-is-bad
    pattern: $X == $X
    paths:
      exclude:
        - "**/*.jinja2"
        - "*_test.go"
        - "project/tests"
        - project/static/*.js
```

When invoked with `semgrep -f rule.yaml project/`, the above rule runs on files inside `project/`, but no results are returned for:

- any file with a `.jinja2` file extension
- any file whose name ends in `_test.go`, such as `project/backend/server_test.go`
- any file inside `project/tests` or its subdirectories
- any file matching the `project/static/*.js` glob pattern

:::note
The glob syntax is from [Python's `wcmatch`](https://pypi.org/project/wcmatch/) and is used to match against the given file and all its parent directories.
:::

### Limiting a rule to paths

Conversely, to run a rule _only_ on specific files, set a `paths:` key with one or more of these filters:

```yaml
rules:
  - id: eqeq-is-bad
    pattern: $X == $X
    paths:
      include:
        - "*_test.go"
        - "project/server"
        - "project/schemata"
        - "project/static/*.js"
        - "tests/**/*.js"
```

When invoked with `semgrep -f rule.yaml project/`, this rule runs on files inside `project/`, but results are returned only for:

- files whose name ends in `_test.go`, such as `project/backend/server_test.go`
- files inside `project/server`, `project/schemata`, or their subdirectories
- files matching the `project/static/*.js` glob pattern
- all files with the `.js` extension, arbitrary depth inside the tests folder

If you are writing tests for your rules, add any test file or directory to the included paths as well.

:::note
When mixing inclusion and exclusion filters, the exclusion ones take precedence.
:::

Example:

```yaml
paths:
  include: "project/schemata"
  exclude: "*_internal.py"
```

The above rule returns results from `project/schemata/scan.py` but not from `project/schemata/scan_internal.py`.

## Other examples

This section contains more complex rules that perform advanced code searching.

### Complete useless comparison

```yaml
rules:
  - id: eqeq-is-bad
    patterns:
      - pattern-not-inside: |
          def __eq__(...):
              ...
      - pattern-not-inside: assert(...)
      - pattern-not-inside: assertTrue(...)
      - pattern-not-inside: assertFalse(...)
      - pattern-either:
          - pattern: $X == $X
          - pattern: $X != $X
          - patterns:
              - pattern-inside: |
                  def __init__(...):
                       ...
              - pattern: self.$X == self.$X
      - pattern-not: 1 == 1
    message: "useless comparison operation `$X == $X` or `$X != $X`"
```

The above rule makes use of many operators. It uses `pattern-either`, `patterns`, `pattern`, and `pattern-inside` to carefully consider different cases, and uses `pattern-not-inside` and `pattern-not` to whitelist certain useless comparisons.

## Full specification

The [full configuration-file format](https://github.com/semgrep/semgrep-interfaces/blob/main/rule_schema_v1.yaml) is defined as
a [jsonschema](http://json-schema.org/specification.html) object.
````

### `testing-rules.md`

````markdown
---
append_help_link: true
slug: testing-rules
description: "Semgrep provides a convenient testing mechanism for your rules. You can simply write code and provide a few annotations to let Semgrep know where you are or aren't expecting findings."
tags:
  - Rule writing
---

# Testing rules

Semgrep provides a convenient testing mechanism for your rules. You can simply write code and provide a few annotations to let Semgrep know where you are or aren't expecting findings. Semgrep provides the following annotations:

- `ruleid: <rule-id>`, for protecting against false negatives
- `ok: <rule-id>` for protecting against false positives
- `todoruleid: <rule-id>` for future "positive" rule improvements
- `todook: <rule-id>` for future "negative" rule improvements

Other than annotations there are three things to remember when creating tests:

1. The `--test` flag tells Semgrep to run tests in the specified directory.
2. Annotations are specified as a comment above the offending line.
3. Semgrep looks for tests based on the rule filename and the languages
   specified in the rule. In other words, `path/to/rule.yaml` searches for
   `path/to/rule.py`, `path/to/rule.js` and similar, based on the languages specified in the rule.

:::info
The `.test.yaml` file extension can also be used for test files. This is necessary when testing YAML language rules.
:::

## Testing autofix

Semgrep's testing mechanism also provides a way to test the behavior of any `fix` values defined in the rules.

To define a test for autofix behavior:

1. Create a new **autofix test file** with the `.fixed` suffix before the file type extension.
   For example, name the autofix test file of a rule with test code in `path/to/rule.py` as `path/to/rule.fixed.py`.
2. Within the autofix test file, enter the expected result of applied autofix rule to the test code.
3. Run `semgrep --test` to verify that your autofix test file is correctly detected.

When you use `semgrep --test`, Semgrep applies the autofix rule to the original test code (`path/to/rule.py`), and then verifies whether this matches the expected outcome defined in the autofix test file (`path/to/rule.fixed.py)`. If there is a mismatch, the line diffs are printed.

:::info
**Hint**: Creating an autofix test for a rule with autofix can take less than a minute with the following flow of commands:

```sh
cp rule.py rule.fixed.py
semgrep --config rule.yaml rule.fixed.py --autofix
```

These commands apply the autofix of the rule to the test code. After Semgrep delivers a fix, inspect whether the outcome of this fix looks as expected (for example using `vimdiff rule.py rule.fixed.py`).
:::

## Example

Consider the following rule:

```yaml
rules:
- id: insecure-eval-use
  patterns:
  - pattern: eval($VAR)
  - pattern-not: eval("...")
  fix: secure_eval($VAR)
  message: Calling 'eval' with user input
  languages: [python]
  severity: WARNING
```

Given the above is named `rules/detect-eval.yaml`, you can create `rules/detect-eval.py`:

```python
from lib import get_user_input, safe_get_user_input, secure_eval

user_input = get_user_input()
# ruleid: insecure-eval-use
eval(user_input)

# ok: insecure-eval-use
eval('print("Hardcoded eval")')

totally_safe_eval = eval
# todoruleid: insecure-eval-use
totally_safe_eval(user_input)

# todook: insecure-eval-use
eval(safe_get_user_input())
```

Run the tests with the following:

```sh
semgrep --test rules/
```

Which will produce the following output:

```sh
1/1: ✓ All tests passed
No tests for fixes found.
```

Semgrep tests automatically avoid failing on lines marked with `# todoruleid` or `# todook`.

## Storing rules and test targets in different directories

Creating different directories for rules and tests helps users manage a growing library of custom rules. To store rules and test targets in different directories use the `--config` option.

For example, in the directory with the following structure:

```sh
$ tree tests

tests
├── rules
│   └── python
│       └── insecure-eval-use.yaml
└── targets
    └── python
        └── insecure-eval-use.py

4 directories, 2 files
```

Use of the following command:

```sh
semgrep --test --config tests/rules/ tests/targets/
```

Produces the same output as in the previous example.

The subdirectory structure of these two directories must be the same for Semgrep to correctly find the associated files.

To test the autofix behavior, add the autofix test file `rules/detect-eval.fixed.py` to represent the expected outcome of applying the fix to the test code:

```python
from lib import get_user_input, safe_get_user_input, secure_eval

user_input = get_user_input()
# ruleid: insecure-eval-use
secure_eval(user_input)

# ok: insecure-eval-use
eval('print("Hardcoded eval")')

totally_safe_eval = eval
# todoruleid: insecure-eval-use
totally_safe_eval(user_input)

# todook: insecure-eval-use
secure_eval(safe_get_user_input())
```

So that the directory structure is printed as the following:

```sh
$ tree tests

tests
├── rules
│   └── python
│       └── insecure-eval-use.yaml
└── targets
    └── python
        └── insecure-eval-use.py
        └── insecure-eval-use.fixed.py

4 directories, 2 files
```

Use of the following command:

```sh
semgrep --test --config tests/rules/ tests/targets/
```

Results in the following outcome:

```sh
1/1: ✓ All tests passed
1/1: ✓ All fix tests passed
```

If the fix does not behave as expected, the output prints a line diff.
For example, if we replace `secure_eval` with `safe_eval`, we can see that lines 5 and 15 are not rendered as expected.

```sh
1/1: ✓ All tests passed
0/1: 1 fix tests did not pass:
--------------------------------------------------------------------------------
 ✖ targets/python/detect-eval.fixed.py <> autofix applied to targets/python/detect-eval.py

 ---
 +++
 @@ -5 +5 @@
 -safe_eval(user_input)
 +secure_eval(user_input)
 @@ -15 +15 @@
 -safe_eval(safe_get_user_input())
 +secure_eval(safe_get_user_input())

```

## Validating rules

At Semgrep, Inc., we believe in checking the code we write, and that includes rules.

You can run `semgrep --validate --config [filename]` to check the configuration. This command runs a combination of Semgrep rules and OCaml checks against your rules to search for issues such as duplicate patterns and missing fields. All rules submitted to the Semgrep Registry are validated.

The semgrep rules are pulled from `p/semgrep-rule-lints`.

This feature is still experimental and under active development. Your feedback is welcomed!

## Enabling autofix in Semgrep Code

<EnableAutofix />
````

### `data-flow\constant-propagation.md`

````markdown
---
slug: constant-propagation
append_help_link: true
description: >-
  Semgrep performs flow-sensitive constant folding and this information is used by the matching engine.
tags:
    - Rule writing
---

# Constant propagation

Semgrep supports intra-procedural constant propagation. This analysis tracks whether a variable _must_ carry a constant value at a given point in the program. Semgrep then performs constant folding when matching literal patterns. Semgrep can track Boolean, numeric, and string constants.

For example:

<iframe src="https://semgrep.dev/embed/editor?snippet=Gw7z" border="0" frameBorder="0" width="100%" height="432"></iframe>

## `metavariable-comparison`

Using constant propagation, the [`metavariable-comparison`](/writing-rules/rule-syntax/#metavariable-comparison) operator works with any constant variable, instead of just literals.

For example:

<iframe src="https://semgrep.dev/embed/editor?snippet=Dyzd" border="0" frameBorder="0" width="100%" height="432"></iframe>

## Mutable objects

In general, Semgrep assumes that constant objects are immutable and won't be modified by function calls. This may lead to false positives, especially in languages where strings are mutable such as C and Ruby.

The only exceptions are method calls whose returning value is ignored. In these cases, Semgrep assumes that the method call may be mutating the callee object. This helps reducing false positives in Ruby. For example:

<iframe src="https://semgrep.dev/embed/editor?snippet=08yB" border="0" frameBorder="0" width="100%" height="432"></iframe>

If constant propagation doesn't seem to work, consider whether the constant may be unexpectedly mutable. For example, given the following rule designed to taint the `REGEX` class variable:

```yaml
rules:
  - id: redos-detection
    message: Potential ReDoS vulnerability detected with $REGEX
    severity: ERROR
    languages:
      - java
    mode: taint
    options:
      symbolic_propagation: true
    pattern-sources:
      - patterns:
          - pattern: $REDOS
          - metavariable-analysis:
              analyzer: redos
              metavariable: $REDOS
    pattern-sinks:
      - pattern: Pattern.compile(...)
```

Semgrep fails to match its use in `Test2` when presented with the following code:

```java
import java.util.regex.Pattern;

public String REGEX = "(a+)+$";

public class Test2 {
    public static void main(String[] args) {
        Pattern pattern = Pattern.compile(REGEX);
    }
}
```

However, if you change the variable from `public` to `private`, Semgrep does return a match:

```java
import java.util.regex.Pattern;

private String REGEX = "(a+)+$";

public class Test2 {
    public static void main(String[] args) {
        Pattern pattern = Pattern.compile(REGEX);
    }
}
```

Because `REGEX` is public in the first code snippet, Semgrep doesn't propagate its value to other classes on the assumption that it could have mutated. However, in the second example, Semgrep understands that `REGEX` is private and is only assigned to once. Therefore, Semgrep assumes it to be immutable.

The rule would also work with:

```java
...
public final String REGEX = "(a+)+$";
...
```

## Disable constant propagation

You can disable constant propagation in a per-rule basis using rule [`options:`](/writing-rules/rule-syntax/#options) by setting `constant_propagation: false`.

<iframe src="https://semgrep.dev/embed/editor?snippet=jwvn" border="0" frameBorder="0" width="100%" height="432"></iframe>
````

### `data-flow\data-flow-overview.md`

````markdown
---
slug: data-flow-overview
append_help_link: true
description: >-
  Semgrep can run data-flow analyses on your code, this is used for constant propagation and for taint tracking.
sidebar_label: Engine overview
tags:
  - Rule writing
---

# Data-flow analysis engine overview

Semgrep provides an intra-procedural data-flow analysis engine that opens various Semgrep capabilities. Semgrep provides the following data-flow analyses:

- [Constant propagation](/writing-rules/data-flow/constant-propagation) allows Semgrep to, for example, match `return 42` against `return x` when `x` can be reduced to `42` by constant folding. There is also a specific experimental feature of [Constant propagation](/writing-rules/data-flow/constant-propagation), called [Symbolic propagation](/writing-rules/experiments/symbolic-propagation).
- [Taint tracking (known also as taint analysis)](/writing-rules/data-flow/taint-mode/) enables you to write simple rules that catch complex [injection bugs](https://owasp.org/www-community/Injection_Flaws), such as those that can result in [cross-site scripting (XSS)](https://owasp.org/www-community/attacks/xss/).

In principle, all data flow related features are available for any of Semgrep's [supported languages](/supported-languages). Interfile (cross-file) analysis also supports data-flow analysis. For more details, see [<i class="fa-regular fa-file-lines"></i> Perform cross-file analysis](/semgrep-code/semgrep-pro-engine-intro) documentation.

:::info
Ensure that you understand the [design trade-offs](#design-trade-offs) and limitations of the data-flow engine. For further details, see also the [data-flow status](#data-flow-status).
:::

Semgrep provides no user-friendly way of specifying a new data-flow analysis. Please [let us know if you have suggestions](https://github.com/semgrep/semgrep/issues/new/choose). If you can code in OCaml, your contribution is welcome. See [Contributing](/contributing/contributing) documentation for more details.

## Design trade-offs

Semgrep strives for simplicity and delivers a lightweight, and fast static analysis. In addition to being intra-procedural, here are some other trade-offs:

- No path sensitivity: All _potential_ execution paths are considered, despite that some may not be feasible.
- No pointer or shape analysis: _Aliasing_ that happens in non-trivial ways may not be detected, such as through arrays or pointers. Individual elements in arrays or other data structures are not tracked. The dataflow engine supports limited field sensitivity for taint tracking, but not yet for constant propagation.
- No soundness guarantees: Semgrep ignores the effects of `eval`-like functions on the program state. It doesn’t make worst-case sound assumptions, but rather "reasonable" ones.

Expect both false positives and false negatives. You can remove false positives in different ways, for example, using [pattern-not](/writing-rules/rule-syntax#pattern-not) and [pattern-not-inside](/writing-rules/rule-syntax#pattern-not-inside). We want to provide you with a way of eliminating false positives, so [create an issue](https://github.com/semgrep/semgrep/issues/new/choose) if run into any problems. We are happy to trade false negatives for simplicity and fewer false positives, but you are welcome to open a feature request if Semgrep misses some difficult bug you want to catch.

## Data-flow status

<DataFlowStatus />
````

### `data-flow\status.md`

````markdown
---
slug: status
append_help_link: true
tags:
    - Rule writing
description: >-
  The status of the data-flow analysis.
---

# Data-flow status

<DataFlowStatus />
````

### `data-flow\taint-mode.md`

````markdown
---
slug: taint-mode
append_help_link: true
tags:
    - Rule writing
description: >-
  Taint mode allows you to write simple rules that catch complex injection bugs thanks to taint analysis.
---

# Taint analysis

Semgrep supports [taint analysis](https://en.wikipedia.org/wiki/Taint_checking) (or taint tracking) through taint rules (specified by adding `mode: taint` to your rule). Taint analysis is a data-flow analysis that tracks the flow of untrusted, or **tainted** data throughout the body of a function or method. Tainted data originate from tainted **sources**. If tainted data is not transformed or checked accordingly (**sanitized**), taint analysis reports a finding whenever tainted data reach a vulnerable function, called a **sink**. Tainted data flow from sources to sinks through **propagators**, such as assignments, or function calls.

The following video provides a quick overview of taint mode:
<iframe class="yt_embed" width="100%" height="432px" src="https://www.youtube.com/embed/6MxMhFPkZlU" frameborder="0" allowfullscreen></iframe>

## Getting started

Taint tracking rules must specify `mode: taint`, which enables the following operators:

- `pattern-sources` (required)
- `pattern-propagators` (optional)
- `pattern-sanitizers` (optional)
- `pattern-sinks` (required)

These operators (which act as `pattern-either` operators) take a list of patterns that specify what is considered a source, a propagator, a sanitizer, or a sink. Note that you can use **any** pattern operator and you have the same expressive power as in a `mode: search` rule.

For example:

<iframe src="https://semgrep.dev/embed/editor?snippet=xG6g" border="0" frameBorder="0" width="100%" height="432"></iframe>

Here Semgrep tracks the data returned by `get_user_input()`, which is the source of taint. Think of Semgrep running the pattern `get_user_input(...)` on your code, finding all places where `get_user_input` gets called, and labeling them as tainted. That is exactly what is happening under the hood!

The rule specifies the sanitizer `sanitize_input(...)`, so any expression that matches that pattern is considered sanitized. In particular, the expression `sanitize_input(data)` is labeled as sanitized. Even if `data` is tainted, as it occurs inside a piece of sanitized code, it does not produce any findings.

Finally, the rule specifies that anything matching either `html_output(...)` or `eval(...)` should be regarded as a sink. There are two calls `html_output(data)` that are both labeled as sinks. The first one in `route1` is not reported because `data` is sanitized before reaching the sink, whereas the second one in `route2` is reported because the `data` that reaches the sink is still tainted.

You can find more examples of taint rules in the [Semgrep Registry](https://semgrep.dev/r?owasp=injection%2Cxss), for instance: [express-sandbox-code-injection](https://semgrep.dev/editor?registry=javascript.express.security.express-sandbox-injection.express-sandbox-code-injection).

:::info
[Metavariables](/writing-rules/pattern-syntax#metavariables) used in `pattern-sources` are considered _different_ from those used in `pattern-sinks`, even if they have the same name! See [Metavariables, rule message, and unification](#metavariables-rule-message-and-unification) for further details.
:::

## Sources

A taint source is specified by a pattern. Like in a search-mode rule, you can start this pattern with one of the following keys: `pattern`, `patterns`, `pattern-either`, `pattern-regex`. Note that **any** subexpression that is matched by this pattern will be regarded as a source of taint.

In addition, taint sources accept the following options:

| Option           | Type                      | Default | Description                                              |
| :--------------- | :------------------------ | :------ | :------------------------------------------------------- |
| `exact`          | {`false`, `true`}         | `false` | See [_Exact sources_](#exact-sources).                   |
| `by-side-effect` | {`false`, `true`, `only`} | `false` | See [_Sources by side-effect_](#sources-by-side-effect). |
| `control` (Pro)  | {`false`, `true`}         | `false` | See [_Control sources_](#control-sources-pro-).          |

Example:

```yaml
pattern-sources:
- pattern: source(...)
```

### Exact sources

Given the source specification below, and a piece of code such as `source(sink(x))`, the call `sink(x)` is reported as a tainted sink.

```yaml
pattern-sources:
- pattern: source(...)
```

The reason is that the pattern `source(...)` matches all of `source(sink(x))`, and that makes Semgrep consider every subexpression in that piece of code as being a source. In particular, `x` is a source, and it is being passed into `sink`!

<iframe src="https://semgrep.dev/embed/editor?snippet=eqYN8" border="0" frameBorder="0" width="100%" height="432"></iframe>

This is the default for historical reasons, but it may change in the future.

It is possible to instruct Semgrep to only consider as taint sources the "exact" matches of a source pattern by setting `exact: true`:

```yaml
pattern-sources:
- pattern: source(...)
  exact: true
```

Once the source is "exact," Semgrep will no longer consider subexpressions as taint sources, and `sink(x)` inside `source(sink(x))` will not be reported as a tainted sink (unless `x` is tainted in some other way).

<iframe src="https://semgrep.dev/embed/editor?snippet=Zq5ow" border="0" frameBorder="0" width="100%" height="432"></iframe>

For many rules this distinction is not very meaningful because it does not always make sense that a sink occurs inside the arguments of a source function.

:::note
If one of your rules relies on non-exact matching of sources, we advice you to make it explicit with `exact: false`, even if it is the current default, so that your rule does not break if the default changes.
:::

### Sources by side-effect

Consider the following hypothetical Python code, where `make_tainted` is a function that makes its argument tainted by side-effect:

```python
make_tainted(my_set)
sink(my_set)
```

This kind of source can be specified by setting `by-side-effect: true`:

```yaml
pattern-sources:
  - patterns:
      - pattern: make_tainted($X)
      - focus-metavariable: $X
    by-side-effect: true
```

When this option is enabled, and the source specification matches a variable (or in general, an [l-value](https://en.wikipedia.org/wiki/Value_(computer_science)#lrvalue)) exactly, then Semgrep assumes that the variable (or l-value) becomes tainted by side-effect at the precise places where the source specification produces a match.

<iframe src="https://semgrep.dev/embed/editor?snippet=5r400" border="0" frameBorder="0" width="100%" height="432"></iframe>

The matched occurrences themselves are considered tainted; that is, the occurrence of `x` in `make_tainted(x)` is itself tainted too. If you do not want this to be the case, then set `by-side-effect: only` instead.

:::note
You must use `focus-metavariable: $X` to focus the match on the l-value that you want to taint, otherwise `by-side-effect` does not work.
:::

If the source does not set `by-side-effect`, then only the very occurrence of `x` in `make_tainted(x)` will be tainted, but not the occurrence of `x` in `sink(x)`. The source specification matches only the first occurrence and, without `by-side-effect: true`, Semgrep does not know that `make_tainted` is updating the variable `x` by side-effect. Thus, a taint rule using such a specification does not produce any finding.

:::info
You could be tempted to write a source specification as the following example (and this was the official workaround before `by-side-effect`):

```yaml
pattern-sources:
- patterns:
  - pattern-inside: |
      make_tainted($X)
      ...
  - pattern: $X
```

This tells Semgrep that **every** occurrence of `$X` after `make_tainted($X)` must be considered a source.

This approach has two main limitations. First, it overrides any sanitization that can be performed on the code matched by `$X`. In the example code below, the call `sink(x)` is reported as tainted despite `x` having been sanitized!

```python
make_tainted(x)
x = sanitize(x)
sink(x) # false positive
```

Note also that [`...` ellipses operator](/writing-rules/pattern-syntax/#ellipses-and-statement-blocks) has limitations. For example, in the code below Semgrep does not match any finding if such source specification is in use:

```python
if cond:
    make_tainted(x)
sink(x) # false negative
```

The `by-side-effect` option was added precisely [to address those limitations](https://semgrep.dev/playground/s/JDv4y). However, that kind of workaround can still be useful in other situations!
:::

### Function arguments as sources

To specify that an argument of a function must be considered a taint source, simply write a pattern that matches that argument:

```yaml
pattern-sources:
  - patterns:
    - pattern-inside: |
        def foo($X, ...):
          ...
    - focus-metavariable: $X
```

Note that the use of `focus-metavariable: $X` is very important, and using `pattern: $X` is **not** equivalent. With `focus-metavariable: $X`, Semgrep matches the formal parameter exactly. Click "Open in Playground" below and use "Inspect Rule" to visualize what the source is matching.

<iframe src="https://semgrep.dev/embed/editor?snippet=L1vJ6" border="0" frameBorder="0" width="100%" height="432"></iframe>

The following example does the same with this other taint rule that uses `pattern: $X`. The `pattern: $X` does not match the formal parameter itself, but matches all its uses inside the function definition. Even if `x` is sanitized via `x = sanitize(x)`, the occurrence of `x` inside `sink(x)` is a taint source itself (due to `pattern: $X`) and so `sink(x)` is tainted!

<iframe src="https://semgrep.dev/embed/editor?snippet=Qr3Y4" border="0" frameBorder="0" width="100%" height="432"></iframe>

### Control sources (Pro) 🧪

**Control taint sources is a Semgrep Pro feature.**

Typically taint analysis tracks the flow of tainted _data_, but taint sources can also track the flow of tainted _control_ by setting `control: true`.

```yaml
pattern-sources:
- pattern: source(...)
  control: true
```

This is useful for checking _reachability_, that is to check if from a given code location the control-flow can reach another code location, regardless of whether there is any flow of data between them. In the following example we check whether `foo()` could be followed by `bar()`:

<iframe src="https://semgrep.dev/embed/editor?snippet=yyjrx" border="0" frameBorder="0" width="100%" height="432"></iframe>

By using a control source, you can define a context from which Semgrep detects if a call to some other code, such as a sink, can be reached.

:::note
Use [taint labels](#taint-labels-pro-) to combine both data and control sources in the same rule.
:::

## Sanitizers

A taint sanitizer is specified by a pattern. Like in a search-mode rule, you can start this pattern with one of the following keys: `pattern`, `patterns`, `pattern-either`, `pattern-regex`. Note that **any** subexpression that is matched by this pattern will be regarded as sanitized.

In addition, taint sanitizers accept the following options:

| Option           | Type                      | Default | Description                                                    |
| :--------------- | :------------------------ | :------ | :------------------------------------------------------------- |
| `exact`          | {`false`, `true`}         | `false` | See [_Exact sanitizers_](#exact-sanitizers).                   |
| `by-side-effect` | {`false`, `true`, `only`} | `false` | See [_Sanitizers by side-effect_](#sanitizers-by-side-effect). |

Example:

```yaml
pattern-sanitizers:
- pattern: sanitize(...)
```

### Exact sanitizers

Given the sanitizer specification below, and a piece of code such as `sanitize(sink("taint"))`, the call `sink("taint")` is **not** reported.

```yaml
pattern-sanitizers:
- pattern: sanitize(...)
```

The reason is that the pattern `sanitize(...)` matches all of `sanitize(sink("taint"))`, and that makes Semgrep consider every subexpression in that piece of code as being sanitized. In particular, `"taint"` is considered to be sanitized!

<iframe src="https://semgrep.dev/embed/editor?snippet=v83Rb" border="0" frameBorder="0" width="100%" height="432"></iframe>

This is the default for historical reasons, but it may change in the future.

It is possible to instruct Semgrep to only consider as sanitized the "exact" matches of a sanitizer pattern by setting `exact: true`:

```yaml
pattern-sanitizers:
- pattern: sanitize(...)
  exact: true
```

Once the source is "exact," Semgrep will no longer consider subexpressions as sanitized, and `sink("taint")` inside `sanitize(sink("taint"))` will be reported as a tainted sink.

<iframe src="https://semgrep.dev/embed/editor?snippet=Zqz8o" border="0" frameBorder="0" width="100%" height="432"></iframe>

For many rules this distinction is not very meaningful because it does not always make sense that a sink occurs inside the arguments of a sanitizer function.

:::note
If one of your rules relies on non-exact matching of sanitizers, We at Semgrep advise you to make it explicit with `exact: false`, even if it is the current default, so that your rule does not break if the default changes.
:::

### Sanitizers by side-effect

Consider the following hypothetical Python code, where it is guaranteed that after `check_if_safe(x)`, the value of `x` must be a safe one.

```python
x = source()
check_if_safe(x)
sink(x)
```

This kind of sanitizer can be specified by setting `by-side-effect: true`:

```yaml
pattern-sanitizers:
  - patterns:
      - pattern: check_if_safe($X)
      - focus-metavariable: $X
    by-side-effect: true
```

When this option is enabled, and the sanitizer specification matches a variable (or in general, an l-value) exactly, then Semgrep assumes that the variable (or l-value) is sanitized by side-effect at the precise places where the sanitizer specification produces a match.

<iframe src="https://semgrep.dev/embed/editor?snippet=4bvGz" border="0" frameBorder="0" width="100%" height="432"></iframe>

:::note
It is important to use `focus-metavariable: $X` to focus the match on the l-value that we want to sanitize, otherwise `by-side-effect` does not work as expected.
:::

If the sanitizer does not set `by-side-effect`, then only the very occurrence of `x` in `check_if_safe(x)` will be sanitized, but not the occurrence of `x` in `sink(x)`. The sanitizer specification matches only the first occurrence and, without `by-side-effect: true`, Semgrep does not know that `check_if_safe` is updating/sanitizing the variable `x` by side-effect. Thus, a taint rule using such specification does produce a finding for `sink(x)` in the example above.

:::info
You can be tempted to write a sanitizer specification as the one below (and this was the official workaround before `by-side-effect`):

```yaml
pattern-sanitizers:
- patterns:
  - pattern-inside: |
      check_if_safe($X)
      ...
  - pattern: $X
```

This tells Semgrep that **every** occurrence of `$X` after `check_if_safe($X)` must be considered sanitized.

This approach has two main limitations. First, it overrides any further tainting that can be performed on the code matched by `$X`.  In the example code below, the call `sink(x)` is  **not** reported as tainted despite `x` having been tainted!

```python
check_if_safe(x)
x = source()
sink(x) # false negative
```

Note also that [`...` ellipses operator](/writing-rules/pattern-syntax/#ellipses-and-statement-blocks) has limitations. For example, in the code below Semgrep still matches despite `x` having been sanitized in both branches:

```python
if cond:
    check_if_safe(x)
else
    check_if_safe(x)
sink(x) # false positive
```

The `by-side-effect` option was added precisely [to address those limitations](https://semgrep.dev/playground/s/PeB3W). However, that kind of workaround can still be useful in other situations!
:::

## Sinks

A taint sink is specified by a pattern. Like in a search-mode rule, you can start this pattern with one of the following keys: `pattern`, `patterns`, `pattern-either`, `pattern-regex`. Unlike sources and sanitizers, by default Semgrep does not consider the subexpressions of the matched expressions as sinks.

In addition, taint sinks accept the following options:

| Option           | Type              | Default | Description                                 |
| :--------------- | :---------------- | :------ | :------------------------------------------ |
| `exact`          | {`false`, `true`} | `true`  | See [_Non-exact sinks_](#non-exact-sinks).  |
| `at-exit` (Pro)  | {`false`, `true`} | `false` | See [_At-exit sinks_](#at-exit-sinks-pro-). |

Example:

```yaml
pattern-sinks:
- pattern: sink(...)
```

### Non-exact sinks

Given the sink specification below, a piece of code such as `sink("foo" if tainted else "bar")` will **not** be reported as a tainted sink.

```yaml
pattern-sources:
- pattern: sink(...)
```

This is because Semgrep considers that the sink is the argument of the `sink` function, and the actual argument being passed is `"foo" if tainted else "bar"` that evaluates to either `"foo"` or `"bar"`, and neither of them are tainted.

<iframe src="https://semgrep.dev/embed/editor?snippet=KxJ17" border="0" frameBorder="0" width="100%" height="432"></iframe>

It is possible to instruct Semgrep to consider as a taint sink any of the subexpressions matching the sink pattern, by setting `exact: false`:

```yaml
pattern-sinks:
- pattern: sink(...)
  exact: false
```

Once the sink is "non-exact" Semgrep will consider subexpressions as taint sinks, and `tainted` inside `sink("foo" if tainted else "bar")` will then be reported as a tainted sink.

<iframe src="https://semgrep.dev/embed/editor?snippet=qNwez" border="0" frameBorder="0" width="100%" height="432"></iframe>

### Function arguments as sinks

We can specify that only one (or a subset) of the arguments of a function is the actual sink by using `focus-metavariable`:

```javascript
pattern-sinks:
  - patterns:
    - pattern: sink($SINK, ...)
    - focus-metavariable: $SINK
```

This rule causes Semgrep to only annotate the first parameter passed to `sink` as the sink, rather than the function `sink` itself. If taint goes into any other parameter of `sink`, then that is not considered a problem.

<iframe src="https://semgrep.dev/embed/editor?snippet=v83Nl" border="0" frameBorder="0" width="100%" height="432"></iframe>

Anything that you can match with Semgrep can be made into a sink, like the index in an array access:

```javascript
pattern-sinks:
  - patterns:
    - pattern-inside: $ARRAY[$SINK]
    - focus-metavariable: $SINK
```

:::note
If you specify a sink such as `sink(...)` then any tainted data passed to `sink`, through any of its arguments, results in a finding.

<iframe src="https://semgrep.dev/embed/editor?snippet=OrAAe" border="0" frameBorder="0" width="100%" height="432"></iframe>
:::

### At-exit sinks (Pro) 🧪

**At-exit taint sinks is a Semgrep Pro feature.**

At-exit sinks are meant to facilitate writing leak-detection rules using taint mode. By setting `at-exit: true` you can restrict a sink specification to only match at "exit" statements, that is statements after which the control-flow will exit the function being analyzed.

```
pattern-sinks:
- pattern-either:
  - pattern: return ...
  - pattern: $F(...)
  at-exit: true
```

The above sink pattern matches either `return` statements (which are always "exit" statements), or function calls occurring as "exit" statements.

Unlike regular sinks, at-exit sinks trigger a finding if any tainted l-value reaches the location of the sink. For example, the at-exit sink specification above will trigger a finding at a `return 0` statement if some tainted l-value reaches the `return`, even if `return 0` itself is not tainted. The location itself is the sink rather than the code that is at that location.

You can use this, for example, to check that file descriptors are being closed within the same function where they were opened.

<iframe src="https://semgrep.dev/embed/editor?snippet=OrAzB" border="0" frameBorder="0" width="100%" height="432"></iframe>

The `print(content)` statement is reported because the control flow exits the function at that point, and the file has not been closed.

## Propagators (Pro)

**Custom taint propagators is a Semgrep Pro feature.**

By default, tainted data automatically propagates through assignments, operators, and function calls (from inputs to output). However, there are other ways in which taint can propagate, which can require language or library-specific knowledge that Semgrep does not have built-in.

A taint propagator requires a pattern to be specified. Like in a search-mode rule, you can start this pattern with one of the following keys: `pattern`, `patterns`, `pattern-either`, `pattern-regex`.

A propagator also needs to specify the origin (`from`) and the destination (`to`) of the taint to be propagated.

| Field  | Type         | Description                 |
| :----- | :----------- | :-------------------------- |
| `from` | metavariable | Source of propagation.      |
| `to`   | metavariable | Destination of propagation. |

In addition, taint propagators accept the following options:

| Option           | Type              | Default | Description                                                                |
| :--------------- | :---------------- | :------ | :------------------------------------------------------------------------- |
| `by-side-effect` | {`false`, `true`} | `true`  | See [_Propagation without side-effect_](#propagation-without-side-effect). |

For example, given the following propagator, if taint goes into the second argument of `strcpy`, its first argument will get the same taint:

```yaml
pattern-propagators:
- pattern: strcpy($DST, $SRC)
  from: $SRC
  to: $DST
```

:::info
Taint propagators only work intra-procedurally, that is, within a function or method. You cannot use taint propagators to propagate taint across different functions/methods. Use [inter-procedural analysis](#inter-procedural-analysis-pro).
:::

### Understanding custom propagators

Consider the following Python code where an unsafe `user_input` is stored into a `set` data structure. A random element from `set` is then passed into a `sink` function. This random element can be `user_input` itself, leading to an injection vulnerability!

```python
def test(s):
    x = user_input
    s = set([])
    s.add(x)
    #ruleid: test
    sink(s.pop())
```

The following rule cannot find the above-described issue. The reason is that Semgrep is not aware that executing `s.add(x)` makes `x` one of the elements in the set data structure `s`.

```yaml
mode: taint
pattern-sources:
- pattern: user_input
pattern-sinks:
- pattern: sink(...)
```

The use of **taint propagators** enables Semgrep to propagate taint in this and other scenarios.
Taint propagators are specified under the `pattern-propagators` key:

```yaml
pattern-propagators:
- pattern: $S.add($E)
  from: $E
  to: $S
```

In the example above, Semgrep finds the pattern `$S.add($E)`, and it checks whether the code matched by `$E` is tainted. If it is tainted, Semgrep propagates that same taint to the code matched by `$S`. Thus, adding tainted data to a set marks the set itself as tainted.

<iframe src="https://semgrep.dev/embed/editor?snippet=dGRE" border="0" frameBorder="0" width="100%" height="432"></iframe>

Note that `s` becomes tainted _by side-effect_ after `s.add(x)`, this is due to `by-side-effect: true` being the default for propagators, and because `s` is an l-value.

In general, a taint propagator must specify:

1. A pattern containing **two** metavariables. These two metavariables specify where taint is propagated **from** and **to**.
2. The `to` and `from` metavariables. These metavariables should match an **expression**.
    - The `from` metavariable specifies the entry point of the taint.
    - The `to` metavariable specifies where the tainted data is propagated to, typically an object or data structure. If option `by-side-effect` is enabled (as it is by default) and the `to` metavariable matches an l-value, the propagation is side-effectful.

In the example above, pattern `$S.add($E)` includes two metavariables `$S` and `$E`. Given `from: $E` and `to: $S`, and with `$E` matching `x` and `$S` matching `s`, when `x` is tainted then `s` becomes tainted (by side-effect) with the same taint as `x`.

Another situation where taint propagators can be useful is to specify in Java that, when iterating a collection that is tainted, the individual elements must also be considered tainted:

```yaml
pattern-propagators:
- pattern: $C.forEach(($X) -> ...)
  from: $C
  to: $X
```

### Propagation without side-effect

Taint propagators can be used in very imaginative ways, and in some cases you may not want taint to propagate by side-effect. This can be achieved by disabling `by-side-effect`, which is enabled by default.

For example:

```yaml
pattern-propagators:
  - patterns:
    - pattern: |
        if something($FROM):
          ...
          $TO()
          ...
    from: $FROM
    to: $TO
    by-side-effect: false
```

The propagator above specifies that inside an `if` block, where the condition is `something($FROM)`, we want to propagate taint from `$FROM` to any function that is being called without arguments, `$TO()`.

<iframe src="https://semgrep.dev/embed/editor?snippet=4bv6x" border="0" frameBorder="0" width="100%" height="432"></iframe>

Because the rule disables `by-side-effect`, the `sink` occurrence that is inside the `if` block is tainted, but this does not affect the `sink` occurrence outside the `if` block.

## Findings

Taint findings are accompanied by a taint trace that explains how the taint flows from source to sink.

<!-- <iframe src="https://semgrep.dev/embed/editor?snippet=KxJRL" border="0" frameBorder="0" width="100%" height="432"></iframe> -->

### Deduplication of findings

Semgrep tracks all the possible ways that taint can reach a sink, but at present it only reports one taint trace among the possible ones. Click "Open in Playground" in the example below, run the example to get one finding, and then ask the Playground to visualize the dataflow of the finding. Even though `sink` can be tainted via `x` or via `y`, the trace will only show you one of these possibilities. If you replace `x = user_input` with `x = "safe"`, then Semgrep will then report the taint trace via `y`.

<iframe src="https://semgrep.dev/embed/editor?snippet=WAYzL" border="0" frameBorder="0" width="100%" height="432"></iframe>

### Report findings on the sources (Pro)

**Reporting findings on the source of taint is a Semgrep Pro feature.**

By default Semgrep reports taint findings at the location of the sink being matched. You must look at the taint trace to identify where the taint is coming from. It is also possible to make Semgrep report the findings at the location of the taint sources, by setting the [rule-level option](/writing-rules/rule-syntax/#options) `taint_focus_on` to `source`. Then

```yaml
options:
  taint_focus_on: source
```

<iframe src="https://semgrep.dev/embed/editor?snippet=JDPGP" border="0" frameBorder="0" width="100%" height="432"></iframe>

The [deduplication of findings](#deduplication-of-findings) still applies in this case. While Semgrep will now report all the taint sources, if a taint source can reach multiple sinks, the taint trace will only inform you about one of them.

## Minimizing false positives

The following [rule options](/writing-rules/rule-syntax/#options) can be used to minimize false positives:

| Rule option                                 | Default | Description                                                                                                                                                                                                                                    |
| :------------------------------------------ | :------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `taint_assume_safe_booleans`                | `false` | Boolean data is never considered tainted (works better with type annotations).                                                                                                                                                                 |
| `taint_assume_safe_numbers`                 | `false` | Numbers (integers, floats) are never considered tainted (works better with type annotations).                                                                                                                                                  |
| `taint_assume_safe_indexes`                 | `false` | An index expression `I` tainted does not make an access expression `E[I]` tainted (it is only tainted if `E` is tainted).                                                                                                                      |
| `taint_assume_safe_functions`               | `false` | A function call like `F(E)` is not considered tainted even if `E` is tainted. (When using Pro's [inter-procedural taint analysis](#inter-procedural-analysis-pro), this only applies to functions for which Semgrep cannot find a definition.) |
| `taint_only_propagate_through_assignments`  | `false` | Disables all implicit taint propagation except for assignments.                                                                                                                                                                                |

### Restrict taint by type (Pro)

By enabling `taint_assume_safe_booleans` Semgrep automatically sanitizes Boolean expressions when it can infer that the expression resolves to Boolean.

For example, comparing a tainted string against a constant string will not be considered a tainted expression:

<iframe src="https://semgrep.dev/embed/editor?snippet=6JvzK" border="0" frameBorder="0" width="100%" height="432"></iframe>

Similarly, enabling `taint_assume_safe_numbers` Semgrep will automatically sanitize numeric expressions when it can infer that the expression is numeric.

<iframe src="https://semgrep.dev/embed/editor?snippet=oqjgX" border="0" frameBorder="0" width="100%" height="432"></iframe>

You could define explicit sanitizers that clean the taint from Boolean or numeric expressions, but these options are more convenient and also more efficient.

:::note
Semgrep Pro's ability to infer types for expressions varies depending on the language. For example, in Python type annotations are not always present, and the `+` operator can also be used to concatenate strings. Semgrep also ignores the types of functions and classes coming from third-party libraries.

<iframe src="https://semgrep.dev/embed/editor?snippet=zdjnn" border="0" frameBorder="0" width="100%" height="432"></iframe>
:::

### Assume tainted indexes are safe

By default, Semgrep assumes that accessing an array-like object with a tainted index (that is, `obj[tainted]`) is itself a tainted **expression**, even if the **object** itself is not tainted. Setting `taint_assume_safe_indexes: true` makes Semgrep assume that these expressions are safe.

<iframe src="https://semgrep.dev/embed/editor?snippet=X56pj" border="0" frameBorder="0" width="100%" height="432"></iframe>

### Assume function calls are safe

:::note
We refer to a function call as _opaque_ when Semgrep does not have access to its definition, to examine it and determine its "taint behavior" (for example, whether the function call propagates or not any taint that comes through its inputs). In Semgrep OSS, where taint analysis is intra-procedural, all function calls are opaque. In Semgrep Pro, with [inter-procedural taint analysis](#inter-procedural-analysis-pro), an opaque function could be one coming from a third-party library.
:::

By default Semgrep considers that an _opaque_ function call propagates any taint passed through any of its arguments to its output.

For example, in the code below, `some_safe_function` receives tainted data as input, so Semgrep assumes that it also returns tainted data as output. As a result, a finding is produced.

```javascript
var x = some_safe_function(tainted);
sink(x); // undesired finding here
```

This can generate false positives, and for certain rules on certain codebases it can produce a high amount of noise.

Setting `taint_assume_safe_functions: true` makes Semgrep assume that opaque function calls are safe and do not propagate any taint. If it is desired that specific functions do propagate taint, then that can be achieved via custom propagators:

<iframe src="https://semgrep.dev/embed/editor?snippet=gBD0" border="0" frameBorder="0" width="100%" height="432"></iframe>

### Propagate only through assignments 🧪

Setting `taint_only_propagate_through_assignments: true` makes Semgrep to only propagate taint through trivial assignments of the form `<l-value> = <tainted-expression>`. It requires the user to be explicit about any other kind of taint propagation that is to be performed.

For example, neither `unsafe_function(tainted)` nor `tainted_string + "foo"` will be considered tainted expressions:

<iframe src="https://semgrep.dev/embed/editor?snippet=bwekv" border="0" frameBorder="0" width="100%" height="432"></iframe>

## Metavariables, rule message, and unification

The patterns specified by `pattern-sources` and `pattern-sinks` (and `pattern-sanitizers`) are all independent of each other. If a metavariable used in `pattern-sources` has the same name as a metavariable used in `pattern-sinks`, these are still different metavariables.

In the message of a taint-mode rule, you can refer to any metavariable bound by `pattern-sinks`, as well as to any metavariable bound by `pattern-sources` that does not conflict with a metavariable bound by `pattern-sinks`.

Semgrep can also treat metavariables with the same name as the _same_ metavariable, simply set `taint_unify_mvars: true` using rule `options`. Unification enforces that whatever a metavariable binds to in each of these operators is, syntactically speaking, the **same** piece of code. For example, if a metavariable binds to a code variable `x` in the source match, it must bind to the same code variable `x` in the sink match. In general, unless you know what you are doing, avoid metavariable unification between sources and sinks.

The following example demonstrates the use of source and sink metavariable unification:

<iframe src="https://semgrep.dev/embed/editor?snippet=G652" border="0" frameBorder="0" width="100%" height="432"></iframe>

## Inter-procedural analysis (Pro)

**Inter-procedural taint analysis is a Semgrep Pro feature.**

[Semgrep Pro](/semgrep-pro-vs-oss/) can perform inter-procedural taint analysis, that is, to track taint across multiple functions.

In the example below, `user_input` is passed to `foo` as input and, from there, flows to the sink at line 3, through a call chain involving three functions. Semgrep is able to track this and report the sink as tainted. Semgrep also provides an inter-procedural taint trace that explains how exactly `user_input` reaches the `sink(z)` statement (click "Open in Playground" then click "dataflow" in the "Matches" panel).

<iframe src="https://semgrep.dev/embed/editor?snippet=PeBXv" border="0" frameBorder="0" width="100%" height="432"></iframe>

Using the CLI option `--pro-intrafile`, Semgrep will perform inter-procedural (across functions) _intra_-file (within one file) analysis. That is, it will track taint across functions, but it will not cross file boundaries. This is supported for essentially every language, and performance is very close to that of intra-procedural taint analysis.

Using the CLI option `--pro`, Semgrep will perform inter-procedural (across functions) as well as _inter_-file (across files) analysis. Inter-file analysis is only supported for [a subset of languages](/supported-languages/#semgrep-code-language-support). For a rule to run inter-file it also needs to set `interfile: true`:

```yaml
options:
  interfile: true
```

**Memory requirements for inter-file analysis:**
While interfile analysis is more powerful, it also demands more memory resources. The Semgrep team advises a minimum of 4 GB of memory per core, but **recommend 8 GB per core or more**. The amount of memory needed depends on the codebase and on the number of interfile rules being run.

## Taint mode sensitivity

### Field sensitivity

The taint engine provides basic field sensitivity support. It can:

- Track that `x.a.b` is tainted, but `x` or `x.a` is  **not** tainted. If `x.a.b` is tainted, any extension of `x.a.b` (such as `x.a.b.c`) is considered tainted by default.
- Track that `x.a` is tainted, but remember that `x.a.b` has been sanitized. Thus the engine records that `x.a.b` is **not** tainted, but `x.a` or `x.a.c` are still tainted.

:::note
The taint engine does track taint **per variable** and not **per object in memory**. The taint engine does not track aliasing at present.
:::

<iframe src="https://semgrep.dev/embed/editor?snippet=5rvkj" border="0" frameBorder="0" width="100%" height="432"></iframe>

### Index sensitivity (Pro)

**Index sensitivity is a Semgrep Pro feature.**

Semgrep Pro has basic index sensitivity support:

- Only for accesses using the built-in `a[E]` syntax.
- Works for _statically constant_ indexes that may be either integers (e.g. `a[42]`) or strings (e.g. `a["foo"]`).
- If an arbitrary index `a[i]` is sanitized, then every index becomes clean of taint.

<iframe src="https://semgrep.dev/embed/editor?snippet=GdoK6" border="0" frameBorder="0" width="100%" height="432"></iframe>

## Taint labels (Pro) 🧪

Taint labels increase the expressiveness of taint analysis by allowing you to specify and track different kinds of tainted data in one rule using labels. This functionality has various uses, for example, when data becomes dangerous in several steps that are hard to specify through single pair of source and sink.

<iframe class="yt_embed" width="100%" height="432px" src="https://www.youtube.com/embed/lAbJdzMUR4k" frameborder="0" allowfullscreen></iframe>

To include taint labels into a taint mode rule, follow these steps:

1. Attach a `label` key to the taint source. For example, `label: TAINTED` or `label: INPUT`. See the example below:

    ```yaml
      pattern-sources:
        - pattern: user_input
          label: INPUT
    ```

    Semgrep accepts any valid Python identifier as a label.

2. Restrict a taint source to a subset of labels using the `requires` key. Extending the previous example, see the `requires: INPUT` below:

    ```yaml
        pattern-sources:
          - pattern: user_input
            label: INPUT
          - pattern: evil(...)
            requires: INPUT
            label: EVIL
    ```

    Combine labels using the `requires` key. To combine labels, use Python Boolean operators. For example: `requires: LABEL1 and not LABEL2`.

3. Use the `requires` key to restrict a taint sink in the same way as source:

    ```yaml
        pattern-sinks:
          - pattern: sink(...)
            requires: EVIL
    ```

:::info

- Semgrep accepts valid Python identifiers as labels.
- Restrict a source to a subset of labels using the `requires` key. You can combine more labels in the `requires` key using Python Boolean operators. For example: `requires: LABEL1 and not LABEL2`.
- Restrict a sink also. The extra taint is only produced if the source itself is tainted and satisfies the `requires` formula.

:::

In the example below, let's say that `user_input` is dangerous but only when it passes through the `evil` function. This can be specified with taint labels as follows:

<iframe src="https://semgrep.dev/embed/editor?snippet=PwKY" border="0" frameBorder="0" width="100%" height="432"></iframe>

<!--
TODO: For some reason the embedded editor doesn't like the rule, even though the Playground can run it.

Interestingly, you can (ab)use taint labels to write some [typestate analyses](https://en.wikipedia.org/wiki/Typestate_analysis)!

<iframe src="https://semgrep.dev/embed/editor?snippet=DYxo" border="0" frameBorder="0" width="100%" height="432"></iframe>
-->
````

### `experiments\aliengrep.md`

````markdown
---
slug: aliengrep
append_help_link: true
description: "Aliengrep is a variant of the generic mode that is more configurable than spacegrep."
title: Aliengrep
hide_title: true
---

## Aliengrep

:::caution
This is an experimental matching mode for Semgrep OSS Engine. Many of the features described in this document are subject to change. Your feedback is important and helps us, the Semgrep team, to make desirable adjustments. You can file an issue in our [Semgrep OSS Engine GitHub repository](https://github.com/semgrep/semgrep/issues) or ask us anything in <a href="https://go.semgrep.dev/slack">Semgrep Community Slack group</a>.
:::

Aliengrep is an alternative to the [generic pattern-matching engine](/writing-rules/generic-pattern-matching) for analyzing files written in any language. The pattern syntax resembles the usual Semgrep pattern syntax. This document provides a reference to the syntactic features that Aliengrep supports.

## Minimal example

Specify that a rule uses the Aliengrep engine by setting `options.generic_engine: aliengrep`. See the Semgrep rule example below:

```yaml
rules:
- id: example
  severity: WARNING
  languages: [generic]
  options:
    generic_engine: aliengrep
  message: "found the word 'hello'"
  pattern: "hello"
```

:::note
We are considering a dedicated field `analyzer: aliengrep` instead of `options.generic_engine: aliengrep`.
:::

## Pattern syntax

The following sections provide descriptions and examples of operators that Aliengrep uses in YAML rule files.

### Whitespace

The whitespace between lexical elements is ignored. By default, whitespace includes spaces, tabs, and newlines. The single-line mode restricts whitespace to only spaces and tabs (see [Single-line mode](#single-line-mode) section below).

Lexical elements in target input are:

* words (configurable)
* brace pairs (configurable)
* single non-word characters

### Metavariables

A metavariable captures a single word in the target input. By default, the set of word characters is `[A-Za-z_0-9]`. The pattern `$THING` matches a whole word such as `hello` or `world` if the target input is `hello, world.`.

```yaml
rules:
- id: example
  severity: WARNING
  languages: [generic]
  options:
    generic_engine: aliengrep
  message: "found a word"
  pattern: "$THING"
```

Repeating a metavariable (back-reference) requires a match of the same sequence that was matched by the first occurrence of the metavariable. For example, the pattern `$A ... $A` matches `a x y a`, assigning `a` to the metavariable `A`. It does not match `a x b`.

### Ellipsis (`...`)

In Semgrep rule syntax, an ellipsis is a specific pattern written as three dots `...`. Ellipsis matches a sequence of any lexical elements. Matching ellipses is lazy or shortest-match-first. For example, the pattern `a ... b` matches `a x b` rather than `a x b b` if the target input is `a x b b c`.

Ellipses at the beginning or at the end of a pattern are anchored. For example, ellipses must match the beginning or the end of the target input, respectively. For example, `...` alone matches the whole input and `a ...` matches the whole input starting from the first occurrence of the word `a`.

### Ellipsis metavariable (capturing ellipsis)

An ellipsis metavariable `$...X` matches the same contents as an ordinary ellipsis `...` but additionally captures the contents and assigns them to the metavariable `X`.

Repeating a metavariable ellipsis such as in `$...A, $...A` requires the same contents to be matched by each repetition, including the same whitespace. This is an unfortunate limitation of the implementation. For example, `$...A, $...A` matches `1 2, 1 2` and `1   2, 1   2` but it doesn't match `1 2, 1   2`.

### Single-line mode

Se the single-line mode with `options.generic_multiline: false` in rule files:

```yaml
rules:
- id: single-line-example
  severity: WARNING
  languages: [generic]
  options:
    generic_engine: aliengrep
    generic_multiline: false
  message: "found a password field"
  pattern: "password: ..."
```

Now instead of matching everything until the end of the target input file, the pattern `password: ...` stops the match at the end of the line. In single-line mode, a regular ellipsis `...` or its named variant `$...X` cannot span multiple lines.

Another feature of the single-line mode is that newlines in rule patterns must match literally. For example, the following YAML rule contains a two-line pattern:

```yaml
rules:
- id: single-line-example2
  severity: WARNING
  languages: [generic]
  options:
    generic_engine: aliengrep
    generic_multiline: false
  message: "found a password field"
  pattern: "a\nb"
```

The pattern `"a\nb"` in the YAML rule file matches the following code:

```
x a
b x
```

The pattern does not match if there is another number of newlines between `a` and `b`. The single-line mode does not match the following target input:

```
x a b x
```

It does however match in the default multiline mode of Aliengrep.

:::caution
YAML syntax makes it easy to introduce significant newline characters in patterns without realizing it. When in doubt and for better clarity, use the quoted string syntax `"a\nb"` as we did in the preceding example. This ensures no trailing newline is added accidentally when using the single-line mode.
:::

### Long ellipsis (`....`)

A long ellipsis (written as four dots, `....`) and its capturing variant `$....X` matches a sequence of any lexical elements even in single-line mode. It's useful for skipping any number of lines in single-line mode.

In multiline mode, a regular ellipsis (three dots `...`) has the same behavior as a long ellipsis (four dots `....`).

:::note
We wonder if the visual difference between `...` and `....` is too subtle. Let us know if you have ideas for a better syntax than four dots `....`.
:::

### Additional word characters captured by metavariables

In the generic modes, a metavariable captures a word. The default pattern followed by a word is `[A-Za-z_0-9]+` (a sequence of one or more alphanumeric characters or underscores). The set of characters that comprise a word can be configured as an option in the Semgrep rule as follows:

```yaml
rules:
- id: custom-word-chars
  severity: WARNING
  languages: [generic]
  options:
    generic_engine: aliengrep
    generic_extra_word_characters: ["+", "/", "="]
  message: "found something"
  pattern: "data = $DATA;"
```

The preceding example allows matching Base64-encoded data such as in the following target input:

```
data = bGlnaHQgd29yaw==;
```

There's currently no option to remove word characters from the default
set.

### Custom brackets

The Aliengrep engine performs brace matching as expected in English text. The default brace pairs are parentheses (`()`), square brackets (`[]`), and curly braces (`{}`). In single-line mode, ASCII single quotes and double quotes are also treated like brace pairs by default. The following rule demonstrates the addition of `<>` as an extra pair of braces by specifying `options.generic_extra_braces`:

```yaml
rules:
- id: edgy-brackets
  severity: WARNING
  languages: [generic]
  options:
    generic_engine: aliengrep
    generic_extra_braces: [["<", ">"]]
  message: "found something"
  pattern: "x ... x"
```

This pattern matches the `x <x> x` in the following target input:
```
a x <x> x a
```

Without declaring `<>` as braces, the rule would match only `x <x`.

The set of brace pairs can be completely replaced by using the field `options.generic_braces` as follows:

```yaml
rules:
- id: edgy-brackets-only
  severity: WARNING
  languages: [generic]
  options:
    generic_engine: aliengrep
    generic_braces: [["<", ">"]]
  message: "found something"
  pattern: "x ... x"
```

### Case-insensitive matching

Some languages are case-insensitive according to Unicode rules (UTF-8 encoding). To deal with this, Aliengrep offers an option for case-insensitive matching `options.generic_caseless: true`.

```yaml
rules:
- id: caseless
  severity: WARNING
  languages: [generic]
  options:
    generic_engine: aliengrep
    generic_multiline: false
    generic_caseless: true
  message: "found something"
  pattern: "Content-Type: $...CT"
```

This rule matches `Content-Type: text/html` but also `content-type: text/html` or `CONTENT-TyPe: text/HTML` among all the possible variants.

:::caution
Back-referencing a metavariable requires an exact repeat of the text captured by the metavariable, even in caseless mode. For example, `$X $X` matches `ab ab` and `AB AB` but not `ab AB`.
:::
````

### `experiments\deprecated-experiments.md`

````markdown
# Deprecated experiments

## Equivalences

:::note
This feature was deprecated in Semgrep v0.61.0.
:::

Equivalences enable defining equivalent code patterns (i.e. a commutative property: `$X + $Y <==> $Y + $X`). Equivalence rules use the `equivalences` top-level key and one `equivalence` key for each equivalence.

For example:

<iframe src="https://semgrep.dev/embed/editor?snippet=jNnn" border="0" frameBorder="0" width="100%" height="432"></iframe>
````

### `experiments\display-propagated-metavariable.md`

````markdown
---
slug: display-propagated-metavariable
append_help_link: true
description: "This document provides information about experimental syntax addition to [Displaying matched metavariable in rule message](/writing-rules/pattern-syntax/#display-matched-metavariable-in-rule-message). Semgrep enables you to display values of matched metavariables in rule messages. However, in some cases, the matched value of the metavariable is not the real value you were looking for."
---

# Displaying propagated value of metavariables

This document provides information about experimental syntax supplement to [Display matched metavariables in rule messages](/writing-rules/pattern-syntax#display-matched-metavariables-in-rule-messages). Semgrep enables you to display values of matched metavariables in rule messages. However, in some cases, the matched value of the metavariable is not the real value you were looking for.

See the following rule message and part of a Semgrep rule (formula):

```yaml
- message: >-
  Creating a buffer using $X
- patterns:
   - pattern: byte[] buf = new byte[$X];
   - metavariable-comparison:
        metavariable: $X
        comparison: $X < 2048
```

Testing code:

```java
int size = 512;
byte[] buf = new byte[size];
```

Semgrep matches this code because it performs constant propagation. Therefore, Semgrep recognizes that the value of `size` is `512`. Consequently, Semgrep evaluates that the buffer size is less than `2048`. But what is the value of `$X`?

If the rule message states `Creating a buffer using $X`, the resulting message output is not helpful in this particular case:

```
Creating a buffer using size
```

This is caused by the value of `$X` within the code, which is `size`. However, the underlying value of `size` is `512`. The goal of the rule message is to access this underlying value in our message.

To retrieve the correct value in the case described above, use `value($X)` in the rule message (for example (`Creating a buffer using value($X)`). Semgrep replaces the `value($X)` with the underlying propagated value of the metavariable `$X` if it computes one (otherwise, Semgrep uses the matched value).

:::info
Regular Semgrep syntax for displaying matched metavariables in rule messages is for example `$X`. For specific propagated values, use experimental syntax `value($X)` instead. For more information about the standard syntax, see [Displaying matched metavariables in rule messages](/writing-rules/pattern-syntax#display-matched-metavariables-in-rule-messages).
:::

Run the following example in Semgrep Playground to see the message (click **Open in Editor**, and then **Run**, unroll the **1 Match** to see the message):

<iframe title="Metavariable value in message example" src="https://semgrep.dev/embed/editor?snippet=Dr0G" width="100%" height="432" frameborder="0"></iframe>
````

### `experiments\extract-mode.md`

````markdown
---
id: extract-mode
append_help_link: true
description: "This article explains the extract mode, which allows for easier handling of files containing more than one language."
---

# Extract mode

:::danger Deprecation notice
As of Semgrep 1.65.0, extract mode has been deprecated and removed from Semgrep. This feature may return in the future.
:::

Extract mode enables you to run existing rules on subsections of files where the rule language is different than the language of the file. For example, running a JavaScript rule on code contained inside of script tags in an HTML document.

<!--
:::info
The extract mode feature is still in a very experimental stage and may not work as intended. The Semgrep team is planning to improve this feature in the future. Reach out for help and suggestions on the <a href="https://go.semgrep.dev/slack">Semgrep Community Slack</a>.
::: -->

## Example of extract mode

Without extract mode, writing rules to validate template, Markdown or configuration files which contain code in another language can be burdensome and require significant rule duplication.

Let's take the following Bash rule as an example (a simplified version of the [`curl-eval`](https://github.com/semgrep/semgrep-rules/blob/release/bash/curl/security/curl-eval.yaml) rule from the Semgrep Registry):

```yaml
rules:
  - id: curl-eval
    severity: WARNING
    languages:
      - bash
    message: Evaluating data from a `curl` command is unsafe.
    mode: taint
    pattern-sources:
      - pattern: |
          $(curl ...)
      - pattern: |
          `curl ...`
    pattern-sinks:
      - pattern: eval ...
```

Usually, Semgrep uses this rule only against Bash files. However, a project might contain Dockerfiles or Python scripts that invoke Bash commands&mdash;without an extract mode rule, Semgrep does **not** run any Bash rules against commands contained in files of different languages.

However, with extract mode, you can provide Semgrep with instructions on how to extract any Bash commands used in a Docker `RUN` instruction or as an argument to Python's `os.system` standard library function.

```yaml
rules:
  - id: extract-docker-run-to-bash
    mode: extract
    languages:
      - dockerfile
    pattern: RUN $...CMD
    extract: $...CMD
    dest-language: bash
  - id: extract-python-os-system-to-bash
    mode: extract
    languages:
      - python
    pattern: os.system("$CMD")
    extract: $CMD
    dest-language: bash
```

By adding the extract mode rules as shown in the previous code snippet, Semgrep matches Bash code contained in the following Python file and reports the contained Bash as matching against the `curl-eval` rule.

```python
from os import system

if system('eval `curl -s "http://www.very-secure-website.net"`'):
    print("Command failed!")
else:
    print("Success")
```

Likewise, if a query included a Dockerfile with an equivalent Bash command, Semgrep reports the contained Bash as matching against the `curl-eval` rule. See the following Dockerfile example that contains a Bash command:

```dockerfile
FROM fedora
RUN dnf install -y unzip zip curl which
RUN eval `curl -s "http://www.very-secure-website.net"`
```

## Extract mode rule schema

Extract mode rules **require** the following [usual Semgrep rule keys](/writing-rules/rule-syntax/#required):

  - `id`
  - `languages`
  - One of `pattern`, `patterns`, `pattern-either`, or `pattern-regex`

Extract mode rules **also require** two additional fields:

  - `extract`
  - `dest-language`

Extract mode has two **optional** fields:

  - `reduce`
  - `json`

The fields specific to extract mode are further explained in the sections below.

### `extract`

The `extract` key is required in extract mode. The value must be a metavariable appearing in your pattern(s). Semgrep uses the code bound to the metavariable for subsequent queries of non-extract mode rules targeting `dest-language`.

### `dest-language`

The `dest-language` key is required in extract mode. The value must be a [language tag](/writing-rules/rule-syntax/#language-extensions-and-languages-key-values).

### `transform`

The `transform` is an optional key in the extract mode. The value of this key specifies whether the extracted content is parsed as raw source code or as a JSON array.

The value of `transform` key must be one of the following:
<dl>
    <dt><code>no_transform</code></dt>
    <dd><p>Extract the matched content as raw source code. This is the <b>default</b> value.</p></dd>
    <dt><code>concat_json_string_array</code></dt>
    <dd><p>Extract the matched content as a JSON array. Each element of the array correspond to a line the resulting source code. This value is useful in extracting code from JSON formats such as Jupyter Notebooks.</p></dd>
</dl>

### `reduce`

The `reduce` key is optional in extract mode. The value of this key specifies a method to combine the ranges extracted by a single rule within a file.

The value of `reduce` key must be one of the following:
<dl>
    <dt><code>separate</code></dt>
    <dd><p>Treat all matched ranges as separate units for subsequent queries. This is the <b>default</b> value.</p></dd>
    <dt><code>concat</code></dt>
    <dd><p>Concatenate all matched ranges together and treat this result as a single unit for subsequent queries.</p></dd>
</dl>

## Limitations of extract mode

Although extract mode supports JSON array decoding with the `json` key, it does not support other additional processing for the extracted text, such as un-escaping strings.

While extract mode can help to enable rules which try and track taint across a language boundary within a file, taint rules cannot have a source and sink split across the original file and extracted text.
````

### `experiments\introduction.md`

````markdown
---
id: introduction
slug: introduction
title: Introduction
hide_title: true
append_help_link: true
description: "Introduction of Semgrep experiments that also documents that some experiments can sunset or become GA, which means that particular documents can change their position in docs also."
---

## Introduction to Semgrep experiments

The experiments category documents experimental features and the way you can use them. In the future, as it is the nature of experiments, some of these experiments can become deprecated, and others can become generally available (GA), meaning that GA features are fully supported parts of Semgrep. If a feature is deprecated, its documentation is moved to the [Deprecated experiments](/writing-rules/experiments/deprecated-experiments) document. If a feature becomes GA, its docs are moved to a relevant category outside of the experiments section.

Enjoy the experiments, tweak the code, and most importantly share your thoughts! If you see any issues with the experimental features, please [file a bug](https://github.com/semgrep/semgrep/issues/new/choose).
````

### `experiments\metavariable-type.md`

````markdown
---
slug: metavariable-type
append_help_link: true
description: "With this experimental field, Semgrep matches captured metavariables with specific types"
---

# Matching captured metavariables with specific types

The `metavariable-type` operator is used to compare metavariables against their types. It utilizes the `type` key to specify the string representation of the type expression in the target language. For example, you can use `String` for Java's String type and `string` for Go's string type. Optionally, the `language` key can be used to manually indicate the target language of the type expression.

`metavariable-type` provides several advantages over typed metavariables. Firstly, it removes the requirement for users to memorize special syntax for defining typed metavariables in various target languages. Moreover, `metavariable-type` enables users to extract type expressions from the pattern expression and include them in other conditional filters for metavariables. This improves the readability of rules and promotes better organization of the code.

For instance, the following rule that identifies potentially unsafe usage of the referential equality operator when comparing String objects in Java:

```yaml
rules:
  - id: no-string-eqeq
    severity: WARNING
    message: Avoid using the referential equality operator when comparing String objects
    languages:
      - java
    patterns:
      - pattern-not: null == (String $Y)
      - pattern: $X == (String $Y)
```

can be modified to the following rule:

```yaml
rules:
  - id: no-string-eqeq
    severity: WARNING
    message: Avoid using the referential equality operator when comparing String objects
    languages:
      - java
    patterns:
      - pattern-not: null == $Y
      - pattern: $X == $Y
      - metavariable-type:
          metavariable: $Y
          type: String
```
````

### `experiments\multiple-focus-metavariables.md`

````markdown
---
slug: multiple-focus-metavariables
append_help_link: true
description: "With this rule, Semgrep matches all pieces of code captured by the focus metavariables."
---

# Including multiple focus metavariables using set union semantics

Semgrep matches all pieces of code captured by focus metavariables when you specify them in a rule. Specify the metavariables you want to focus on in a YAML list format.

:::info
This feature is using `focus-metavariable`, see [`focus-metavariable`](/writing-rules/rule-syntax/#focus-metavariable) documentation for more information.
:::

There are two ways in which you can include multiple focus metavariables:

- **Set union**: Experimental feature described below in the section [Set union](#set-union). This feature returns the union of all matches of the specified metavariables.
- **Set intersection**: Only matches the overlapping region of all the focused code. For more information, see [Including more focus metavariables using set intersection semantics](/writing-rules/rule-syntax/#including-multiple-focus-metavariables-using-set-intersection-semantics).

## Set union

For example, there is a pattern that binds several metavariables. You want to produce matches focused on two or more of these metavariables. If you specify a list of metavariables under `focus-metavariable`, each focused metavariable matches code independently of the others.

```yaml
    patterns:
      - pattern: foo($X, ..., $Y)
      - focus-metavariable:
        - $X
        - $Y
```

This syntax enables Semgrep to match these metavariables regardless of their position in code. See the following example:

<iframe src="https://semgrep.dev/embed/editor?snippet=D602" border="0" frameBorder="0" width="100%" height="432"></iframe>

:::tip
Among many use cases, the **set union** syntax allows you to simplify taint analysis rule writing. For example, see the following rule:
<iframe src="https://semgrep.dev/embed/editor?snippet=w6Qx" border="0" frameBorder="0" width="100%" height="432"></iframe>
:::

<!-- Once this feature is no longer experimental, move the text under the ### `focus-metavariable` to docs/writing-rules/rule-syntax.md and change the # Using multiple focus metavariables header to level 4 (####) -->
````

### `experiments\pattern-syntax.md`

````markdown
---
slug: pattern-syntax
title: Pattern syntax (Experimental)
hide_title: true
description: Learn how to use Semgrep's experimental pattern syntax to search code for a specific code pattern.
tags:
  - Rules
  - Semgrep Code
---


## Pattern syntax (experimental)

Patterns are the expressions Semgrep uses to match code when it scans for vulnerabilities. This article describes the new syntax for Semgrep pattern operators. See [Pattern syntax](/writing-rules/pattern-syntax) for information on the existing pattern syntax.

There is often a one-to-one translation from the existing syntax to the experimental syntax. These changes are marked with <i class= "fa-solid fa-diamond"></i>. However, some changes are quite different. These changes are marked with <i class="fa-solid fa-exclamation"></i>

:::warning

* These patterns are **experimental** and subject to change.
* You can't mix and match existing pattern syntax with the experimental syntax.

:::

## <i class="fa-solid fa-exclamation"></i> `pattern`

The `pattern` operator looks for code matching its expression in the existing syntax. However, `pattern` is no longer required when using the experimental syntax. For example, you can use `...` wherever `pattern: "...``` appears. For example, you can omit`pattern` and write the following:

```yaml
any:
  - "badthing1"
  - "badthing2"
  - "badthing3"
```

or, for multi-line patterns

```yaml
any:
  - |
      manylines(
        badthinghere($A)
      )
  - |
      orshort()
```

You don't need double quotes for a single-line pattern when omitting the `pattern` key, but note that this can cause YAML parsing issues.

As an example, the following YAML parses:

```yaml
any:
  - "def foo(): ..."
```

This, however, causes problems since `:` is also used to denote a YAML dictionary:

```yaml
any:
  - def foo(): ...
```

### <i class="fa-solid fa-diamond"></i> `any`

Replaces [pattern-either](/writing-rules/rule-syntax/#pattern-either). Matches any of the patterns specified.

```yaml
any:
  - <pat1>
  - <pat2>
    ...
  - <patn>
```

### <i class="fa-solid fa-diamond"></i> `all`

Replaces [patterns](/writing-rules/rule-syntax/#patterns). Matches all of the patterns specified.

```yaml
all:
  - <pat1>
  - <pat2>
    ...
  - <patn>
```

### <i class="fa-solid fa-diamond"></i> `inside`

Replaces [pattern-inside](/writing-rules/rule-syntax/#pattern-inside). Match any of the sub-patterns inside of the primary pattern.

```yaml
inside:
  any:
    - <pat1>
    - <pat2>
```

Alternatively:

```yaml
any:
  - inside: <pat1>
  - inside: <pat2>
```

### <i class="fa-solid fa-diamond"></i> `not`

Replaces [pattern-not](/writing-rules/rule-syntax/#pattern-not). Accepts any pattern and does **not** match on those patterns.

```yaml
not:
  any:
    - <pat1>
    - <pat2>
```

Alternatively:

```yaml
all:
  - not: <pat1>
  - not: <pat2>
```

### <i class="fa-solid fa-diamond"></i> `regex`

Replaces [pattern-regex](/writing-rules/rule-syntax/#pattern-regex) Matches based on the regex provided.

```yaml
regex: "(.*)"
```

## Metavariables

Metavariables are an abstraction to match code when you don't know the value or contents beforehand. They're similar to [capture groups](https://regexone.com/lesson/capturing_groups) in regular expressions and can track values across a specific code scope. This
includes variables, functions, arguments, classes, object methods, imports,
exceptions, and more.

Metavariables begin with a `$` and can only contain uppercase characters, `_`, or digits. Names like `$x` or `$some_value` are invalid. Examples of valid metavariables include `$X`, `$WIDGET`, or `$USERS_2`.

### <i class="fa-solid fa-exclamation"></i> `where`

Unlike Semgrep's existing pattern syntax, the following operators no longer occur under `pattern` or `all`:

* `metavariable-pattern`
* `metavariable-regex`
* `metavariable-comparison`
* `metavariable-analysis`
* `focus-metavariable`

These operators must occur within a `where` clause.

A `where` clause is required in a pattern where you're using metavariable operators. It indicates that Semgrep should match based on the pattern if all the conditions are true.

As an example, take a look at the following example:

```yaml
all:
  - inside: |
      def $FUNC(...):
        ...
  - |
      eval($X)
where:
  - <condition>
```

Because the `where` clause is on the same indentation level as `all`, Semgrep understands that everything under `where` must be paired with the entire `all` pattern. As such, the results of the ranges matched by the `all` pattern are modified by the `where` pattern, and the output includes some final set of ranges that are matched.

### <i class="fa-solid fa-diamond"></i> `metavariable`

Replaces:

* [metavariable-regex](/writing-rules/rule-syntax/#metavariable-regex)
* [metavariable-pattern](/writing-rules/rule-syntax/#metavariable-pattern)
* [metavariable-analysis](/writing-rules/metavariable-analysis)

This operator looks inside the metavariable for a match.

```yaml
...
where:
  - metavariable: $A
    regex: "(.*)
  - metavariable: $B
    patterns: |
      - "foo($C)"
  - metavariable: $D
    analyzer: entropy
```

### <i class="fa-solid fa-diamond"></i> `comparison`

Replaces [metavariable-comparison](/writing-rules/rule-syntax/#metavariable-comparison). Compares metavariables against a basic [Python comparison](https://docs.python.org/3/reference/expressions.html#comparisons) expression.

```yaml
...
where:
  - comparison: $A == $B
```

### <i class="fa-solid fa-diamond"></i> `focus`

Replaces [focus-metavariable](/writing-rules/rule-syntax/#focus-metavariable). Puts focus on the code region matched by a single metavariable or a list of metavariables.

```yaml
...
where:
  - focus: $A
```

## <i class="fa-solid fa-exclamation"></i> `as-metavariable`

> `as-metavariable` is only available in the new syntax.

`as-metavariable` is a rule-writing feature that bridges the gap between metavariables and matches. Metavariables get access to things like `metavariable-comparison`, `metavariable-regex`, and `metavariable-pattern`, but you can’t use them on arbitrary matches. However, the `as` operator lets you embed arbitrary matches into metavariables, or bind arbitrary matches to a name.

The syntax is as follows:

```yaml
all:
  - pattern: |
    @decorator
    def $FUNC(...):
      ...
  as: $DECORATED_FUNC
```

Since `as` appears in the same indentation as the `pattern`, Semgrep couples the two. This augmented `pattern` operator matches the enclosed pattern, but produces an environment where `$DECORATED_FUNC` is bound to the match it corresponds to. So for instance, the following rule:

```yaml
match:
  pattern: |
    @decorator
    def $FUNC(...):
      ...
  as: $DECORATED_FUNC
fix: |
  @another_decorator
  $DECORATED_FUNC
```

Allows you to capture the decorated function. You can then use it in, for example, autofix's metavariable or metavariable ellipses interpolation, where you express something like "rewrite X, but with Y."

## <i class="fa-solid fa-exclamation"></i> Syntax search mode

New syntax search mode rules must be nested underneath a top-level `match` key. For example:

```yaml
rules:
  - id: find-bad-stuff
    severity: ERROR
    languages: [python]
    message: |
      Don't put bad stuff!
    match:
      any:
        - |
            eval(input())
        - all:
            - inside: |
                def $FUNC(..., $X, ...):
                  ...
            - |
                eval($X)
```

## <i class="fa-solid fa-exclamation"></i> Taint mode

The new syntax supports taint mode, and such roles no longer require `mode: taint` in the rule. Instead, everything must be nested under a top-level `taint` key.

```yaml
rules:
  - id: find-bad-stuff
    severity: ERROR
    languages: [python]
    message: |
      Don't put bad stuff!
    taint:
      sources:
        - input()
      sinks:
        - eval(...)
      propagators:
        - pattern: |
            $X = $Y
          from: $Y
          to: $X
      sanitizers:
        - magiccleanfunction(...)
```

### <i class="fa-solid fa-diamond"></i> Taint mode key names

The key names for the new syntax taint rules are as follows:

* `pattern-sources` --> sources
* `pattern-sinks` --> sinks
* `pattern-propagators` --> propagators
* `pattern-sanitizers` --> sanitizers
````

### `experiments\project-depends-on.md`

````markdown
---
slug: r2c-internal-project-depends-on
append_help_link: true
description: "r2c-internal-project-depends-on lets Semgrep rules only return results if the project depends on a specific version of a third-party package."
---

# r2c-internal-project-depends-on

This Semgrep rules key allows specifying third-party dependencies along with the semver (semantic version) range that should trigger the rule. The `r2c-internal-project-depends-on` filters the rule unless one of the children is matched by a lockfile.

We welcome external contributors to try out the key, but keep in mind there's no expectation of stability across releases yet. **The API and behavior of this feature is subject to change**.

In the rules.yaml, specify `r2c-internal-project-depends-on` key either as a dependency, or a sequence of dependencies with `depends-on-either` key (see the example below).

A dependency consists of three keys:

* `namespace`: The package registry where the third-party dependency is found.
* `package`: The name of the third-party dependency as it appears in the lockfile.
* `version`: A semantic version range. Uses [Python packaging specifiers](https://packaging.pypa.io/en/latest/specifiers.html) which support almost all NPM operators, except for `^`.

So a `r2c-internal-project-depends-on` key will either look like this:

```yaml
r2c-internal-project-depends-on:
  namespace: ...
  package: ...
  version: ...
```

Or it can have the following layout with `depends-on-either`:

```yaml
r2c-internal-project-depends-on:
  depends-on-either:
    - namespace: ...
      package: ...
      version: ...
    - namespace: ...
      package: ...
      version: ...
    ...
```

## Example

Here is an example `r2c-internal-project-depends-on` rule that searches for a known vulnerable version of the AWS CLI from April 2017, but only reports the vulnerability if the `s3` module (where the vulnerability is located) is actually used:

```yaml
rules:
- id: vulnerable-awscli-apr-2017
  severity: WARNING
  pattern-either:
  - pattern: boto3.resource('s3', ...)
  - pattern: boto3.client('s3', ...)
  r2c-internal-project-depends-on:
    namespace: pypi
    package: awscli
    version: "<= 1.11.82"
  message: this version of awscli is subject to a directory traversal vulnerability in the s3 module
  languages: [python]
```

## Findings of r2c-internal-project-depends-on

Findings produced by rules with the `r2c-internal-project-depends-on` can be of two types: _reachable_ and _nonreachable_.

* A _reachable_ finding is one with both a dependency match and a pattern match: a vulnerable dependency was found and the vulnerable part of the dependency (according to the patterns in the rule) is used somewhere in the code.
* An _unreachable_ finding is one with only a dependency match. Reachable findings are reported as coming from the code that was pattern matched. Unreachable findings are reported as coming from the lockfile that was dependency matched. For both types of findings, Semgrep specifies whether they are unreachable or reachable along with all matched dependencies, in the `extra` field of Semgrep's JSON output, using the `dependency_match_only` and `dependency_matches` fields, respectively.

A finding is only considered reachable if the file containing the pattern match actually depends on the dependencies in the lockfile containing the dependency match. A file depends on a lockfile if it is the nearest lockfile going up the directory tree.

## r2c-internal-project-depends-on language support

| Language   | Namespace  | Scans dependencies from          |
|:---------- |:-----------|:---------------------------------|
| Python     | pypi       | `Pipfile.lock`                   |
| JavaScript | npm        | `yarn.lock`, `package-lock.json` |
| Java       | maven      | `pom.xml`                        |
| Go         | gomod      | `go.mod`                         |
| Ruby       | gem        | `Gemfile.lock`                   |
| Rust       | cargo      | `cargo.lock`                     |

## Limitations

Dependency resolution uses the source of dependency information with the _least amount of ambiguity_ available. For all supported languages except Java, the _least amount of ambiguity_ provides a lockfile, which lists exact version information for each dependency that a project uses. Dependency resolution does not scan, for example, `package.json` files, because they can contain version ranges. In the case of Java, Maven does not support the creation of lockfiles, so `pom.xml` is the least ambiguous source of information we have, and we consider only dependencies listed with exact versions.
````

### `experiments\symbolic-propagation.md`

````markdown
---
slug: symbolic-propagation
append_help_link: true
description: "Symbolic propagation allows Semgrep to perform matching modulo variable assignments."
---

# Symbolic propagation

Symbolic propagation allows Semgrep to perform matching modulo variable assignments. Consider the following Python code:

```python
import pandas

def test1():
    # ruleid: test
    pandas.DataFrame(x).index.set_value(a, b, c)

def test2():
    df = pandas.DataFrame(x)
    ix = df.index
    # ruleid: test
    ix.set_value(a, b, c)
```

If we tried to match the pattern `pandas.DataFrame(...).index.set_value(...)` against the above code, Semgrep would normally match `test1` but not `test2`. It does not match `test2` because there are intermediate assignments, and Semgrep does not know that `ix` is equals to `df.index` or that `df` is equals to `pandas.DataFrame(x)`. If we wanted Semgrep to match such code, we had to be explicit about it.

Symbolic propagation is a generalization of [constant propagation](/writing-rules/data-flow/constant-propagation) that addresses this limitation. It enables Semgrep to perform matching modulo variable assignments. Thus, Semgrep is then able to match both `test1` and `test2` with the same simple pattern. This feature needs to be enabled explicitly via rule `options:` by setting `symbolic_propagation: true`.

<iframe src="https://semgrep.dev/embed/editor?snippet=JeBP" border="0" frameBorder="0" width="100%" height="432"></iframe>

## Limitations of symbolic propagation

Currently, symbolic propagation does not cross branching boundaries, such as `if` clauses or loops. Consider the following Python code, adapted from the example shown above:

```python
import pandas

def test1():
    # ruleid: test
    pandas.DataFrame(x).index.set_value(a, b, c)

def test2():
    if (x < 5):
        df = pandas.DataFrame(x)
        pass
    ix = df.index
    # ruleid: test
    ix.set_value(a, b, c)
```

In this case, even if `symbolic_propagation: true` is used, Semgrep does not match `test2`, because the assignment of `df` to `pandas.DataFrame(x)` is not propagated over the conditional to the final two lines.
````

### `experiments\join-mode\overview.md`

````markdown
---
id: overview
append_help_link: true
description: "Join mode runs several Semgrep rules at once and only returns results if certain conditions on the results are met."
---

# Join mode overview

Join mode runs several Semgrep rules at once and only returns results if certain conditions on the results are met. Semgrep OSS Engine is brilliant for finding code patterns with an easy syntax, but its search is typically limited to single files. Join mode is an experimental mode that lets you cross file boundaries, allowing you to write rules for whole code bases instead of individual files. As the name implies, this was inspired by join clauses in SQL queries.

Think of join mode like this: distinct Semgrep rules are used to gather information about a code base. Then, the conditions you define are used to select specific results from these rules, and the selected results are reported by Semgrep. You can join results on metavariable contents or on the result's file path.

:::info
You can also use cross-file (interfile) analysis. For more information, see [<i class="fa-regular fa-file-lines"></i> Perform cross-file analysis](/semgrep-code/semgrep-pro-engine-intro).
:::

## Example

Here’s an example join mode rule that detects a cross-site scripting (XSS) vulnerability with high precision.

```yaml
rules:
- id: flask-likely-xss
  mode: join
  join:
    refs:
      - rule: flask-user-input.yaml
        as: user-input
      - rule: unescaped-template-extension.yaml
        as: unescaped-extensions
      - rule: any-template-var.yaml
        renames:
        - from: '$...EXPR'
          to: '$VAR'
        as: template-vars
    on:
    - 'user-input.$VAR == unescaped-extensions.$VALUE'
    - 'unescaped-extensions.$VAR == template-vars.$VAR'
    - 'unescaped-extensions.$PATH > template-vars.path'
  message: |
    Detected a XSS vulnerability: '$VAR' is rendered
    unsafely in '$PATH'.
  severity: ERROR
```

Let's explore how this works. First, some background on the vulnerability. Second, we'll walk through the join mode rule.

**Vulnerability background:**

In Flask, templates are only HTML-escaped if the [template file ends with the `.html` extension](https://flask.palletsprojects.com/en/2.0.x/templating/#jinja-setup). Therefore, detecting these two conditions present in a Flask application is a high indicator of

1. User input directly enters a template without the `.html` extension
2. The user input is directly rendered in the template

**Join mode rule explanation:**

Now, let's turn these conditions into the join mode rule.  We need to find three code patterns:

1. User input
2. Templates without the `.html` extension
3. Variables rendered in a template

We can write individual Semgrep rules for each of these code patterns.

```yaml
rules:
- id: flask-user-input
  languages: [python]
  severity: INFO
  message: $VAR
  pattern: '$VAR = flask.request.$SOMETHING.get(...)'
```

```yaml
rules:
- id: unescaped-template-extension
  message: |
    Flask does not automatically escape Jinja templates unless they have
    .html as an extension. This could lead to XSS attacks.
  patterns:
  - pattern: flask.render_template("$PATH", ..., $VAR=$VALUE, ...)
  - metavariable-pattern:
      metavariable: $PATH
      language: generic
      patterns:
      - pattern-not-regex: .*\.html$
  languages: [python]
  severity: WARNING
```

```yaml
rules:
- id: any-template-var
  languages: [generic]
  severity: INFO
  message: '$...EXPR'
  pattern: '{{ $...EXPR }}'
```

Finally, we want to "join" the results from these together. Below are the join conditions, in plain language.

1. The variable `$VAR` from `flask-user-input` has the same content as the value `$VALUE` from `unescaped-template-extension`
2. The keyword argument `$VAR` from `unescaped-template-extension` has the same content as `$...EXPR` from `any-template-var`
3. The template file name `$PATH` from `unescaped-template-extension` is a substring of the file path of a result from `any-template-var`

We can translate these roughly into the following condition statements.

```
- 'user-input.$VAR == unescaped-extensions.$VALUE'
- 'unescaped-extensions.$VAR == template-vars.$VAR'
- 'unescaped-extensions.$PATH > template-vars.path'
```

Combining the three code pattern Semgrep rules and the three conditions gives us the join rule at the top of this section. This rule matches the code displayed below.

![Screenshot of code the join rule matches](/img/join-mode-example.png)

```bash
> semgrep -f flask-likely-xss.yaml
running 1 rules...
running 3 rules...
ran 3 rules on 16 files: 14 findings
matching...
matching done.
./templates/launch.htm.j2
severity:error rule:flask-likely-xss: Detected a XSS vulnerability: '$VAR' is rendered unsafely in '$PATH'.
9: <li>person_name_full is <b>{{ person_name_full }}</b></li>
```

**Helpers:**

For convenience, when writing a join mode rule, you can use the `renames` and `as` keys.

The `renames` key lets you rename metavariables from one rule to something else in your conditions. **This is necessary for named expressions, e.g., `$...EXPR`.**

The `as` key behaves similarly to `AS` clauses in SQL. This lets you rename the result set for use in the conditions. If the `as` key is not specified, the result set uses the **rule ID**.

## Syntax

### `join`

The `join` key is required when in join mode. This is just a top-level key that groups the join rule parts together.

#### Inline rule example

The following rule attempts to detect cross-site scripting in a Flask application by checking whether a template variable is rendered unsafely through Python code.

```yaml
rules:
- id: flask-likely-xss
  mode: join
  join:
    rules:
      - id: user-input
        pattern: |
          $VAR = flask.request.$SOMETHING.get(...)
        languages: [python]
      - id: unescaped-extensions
        languages: [python]
        patterns:
        - pattern: |
            flask.render_template("$TEMPLATE", ..., $KWARG=$VAR, ...)
        - metavariable-pattern:
            metavariable: $TEMPLATE
            language: generic
            patterns:
            - pattern-not-regex: .*\.html$
      - id: template-vars
        languages: [generic]
        pattern: |
          {{ $VAR }}
    on:
    - 'user-input.$VAR == unescaped-extensions.$VAR'
    - 'unescaped-extensions.$KWARG == template-vars.$VAR'
    - 'unescaped-extensions.$TEMPLATE < template-vars.path'
  message: |
    Detected a XSS vulnerability: '$VAR' is rendered
    unsafely in '$TEMPLATE'.
  severity: ERROR
```

The required fields under the `rules` key are the following:

- `id`
- `languages`
- A set of `pattern` clauses.

The optional fields under the `rules` key are the following:

- `message`
- `severity`

:::note
Refer to the metavariables captured by the rule in the `on` conditions by the rule `id`. For inline rules, aliases do **not** work.
:::

### `refs`

Short for references, `refs` is a list of external rules that make up your code patterns. Each entry in `refs` is an object with the required key `rule` and optional keys `renames` and `as`.

### `rule`

Used with `refs`, `rule` points to an external rule location to use in this join rule. Even though Semgrep rule files can typically contain multiple rules under the `rules` key, join mode **only uses the first rule in the provided file**.

Anything that works with `semgrep --config <here>` also works as the value for `rule`.

### `renames`

An optional key for an object in `refs`, `renames` renames the metavariables from the associated `rule`. The value of `renames` is a list of objects whose keys are `from` and `to`. The `from` key specifies the metavariable to rename, and the `to` key specifies the new name of the metavariable.

:::warning
Renaming is necessary for named expressions, e.g., `$...EXPR`.
:::

### `as`

An optional key for an object in `refs`, `as` lets you specify an alias for the results collected by this rule for use in the `on` conditions. Without the `as` key, the default name for the results collected by this rule is the rule ID of the rule in `rule`. If you use `as`, the results can be referenced using the alias specified by `as`.

### `on`

The `on` key is required in join mode. This is where the join conditions are listed. The value of `on` is a list of strings which have the format:

```
<result_set>.<property> <operator> <result_set>.<property>
```

`result_set` is the name of the result set produced by one of the `refs`. See the `as` key for more information.

`property` is either a metavariable, such as `$VAR`, or the keyword `path`, which returns the path of the finding.

`operator` is one of the following.

| Operator | Example                                             | Description                                                            |
| -------- | --------------------------------------------------- | ---------------------------------------------------------------------- |
| `==`     | `secret-env-var.$VALUE == log-statement.$FORMATVAR` | Matches when the contents of both sides are exactly equal.             |
| `!=`     | `url-allowlist.$URL != get-request.$URL`            | Matches when the contents of both sides are not equal.                 |
| `<`      | `template-var.path < unsafe-template.$PATH`         | Matches when the right-hand side is a substring of the left-hand side. |
| `>`      | `unsafe-template.$PATH > template-var.path`         | Matches when the left-hand side is a substring of the right-hand side. |

## Limitations

Join mode **is not taint mode**! While it can look on the surface like join mode is "connecting" things together, it is actually just creating sets for each Semgrep rule and returning all the results that meet the conditions. This means some false positives will occur if unrelated metavariable contents happen to have the same value.

To use join mode with `refs`, you must define your individual Semgrep rules in independent locations. This can be anything that works with `semgrep --config <here>`, such as a file, a URL, or a Semgrep registry pointer like `r/java.lang.security.some.rule.id`.

Join mode does not work in the Semgrep Playground or Semgrep Editor, as it is an experimental feature.

Currently, join mode only reports the code location of the **last finding that matches the conditions**. Join mode parses the conditions from top-to-bottom, left-to-right. This means that findings from the "bottom-right" condition become the reported code location.

## More ideas

Join mode effectively lets you ask questions of entire code bases. Here are some examples of the kinds of questions you can use join mode to answer.

- Do any of my dependencies use `dangerouslySetInnerHTML`, and do I directly import that dependency?
- Does a key in this JSON file have a dangerous value, and do I load this JSON file and use the key in a dangerous function?
- Is an unsafe variable rendered in an HTML template?
````

### `experiments\join-mode\recursive-joins.md`

````markdown
# Recursive joins

Join mode is an extension of Semgrep that runs multiple rules at once and only returns results if certain conditions are met. This is an experimental mode that enables you to cross file boundaries, allowing you to write rules for whole codebases instead of individual files. More information is available in [Join mode overview](/writing-rules/experiments/join-mode/overview).

Recursive join mode has a recursive operator, `-->`, which executes a recursive query on the given condition. This recursive operator allows you to write a Semgrep rule that effectively crawls the codebase on a condition you specify, letting you build chains such as function call chains or class inheritance chains.

## Understanding recursive join mode

In the background, join rules turn captured metavariables into database table columns. For example, a rule with $FUNCTIONNAME, $FUNCTIONCALLED, and $PARAMETER is a table similar to the following:

| $FUNCTIONNAME | $FUNCTIONCALLED | $PARAMETER   |
|---------------|-----------------|--------------|
| getName       | writeOutput     | user         |
| getName       | lookupUser      | uid          |
| lookupUser    | databaseQuery   | uid          |

The join conditions then join various tables together and return a result if any rows match the criteria.

Recursive join mode conditions use [recursive joins](https://www.sqlite.org/lang_with.html#recursive_common_table_expressions) to construct a table that recursively joins with itself. For example, you can use a Semgrep rule that gets all function calls and join them recursively to approximate a callgraph.

Consider the following Python script and rule.

```python
def function_1():
    print("hello")
    function_2()

def function_2():
    function_4()

def function_3():
    function_5()

def function_4():
    function_5()

def function_5():
    print("goodbye")
```

```yaml
rules:
- id: python-callgraph
  message: python callgraph
  languages: [python]
  severity: INFO
  pattern: |
    def $CALLER(...):
      ...
      $CALLEE(...)
```

A join condition such as the following: `python-callgraph.$CALLER --> python-callgraph.$CALLEE` produces a table below. Notice how `function_1` appears with `function_4` and `function_5` as callees, even though it is not directly called.

| $CALLER  | $CALLEE  |
|----------|----------|
|function_1|function_2|
|function_1|function_4|
|function_1|function_5|
|function_1|print     |
|function_2|function_4|
|function_2|function_5|
|function_3|function_5|
|function_4|function_5|
|function_5|print     |

## Example rule

It's important to think of a join mode rule as "asking questions about the whole project", rather than looking for a single pattern. For example, to find an SQL injection, you need to understand a few things about the project:

1. Is there any user input?
1. Do any functions manually build an SQL string using function input?
1. Can the user input reach the function that manually builds the SQL string?

Now, you can write individual Semgrep rules that gather information about each of these questions. This example uses [Vulnado](https://github.com/ScaleSec/vulnado) for finding an SQL injection. Vulnado is a Spring application.

The first rule searches for user input into the Spring application. This rule also captures sinks that use a user-inputtable parameter as an argument.

```yaml
rules:
- id: java-spring-user-input
  message: user input
  languages: [java]
  severity: INFO
  mode: taint
  pattern-sources:
  - pattern: |
      @RequestMapping(...)
      $RETURNTYPE $USERINPUTMETHOD(..., $TYPE $PARAMETER, ...) {
        ...
      }
  pattern-sinks:
  - patterns:
    - pattern: $OBJ.$SINK(...)
    - pattern: $PARAMETER
```

A second rule looks for all methods in the application that build an SQL string with a method parameter.

```yaml
rules:
- id: method-parameter-formatted-sql
  message: method uses parameter for sql string
  languages: [java]
  severity: INFO
  patterns:
  - pattern-inside: |
      $RETURNTYPE $METHODNAME(..., $TYPE $PARAMETER, ...) {
        ...
      }
  - patterns:
    - pattern-either:
      - pattern: |
          "$SQLSTATEMENT" + $PARAMETER
      - pattern: |
          String.format("$SQLSTATEMENT", ..., $PARAMETER, ...)
    - metavariable-regex:
        metavariable: $SQLSTATEMENT
        regex: (?i)(select|delete|insert).*
```

Finally, the third rule is used to construct a pseudo-callgraph:

```yaml
rules:
- id: java-callgraph
  languages: [java]
  severity: INFO
  message: $CALLER calls $OBJ.$CALLEE
  patterns:
  - pattern-inside: |
      $TYPE $CALLER(...) {
        ...
      }
  - pattern: $OBJ.$CALLEE(...)
```

The join rule, is displayed as follows:

```yaml
rules:
- id: spring-sql-injection
  message: SQLi
  severity: ERROR
  mode: join
  join:
    refs:
    - rule: rule_parts/java-spring-user-input.yaml
      as: user-input
    - rule: rule_parts/method-parameter-formatted-sql.yaml
      as: formatted-sql
    - rule: rule_parts/java-callgraph.yaml
      as: callgraph
    on:
    - 'callgraph.$CALLER --> callgraph.$CALLEE'
    - 'user-input.$SINK == callgraph.$CALLER'
    - 'callgraph.$CALLEE == formatted-sql.$METHODNAME'
```

The `on:` conditions, in order, read as follows:

- Recursively generate a pseudo callgraph on $CALLER to $CALLEE.
- Match when a method with user input has a $SINK that is the $CALLER in the pseudo-callgraph.
- Match when the $CALLEE is the $METHODNAME of a method that uses a parameter to construct an SQL string.

Running this on Vulnado produces tables that look like this:

|$RETURNTYPE |$USERINPUTMETHOD |$TYPE      |$PARAMETER  |$OBJ     |$SINK       |
|------------|-----------------|-----------|------------|---------|------------|
|...         |...              |...        | ...        |...      |...         |
|LoginResponse|login           |LoginRequest|input      |user     |token       |
|LoginResponse|login           |LoginRequest|input      |User     |getUser     |
|...         |...              |...        | ...        |...      |...         |

| $RETURNTYPE | $METHODNAME | $TYPE  | $PARAMETER | $SQLSTATEMENT                          |
| ----------- | ----------- | ------ | ---------- | -------------------------------------- |
| ...         | ...         | ...    | ...        | ...                                    |
| User        | fetch       | String | un         | select * from users where username = ' |
| ...         | ...         | ...    | ...        | ...                                    |

|$CALLER    |$CALLEE    |
|-----------|-----------|
|...        |...        |
|login      |getUser    |
|login      |fetch      |
|getUser    |fetch      |
|...        |...        |

The join conditions select rows which meet the conditions.

- Match when a method with user input has a $SINK that is the $CALLER in the pseudo-callgraph.

| ... | user-input.$SINK | == | callgraph.$CALLER | ... |
| --- | ---------------- | -- | ----------------- | --- |
| ... | getUser          | == | getUser           | ... |

- Match when the $CALLEE is the $METHODNAME of a method that uses a parameter to construct an SQL string.

| ... | callgraph.$CALLEE | == | formatted-sql.$METHODNAME | ... |
| --- | ----------------- | -- | ------------------------- | --- |
| ... | fetch             | == | fetch                     | ... |

```console
(semgrep) ➜  join_mode_demo semgrep -f vulnado-sqli.yaml vulnado
Running 1 rules...
Running 3 rules...
100%|██████████████████████████|3/3
ran 3 rules on 11 files: 158 findings
vulnado/src/main/java/com/scalesec/vulnado/User.java
rule:spring-sql-injection: SQLi
55:      String query = "select * from users where username = '" + un + "' limit 1";
ran 0 rules on 0 files: 1 findings
```

## Limitations

Join mode only works on the metavariable contents, which means it's fundamentally operating with text strings and not code constructs. There will be some false positives if similarly-named metavariables are extracted.

## Use cases

- Approximating callgraphs in a project
- Approximating class inheritance
````

"""

END GUIDE

## OUTPUT INSTRUCTIONS

- Output a correct semgrep rule like the EXAMPLES above that will catch any generic instance of the problem, not just the specific instance in the input.
- Do not overfit on the specific example in the input. Make it a proper Semgrep rule that will capture the general case.
- Do not output warnings or notes—just the requested sections.

## INPUT

INPUT:
