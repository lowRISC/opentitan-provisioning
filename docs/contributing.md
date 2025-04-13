## Contribution Guide

The ot-provisioning project follows the contribution guidelines of the
OpenTitan project. The following sections contain references to important
documents as well as some tips on how to adopt best practices.

## Contribution Guides

The following guides provide detailed guides on how to contribute to the
project:

*   [lowRISC Code of Conduct](https://lowrisc.org/code-of-conduct/)
*   [OpenTitan Lightweight Contribution Guide](https://docs.opentitan.org/doc/project/contributing/)
*   [OpenTitan In-depth Contribution Guide](https://docs.opentitan.org/doc/project/detailed_contribution_guide/)
*   [GitHub Notes | OpenTitan Documentation](https://docs.opentitan.org/doc/ug/github_notes/):
    Instructions on how to fork and configure the repository and manage pull
    requests from a git perspective.

## Style Guides

Style guides are enforced to ensure the repository meets uniform style
conventions. Code reviewers are responsible for enforcing these guidelines.

*   [C and C++ Coding Style Guide | OpenTitan Documentation](https://docs.opentitan.org/doc/sg/c_cpp_coding_style/)
*   [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
*   [Go Style Guide](https://google.github.io/styleguide/go/)
*   [Shell Style Guide](https://google.github.io/styleguide/shellguide.html)

The repository provides the following formatting utilities to automate the
application of some style guidelines:

```shell
# Format C++ code
bazelisk run clang_format

# Format Golang code
bazelisk run gofmt
```

## Code Review Practices

The following documents provide guidelines for commit authors and reviewers.
References to these best practices are used during code reviews to
capture the rationale behind the process.

* [Code Review Developer Guide](https://google.github.io/eng-practices/review/)
  * [The Code Reviewer’s Guide](https://google.github.io/eng-practices/review/reviewer/)
  * [The Change Author’s Guide](https://google.github.io/eng-practices/review/developer/)

## Read More

* [Documentation index](./README.md)