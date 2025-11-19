# dnstapir-pop: DNS TAPIR Policy Processor

The *DNS TAPIR Policy Processor*, dnstapir-pop, is the component that processes the intelligence data from the DNS TAPIR Core
(and possibly other sources) and applies local policy to reach a filtering decision. 

It is the connection between the core and the
edge platform. It manages local configurations and gets updates from
the core with alerts and config changes.

dnstapir-pop is responsible for the task of integrating all intelligence sources
into a single Response Policy Zone (RPZ) that is as compact as possible.
The RPZ file is used by the DNS resolver to implement blocklists and other
policy-related functions.

## A unified single RPZ zone instead of multiple sources

dnstapir-pop presents a single output with all conflicts resolved,
rather than feeding the resolver multiple sources of data from
which to look for policy guidance, where sources can even be conflicting
(eg. a domainname may be flagged by one source but allowlisted by another).

The result is smaller, as no allowlisting information is needed for the resolver.

## dnstapir-pop supports a local policy configuration

dnstapir-pop is able to apply further policy to the intelligence data,
based on a local policy configuration. To enable the resolver operator to
design a suitable threat policy dnstapir-pop uses a number of concepts:

- __lists__: there are three types of lists of domain names:

  - allowlists (names that must not be blocked)
  - denylists (names that must be blocked)
  - doubtlists (names that should perhaps be blocked)

- __observations__: these are attributes of a suspicious domain name. In reality
  whether a particular domain name should be blocked or not is not an
  absolute, it is a question of propabilities. Therefore, rather than
  a binary directive, "this name must be blocked", some intelligence
  sources, including DNS TAPIR, present the resolver operator with
  observed attributes of the name. Examples include:

  - the name has only been observed on the Internet for a short time
  - the name draws huge query traffic
  - the name resolves to an IP address known to host bad
    things, etc.

- __sources__: TEM supports the following types of sources for intelligence data:
  - __RPZ__: imported via AXFR or IXFR. TEM understands DNS NOTIFY.
  - __MQTT__: DNS TAPIR Core Analyser sends out rapid updates for small numbers
    of names via an MQTT message bus infrastructure.
  - __DAWG__: Directed Acyclic Word Graphs are extremely compact data structures.
    TEM is able to mmap very large lists in DAWG format which is used for large allowlists.
  - __CSV Files__: Text files on local disk, either with just domain names, or in
    CSV format are supported.
  - __HTTPS__: To bootstrap an intelligence feed that only distributes deltas
    (like DNS TAPIR, over MQTT), dnstapir-pop can bootstrap the current state of the
    complete feed via HTTPS.

- __outputs__: dnstapir-pop outputs RPZ zones to one or several recipients. Both AXFR and IXFR
  is supported.

## Overview of the dnstapir-pop policy

The resulting policy has the following structure (in order of precedence):

- no allowlisted name is ever included.
- blocklisted names are always included, together with a configurable
  RPZ action.
- doubtlisted names that have particular tags that the resolver operator
  chooses are included, together with a configurable RPZ action.
- the same doubtlisted name that appear in N distinct intelligence feeds
  is included, where N is configureable, as is the RPZ action.
- a doubtlisted name that has M or more tags is included, where both
  M and the action are configurable.
