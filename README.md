# tem: DNS TAPIR Edge Manager

TEM is responsible for the task of integrating all intelligence sources
into a single RPZ that is as compact as possible.

I.e. rather than feeding the resolver multiple sources of data from
which to look for policy guidance, where sources can even be conflicting
(eg. a domainname may be flagged by one source but whitelisted by another),
TEM presents a single output with all conflicts resolved. The result is
also smaller, as no whitelisting informstion is needed for the resolver.

In addition TEM is able to apply further policy to the intelligence data,
based on a local policy configuration. To enable the resolver operator to
design a suitable threat policy TEM uses a number of concepts:

* lists: there are three types of lists of domain names: 
  - whitelists (names that must not be blocked)
  - blacklists (names that must be blocked)
  - greylists (names that should perhaps be blocked)

* tags: these are attributes of a suspicious domain name. In reality
  whether a particular domain name should be blocked or not is not an
  absolute, it is a question of propabilities. Therefore, rather than
  a binary directive, "this name must be blocked", some intelligence
  sources, including DNS TAPIR, present the resolver operator with 
  observed attributes of the name. Examples include: the name has only
  been observed on the Internet for a short time, the name draws huge
  query traffic, the name resolves to an IP address known to host bad
  things, etc.

* sources: TEM supports the following types of sources for intelligence data:
  - RPZ: imported via AXFR or IXFR. TEM understands DNS NOTIFY.
  - MQTT: DNS TAPIR Analyser sends out rapid updates for small numbers
    of names via an MQTT message bus infrastructure.
  - DAWG: Directed Acyclic Word Graphs are extremely compact data structures.
    TEM is able to mmap very large lists in DAWG format which is used for
    large whitelists.
  - Files: Text files on local disk, either with just domain names, or in
    CSV format are supported.
  - HTTPS: To bootstrap an intelligence feed that only distributes deltas 
    (like DNS TAPIR, over MQTT), TEM can bootstrap the current state of the
    complete feed via HTTPS. [NYI]

* outputs: TEM outputs RPZ to one or several recipients. Both AXFR and IXFR
  is supported.

The resulting policy has the following structure (in order of precedence):

* no whitelisted name is ever included.
* blacklisted names are always included, together with a configurable
  RPZ action.
* greylisted names that have particular tags that the resolver operator
  chooses are included, together with a configurable RPZ action.
* the same greylisted name that appear in N distinct intelligence feeds
  is included, where N is configureable, as is the RPZ action.
* a greylisted name that has M or more tags is included, where both
  M and the action are configureable.