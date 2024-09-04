### TAPIR-POP INSTALLATION

TAPIR-POP is most commonly installed as a Docker container, but it can also be run as a separate binary. 
This document focuses on the latter alternative.

## Building TAPIR-POP

Two DNS TAPIR github repositories are relevant to the installation of TAPIR-POP:

* [tapir-pop](https://github.com/dnstapir/tapir-pop) - contains the TAPIR-POP server

TAPIR-POP relies heavily on code from the [tapir](https://github.com/dnstapir/tapir) repository.

Commands to build the TAPIR-POP service are:

```
git clone https://github.com/dnstapir/tapir-pop
cd tapir-pop
go mod tidy
make
[examine and edit the Makefile to set the INSTALL_DIR to something other than /usr/local/libexec]
make install
```

## Configuring TAPIR-POP

By default, TAPIR-POP will look for a configuration files in the directory `/etc/dnstapir`. The primary configuration file is `/etc/dnstapir/tapir-pop.yaml`. If the file is not found, the program will terminate with an error.

In addition to the main configuration file, TAPIR-POP will look for a three more configuration files:

* `/etc/dnstapir/pop-sources.yaml` - contains the configuration for the sources of data that TAPIR-POP will use for policy decisions.
* `/etc/dnstapir/pop-policy.yaml` - contains the local policy configuration for TAPIR-POP. This is instructions for what conditions must be met for a domain name to be filtered.
* `/etc/dnstapir/pop-outputs.yaml` - contains the configuration for various outputs that TAPIR-POP will use. The primary output is always a DNS RPZ zone that is sent to a "downstream" DNS resolver. Additional outputs may be configured, such as more RPZ targets and a local MQTT reflector (to enable local monitoring of the observations that arrive from TAPIR-CORE).

The configuration files are described in their own README files.

## Connecting TAPIR-POP to TAPIR-CORE

The primary requisite is a client certificate and key for the TAPIR-POP server issued by the TAPIR-CORE CA. To obtain these, run the script
`generate-csr.sh` and follow the instructions. The script is only a few lines long and is easy to follow. It takes one parameter, which is a TAPIR "instance id". This is needed to ensure that the CSR is unique.

The result is a file named `tapir-instance-id.csr` and a file named `tapir-instance-id.key`. The CSR file is sent manually to the TAPIR-CORE for signing and in return the TAPIR-CORE will return a signed certificate in a file named `tapir-instance-id.crt`.

The next step is to configure TAPIR-POP with the location of the TAPIR-CORE server, the CA certificate, and the signed certificate. This is done with the `tapir-pop.toml` configuration file.

## Running TAPIR-POP

Before starting TAPIR-POP, ensure that the TAPIR-CLI utility is built and installed:

* [tapir-cli](https://github.com/dnstapir/tapir-cli) - contains the TAPIR-CLI utility that is used to interact with the TAPIR-POP service.

TAPIR-CLI is described in its own README and installation instructions.

When the TAPIR-CLI utility is installed, the TAPIR-POP service can be started with the following command:

```
tapir-pop -v &
```

## Examining the TAPIR-POP logs

By default several log files are created in the `/var/log/dnstapir` directory. The log files are named `tapir-pop.log`, `pop-policy.log`, 
`pop-dnsengine.log` and `pop-mqtt.log`. 