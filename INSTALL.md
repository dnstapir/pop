### TAPIR-POP INSTALLATION

TAPIR-POP is usually installed as a Docker container, but it can also be run as a separate binary. 
This document focuses on the latter alternative.

## Building TAPIR-POP

## Configuring TAPIR-POP

By default, TAPIR-POP will look for a configuration files in the directory `/etc/dnstapir`. The primary configuration file is `/etc/dnstapir/tapir-pop.yaml`. If the file is not found, the program will terminate with an error.

## Connecting TAPIR-POP to TAPIR-CORE

The primary requisite is a client certificate and key for the TAPIR-POP server issued by the TAPIR-CORE CA. To obtain these, run the script
`generate-csr.sh` and follow the instructions. The script is only a few lines long and is easy to follow. It takes one parameter, which is a TAPIR "instance id". This is needed to ensure that the CSR is unique.

The result is a file named `tapir-instance-id.csr` and a file named `tapir-instance-id.key`. The CSR file is sent manually to the TAPIR-CORE for signing and in return the TAPIR-CORE will return a signed certificate in a file named `tapir-instance-id.crt`.

The next step is to configure TAPIR-POP with the location of the TAPIR-CORE server, the CA certificate, and the signed certificate. This is done with the `tapir-pop.toml` configuration file.
