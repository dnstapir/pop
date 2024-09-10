#!/bin/sh

if [ $# != 1 ]; then
   echo Usage: $0 instance-id
   echo \"instance-id\" is a string that you receive from TAPIR Core that will identify this DNS TAPIR Edge instance.
   exit 1
fi

destdir=/etc/dnstapir/certs
mkdir -p ${destdir}

id=$1

echo Your DNS TAPIR Edge Id is \"$id\".
/bin/echo -n "Proceed [yes]: "
default_ans="yes"
read answer

if [ "$answer" == "" ]; then
  answer=$default_ans
fi

echo You typed: \"$answer\"

if [ "$answer" != "yes" ]; then
  echo Terminating.
  exit 1
fi

openssl genpkey -genparam -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out ecparam.pem
openssl req -new -out tapiredge.csr -newkey ec:ecparam.pem -keyout tapiredge.key -subj "/CN=${id}" -nodes

echo Send the file \"tapiredge.csr\" to DNS TAPIR admin. You will receive a \"${id}.crt\" in return.
echo If using the default configuration, move the .crt file to ${destdir}/tapiredge.crt and the
echo tapiredge.key file to ${destdir}/tapiredge.key. Ensure that the .key file is read protected
echo for common users.
