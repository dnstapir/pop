#!/bin/sh

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

# openssl genpkey -genparam -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out ecparam.pem
# openssl req -new -out tapiredge.csr -newkey ec:ecparam.pem -keyout tapiredge.key -subj "/CN=${id}" -nodes
openssl ecparam -name prime256v1 -genkey -noout -out tapir-pop.key
openssl ec -in tapir-pop.key -pubout -out tapir-pop.pem

echo If using the default configuration, move the two files \"tapir-pop.key\" and
echo \"tapir-pop.pem\" to ${destdir}/certs. Ensure that the .key file is read protected
echo for common users.
