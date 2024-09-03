#!/bin/sh

if [ $# != 1 ]; then
   echo Usage: $0 instance-id
   echo \"instance-id\" is a string that you choose yourself that will identify this DNS TAPIR Edge instance.
   echo A domain name is usually a good idea.
   exit 1
fi

id=$1

echo Your chosen DNS TAPIR Edge Id is \"$id\".
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
openssl req -new -out ${id}.csr -newkey ec:ecparam.pem -keyout ${id}.key -subj "/CN=${id}" -nodes

echo Send the file \"${id}.csr\" to DNS TAPIR admin. You will receive a \"${id}.crt\" in return.
