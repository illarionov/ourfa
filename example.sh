#!/bin/sh

user_from=${1:-"0"}
user_to=${2:-"500"}

HOST=${3:-"localhost"}
LOGIN=${4:-"init"}
PASSWORD=${5:-"init"}

XML_DIR=${6:-"/netup/utm5/xml"}
OURFA_CLIENT=${OURFA_CLIENT:-"/netup/utm5/bin/ourfa_client"}

$OURFA_CLIENT -H "$HOST" -l "$LOGIN" -P "$PASSWORD" -x "$XML_DIR" \
 -a rpcf_get_users_list -o batch --from=${user_from} --to=${user_to} \
 | awk -F "\t" '
 NF==3 {
    key=$1;
    idx=$2;
    val=$3;

    if (key ~ /^(user_id_array)|(login_array)|(basic_account)|(full_name)|(balance)$/) {
       gsub(/[\[\]]/, "", idx);
       users[idx,key] = val;
       idxs[idx]=1;
    }
 }
 END {
   for (idx in idxs) {printf "%s\t%s\t%s\t%s\n",
      users[idx,"basic_account"],
      users[idx,"login_array"],
      users[idx,"balance"],
      users[idx,"full_name"];
      ;}
 }
 ' | iconv -f utf-8

