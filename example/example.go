// AGPL License
// Copyright (c) 2021 ysicing <i@ysicing.me>

package main

import (
	"flag"
	"fmt"

	"github.com/ergoapi/ldap"
)

var mail string

func main() {
	flag.StringVar(&mail, "mail", "", "mail")
	flag.Parse()
	ldapconf := ldap.LdapConf{
		LdapURL:               "ldap://ldap.ops.com:389",
		LdapSearchDn:          "cn=ldapsearch,ou=special,dc=xxxx,dc=com",
		LdapSearchPassword:    "password",
		LdapBaseDn:            "ou=xxxx,dc=xxxx,dc=com",
		LdapFilter:            "",
		LdapUID:               "sAMAccountName",
		LdapScope:             3,
		LdapConnectionTimeout: 30,
	}
	fmt.Print(mail)
	user := ldapconf.Search(mail)
	fmt.Print(user)
}
