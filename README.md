## READ

```
ldap:
  ldap_url: "ldap://172.16.0.2:389"
  ldap_search_dn: "cn=ldapsearch,ou=special,dc=xxxx,dc=com"
  ldap_search_password: "password"
  ldap_base_dn: "ou=xxxx,dc=xxxx,dc=com"
  ldap_uid: sAMAccountName
  ldap_scope: 3
  ldap_connection_timeout: 30
```

## Usage 

```bash
go run example/example.go --mail liuning06
```