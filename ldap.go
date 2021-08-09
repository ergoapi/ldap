//  Copyright (c) 2021. The EFF Team Authors.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  See the License for the specific language governing permissions and
//  limitations under the License.

package ldap

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

const (
	metaChars = "&|!=~*<>()"
)

// LdapConf ldapconf
type LdapConf struct {
	LdapURL               string `json:"ldap_url"`
	LdapSearchDn          string `json:"ldap_search_dn"`
	LdapSearchPassword    string `json:"ldap_search_password"`
	LdapBaseDn            string `json:"ldap_base_dn"`
	LdapFilter            string `json:"ldap_filter"`
	LdapUID               string `json:"ldap_uid"`
	LdapScope             int    `json:"ldap_scope"`
	LdapConnectionTimeout int    `json:"ldap_connection_timeout"`
}

// LdapUser ...
type LdapUser struct {
	Username    string `json:"ldap_username"`
	Email       string `json:"ldap_email"`
	Realname    string `json:"ldap_realname"`
	DisplayName string `json:"ldap_displayName"`
	Department  string `json:"ldap_department"`
	DN          string `json:"-"`
}

// ValidateLdapConf ...
func (ldapConfs LdapConf) ValidateLdapConf() (LdapConf, error) {
	var err error

	if ldapConfs.LdapURL == "" {
		return ldapConfs, fmt.Errorf("can not get any available LDAP_URL")
	}

	ldapConfs.LdapURL, err = formatLdapURL(ldapConfs.LdapURL)

	if err != nil {
		// zlog.Error("invalid LdapURL format, error: %v", err)
		return ldapConfs, err
	}

	switch ldapConfs.LdapScope {
	case 1:
		ldapConfs.LdapScope = goldap.ScopeBaseObject
	case 2:
		ldapConfs.LdapScope = goldap.ScopeSingleLevel
	case 3:
		ldapConfs.LdapScope = goldap.ScopeWholeSubtree
	default:
		return ldapConfs, fmt.Errorf("invalid ldap search scope")
	}

	return ldapConfs, nil

}

func formatLdapURL(ldapURL string) (string, error) {

	var protocol, hostport string
	var err error

	_, err = url.Parse(ldapURL)
	if err != nil {
		return "", fmt.Errorf("parse Ldap Host ERR: %s", err)
	}

	if strings.Contains(ldapURL, "://") {
		splitLdapURL := strings.Split(ldapURL, "://")
		protocol, hostport = splitLdapURL[0], splitLdapURL[1]
		if !((protocol == "ldap") || (protocol == "ldaps")) {
			return "", fmt.Errorf("unknown ldap protocol")
		}
	} else {
		hostport = ldapURL
		protocol = "ldap"
	}

	if strings.Contains(hostport, ":") {
		splitHostPort := strings.Split(hostport, ":")
		port, error := strconv.Atoi(splitHostPort[1])
		if error != nil {
			return "", fmt.Errorf("illegal url port")
		}
		if port == 636 {
			protocol = "ldaps"
		}
	} else {
		switch protocol {
		case "ldap":
			hostport = hostport + ":389"
		case "ldaps":
			hostport = hostport + ":636"
		}
	}
	fLdapURL := protocol + "://" + hostport
	return fLdapURL, nil
}

// Bind establish a connection to ldap based on ldapConfs and bind the user with given parameters.
func (ldapConfs LdapConf) bind(dn string, password string) error {
	conn, err := ldapConfs.dialLDAP()
	if err != nil {
		return err
	}
	defer conn.Close()
	if ldapConfs.LdapSearchDn != "" {
		if err := ldapConfs.bindLDAPSearchDN(conn); err != nil {
			return err
		}
	}
	return conn.Bind(dn, password)
}

func makeFilter(username string, ldapFilter string, ldapUID string) string {

	var filterTag string

	if username == "" {
		filterTag = "*"
	} else {
		filterTag = username
	}

	if ldapFilter == "" {
		ldapFilter = "(" + ldapUID + "=" + filterTag + ")"
	} else {
		if !strings.Contains(ldapFilter, ldapUID+"=") {
			ldapFilter = "(&" + ldapFilter + "(" + ldapUID + "=" + filterTag + "))"
		} else {
			ldapFilter = strings.Replace(ldapFilter, ldapUID+"=*", ldapUID+"="+filterTag, -1)
		}
	}
	// zlog.Debug(ldapFilter)
	return ldapFilter
}

// SearchUser ...
func (ldapConfs LdapConf) SearchUser() ([]LdapUser, *goldap.SearchResult, error) {
	var ldapUsers []LdapUser
	var ldapConn *goldap.Conn
	var err error

	ldapConn, err = ldapConfs.dialLDAP()

	if err != nil {
		return nil, nil, err
	}
	defer ldapConn.Close()

	if ldapConfs.LdapSearchDn != "" {
		err = ldapConfs.bindLDAPSearchDN(ldapConn)
		if err != nil {
			return nil, nil, err
		}
	}

	if ldapConfs.LdapBaseDn == "" {
		return nil, nil, fmt.Errorf("can not get any available LDAP_BASE_DN")
	}

	result, err := searchLDAP(ldapConfs, ldapConn)

	if err != nil {
		return nil, nil, err
	}
	for ldapkey, ldapEntry := range result.Entries {
		if ldapkey > 9 {
			break
		}
		var u LdapUser
		for _, attr := range ldapEntry.Attributes {
			val := attr.Values[0]
			//logger.Slog.Infof("Current ldap entry attr name: %v, %v", attr.Name, val)
			switch strings.ToLower(attr.Name) {
			case strings.ToLower(ldapConfs.LdapUID):
				u.Username = val
			case "uid":
				u.Realname = val
			case "cn":
				u.Realname = val
			case "displayname":
				u.DisplayName = val
			case "mail":
				u.Email = val
			case "email":
				u.Email = val
			case "department":
				u.Department = val
			}
		}
		u.DN = ldapEntry.DN
		ldapUsers = append(ldapUsers, u)
	}
	// logger.Slog.Debug(len(result.Entries), len(ldapUsers))
	return ldapUsers, result, nil
}

func (ldapConfs LdapConf) dialLDAP() (*goldap.Conn, error) {
	var err error
	var ldap *goldap.Conn
	splitLdapURL := strings.Split(ldapConfs.LdapURL, "://")
	protocol, hostport := splitLdapURL[0], splitLdapURL[1]

	// Sets a Dial Timeout for LDAP
	connectionTimeout := ldapConfs.LdapConnectionTimeout
	goldap.DefaultTimeout = time.Duration(connectionTimeout) * time.Second

	switch protocol {
	case "ldap":
		ldap, err = goldap.Dial("tcp", hostport)
	case "ldaps":
		ldap, err = goldap.DialTLS("tcp", hostport, &tls.Config{InsecureSkipVerify: true})
	}

	return ldap, err
}

func (ldapConfs LdapConf) bindLDAPSearchDN(ldap *goldap.Conn) error {

	var err error

	ldapSearchDn := ldapConfs.LdapSearchDn
	ldapSearchPassword := ldapConfs.LdapSearchPassword

	err = ldap.Bind(ldapSearchDn, ldapSearchPassword)
	if err != nil {
		// zlog.Error("Bind search dn error", err)
		return err
	}

	return nil
}

func searchLDAP(ldapConfs LdapConf, ldap *goldap.Conn) (*goldap.SearchResult, error) {
	var err error
	attributes := []string{"uid", "cn", "mail", "email", "dn", "displayName", "department"}
	lowerUID := strings.ToLower(ldapConfs.LdapUID)
	if lowerUID != "uid" && lowerUID != "cn" && lowerUID != "mail" && lowerUID != "email" && lowerUID != "dn" {
		attributes = append(attributes, ldapConfs.LdapUID)
	}
	//logger.Slog.Infof("ldapFilter %v", ldapFilter)
	searchRequest := goldap.NewSearchRequest(
		ldapConfs.LdapBaseDn,
		ldapConfs.LdapScope,
		goldap.NeverDerefAliases,
		0,     // Unlimited results.
		0,     // Search Timeout.
		false, // Types Only
		ldapConfs.LdapFilter,
		attributes,
		nil,
	)

	result, err := ldap.Search(searchRequest)

	if err != nil {
		// zlog.Error("LDAP search error", err)
		return nil, err
	}
	return result, nil
}

func (ldapConfs LdapConf) LdapReq(user, pass string) (*goldap.SearchResult, error) {
	if len(strings.TrimSpace(user)) == 0 {
		return nil, fmt.Errorf("LDAP authentication failed for empty user id.")
	}

	for _, c := range metaChars {
		if strings.ContainsRune(user, c) {
			return nil, fmt.Errorf("the principal contains meta char: %q", c)
		}
	}
	//ldapConfs := LdapConf{}
	//ldapConfs.LdapURL = viper.GetString("ldap.ldap_url")
	//ldapConfs.LdapSearchDn = viper.GetString("ldap.ldap_search_dn")
	//ldapConfs.LdapSearchPassword = viper.GetString("ldap.ldap_search_password")
	//ldapConfs.LdapBaseDn = viper.GetString("ldap.ldap_base_dn")
	//ldapConfs.LdapFilter = viper.GetString("ldap.ldap_filter")
	//ldapConfs.LdapUID = viper.GetString("ldap.ldap_uid")
	//ldapConfs.LdapScope = viper.GetInt("ldap.ldap_scope")
	//ldapConfs.LdapConnectionTimeout = viper.GetInt("ldap.ldap_connection_timeout")
	ldapConfs, err := ldapConfs.ValidateLdapConf()
	if err != nil {
		return nil, fmt.Errorf("invalid ldap request: %v", err)
	}
	ldapConfs.LdapFilter = makeFilter(user, ldapConfs.LdapFilter, ldapConfs.LdapUID)
	ldapUsers, ldapRes, err := ldapConfs.SearchUser()
	if err != nil {
		return nil, fmt.Errorf("ldap search fail: %v", err)
	}
	if len(ldapUsers) == 0 {
		return nil, fmt.Errorf("Not found an entry. ")
	} else if len(ldapUsers) != 1 {
		return nil, fmt.Errorf("Found more than one entry. ")
	}
	// zlog.Debug("Username: %s, DisplayName: %s", ldapUsers[0].Username, ldapUsers[0].DisplayName)
	if err := ldapConfs.bind(ldapUsers[0].DN, pass); err != nil {
		// zlog.Debug("Failed to bind user, username: %s, dn: %s, error: %v", ldapUsers[0].Username, ldapUsers[0].DN, err)
		return nil, fmt.Errorf("Failed to bind user, username: %s, dn: %s, error: %v ", ldapUsers[0].Username, ldapUsers[0].DN, err)
	}
	return ldapRes, nil
}

// Search 搜索
func (ldapConfs LdapConf) Search(username string) []LdapUser {
	for _, c := range metaChars {
		if strings.ContainsRune(username, c) {
			return nil
		}
	}

	ldapConfs, err := ldapConfs.ValidateLdapConf()
	if err != nil {
		return nil
	}

	ldapConfs.LdapFilter = makeFilter(fmt.Sprintf("%v*", username), ldapConfs.LdapFilter, ldapConfs.LdapUID)

	ldapUsers, _, err := ldapConfs.SearchUser()

	if err != nil || len(ldapUsers) == 0 {
		return nil
	}

	return ldapUsers
}
