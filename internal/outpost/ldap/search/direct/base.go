package direct

import (
	"fmt"
	"strings"

	"beryju.io/ldap"
	"github.com/sirupsen/logrus"
	"goauthentik.io/internal/constants"
	ldapConstants "goauthentik.io/internal/outpost/ldap/constants"
	"goauthentik.io/internal/outpost/ldap/search"
	"goauthentik.io/internal/outpost/ldap/server"
)

func (ds *DirectSearcher) SearchBase(req *search.Request) (ldap.ServerSearchResult, error) {
	if req.Scope == ldap.ScopeSingleLevel {
		return ldap.ServerSearchResult{
			ResultCode: ldap.LDAPResultNoSuchObject,
		}, nil
	}
	return ldap.ServerSearchResult{
		Entries: []*ldap.Entry{
			{
				DN: "",
				Attributes: []*ldap.EntryAttribute{
					{
						Name:   "objectClass",
						Values: []string{ldapConstants.OCTop},
					},
					{
						Name:   "entryDN",
						Values: []string{""},
					},
					{
						Name:   "supportedLDAPVersion",
						Values: []string{"3"},
					},
					{
						Name: "supportedCapabilities",
						Values: []string{
							"1.2.840.113556.1.4.800",  // LDAP_CAP_ACTIVE_DIRECTORY_OID
							"1.2.840.113556.1.4.1791", // LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID
							"1.2.840.113556.1.4.1670", // LDAP_CAP_ACTIVE_DIRECTORY_V51_OID
							"1.2.840.113556.1.4.1880", // LDAP_CAP_ACTIVE_DIRECTORY_ADAM_DIGEST_OID
							"1.2.840.113556.1.4.1851", // LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID
							"1.2.840.113556.1.4.1920", // LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS_OID
							"1.2.840.113556.1.4.1935", // LDAP_CAP_ACTIVE_DIRECTORY_V60_OID
							"1.2.840.113556.1.4.2080", // LDAP_CAP_ACTIVE_DIRECTORY_V61_R2_OID
							"1.2.840.113556.1.4.2237", // LDAP_CAP_ACTIVE_DIRECTORY_W8_OID
						},
					},
					{
						Name: "supportedControl",
						Values: []string{
							"2.16.840.1.113730.3.4.9",  // VLV Request LDAPv3 Control
							"2.16.840.1.113730.3.4.10", // VLV Response LDAPv3 Control
							"1.2.840.113556.1.4.474",   // Sort result
							"1.2.840.113556.1.4.319",   // Paged Result Control
						},
					},
					{
						Name:   "subschemaSubentry",
						Values: []string{"cn=subschema"},
					},
					{
						Name: "namingContexts",
						Values: []string{
							strings.ToLower(ds.si.GetBaseDN()),
						},
					},
					{
						Name: "rootDomainNamingContext",
						Values: []string{
							strings.ToLower(ds.si.GetBaseDN()),
						},
					},
					{
						Name:   "vendorName",
						Values: []string{"goauthentik.io"},
					},
					{
						Name:   "vendorVersion",
						Values: []string{fmt.Sprintf("authentik LDAP Outpost Version %s", constants.FullVersion())},
					},
				},
			},
		},
		Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess,
	}, nil
}

// Instead of adding the new object with unsafe to a local store
// Ill could instead fake the answer, so no object store is needed.
// the SID remains static but since the goal is that we only provide login via
// authentik, it should be okay at least for my usecases
// For now the sid remains static but i dont think that it really bothers fileserver in the network
func SambaFakeAnswer(req *search.Request, si server.LDAPServerInstance, entries []*ldap.Entry) []*ldap.Entry {
	val := server.GetFakeDomainEntry()
	filter, _ := ldap.CompileFilter(req.Filter)

	if filter.Children[1] == nil || len(entries) > 0 {
		return entries
	}
	cls := ""
	val1 := ""

	sdiDN := req.BaseDN
	// support for deph = 2 filter, as samba domaininfo is only supported with that for now
	if filter.Tag == ldap.FilterEqualityMatch && filter.Children[1].Value == "sambaDomain" {

		cls = filter.Children[0].Value.(string)
		val1 = filter.Children[1].Value.(string)

		// Domain RN is passed as DN
		listDN := strings.Split(req.BaseDN, ",")

		if len(listDN) > 1 {
			dmInfoRN := strings.Split(listDN[0], "=")
			val[dmInfoRN[0]] = []byte(dmInfoRN[1])
		} else {
			return entries
		}

	} else if filter.Tag == ldap.FilterAnd && filter.Children[1].Tag == ldap.FilterEqualityMatch {
		// In case we query a "sambaDomainInfo", fake the answer
		// quick and dirty: Samba Domain, as we only need that for that
		cls = filter.Children[1].Children[0].Value.(string)
		val1 = filter.Children[1].Children[1].Value.(string)

		sdiDN = cls + "=" + val1 + "," + sdiDN

	} else {
		return entries
	}

	val[cls] = []byte(val1)
	entry := &ldap.Entry{
		DN: sdiDN,
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top"}},
		},
	}

	for attr, val := range val {

		attritem := &ldap.EntryAttribute{
			Name:   attr,
			Values: []string{string(val)},
		}
		entry.Attributes = append(entry.Attributes, attritem)
	}

	entries = append(entries, entry)

	return entries
}
func SambaObjClassFilter(req *search.Request, si server.LDAPServerInstance, entries []*ldap.Entry) []*ldap.Entry {
	switch req.FilterObjectClass {
	case "sambadomain":
		entries = SambaFakeAnswer(req, si, entries)
	default:
		logrus.Info("Not implemented ... ignoring! ", req.FilterObjectClass, req.Filter, strings.Join(req.SearchRequest.Attributes, ", "))
	}

	return entries
}
