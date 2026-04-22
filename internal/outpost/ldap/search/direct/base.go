package direct

import (
	"fmt"
	"strings"

	"beryju.io/ldap"
	log "github.com/sirupsen/logrus"
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

// MOD Mario Kellner:
// samba fileserver comp. Search KVStore for "custom" objectClasses.
// Answer with "custom" objectclasses for domain objects with registriered dn.
func SearchInMemory(req *search.Request, si server.LDAPServerInstance, entries []*ldap.Entry) []*ldap.Entry {
	kv := si.GetKVStore()

	value := kv.Store[strings.ToLower(req.FilterObjectClass)] // Format: "objectClass,baseDN" -> map[string][]byte{attribute: value}

	if value != nil {
		log.Info("Found value for filter object class: ", req.FilterObjectClass)

		for dn, ent := range value {
			entry := &ldap.Entry{
				DN: dn,
				Attributes: []*ldap.EntryAttribute{
					{Name: "objectClass", Values: []string{"top"}},
				},
			}

			for attr, val := range ent {
				attrVal := strings.Split(string(val), ",")

				attritem := &ldap.EntryAttribute{
					Name:   attr,
					Values: attrVal,
				}
				entry.Attributes = append(entry.Attributes, attritem)
			}

			entries = append(entries, entry)
			break // For now return after first find
		}
	}

	return entries
}
