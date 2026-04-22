package server

import (
	"strings"

	"beryju.io/ldap"

	"goauthentik.io/internal/outpost/ldap/constants"
	"goauthentik.io/internal/outpost/ldap/flags"
	api "goauthentik.io/packages/client-go"
)

// MOD Mario Kellner
// Local store inmemory because i dont mind to write in the data base.
// I only want some attributes mapped in this provider and dont modify anything else in authentik
type KVStore struct {
	// Store map[string]map[string][]byte // dn:objCls | dn | attr -> value
	Store map[string]map[string]map[string][]byte
	// DN => objCls
	DNLookup map[string]string
}

func AddDomainInfo(kv *KVStore, BaseDN string) {

	netBoisDomain := "SAMBAAUTHENTIK"
	DN := "sambaDomainName=" + netBoisDomain + "," + BaseDN
	dnl := strings.ToLower(DN)
	kv.Store["sambadomain"] = make(map[string]map[string][]byte)

	kv.Store["sambadomain"][dnl] = map[string][]byte{
		"objectclass":        []byte("sambaDomain"),
		"sambaDomainName":    []byte(netBoisDomain),
		"sambaSID":           []byte(constants.SAMBA_SID_DOMAIN),
		"sambaPwdMustChange": []byte("0"),
		"sambaLogonTime":     []byte("0"),
		"sambaLogoffTime":    []byte("0"),
	}
	kv.DNLookup[dnl] = "sambadomain"

}

type LDAPServerInstance interface {
	GetKVStore() *KVStore
	GetAPIClient() *api.APIClient
	GetOutpostName() string

	GetAuthenticationFlowSlug() string
	GetInvalidationFlowSlug() *string
	GetAppSlug() string
	GetProviderID() int32

	UserEntry(u api.User) *ldap.Entry

	GetBaseDN() string
	GetBaseGroupDN() string
	GetBaseVirtualGroupDN() string
	GetBaseUserDN() string
	GetMFASupport() bool

	GetUserDN(string) string
	GetGroupDN(string) string
	GetVirtualGroupDN(string) string

	GetUserUidNumber(api.User) string
	GetUserGidNumber(api.User) string
	GetGroupGidNumber(api.Group) string

	MembersForGroup(api.Group) []string
	MemberOfForGroup(api.Group) []string

	GetFlags(dn string) *flags.UserFlags
	SetFlags(dn string, flags *flags.UserFlags)

	GetNeededObjects(scope int, baseDN string, filterOC string) (bool, bool)
}
