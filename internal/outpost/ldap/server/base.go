package server

import (
	"beryju.io/ldap"

	"goauthentik.io/internal/outpost/ldap/constants"
	"goauthentik.io/internal/outpost/ldap/flags"
	api "goauthentik.io/packages/client-go"
)

type LDAPServerInstance interface {
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
	GetUserUidNumberFromPk(int32) string
	GetUserGidNumber(api.User) string
	GetGroupGidNumber(api.Group) string

	MembersForGroup(api.Group) []string
	MemberOfForGroup(api.Group) []string

	GetFlags(dn string) *flags.UserFlags
	SetFlags(dn string, flags *flags.UserFlags)

	GetNeededObjects(scope int, baseDN string, filterOC string) (bool, bool)
}

// MOD: Mario Kellner
// Fake Samba Entry with static ID

func GetFakeDomainEntry() map[string][]byte {
	return map[string][]byte{
		"objectclass":        []byte("sambaDomain"),
		"sambaDomainName":    []byte(""),
		"sambaSID":           []byte(constants.SAMBA_SID_DOMAIN),
		"sambaPwdMustChange": []byte("0"),
		"sambaLogonTime":     []byte("0"),
		"sambaLogoffTime":    []byte("0"),
	}

}
