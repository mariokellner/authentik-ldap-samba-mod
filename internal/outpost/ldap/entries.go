package ldap

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"beryju.io/ldap"

	"goauthentik.io/internal/outpost/ldap/constants"
	"goauthentik.io/internal/outpost/ldap/utils"
	api "goauthentik.io/packages/client-go"
)

func (pi *ProviderInstance) UserEntry(u api.User) *ldap.Entry {
	dn := pi.GetUserDN(u.Username)
	attrs := utils.AttributesToLDAP(u.Attributes, func(key string) string {
		return utils.AttributeKeySanitize(key)
	}, func(value []string) []string {
		for i, v := range value {
			if strings.Contains(v, "%s") {
				value[i] = fmt.Sprintf(v, u.Username)
			}
		}
		return value
	})

	if u.IsActive == nil {
		u.IsActive = new(false)
	}
	if u.Email == nil {
		u.Email = new("")
	}

	if u.Attributes["sambaNTPassword"] == nil {
		if u.Attributes["sambaNTPassword"] != nil {
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   "sambaNTPassword",
				Values: []string{u.Attributes["sambaNTPassword"].(string)},
			})
		}
	}
	if u.Attributes["userPassword"] == nil {

		if u.Attributes["userPassword"] != nil {
			attrs = append(attrs, &ldap.EntryAttribute{
				Name:   "userPassword",
				Values: []string{u.Attributes["userPassword"].(string)},
			})
		}
	}

	mmbrOf := pi.GroupsForUser(u)
	mmbrOf = append(mmbrOf, pi.GetGroupDN(u.Username))
	mmbrOf = append(mmbrOf, pi.GetGroupDN("Domain Users"))

	attrs = utils.EnsureAttributes(attrs, map[string][]string{
		"ak-active":      {strings.ToUpper(strconv.FormatBool(*u.IsActive))},
		"ak-superuser":   {strings.ToUpper(strconv.FormatBool(u.IsSuperuser))},
		"memberOf":       mmbrOf,
		"cn":             {u.Username},
		"sAMAccountName": {u.Username},
		"uniqID":         {u.Uid}, // remark: uid is not the database uniq id in samba, so i modified it here
		"uid":            {u.Username},
		"name":           {u.Name},
		"displayName":    {u.Name},
		"mail":           {*u.Email},
		"objectClass": {
			constants.OCTop,
			constants.OCPerson,
			constants.OCOrgPerson,
			constants.OCInetOrgPerson,
			constants.OCUser,
			constants.OCPosixAccount,
			constants.OCAKUser,
			constants.OCSambaSamAccount,
		},
		"uidNumber":       {pi.GetUserUidNumber(u)},
		"gidNumber":       {pi.GetUserGidNumber(u)},
		"homeDirectory":   {fmt.Sprintf("/home/%s", u.Username)},
		"sn":              {u.Name},
		"pwdChangedTime":  {u.PasswordChangeDate.In(time.UTC).Format("20060102150405Z")},
		"createTimestamp": {u.DateJoined.In(time.UTC).Format("20060102150405Z")},
		"modifyTimestamp": {u.LastUpdated.In(time.UTC).Format("20060102150405Z")},

		// Mod Mario Kellner
		"sambaSID":             {constants.SAMBA_SID_DOMAIN + "-" + pi.GetUserGidNumber(u)},
		"sambaPwdLastSet":      {fmt.Sprintf("%d", time.Now().Unix())},
		"sambaAcctFlags":       {"[U          ]"},
		"sambaPrimaryGroupSID": {constants.SAMBA_SID_GROUP_PREFIX + pi.GetUserGidNumber(u)},

		// Additional attributes from user.Attributes
		"gecos":      {u.Name},
		"loginShell": {"/bin/bash"},
	})
	return &ldap.Entry{DN: dn, Attributes: attrs}
}
