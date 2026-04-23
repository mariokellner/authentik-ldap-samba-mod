package utils

import (
	"strings"

	"beryju.io/ldap"
	goldap "github.com/go-ldap/ldap/v3"
	ber "github.com/nmcclain/asn1-ber"
	"github.com/sirupsen/logrus"
	"goauthentik.io/internal/outpost/ldap/constants"
	"goauthentik.io/internal/outpost/ldap/server"
	api "goauthentik.io/packages/client-go"
)

func ParseFilterForUser(req api.ApiCoreUsersListRequest, f *ber.Packet, skip bool) (api.ApiCoreUsersListRequest, bool) {
	switch f.Tag {
	case ldap.FilterEqualityMatch:
		return parseFilterForUserSingle(req, f)
	case ldap.FilterAnd:
		for _, child := range f.Children {
			r, s := ParseFilterForUser(req, child, skip)
			skip = skip || s
			req = r
		}
		return req, skip
	}
	return req, skip
}

func parseFilterForUserSingle(req api.ApiCoreUsersListRequest, f *ber.Packet) (api.ApiCoreUsersListRequest, bool) {
	// We can only handle key = value pairs here
	if len(f.Children) < 2 {
		return req, false
	}
	k := f.Children[0].Value
	// Ensure key is string
	if _, ok := k.(string); !ok {
		return req, false
	}
	v := f.Children[1].Value
	// Null values are ignored
	if v == nil {
		return req, false
	}
	val := stringify(v)
	if val == nil {
		return req, false
	}
	switch k {
	case "uid": // MOD: Mario Kellner
		fallthrough
	case "cn":
		return req.Username(*val), false
	case "name":
	case "displayName":
		return req.Name(*val), false
	case "mail":
		return req.Email(*val), false
	case "member":
		fallthrough
	case "memberOf":
		groupDN, err := goldap.ParseDN(*val)
		if err != nil {
			return req.GroupsByName([]string{*val}), false
		}
		name := groupDN.RDNs[0].Attributes[0].Value
		// If the DN's first ou is virtual-groups, ignore this filter
		if len(groupDN.RDNs) > 1 {
			if groupDN.RDNs[1].Attributes[0].Value == constants.OUUsers || groupDN.RDNs[1].Attributes[0].Value == constants.OUVirtualGroups {
				// Since we know we're not filtering anything, skip this request
				return req, true
			}
		}
		return req.GroupsByName([]string{name}), false
	}
	return req, false
}

// Implement Memory Search Filter
// Before the MS Search returned all entries
// Added some samba search props aswell
func FilterMSSearchUser(user []api.User, f *ber.Packet, skip bool, si server.LDAPServerInstance) ([]api.User, bool) {

	switch f.Tag {

	case ldap.FilterEqualityMatch:
		return FilterMSSearchSubUser(user, f, si)
	case ldap.FilterAnd:
		for _, child := range f.Children {
			r, s := FilterMSSearchUser(user, child, skip, si)
			skip = skip || s
			user = r
		}
		return user, skip
	case ldap.FilterOr:
		results := make([]api.User, 0)

		for _, child := range f.Children {
			r, s := FilterMSSearchUser(user, child, skip, si)
			for _, rs := range r {
				results = append(results, rs)
			}

			skip = skip || s
		}
		user = results
		return user, skip
	default:
		logrus.Info("Not supported Filtertype ", f.Tag)

		return user, skip
	}
}

func FilterMSSearchSubUser(user []api.User, f *ber.Packet, si server.LDAPServerInstance) ([]api.User, bool) {

	if len(f.Children) < 2 {
		return user, false
	}
	key := f.Children[0].Value

	if _, ok := key.(string); !ok {
		return user, false
	}
	v := f.Children[1].Value

	// Null values are ignored
	if v == nil {
		return user, false
	}
	val := stringify(v)

	if val == nil {
		return user, false
	}

	key = strings.ToLower(key.(string))

	newUser := make([]api.User, 0)
	for _, usr := range user {
		switch key {
		case "uid": // MOD: Mario Kellner
			fallthrough
		case "cn":
			if usr.Username == *val {
				newUser = append(newUser, usr)
			}
		case "displayname":
			if usr.Name == *val {
				newUser = append(newUser, usr)
			}
		case "mail":
			if *usr.Email == *val {
				newUser = append(newUser, usr)
			}
		case "uidnumber":
			if string(si.GetUserUidNumber(usr)) == *val {
				newUser = append(newUser, usr)
			}
		case "member":
			fallthrough
		case "memberof":
			groupname := *val
			grpTyp := ""

			groupDN, err := goldap.ParseDN(*val)
			if err == nil {
				groupname = groupDN.RDNs[0].Attributes[0].Value
				grpTyp = groupDN.RDNs[1].Attributes[0].Value
			}

			if grpTyp != constants.OUUsers || grpTyp != constants.OUVirtualGroups {
				for _, nameObj := range usr.GetGroupsObj() {
					if groupname == nameObj.Name {
						newUser = append(newUser, usr)
						break
					}
				}
			}
		case "sambasidlist":
			fallthrough
		case "sambasid":

			if *val == constants.SAMBA_SID_DOMAIN+"-"+si.GetUserUidNumber(usr) {
				newUser = append(newUser, usr)
				break
			}

		case "objectclass":
			newUser = append(newUser, usr)
		default:
			logrus.Info("Not supported key ", key, " => ", *val)

			newUser = append(newUser, usr)
		}
	}
	return newUser, false
}
