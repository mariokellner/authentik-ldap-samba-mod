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

func ParseFilterForGroup(req api.ApiCoreGroupsListRequest, f *ber.Packet, skip bool) (api.ApiCoreGroupsListRequest, bool) {
	switch f.Tag {
	case ldap.FilterEqualityMatch:
		return parseFilterForGroupSingle(req, f)
	case ldap.FilterAnd:
		for _, child := range f.Children {
			r, s := ParseFilterForGroup(req, child, skip)
			skip = skip || s
			req = r
		}
		return req, skip
	}
	return req, skip
}

func parseFilterForGroupSingle(req api.ApiCoreGroupsListRequest, f *ber.Packet) (api.ApiCoreGroupsListRequest, bool) {
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
	// Check key
	switch strings.ToLower(k.(string)) {
	case "cn":
		return req.Name(*val), false
	// case "gidNumber": // TODO Filter vor samba group mapping in direct seacher
	case "member":
		fallthrough
	case "memberOf":
		userDN, err := goldap.ParseDN(*val)
		if err != nil {
			return req.MembersByUsername([]string{*val}), false
		}
		username := userDN.RDNs[0].Attributes[0].Value
		// If the DN's first ou is virtual-groups, ignore this filter
		if len(userDN.RDNs) > 1 {
			if strings.EqualFold(userDN.RDNs[1].Attributes[0].Value, constants.OUVirtualGroups) || strings.EqualFold(userDN.RDNs[1].Attributes[0].Value, constants.OUGroups) {
				// Since we know we're not filtering anything, skip this request
				return req, true
			}
		}
		return req.MembersByUsername([]string{username}), false
	}
	return req, false
}

// Implement Memory Search Filter
// Before the MS Search returned all entries
// Added some samba search props aswell
func FilterMSSearchGroup(groups []api.Group, f *ber.Packet, skip bool, si server.LDAPServerInstance) ([]api.Group, bool) {

	switch f.Tag {

	case ldap.FilterEqualityMatch:
		return FilterMSSearchSubGroup(groups, f, si)
	case ldap.FilterAnd:
		for _, child := range f.Children {
			r, s := FilterMSSearchGroup(groups, child, skip, si)
			skip = skip || s
			groups = r
		}
		return groups, skip
	case ldap.FilterOr:
		results := make([]api.Group, 0)

		for _, child := range f.Children {
			r, s := FilterMSSearchGroup(groups, child, skip, si)
			for _, rs := range r {
				results = append(results, rs)
			}

			skip = skip || s
		}
		groups = results
		return groups, skip
	default:
		logrus.Info("Not supported Filtertype ", f.Tag)

		return groups, skip
	}
}

func FilterMSSearchSubGroup(groups []api.Group, f *ber.Packet, si server.LDAPServerInstance) ([]api.Group, bool) {

	if len(f.Children) < 2 {
		return groups, false
	}
	key := f.Children[0].Value

	if _, ok := key.(string); !ok {
		return groups, false
	}
	v := f.Children[1].Value

	// Null values are ignored
	if v == nil {
		return groups, false
	}
	val := stringify(v)

	if val == nil {
		return groups, false
	}

	key = strings.ToLower(key.(string))

	newGroups := make([]api.Group, 0)
	for _, grp := range groups {
		switch key {
		case "displayname":
			fallthrough
		case "cn":
			if grp.Name == *val {
				newGroups = append(newGroups, grp)
			}
		case "gidnumber":
			if string(si.GetGroupGidNumber(grp)) == *val {
				newGroups = append(newGroups, grp)
			}
		case "memberuid":
			for _, mem := range grp.GetUsersObj() {
				if mem.Username == *val {
					newGroups = append(newGroups, grp)
					break
				}
			}
		case "member":
			fallthrough
		case "memberof":
			username := *val
			userDN, err := goldap.ParseDN(*val)

			if err == nil {
				username = userDN.RDNs[0].Attributes[0].Value
			}

			for _, mem := range grp.GetUsersObj() {
				if mem.Username == username {
					newGroups = append(newGroups, grp)
					break
				}
			}
		case "sambasidlist":
			fallthrough
		case "sambasid":

			if *val == constants.SAMBA_SID_DOMAIN+"-"+si.GetGroupGidNumber(grp) {
				newGroups = append(newGroups, grp)
				break
			}

		case "objectclass":
			newGroups = append(newGroups, grp)
		default:
			logrus.Info("Not supported key ", key, " => ", *val)

			newGroups = append(newGroups, grp)
		}
	}
	return newGroups, false
}
