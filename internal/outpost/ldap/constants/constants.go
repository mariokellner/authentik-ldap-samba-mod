package constants

const OC = "objectClass"

const (
	OCTop         = "top"
	OCDomain      = "domain"
	OCNSContainer = "nsContainer"
	OCSubSchema   = "subschema"
)

const (
	SearchAttributeNone           = "1.1"
	SearchAttributeAllUser        = "*"
	SearchAttributeAllOperational = "+"
)

const (
	OCGroup              = "group"
	OCGroupOfUniqueNames = "groupOfUniqueNames"
	OCGroupOfNames       = "groupOfNames"
	OCAKGroup            = "goauthentik.io/ldap/group"
	OCAKVirtualGroup     = "goauthentik.io/ldap/virtual-group"
	OCPosixGroup         = "posixGroup"
)

const (
	OCPerson        = "person"
	OCUser          = "user"
	OCOrgPerson     = "organizationalPerson"
	OCInetOrgPerson = "inetOrgPerson"
	OCAKUser        = "goauthentik.io/ldap/user"
	OCPosixAccount  = "posixAccount"
)

// mod Mario Kellner
const SAMBA_SID_DOMAIN = "S-1-5-21-133701337-733101337-353103531"

const (
	OCSambaDomain       = "sambaDomain"
	OCSambaGroupMapping = "sambaGroupMapping"
	OCSambaSamAccount   = "sambaSamAccount"
)

const (
	OUUsers         = "users"
	OUGroups        = "groups"
	OUVirtualGroups = "virtual-groups"
)

func GetDomainOCs() map[string]bool {
	return map[string]bool{
		OCTop:    true,
		OCDomain: true,
	}
}

func GetContainerOCs() map[string]bool {
	return map[string]bool{
		OCTop:         true,
		OCNSContainer: true,
	}
}

func GetUserOCs() map[string]bool {
	return map[string]bool{
		OCTop:             true,
		OCPerson:          true,
		OCUser:            true,
		OCOrgPerson:       true,
		OCInetOrgPerson:   true,
		OCAKUser:          true,
		OCPosixAccount:    true,
		OCSambaSamAccount: true,
	}
}

func GetGroupOCs() map[string]bool {
	return map[string]bool{
		OCGroup:              true,
		OCGroupOfUniqueNames: true,
		OCGroupOfNames:       true,
		OCAKGroup:            true,
		OCPosixGroup:         true,
		OCSambaGroupMapping:  true,
	}
}

func GetVirtualGroupOCs() map[string]bool {
	return map[string]bool{
		OCGroup:              true,
		OCGroupOfUniqueNames: true,
		OCGroupOfNames:       true,
		OCAKVirtualGroup:     true,
	}
}

// mod Mario Kellner
func GetSambaOCs() map[string]bool {
	return map[string]bool{
		OCSambaDomain: true,
	}
}
