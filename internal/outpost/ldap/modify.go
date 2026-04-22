package ldap

import (
	"net"
	"reflect"
	"strings"
	"unsafe"

	"beryju.io/ldap"
	log "github.com/sirupsen/logrus"
)

// MOD: Mario Kellner
// Actually i dont know why ldap-go hasnt been used as the ldap provider
// There are many design flaws that even I capable to see even as an GO beginner
// I need that Method because "attributes" in "add Request" is not exported and I neeed
// these properties ...
func GetUnexportedField(obj reflect.Value, field string) reflect.Value {
	rs2 := reflect.New(obj.Type()).Elem()
	rs2.Set(obj)
	rf := rs2.FieldByName(field)
	return reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
}

// MOD Mario Kellner
// In case the SAMBA Server wants to add anything as an Domain Object, I will handle it here
// stores the data inmemory using KVStore
// pretty basic and noot even ldap standard, but it works for my file server!
func (ls *LDAPServer) Add(boundDN string, addReq ldap.AddRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	log.WithField("attributes", addReq).Info("Add request received for DN: ", boundDN, "\n")

	rf := GetUnexportedField(reflect.ValueOf(addReq), "attributes")

	// TODO get current provider
	selProv := ls.providers[0] // since I only use on provider I hardcoded it to 0
	kvStore := &selProv.KV

	localMap := make(map[string]string)
	defDN := rf.Index(0).FieldByName("attrType").String()
	for i := 0; i < rf.Len(); i++ {
		attr := rf.Index(i)
		attrValsInterface := GetUnexportedField(attr, "attrVals").Interface()

		if attrValsSlice, ok := attrValsInterface.([]string); ok {
			jstr := strings.Join(attrValsSlice, ",")

			localMap[attr.FieldByName("attrType").String()] = jstr
		}
	}

	objClass, exists := localMap["objectclass"]

	if !exists || objClass == "" {
		return ldap.LDAPResultObjectClassViolation, nil
	}

	objcls := strings.ToLower(objClass)
	if _, exists := kvStore.Store[objcls]; !exists {
		kvStore.Store[objcls] = make(map[string]map[string][]byte)
	}

	entryKV := make(map[string][]byte)
	for k, v := range localMap {
		entryKV[k] = []byte(v)
	}

	entryDN := getDNForObjectClass(objClass, defDN)

	DN := entryDN + "=" + localMap[entryDN] + "," + selProv.BaseDN
	dnl := strings.ToLower(DN)
	kvStore.Store[objcls][dnl] = filterAttributes(entryKV, &objClass)
	kvStore.DNLookup[dnl] = objcls

	return ldap.LDAPResultSuccess, nil

}

func filterAttributes(entryKV map[string][]byte, objClass *string) map[string][]byte {
	retList := make(map[string][]byte)
	switch *objClass {
	case "sambaDomain":
		retList["sambaDomainName"] = entryKV["sambaDomainName"]
		retList["sambaSID"] = entryKV["sambaSID"]

	default:
		retList = entryKV
	}
	retList["objectclass"] = entryKV["objectclass"]
	return retList
}

func getDNForObjectClass(objClass string, defVal string) string {
	dn := defVal

	switch objClass {
	case "sambaDomain":
		dn = "sambaDomainName"
	}

	return dn
}

func (ls *LDAPServer) Modify(boundDN string, modReq ldap.ModifyRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	log.WithField("attributes", modReq).Info("Modify request received for DN: ", boundDN, "\n")

	selProv := *ls.providers[0] // TODO not hardcoded
	kv := &selProv.KV
	dn := strings.ToLower(modReq.Dn)

	objcls, exists := kv.DNLookup[dn]
	if !exists {
		return ldap.LDAPResultNoSuchObject, nil
	}

	if modReq.ReplaceAttributes != nil {
		for _, ele := range modReq.ReplaceAttributes {
			kv.Store[objcls][dn][ele.AttrType] = []byte(strings.Join(ele.AttrVals, ","))
		}
	}
	if modReq.AddAttributes != nil {
		for _, ele := range modReq.AddAttributes {
			kv.Store[objcls][dn][ele.AttrType] = []byte(strings.Join(ele.AttrVals, ","))
		}
	}
	if modReq.DeleteAttributes != nil {
		for _, ele := range modReq.DeleteAttributes {
			delete(kv.Store[objcls][dn], ele.AttrType)
		}
	}

	return ldap.LDAPResultSuccess, nil
}

// Not implemented jet
func (ls *LDAPServer) Delete(boundDN, delDN string, conn net.Conn) (ldap.LDAPResultCode, error) {
	log.WithField("attributes", delDN).Info("Delete request received for DN: ", boundDN, "\n")

	return ldap.LDAPResultInsufficientAccessRights, nil

}
