package session

import (
	"encoding/gob"
	"errors"
	"net/http"

	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	UserNameKey   = "user.name"
	UserUIDKey    = "user.uid"
	UserGroupsKey = "user.groups"
	UserExtraKey  = "user.extra"
)

type Authenticator struct {
	store Store
	name  string
}

func NewAuthenticator(store Store, name string) *Authenticator {
	return &Authenticator{
		store: store,
		name:  name,
	}
}

func (a *Authenticator) AuthenticateRequest(req *http.Request) (user.Info, bool, error) {
	session, err := a.store.Get(req, a.name)
	if err != nil {
		return nil, false, err
	}

	nameObj, ok := session.Values()[UserNameKey]
	if !ok {
		return nil, false, nil
	}
	name, ok := nameObj.(string)
	if !ok {
		return nil, false, errors.New("user.name on session is not a string")
	}
	if name == "" {
		return nil, false, nil
	}

	uidObj, ok := session.Values()[UserUIDKey]
	if !ok {
		return nil, false, nil
	}
	uid, ok := uidObj.(string)
	if !ok {
		return nil, false, errors.New("user.uid on session is not a string")
	}
	// Tolerate empty string UIDs in the session

	// Extract extra map, if available
	extra, _ := session.Values()[UserExtraKey].(map[string][]string)

	// Extract groups, if available
	groups, _ := session.Values()[UserGroupsKey].([]string)

	return &user.DefaultInfo{
		Name:   name,
		UID:    uid,
		Groups: groups,
		Extra:  extra,
	}, true, nil
}

func init() {
	// used by secure cookie to marshal the session, we have to register the complex types we're going to encode
	gob.Register(map[string][]string{})
	gob.Register([]string{})
}

func (a *Authenticator) AuthenticationSucceeded(user user.Info, state string, w http.ResponseWriter, req *http.Request) (bool, error) {
	session, err := a.store.Get(req, a.name)
	if err != nil {
		return false, err
	}
	values := session.Values()
	values[UserNameKey] = user.GetName()
	values[UserUIDKey] = user.GetUID()
	values[UserGroupsKey] = user.GetGroups()
	values[UserExtraKey] = user.GetExtra()
	return false, a.store.Save(w, req)
}

func (a *Authenticator) InvalidateAuthentication(w http.ResponseWriter, req *http.Request) error {
	session, err := a.store.Get(req, a.name)
	if err != nil {
		return err
	}
	session.Values()[UserNameKey] = ""
	session.Values()[UserUIDKey] = ""
	session.Values()[UserGroupsKey] = []string{}
	session.Values()[UserExtraKey] = map[string][]string{}
	return a.store.Save(w, req)
}
