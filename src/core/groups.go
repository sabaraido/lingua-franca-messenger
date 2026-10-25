package core

import (
	"errors"
	"strconv"
)

var (
	ErrGroupNotFound  = errors.New("group not found")
	ErrGroupExists    = errors.New("group already exists")
	ErrContactMissing = errors.New("contact not found")
)

// findGroup はMSNP8の番号またはMSNP10以降のGUIDでグループを探す。
func (u *User) findGroup(ref string) (int, *Group) {
	for i, g := range u.Groups {
		if g.GUID == ref || strconv.Itoa(g.ID) == ref {
			return i, g
		}
	}
	return -1, nil
}

// Groups はユーザーのグループ一覧のコピーを返す。
func (s *UserStore) Groups(userEmail string) []Group {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[normalizeEmail(userEmail)]
	if !ok {
		return nil
	}
	list := make([]Group, 0, len(u.Groups))
	for _, g := range u.Groups {
		list = append(list, *g)
	}
	return list
}

// FindGroup は番号またはGUIDでグループを探す。
func (s *UserStore) FindGroup(userEmail, ref string) (Group, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[normalizeEmail(userEmail)]
	if !ok {
		return Group{}, false
	}
	if _, g := u.findGroup(ref); g != nil {
		return *g, true
	}
	return Group{}, false
}

// AddGroup はグループを作る。同名のグループがあればエラー。
func (s *UserStore) AddGroup(userEmail, name string) (Group, error) {
	var created Group
	err := s.updateUser(userEmail, func(u *User) error {
		maxID := 0
		for _, g := range u.Groups {
			if g.Name == name {
				return ErrGroupExists
			}
			if g.ID > maxID {
				maxID = g.ID
			}
		}
		g := &Group{ID: maxID + 1, GUID: generateGUID(), Name: name}
		u.Groups = append(u.Groups, g)
		created = *g
		return nil
	})
	return created, err
}

// RemoveGroup はグループを削除し、所属していた連絡先から外す。
func (s *UserStore) RemoveGroup(userEmail, ref string) (Group, error) {
	var removed Group
	err := s.updateUser(userEmail, func(u *User) error {
		i, g := u.findGroup(ref)
		if g == nil {
			return ErrGroupNotFound
		}
		removed = *g
		u.Groups = append(u.Groups[:i], u.Groups[i+1:]...)
		for _, c := range u.Contacts {
			c.Groups = withoutGroup(c.Groups, g.GUID)
		}
		return nil
	})
	return removed, err
}

// RenameGroup はグループ名を変える。
func (s *UserStore) RenameGroup(userEmail, ref, name string) (Group, error) {
	var renamed Group
	err := s.updateUser(userEmail, func(u *User) error {
		_, g := u.findGroup(ref)
		if g == nil {
			return ErrGroupNotFound
		}
		for _, other := range u.Groups {
			if other != g && other.Name == name {
				return ErrGroupExists
			}
		}
		g.Name = name
		renamed = *g
		return nil
	})
	return renamed, err
}

// SetContactGroups は連絡先の所属グループ(GUID または DefaultGroup)を置き換える。
// 所属が DefaultGroup だけなら空として保存する。
func (s *UserStore) SetContactGroups(userEmail, contactRef string, groups []string) error {
	return s.updateUser(userEmail, func(u *User) error {
		_, c := u.findContact(contactRef)
		if c == nil {
			return ErrContactMissing
		}
		for _, ref := range groups {
			if ref == DefaultGroup {
				continue
			}
			if _, g := u.findGroup(ref); g == nil {
				return ErrGroupNotFound
			}
		}
		if len(groups) == 1 && groups[0] == DefaultGroup {
			groups = nil
		}
		c.Groups = append([]string(nil), groups...)
		return nil
	})
}

func withoutGroup(groups []string, ref string) []string {
	out := groups[:0]
	for _, g := range groups {
		if g != ref {
			out = append(out, g)
		}
	}
	return out
}
