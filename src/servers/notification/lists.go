package notification

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sabaraido/lingua-franca-messenger/src/core"
)

// コンタクトリスト(FL/AL/BL/RL)とグループの操作。
//
// MSNP8/9 と MSNP10以降では書式が異なる:
//   - MSNP8/9: 応答にリストのバージョン番号が付き、連絡先はメールアドレス、グループは番号で指す。
//     グループ0("その他の連絡先")が常に存在し、FLの連絡先は必ずどれかのグループに属する。
//   - MSNP10以降: バージョン番号の代わりにタイムスタンプを使い、連絡先とグループはGUIDで指す。
//     グループ0はなく、どのグループにも属さない連絡先がありうる。

// MSNPのエラーコード
const (
	errInvalidParameter = 201
	errInvalidUser      = 205
	errNotInList        = 216
	errInvalidGroup     = 224
	errGroupExists      = 228
	errGroupNameTooLong = 229
	errCannotRemoveZero = 230
)

const maxGroupNameLen = 61

func (s *Server) sendError(sess *clientSession, code int, trID string) {
	s.send(sess, fmt.Sprintf("%d %s\r\n", code, trID))
}

// msnTimestamp はMSNP10以降のSYNで使うリストのタイムスタンプ。
// 常に現在時刻を返し、クライアントのキャッシュは使わせずにフル同期させる。
func msnTimestamp() string {
	return time.Now().Format("2006-01-02T15:04:05.0000000-07:00")
}

func listBits(c core.Contact) int {
	listNums := map[string]int{"FL": 1, "AL": 2, "BL": 4, "RL": 8}
	bits := 0
	for _, l := range c.Lists {
		bits |= listNums[l]
	}
	return bits
}

// memberships はMSNP8/9から見た所属グループ。空ならグループ0だけ。
func memberships(c core.Contact) []string {
	if len(c.Groups) == 0 {
		return []string{core.DefaultGroup}
	}
	return c.Groups
}

// groupIDsMSNP8 はLSTに載せるグループ番号のリスト("0,2" など)。
func groupIDsMSNP8(c core.Contact, groups map[string]core.Group) string {
	var ids []string
	for _, ref := range memberships(c) {
		if ref == core.DefaultGroup {
			ids = append(ids, "0")
		} else if g, ok := groups[ref]; ok {
			ids = append(ids, strconv.Itoa(g.ID))
		}
	}
	if len(ids) == 0 {
		return "0"
	}
	return strings.Join(ids, ",")
}

// groupGUIDsMSNP10 はLSTに載せるグループGUIDのリスト。グループ0は含めない。
func groupGUIDsMSNP10(c core.Contact) string {
	var guids []string
	for _, ref := range c.Groups {
		if ref != core.DefaultGroup {
			guids = append(guids, ref)
		}
	}
	return strings.Join(guids, ",")
}

func groupsByGUID(groups []core.Group) map[string]core.Group {
	m := make(map[string]core.Group, len(groups))
	for _, g := range groups {
		m[g.GUID] = g
	}
	return m
}

// groupRef はクライアントが指定したグループ(MSNP8の番号 / MSNP10のGUID)を
// Contact.Groups の値に変換する。
func (s *Server) groupRef(sess *clientSession, ref string) (string, bool) {
	if sess.usesListVersions() && ref == "0" {
		return core.DefaultGroup, true
	}
	g, ok := s.Users.FindGroup(sess.userEmail, ref)
	return g.GUID, ok
}

func (s *Server) findContact(owner, ref string) (core.Contact, bool) {
	for _, c := range s.Users.GetContacts(owner) {
		if strings.EqualFold(c.Email, ref) || c.GUID == ref {
			return c, true
		}
	}
	return core.Contact{}, false
}

// syncMSNP8 はMSNP8/9形式でコンタクトリストを送る。
//
//	SYN trID version lstCount lsgCount
//	GTC A / BLP AL
//	LSG 0 Other%20Contacts 0 / LSG id name 0
//	LST email friendlyname listBits [groupIDs]   (groupIDsはFLに入っている場合のみ)
//
// ILNはSYNではなく、最初のCHGへの応答として送る。
func (s *Server) syncMSNP8(sess *clientSession, trID string, clientVer int64) {
	contacts := s.Users.GetContacts(sess.userEmail)
	groups := s.Users.Groups(sess.userEmail)
	byGUID := groupsByGUID(groups)
	ver := s.syncListVersion(clientVer)

	msgs := []string{
		fmt.Sprintf("SYN %s %d %d %d\r\n", trID, ver, len(contacts), len(groups)+1),
		"GTC A\r\n",
		fmt.Sprintf("BLP %s\r\n", s.Users.Privacy(sess.userEmail)),
		"LSG 0 Other%20Contacts 0\r\n",
	}
	for _, g := range groups {
		msgs = append(msgs, fmt.Sprintf("LSG %d %s 0\r\n", g.ID, escapeName(g.Name)))
	}
	for _, c := range contacts {
		bits := listBits(c)
		line := fmt.Sprintf("LST %s %s %d", c.Email, escapeName(s.resolveFriendlyName(c.Email, c.FriendlyName)), bits)
		if c.HasList("FL") {
			line += " " + groupIDsMSNP8(c, byGUID)
		}
		msgs = append(msgs, line+"\r\n")
	}
	for _, m := range msgs {
		s.send(sess, m)
	}
}

// syncMSNP10 はMSNP10以降の形式でコンタクトリストを送る。
//
//	SYN trID timestamp timestamp lstCount lsgCount
//	GTC A / BLP AL / PRP MFN name
//	LSG name guid
//	LST N=email F=name C=guid listBits [groupGUIDs]   (FLの場合)
//	LST N=email F=name listBits                       (FL以外のみの場合)
func (s *Server) syncMSNP10(sess *clientSession, trID string) {
	contacts := s.Users.GetContacts(sess.userEmail)
	groups := s.Users.Groups(sess.userEmail)
	ts := msnTimestamp()

	msgs := []string{
		fmt.Sprintf("SYN %s %s %s %d %d\r\n", trID, ts, ts, len(contacts), len(groups)),
		"GTC A\r\n",
		fmt.Sprintf("BLP %s\r\n", s.Users.Privacy(sess.userEmail)),
		fmt.Sprintf("PRP MFN %s\r\n", escapeName(sess.friendlyName)),
	}
	for _, g := range groups {
		msgs = append(msgs, fmt.Sprintf("LSG %s %s\r\n", escapeName(g.Name), g.GUID))
	}
	for _, c := range contacts {
		name := escapeName(s.resolveFriendlyName(c.Email, c.FriendlyName))
		var line string
		if c.HasList("FL") {
			line = fmt.Sprintf("LST N=%s F=%s C=%s %d", c.Email, name, c.GUID, listBits(c))
			if guids := groupGUIDsMSNP10(c); guids != "" {
				line += " " + guids
			}
		} else {
			line = fmt.Sprintf("LST N=%s F=%s %d", c.Email, name, listBits(c))
		}
		msgs = append(msgs, line+"\r\n")
	}
	for _, m := range msgs {
		s.send(sess, m)
	}
}

// handleADC はMSNP10以降のコンタクト追加。
//
//	ADC trID FL N=email F=name     -> ADC trID FL N=email F=name C=guid
//	ADC trID FL C=guid groupGUID   -> そのまま返す(グループへの追加)
//	ADC trID AL|BL N=email         -> ADC trID AL N=email
func (s *Server) handleADC(sess *clientSession, parts []string, trID string) {
	if len(parts) < 4 {
		s.sendError(sess, errInvalidParameter, trID)
		return
	}
	listType := parts[2]

	if strings.HasPrefix(parts[3], "C=") {
		if listType != "FL" || len(parts) < 5 {
			s.sendError(sess, errInvalidParameter, trID)
			return
		}
		c, ok := s.findContact(sess.userEmail, strings.TrimPrefix(parts[3], "C="))
		if !ok || !c.HasList("FL") {
			s.sendError(sess, errNotInList, trID)
			return
		}
		ref, ok := s.groupRef(sess, parts[4])
		if !ok {
			s.sendError(sess, errInvalidGroup, trID)
			return
		}
		if err := s.Users.SetContactGroups(sess.userEmail, c.GUID, appendUnique(c.Groups, ref)); err != nil {
			log.Printf("[NS] ADC group: %v", err)
			s.sendError(sess, errInvalidGroup, trID)
			return
		}
		s.send(sess, fmt.Sprintf("ADC %s FL C=%s %s\r\n", trID, c.GUID, parts[4]))
		return
	}

	email := strings.TrimPrefix(parts[3], "N=")
	if !strings.Contains(email, "@") {
		s.sendError(sess, errInvalidUser, trID)
		return
	}
	if listType != "FL" {
		s.addToList(sess, listType, email, "")
		s.send(sess, fmt.Sprintf("ADC %s %s N=%s\r\n", trID, listType, email))
		return
	}

	friendlyName := ""
	if len(parts) >= 5 {
		friendlyName, _ = url.QueryUnescape(strings.TrimPrefix(parts[4], "F="))
	}
	friendlyName = s.resolveFriendlyName(email, friendlyName)
	s.addToList(sess, "FL", email, friendlyName)
	// FL追加の場合はALにも追加
	s.addToList(sess, "AL", email, friendlyName)
	guid := s.Users.GetContactGUID(sess.userEmail, email)
	s.send(sess, fmt.Sprintf("ADC %s FL N=%s F=%s C=%s\r\n", trID, email, escapeName(friendlyName), guid))
	s.sendContactPresence(sess, email, "")
}

// handleADD はMSNP8/9のコンタクト追加: ADD trID list email friendlyname [group]
//
//	-> ADD trID list version email friendlyname [group]
//
// FLに入っている連絡先への ADD FL は、グループへの追加として扱う。
func (s *Server) handleADD(sess *clientSession, parts []string, trID string) {
	if len(parts) < 5 {
		s.sendError(sess, errInvalidParameter, trID)
		return
	}
	listType := parts[2]
	email := parts[3]
	if !strings.Contains(email, "@") {
		s.sendError(sess, errInvalidUser, trID)
		return
	}
	friendlyName, _ := url.QueryUnescape(parts[4])
	friendlyName = s.resolveFriendlyName(email, friendlyName)

	if listType != "FL" {
		s.addToList(sess, listType, email, friendlyName)
		s.send(sess, fmt.Sprintf("ADD %s %s %d %s %s\r\n", trID, listType, s.nextListVersion(), email, escapeName(friendlyName)))
		return
	}

	groupID := "0"
	if len(parts) >= 6 {
		groupID = parts[5]
	}
	ref, ok := s.groupRef(sess, groupID)
	if !ok {
		s.sendError(sess, errInvalidGroup, trID)
		return
	}

	existing, inFL := s.findContact(sess.userEmail, email)
	inFL = inFL && existing.HasList("FL")
	groups := []string{ref}
	if inFL {
		groups = appendUnique(memberships(existing), ref)
	} else {
		s.addToList(sess, "FL", email, friendlyName)
	}
	if err := s.Users.SetContactGroups(sess.userEmail, email, groups); err != nil {
		log.Printf("[NS] ADD group: %v", err)
	}

	s.send(sess, fmt.Sprintf("ADD %s FL %d %s %s %s\r\n", trID, s.nextListVersion(), email, escapeName(friendlyName), groupID))
	if !inFL {
		s.sendContactPresence(sess, email, trID)
	}
}

// handleREM はコンタクトの削除。
//
//	MSNP8/9: REM trID list email [group]  -> REM trID list version email [group]
//	         グループを指定した場合はそのグループから外し、どのグループにも残らなければFLから消す。
//	MSNP10:  REM trID FL guid [groupGUID] -> そのまま返す(グループ指定時はグループから外すだけ)
//	         REM trID AL|BL email
func (s *Server) handleREM(sess *clientSession, parts []string, trID string) {
	if len(parts) < 4 {
		s.sendError(sess, errInvalidParameter, trID)
		return
	}
	listType := parts[2]
	c, ok := s.findContact(sess.userEmail, parts[3])
	if !ok || !c.HasList(listType) {
		s.sendError(sess, errNotInList, trID)
		return
	}

	removeFromList := true
	if listType == "FL" && len(parts) >= 5 {
		ref, ok := s.groupRef(sess, parts[4])
		if !ok {
			s.sendError(sess, errInvalidGroup, trID)
			return
		}
		current := c.Groups
		if sess.usesListVersions() {
			current = memberships(c)
		}
		remaining := withoutRef(current, ref)
		// MSNP8/9 ではどのグループにも残らなければFLから消す。MSNP10ではグループなしで残す。
		if !sess.usesListVersions() || len(remaining) > 0 {
			removeFromList = false
			if err := s.Users.SetContactGroups(sess.userEmail, c.GUID, remaining); err != nil {
				log.Printf("[NS] REM group: %v", err)
			}
		}
	}

	if removeFromList {
		if err := s.Users.RemoveContact(sess.userEmail, c.GUID, listType); err != nil {
			log.Printf("[NS] REM: failed to remove contact: %v", err)
		}
		switch listType {
		case "FL":
			_ = s.Users.SetContactGroups(sess.userEmail, c.GUID, nil) // FL以外に残る場合に備えて所属をリセット
			s.updateReverseList(sess, c.Email, false)
		case "AL", "BL":
			s.refreshPresenceFor(sess, c.Email)
		}
	}

	if sess.usesListVersions() {
		resp := fmt.Sprintf("REM %s %s %d %s", trID, listType, s.nextListVersion(), parts[3])
		if len(parts) >= 5 {
			resp += " " + parts[4]
		}
		s.send(sess, resp+"\r\n")
	} else {
		s.send(sess, fmt.Sprintf("REM %s %s\r\n", trID, strings.Join(parts[2:], " ")))
	}
}

// handleADG はグループの作成。
//
//	MSNP8/9: ADG trID name 0 -> ADG trID version name id 0
//	MSNP10:  ADG trID name   -> ADG trID name guid
func (s *Server) handleADG(sess *clientSession, parts []string, trID string) {
	if len(parts) < 3 {
		s.sendError(sess, errInvalidParameter, trID)
		return
	}
	name, _ := url.QueryUnescape(parts[2])
	if code := validateGroupName(name); code != 0 {
		s.sendError(sess, code, trID)
		return
	}
	g, err := s.Users.AddGroup(sess.userEmail, name)
	if err != nil {
		s.sendError(sess, groupErrorCode(err), trID)
		return
	}
	if sess.usesListVersions() {
		s.send(sess, fmt.Sprintf("ADG %s %d %s %d 0\r\n", trID, s.nextListVersion(), escapeName(g.Name), g.ID))
	} else {
		s.send(sess, fmt.Sprintf("ADG %s %s %s\r\n", trID, escapeName(g.Name), g.GUID))
	}
}

// handleRMG はグループの削除。
//
//	MSNP8/9: RMG trID id   -> RMG trID version id
//	MSNP10:  RMG trID guid -> RMG trID guid
func (s *Server) handleRMG(sess *clientSession, parts []string, trID string) {
	if len(parts) < 3 {
		s.sendError(sess, errInvalidParameter, trID)
		return
	}
	if sess.usesListVersions() && parts[2] == "0" {
		s.sendError(sess, errCannotRemoveZero, trID)
		return
	}
	if _, err := s.Users.RemoveGroup(sess.userEmail, parts[2]); err != nil {
		s.sendError(sess, groupErrorCode(err), trID)
		return
	}
	if sess.usesListVersions() {
		s.send(sess, fmt.Sprintf("RMG %s %d %s\r\n", trID, s.nextListVersion(), parts[2]))
	} else {
		s.send(sess, fmt.Sprintf("RMG %s %s\r\n", trID, parts[2]))
	}
}

// handleREG はグループ名の変更。
//
//	MSNP8/9: REG trID id name 0 -> REG trID version id name 0
//	MSNP10:  REG trID guid name -> REG trID guid name
func (s *Server) handleREG(sess *clientSession, parts []string, trID string) {
	if len(parts) < 4 {
		s.sendError(sess, errInvalidParameter, trID)
		return
	}
	name, _ := url.QueryUnescape(parts[3])
	if code := validateGroupName(name); code != 0 {
		s.sendError(sess, code, trID)
		return
	}
	g, err := s.Users.RenameGroup(sess.userEmail, parts[2], name)
	if err != nil {
		s.sendError(sess, groupErrorCode(err), trID)
		return
	}
	if sess.usesListVersions() {
		s.send(sess, fmt.Sprintf("REG %s %d %d %s 0\r\n", trID, s.nextListVersion(), g.ID, escapeName(g.Name)))
	} else {
		s.send(sess, fmt.Sprintf("REG %s %s %s\r\n", trID, g.GUID, escapeName(g.Name)))
	}
}

func validateGroupName(name string) int {
	switch {
	case strings.TrimSpace(name) == "":
		return errInvalidParameter
	case len([]rune(name)) > maxGroupNameLen:
		return errGroupNameTooLong
	}
	return 0
}

func groupErrorCode(err error) int {
	switch {
	case errors.Is(err, core.ErrGroupExists):
		return errGroupExists
	case errors.Is(err, core.ErrGroupNotFound):
		return errInvalidGroup
	}
	return errInvalidParameter
}

func appendUnique(list []string, v string) []string {
	out := append([]string(nil), list...)
	for _, x := range out {
		if x == v {
			return out
		}
	}
	return append(out, v)
}

func withoutRef(list []string, v string) []string {
	var out []string
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// addToList はコンタクトをリストに追加し、FLなら相手のRLを、AL/BLなら相手から見た在席状態を更新する。
func (s *Server) addToList(sess *clientSession, listType, email, friendlyName string) {
	if err := s.Users.AddContact(sess.userEmail, email, friendlyName, listType); err != nil {
		log.Printf("[NS] add %s to %s: %v", email, listType, err)
		return
	}
	switch listType {
	case "FL":
		s.updateReverseList(sess, email, true)
	case "AL", "BL":
		s.refreshPresenceFor(sess, email)
	}
}

// updateReverseList は相手のRL(自分をFLに入れている人の一覧)を更新し、相手がオンラインなら知らせる。
func (s *Server) updateReverseList(sess *clientSession, email string, added bool) {
	if _, ok := s.Users.Get(email); !ok {
		return
	}
	var err error
	if added {
		if s.Users.HasList(email, sess.userEmail, "RL") {
			return
		}
		err = s.Users.AddContact(email, sess.userEmail, sess.friendlyName, "RL")
	} else {
		if !s.Users.HasList(email, sess.userEmail, "RL") {
			return
		}
		err = s.Users.RemoveContact(email, sess.userEmail, "RL")
	}
	if err != nil {
		log.Printf("[NS] update RL of %s: %v", email, err)
		return
	}

	var msgs []outgoing
	s.mu.RLock()
	if target := s.sessionForLocked(email); target != nil {
		var msg string
		switch {
		case added && target.usesListVersions():
			msg = fmt.Sprintf("ADD 0 RL %d %s %s\r\n", s.nextListVersion(), sess.userEmail, escapeName(sess.friendlyName))
		case added:
			msg = fmt.Sprintf("ADC 0 RL N=%s F=%s\r\n", sess.userEmail, escapeName(sess.friendlyName))
		case target.usesListVersions():
			msg = fmt.Sprintf("REM 0 RL %d %s\r\n", s.nextListVersion(), sess.userEmail)
		default:
			msg = fmt.Sprintf("REM 0 RL %s\r\n", sess.userEmail)
		}
		msgs = append(msgs, outgoing{target, msg})
	}
	s.mu.RUnlock()
	s.sendAll(msgs)
}

// sendContactPresence はFLに追加した相手がオンラインなら、その在席状態を知らせる。
// trIDが空ならNLN、そうでなければILN(MSNP8のADDへの応答)で送る。
func (s *Server) sendContactPresence(sess *clientSession, email, trID string) {
	var msgs []outgoing
	s.mu.RLock()
	if other := s.sessionForLocked(email); other != nil && other.visible() && s.allows(other.userEmail, sess.userEmail) {
		if trID == "" {
			msgs = append(msgs, outgoing{sess, fmt.Sprintf("NLN %s\r\n", presenceArgs(other, sess)) + ubxLocked(other, sess)})
		} else {
			msgs = append(msgs, outgoing{sess, fmt.Sprintf("ILN %s %s\r\n", trID, presenceArgs(other, sess)) + ubxLocked(other, sess)})
		}
	}
	s.mu.RUnlock()
	s.sendAll(msgs)
}
