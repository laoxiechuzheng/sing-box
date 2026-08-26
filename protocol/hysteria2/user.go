package hysteria2

import (
	"github.com/sagernet/sing-box/option"
)

func (h *Inbound) UpdateUsers(users []option.Hysteria2User) error {
	userList := make([]int, 0, len(users))
	userNameList := make([]string, 0, len(users))
	userPasswordList := make([]string, 0, len(users))
	for index, user := range users {
		userList = append(userList, index)
		userNameList = append(userNameList, user.Name)
		userPasswordList = append(userPasswordList, user.Password)
	}
	// Publish the name list before the authenticator starts handing out the
	// matching indices, otherwise an incoming connection authenticated against
	// the new user set can observe the previous, shorter list.
	h.userNameList.Store(&userNameList)
	h.service.UpdateUsers(userList, userPasswordList)
	return nil
}
