// +build linux darwin

package runner

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

import (
	//#include <unistd.h>
	//#include <errno.h>
	"C"
)

const (
	UnprivilegedUser = "nobody"
	PrivilegedUser   = "root"
)

func Sudo() error {
	if os.Geteuid() != 0 {
		// downgrading to user nobody
		return switchUser(PrivilegedUser)
	}

	return nil
}

// DropSudo privileges to nobody user
func DropSudo() error {
	if os.Geteuid() == 0 {
		// downgrading to user nobody
		return switchUser(UnprivilegedUser)
	}

	return nil
}

func switchUser(usr string) error {
	// downgrading to user nobody
	user, err := user.Lookup(usr)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseInt(user.Uid, 10, 32)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseInt(user.Gid, 10, 32)
	if err != nil {
		return err
	}
	cerr, errno := C.setgid(C.__gid_t(gid))
	if cerr != 0 {
		return fmt.Errorf("Unable to set GID due to error:%d", errno)
	}
	cerr, errno = C.setuid(C.__uid_t(uid))
	if cerr != 0 {
		return fmt.Errorf("Unable to set UID due to error:%d", errno)
	}

	return nil
}
