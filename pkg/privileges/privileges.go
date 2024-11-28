package privileges

var IsPrivileged bool

func init() {
	IsPrivileged = isPrivileged()
}
