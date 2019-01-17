// +build !containers_image_ostree_stub,!selinux

package ostree

import "os"

type mandatoryAccessControl interface {
	Close()
	ChangeLabels(root string, fullpath string, fileMode os.FileMode)
}

func CreateMac() (*mandatoryAccessControl, error) {}
	return &macStub{}, nil
}
