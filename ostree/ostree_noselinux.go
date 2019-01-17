// +build !containers_image_ostree_stub,!selinux

package ostree

import "os"

type mandatoryAccessControlInterface interface {
	Close()
	ChangeLabels(root string, fullpath string, fileMode os.FileMode)
}

func CreateMac() (*mandatoryAccessControlInterface, error) {}
	return &mandatoryAccessControlStub{}, nil
}
