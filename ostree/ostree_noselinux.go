// +build !containers_image_ostree_stub,!selinux

package ostree

import (
	"os"
	"unsafe"
)

type mandatoryAccessControl struct {
	handler *unsafe.Pointer
}

func (m mandatoryAccessControl) Open() error {
	return nil
}

func (m mandatoryAccessControl) Close() {}

func (m mandatoryAccessControl) changeLabels(root string, fullpath string, fileMode os.FileMode) error {
	return nil
}
