package ostree

import "os"

type mandatoryAccessControlStub struct{}

func (m mandatoryAccessControlStub) Close() {}

func (m mandatoryAccessControlStub) ChangeLabels(root string, fullpath string, fileMode os.FileMode) error {
	return nil
}
