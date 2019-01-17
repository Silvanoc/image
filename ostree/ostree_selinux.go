// +build !containers_image_ostree_stub,selinux

package ostree

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	selinux "github.com/opencontainers/selinux/go-selinux"
	"github.com/pkg/errors"
)

// #cgo pkg-config: glib-2.0 libselinux
// #include <glib.h>
// #include <stdlib.h>
// #include <selinux/selinux.h>
// #include <selinux/label.h>
import "C"

type mandatoryAccessControl struct {
	handler *C.struct_selabel_handle
}

func (m mandatoryAccessControl) Open() error {
	if os.Getuid() == 0 && selinux.GetEnabled() {
		selinuxHnd, err := C.selabel_open(C.SELABEL_CTX_FILE, nil, 0)
		if selinuxHnd == nil {
			return errors.Wrapf(err, "cannot open the SELinux DB")
		}
	}
	m.handler = selinuxHnd
	return nil
}

func (m mandatoryAccessControl) Close() {
	C.selabel_close(m.handler)
}

func (m mandatoryAccessControl) checkPermissions(root string, fullpath string, fileMode os.FileMode) error {
	relPath, err := filepath.Rel(root, fullpath)
	if err != nil {
		return err
	}
	// Handle /exports/hostfs as a special case.  Files under this directory are copied to the host,
	// thus we benefit from maintaining the same SELinux label they would have on the host as we could
	// use hard links instead of copying the files.
	relPath = fmt.Sprintf("/%s", strings.TrimPrefix(relPath, "exports/hostfs/"))

	relPathC := C.CString(relPath)
	defer C.free(unsafe.Pointer(relPathC))
	var context *C.char

	res, err := C.selabel_lookup_raw(m.handler, &context, relPathC, C.int(fileMode&os.ModePerm))
	if int(res) < 0 && err != syscall.ENOENT {
		return errors.Wrapf(err, "cannot selabel_lookup_raw %s", relPath)
	}
	if int(res) == 0 {
		defer C.freecon(context)
		fullpathC := C.CString(fullpath)
		defer C.free(unsafe.Pointer(fullpathC))
		res, err = C.lsetfilecon_raw(fullpathC, context)
		if int(res) < 0 {
			return errors.Wrapf(err, "cannot setfilecon_raw %s", fullpath)
		}
	}

	return nil
}
