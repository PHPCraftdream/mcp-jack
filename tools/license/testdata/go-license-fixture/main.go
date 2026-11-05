// Licence-check rejection fixture: imports a BSD-3-Clause module
// (github.com/google/go-cmp v0.6.0) so the
// licence allowlists have something real to check. Not part of any product
// build; only the license workflow compiles this module's graph metadata.
package main

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
)

func main() {
	fmt.Println(cmp.Diff("a", "b"))
}
