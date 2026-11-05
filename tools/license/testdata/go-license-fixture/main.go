// Licence-check rejection fixture: imports an Apache-2.0-only module so the
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
