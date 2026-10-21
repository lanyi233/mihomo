//go:build !with_ebpf || (!linux && !android)

package route

import "github.com/metacubex/chi"

func addEBPFRoutes(r chi.Router) {}
