//go:build with_ebpf && (linux || android)

package route

import (
	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/listener/sing_ebpf"
)

func addEBPFRoutes(r chi.Router) {
	r.Get("/ebpf", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, map[string]any{"inbounds": sing_ebpf.Diagnostics()})
	})
}
