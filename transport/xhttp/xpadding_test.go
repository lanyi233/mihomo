package xhttp

import (
	"io"
	"net"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
)

// Panels such as Remnawave write x-padding-bytes: "0-0" when padding is
// switched off. Xray-core reads a range whose upper bound is 0 as unset and
// uses 100-1000 on both ends, so a client configured that way must still send
// padding the server accepts -- whether the server was given the same "0-0"
// or left padding at its default.
func TestXPaddingBytesZeroRangeStillSendsPaddingTheServerAccepts(t *testing.T) {
	testCases := []struct {
		name   string
		mode   string
		method string
		target string
	}{
		{
			name:   "StreamOne",
			mode:   "stream-one",
			method: http.MethodPost,
			target: "https://example.com/xhttp/",
		},
		{
			name:   "PacketUpDownload",
			mode:   "packet-up",
			method: http.MethodGet,
			target: "https://example.com/xhttp/session",
		},
	}

	for _, serverPadding := range []string{"0-0", ""} {
		for _, testCase := range testCases {
			t.Run(testCase.name+"/server="+serverPadding, func(t *testing.T) {
				clientConfig := Config{
					Path:          "/xhttp",
					Mode:          testCase.mode,
					XPaddingBytes: "0-0",
				}
				serverConfig := clientConfig
				serverConfig.XPaddingBytes = serverPadding

				handler, err := NewServerHandler(ServerOption{
					Config: serverConfig,
					ConnHandler: func(conn net.Conn) {
						_ = conn.Close()
					},
				})
				if !assert.NoError(t, err) {
					return
				}

				req := httptest.NewRequest(testCase.method, testCase.target, io.NopCloser(http.NoBody))
				recorder := httptest.NewRecorder()

				if !assert.NoError(t, clientConfig.FillStreamRequest(req, "")) {
					return
				}

				handler.ServeHTTP(recorder, req)

				assert.Equal(t, http.StatusOK, recorder.Result().StatusCode, recorder.Body.String())
			})
		}
	}
}
