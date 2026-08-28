package negotiate_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shouni/gcp-kit/negotiate"
)

func TestJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	negotiate.JSON(rec, req, http.StatusCreated, map[string]string{"id": "job-1"})

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"id":"job-1"}` {
		t.Errorf("body = %q", got)
	}
	// JSON しか返さない経路に Vary は要らない。立てるのは WantsJSON の仕事。
	if got := rec.Header().Get("Vary"); got != "" {
		t.Errorf("Vary = %q, want 空（JSON は表現を出し分けない）", got)
	}
}

// TestJSONLogsEncodeFailure は、ヘッダー送信後に失敗しても記録が残ることを検証します。
// 状態コードはもう差し替えられないため、記録が唯一の手掛かりになります。
func TestJSONLogsEncodeFailure(t *testing.T) {
	var buf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(restore) })

	// chan は JSON にできないため、Encode がヘッダー送信後に失敗します。
	// リクエストの有無で分けているのは、ログ用のコンテキストを r から取るためです。
	// ハンドラーの外から呼ばれても記録は残る必要があります。
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/", nil),
		nil,
	} {
		buf.Reset()
		rec := httptest.NewRecorder()

		negotiate.JSON(rec, req, http.StatusOK, make(chan int))

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200（ヘッダーは送信済みで変えられない）", rec.Code)
		}
		if !strings.Contains(buf.String(), "エンコードに失敗") {
			t.Errorf("エンコード失敗が記録されていません (req=%v): %s", req != nil, buf.String())
		}
	}
}

func TestError(t *testing.T) {
	tests := []struct {
		name            string
		accept          string
		wantContentType string
		wantBody        string
	}{
		{
			name:            "JSON を求めた相手には JSON",
			accept:          "application/json",
			wantContentType: "application/json; charset=utf-8",
			wantBody:        `{"error":"not found"}`,
		},
		{
			name:            "ページを求めた相手には text/plain",
			accept:          "text/html",
			wantContentType: "text/plain; charset=utf-8",
			wantBody:        "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept", tt.accept)

			negotiate.Error(rec, req, http.StatusNotFound, "not found")

			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != tt.wantContentType {
				t.Errorf("Content-Type = %q, want %q", got, tt.wantContentType)
			}
			if got := strings.TrimSpace(rec.Body.String()); got != tt.wantBody {
				t.Errorf("body = %q, want %q", got, tt.wantBody)
			}
			// 応答が Accept で変わる以上、キャッシュへ伝える必要がある。
			if got := rec.Header().Get("Vary"); got != "Accept" {
				t.Errorf("Vary = %q, want %q", got, "Accept")
			}
		})
	}
}

// TestErrorBodyShape は、エラー本文の形が {"error": ...} であることを固定します。
// 4 つのバックエンドを 1 つのクライアントから呼ぶため、形が割れると読み方が変わります。
func TestErrorBodyShape(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")

	negotiate.Error(rec, req, http.StatusBadGateway, "ストレージから読めませんでした")

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("本文が JSON として読めません: %v (%s)", err, rec.Body.String())
	}
	if len(body) != 1 {
		t.Errorf("body = %v, want キーは error だけ", body)
	}
	if body["error"] != "ストレージから読めませんでした" {
		t.Errorf("body[error] = %v", body["error"])
	}
}

func TestWriteNilArgs(t *testing.T) {
	// nil の ResponseWriter でも落ちない。
	negotiate.JSON(nil, nil, http.StatusOK, map[string]string{})

	// リクエストが nil でも書き出せる（ログ用のコンテキストだけ既定に倒れる）。
	noReq := httptest.NewRecorder()
	negotiate.JSON(noReq, nil, http.StatusOK, map[string]string{"ok": "yes"})
	if got := strings.TrimSpace(noReq.Body.String()); got != `{"ok":"yes"}` {
		t.Errorf("body = %q", got)
	}

	// r が nil なら JSON は求められていない扱いになり、text/plain へ倒れる。
	rec := httptest.NewRecorder()
	negotiate.Error(rec, nil, http.StatusInternalServerError, "boom")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "boom" {
		t.Errorf("body = %q", got)
	}
}

// TestErrorJSON は、相手が何を求めていても JSON を返すことを検証します。
//
// JSON しか返さないルートでは、成功時が無条件 JSON である以上、エラーも同じ形で
// なければ呼び出し側が成功と失敗で本文の読み方を変えることになります。
func TestErrorJSON(t *testing.T) {
	for _, accept := range []string{"application/json", "text/html", "*/*", ""} {
		t.Run("Accept="+accept, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if accept != "" {
				req.Header.Set("Accept", accept)
			}

			negotiate.ErrorJSON(rec, req, http.StatusBadGateway, "読み出しに失敗しました")

			if rec.Code != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
				t.Errorf("Content-Type = %q", got)
			}

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("本文が JSON として読めません: %v (%s)", err, rec.Body.String())
			}
			if body["error"] != "読み出しに失敗しました" {
				t.Errorf("body[error] = %v", body["error"])
			}
			// 応答が Accept で変わらない以上、Vary を立てる理由がありません。
			if got := rec.Header().Get("Vary"); got != "" {
				t.Errorf("Vary = %q, want 空", got)
			}
		})
	}
}

// TestErrorAndErrorJSONAgreeForJSONCallers は、JSON を求めた相手には
// 2 つが同じ応答を返すことを固定します。違いは「求めていない相手に何を返すか」
// だけである、という関係を崩さないためです。
func TestErrorAndErrorJSONAgreeForJSONCallers(t *testing.T) {
	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept", "application/json")
		return req
	}

	negotiated := httptest.NewRecorder()
	negotiate.Error(negotiated, newReq(), http.StatusNotFound, "見つかりません")

	always := httptest.NewRecorder()
	negotiate.ErrorJSON(always, newReq(), http.StatusNotFound, "見つかりません")

	if negotiated.Code != always.Code {
		t.Errorf("status = %d / %d", negotiated.Code, always.Code)
	}
	if negotiated.Body.String() != always.Body.String() {
		t.Errorf("body = %q / %q", negotiated.Body.String(), always.Body.String())
	}
	if got, want := negotiated.Header().Get("Content-Type"), always.Header().Get("Content-Type"); got != want {
		t.Errorf("Content-Type = %q / %q", got, want)
	}
	// Error は判定するので Vary を立て、ErrorJSON は立てません。
	if negotiated.Header().Get("Vary") != "Accept" {
		t.Error("Error が Vary: Accept を立てていません")
	}
	if always.Header().Get("Vary") != "" {
		t.Error("ErrorJSON が Vary を立てています")
	}
}
