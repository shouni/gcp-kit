package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCookieStoreRoundTrip は、保存した値が読み戻せることと、発行したクッキーに
// 防御属性が載ることを確認します。
//
// 属性は、落ちても機能は動くので気付けません。HttpOnly が外れたクッキーでも
// ログインは通り、壊れているのは XSS に対する防御だけです。
func TestCookieStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store := NewCookieStore(
		Options{Path: "/", MaxAge: 3600, HTTPOnly: true, Secure: true, SameSite: http.SameSiteLaxMode},
		[]byte(testCookieKey), []byte(testCookieKey),
	)

	rr := httptest.NewRecorder()
	session, err := store.Get(httptest.NewRequest(http.MethodGet, "/", nil), "s")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !session.IsNew {
		t.Error("クッキーが無いのに IsNew が false です")
	}
	session.Values[DefaultUserSessionKey] = "user@example.com"
	if err := store.Save(httptest.NewRequest(http.MethodGet, "/", nil), rr, session); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	got := cookies[0]
	if !got.HttpOnly || !got.Secure || got.SameSite != http.SameSiteLaxMode || got.Path != "/" || got.MaxAge != 3600 {
		t.Errorf("cookie attributes = %+v", got)
	}
	// 中身が平文で載っていないこと。securecookie を通していれば起こりませんが、
	// 通し忘れても読み書きは成立してしまうので、ここで見ます。
	if got.Value == "" || got.Value == "user@example.com" {
		t.Errorf("cookie value = %q（暗号化されていません）", got.Value)
	}

	readReq := httptest.NewRequest(http.MethodGet, "/", nil)
	readReq.AddCookie(got)
	back, err := store.Get(readReq, "s")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if back.IsNew {
		t.Error("既存のクッキーを読んだのに IsNew が true です")
	}
	if back.Values[DefaultUserSessionKey] != "user@example.com" {
		t.Errorf("Values = %v", back.Values)
	}
}

// TestCookieStoreRejectsOtherKeys は、別の鍵で焼いたクッキーを受け付けないことを
// 確認します。読めない場合も、呼び出し元が触れる空のセッションを返します。
func TestCookieStoreRejectsOtherKeys(t *testing.T) {
	t.Parallel()

	opts := Options{Path: "/", MaxAge: 3600}
	mine := NewCookieStore(opts, []byte(testCookieKey), []byte(testCookieKey))
	theirs := NewCookieStore(opts, []byte("abcdefghijklmnop"), []byte("abcdefghijklmnop"))

	rr := httptest.NewRecorder()
	session, _ := theirs.Get(httptest.NewRequest(http.MethodGet, "/", nil), "s")
	session.Values[DefaultUserSessionKey] = "intruder@example.com"
	if err := theirs.Save(httptest.NewRequest(http.MethodGet, "/", nil), rr, session); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(rr.Result().Cookies()[0])
	got, err := mine.Get(req, "s")
	if err == nil {
		t.Error("別の鍵で焼いたクッキーを受け付けました")
	}
	if got == nil {
		t.Fatal("読めない場合も nil ではなく空のセッションを返す約束です")
	}
	if len(got.Values) != 0 {
		t.Errorf("Values = %v、読めなかったのに値が残っています", got.Values)
	}
}
