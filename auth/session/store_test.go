package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// saveNew は、空のセッションに値を入れて保存し、発行されたクッキーを返します。
func saveNew(t *testing.T, store Store, values map[string]string) *http.Cookie {
	t.Helper()

	session, err := store.Get(httptest.NewRequest(http.MethodGet, "/", nil), "s")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	for k, v := range values {
		session.Values[k] = v
	}

	rr := httptest.NewRecorder()
	if err := store.Save(httptest.NewRequest(http.MethodGet, "/", nil), rr, session); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	return cookies[0]
}

// getWith は、クッキーを付けてセッションを読み出します。
func getWith(t *testing.T, store Store, c *http.Cookie) *Session {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	session, err := store.Get(req, "s")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if session == nil {
		t.Fatal("Get() は nil を返さない約束です")
	}
	return session
}

// TestMemoryStoreRoundTrip は、保存した値が読み戻せることと、発行したクッキーに
// 防御属性が載ることを確認します。
//
// 属性は落ちても機能が動くので気付けません。HttpOnly が外れたクッキーでも
// ログインは通り、壊れているのは XSS に対する防御だけです。
func TestMemoryStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(StoreConfig{MaxAge: time.Hour, Secure: true})

	got := saveNew(t, store, map[string]string{DefaultUserSessionKey: "user@example.com"})

	if !got.HttpOnly || !got.Secure || got.SameSite != http.SameSiteLaxMode || got.Path != "/" || got.MaxAge != 3600 {
		t.Errorf("cookie attributes = %+v", got)
	}
	// クッキーが運ぶのは不透明な ID だけで、中身は載りません。
	if got.Value == "" || got.Value == "user@example.com" {
		t.Errorf("cookie value = %q（ID ではありません）", got.Value)
	}

	back := getWith(t, store, got)
	if back.IsNew {
		t.Error("保存済みのセッションを読んだのに IsNew が true です")
	}
	if back.Values[DefaultUserSessionKey] != "user@example.com" {
		t.Errorf("Values = %v", back.Values)
	}
	if back.ID != got.Value {
		t.Errorf("ID = %q, want %q", back.ID, got.Value)
	}
}

// TestMemoryStoreIgnoresUnknownID は、保存されていない ID を採用しないことを
// 確認します。
//
// ★ これがセッション固定攻撃への防御です。ID はクッキー経由で攻撃者が指定できるので、
// 採用してしまうと「攻撃者が選んだ ID のセッションを被害者が使う」状態を作れます。
// クッキーストアには ID の概念が無く、この防御は存在しませんでした。
func TestMemoryStoreIgnoresUnknownID(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(StoreConfig{MaxAge: time.Hour})
	planted := &http.Cookie{Name: "s", Value: "attacker-known-id"}

	session := getWith(t, store, planted)
	if !session.IsNew {
		t.Error("保存されていない ID が既存セッションとして扱われました")
	}
	if session.ID != "" {
		t.Errorf("ID = %q、保存されていない ID を採用しています", session.ID)
	}

	// 保存すると、攻撃者の知らない ID が振られること。
	session.Values[DefaultUserSessionKey] = "user@example.com"
	rr := httptest.NewRecorder()
	if err := store.Save(httptest.NewRequest(http.MethodGet, "/", nil), rr, session); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if session.ID == "" || session.ID == planted.Value {
		t.Errorf("ID = %q, want 新しい ID", session.ID)
	}
	if got := rr.Result().Cookies()[0].Value; got == planted.Value {
		t.Error("仕込まれた ID がそのままクッキーへ返されました")
	}
}

// TestMemoryStoreExpires は、期限を過ぎたセッションが読めないことを確認します。
func TestMemoryStoreExpires(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(StoreConfig{MaxAge: time.Nanosecond})
	c := saveNew(t, store, map[string]string{DefaultUserSessionKey: "user@example.com"})

	time.Sleep(time.Millisecond)

	session := getWith(t, store, c)
	if !session.IsNew || len(session.Values) != 0 {
		t.Errorf("期限切れのセッションが読めています: %+v", session)
	}
}

// TestMemoryStoreDeletes は、MaxAge が負の Save が実体ごと消すことを確認します。
//
// クッキーを落とすだけでは、盗まれたクッキーは有効なままです。サーバー側の実体を
// 消すことが「本当のログアウト」の中身で、クッキーストアにはできませんでした。
func TestMemoryStoreDeletes(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(StoreConfig{MaxAge: time.Hour})
	c := saveNew(t, store, map[string]string{DefaultUserSessionKey: "user@example.com"})

	session := getWith(t, store, c)
	session.Options.MaxAge = -1
	rr := httptest.NewRecorder()
	if err := store.Save(httptest.NewRequest(http.MethodGet, "/", nil), rr, session); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if got := rr.Result().Cookies()[0].MaxAge; got != -1 {
		t.Errorf("cookie MaxAge = %d, want -1", got)
	}

	// 同じクッキーをもう一度出しても、実体が無いので通らないこと。
	if back := getWith(t, store, c); !back.IsNew {
		t.Error("削除したはずのセッションが、元のクッキーで読めています")
	}
}
