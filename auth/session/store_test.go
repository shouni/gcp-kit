package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
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
// 消すことが「本当のログアウト」の中身です。
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

// TestIsValidSessionID は、発行した形の ID だけを通すことを確認します。
//
// ID はクッキーで届く＝相手が決められる値で、Firestore ストアはそれをドキュメントの
// パスに使います。"/" を通してしまうと、Doc() がサブコレクションのパスとして解釈し、
// 本来のコレクションの外を指せます。
func TestIsValidSessionID(t *testing.T) {
	t.Parallel()

	minted, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID() error = %v", err)
	}
	if !isValidSessionID(minted) {
		t.Fatalf("発行した ID %q が弾かれました", minted)
	}

	for _, id := range []string{
		"",
		"attacker-known-id",                   // 長さが違う
		minted[:len(minted)-1],                // 1 文字短い
		minted + "x",                          // 1 文字長い
		strings.Repeat("a", 42) + "/",         // サブコレクションへのパス
		strings.Repeat("a", 41) + "/./",       // 同上（相対パス片）
		strings.Repeat("a", 42) + ".",         // Firestore の禁則
		strings.Repeat("_", 43),               // Firestore が予約する "__…__"
		"__" + strings.Repeat("a", 39) + "__", // 同上（文字種と長さは正しい）
		strings.Repeat("a", 42) + " ",         // 空白
		strings.Repeat("a", 42) + "\n",        // 制御文字
		strings.Repeat("a", 42) + "\u00e3",    // 非 ASCII
	} {
		if isValidSessionID(id) {
			t.Errorf("isValidSessionID(%q) = true、want false", id)
		}
	}
}

// TestNewSessionIDIsAlwaysValid は、発行した ID が必ず自分の検証を通ることを
// 確認します。通らない ID を発行すると、その回だけ保存が失敗し、しかも乱数由来なので
// 再現しません。
func TestNewSessionIDIsAlwaysValid(t *testing.T) {
	t.Parallel()

	for range 1000 {
		id, err := newSessionID()
		if err != nil {
			t.Fatalf("newSessionID() error = %v", err)
		}
		if !isValidSessionID(id) {
			t.Fatalf("発行した ID %q が自分の検証を通りません", id)
		}
	}
}

// TestFirestoreStoreRejectsMalformedIDBeforeTheRPC は、形の合わない ID が
// Firestore へ渡らないことを確認します。
//
// client を nil にしてあるのが検証そのものです。問い合わせに進めば nil 参照で
// パニックするので、素通りするようになれば必ずここで落ちます。
func TestFirestoreStoreRejectsMalformedIDBeforeTheRPC(t *testing.T) {
	t.Parallel()

	store := &firestoreStore{collection: "sessions", opts: StoreConfig{MaxAge: time.Hour}.options()}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "s", Value: "sessions/../other/doc"})

	session, err := store.Get(req, "s")
	if err != nil {
		t.Fatalf("Get() error = %v、want nil（実体が無いのと同じ扱い）", err)
	}
	if !session.IsNew || session.ID != "" {
		t.Fatalf("IsNew = %v, ID = %q、形の合わない ID を採用しています", session.IsNew, session.ID)
	}
}

// TestFirestoreStoreRefusesForeignID は、手で入れた ID をそのまま書かないことを
// 確認します。Get が採用する ID は検証済みなので、ここへ来るのは呼び出し側が
// 組み立てた値だけです。
func TestFirestoreStoreRefusesForeignID(t *testing.T) {
	t.Parallel()

	store := &firestoreStore{collection: "sessions", opts: StoreConfig{MaxAge: time.Hour}.options()}

	session := NewSession("s")
	session.ID = "sessions/../other/doc"

	err := store.Save(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder(), session)
	if err == nil {
		t.Fatal("Save() error = nil、want error")
	}
}
