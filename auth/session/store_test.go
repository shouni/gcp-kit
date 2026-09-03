package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMemoryStoreRoundTrip は、保存した値が同じ ID で読み戻せること、返る map が
// 保存側と共有されていないことを確認します。
func TestMemoryStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()
	values := map[string]string{DefaultUserSessionKey: "user@example.com"}

	if err := store.Save(ctx, "id-1", values, time.Hour); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	values[DefaultUserSessionKey] = "changed-after-save"

	back, err := store.Load(ctx, "id-1")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if back[DefaultUserSessionKey] != "user@example.com" {
		t.Errorf("Load() = %v, want the values as saved（保存後の変更が漏れています）", back)
	}
	back[DefaultUserSessionKey] = "changed-after-load"
	if again, _ := store.Load(ctx, "id-1"); again[DefaultUserSessionKey] != "user@example.com" {
		t.Error("Load() が返した map を書き換えると保存側が変わります")
	}
}

// TestMemoryStoreNotFound は、無い ID が ErrNotFound になることを確認します。
// Handler はこれを「実体が無い」と読んでクッキーの ID を採用しません。
func TestMemoryStoreNotFound(t *testing.T) {
	t.Parallel()

	if _, err := NewMemoryStore().Load(context.Background(), "never-saved"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error = %v, want ErrNotFound", err)
	}
}

// TestMemoryStoreExpires は、期限を過ぎた実体が読めないことを確認します。
func TestMemoryStoreExpires(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Save(ctx, "id-1", map[string]string{"k": "v"}, time.Nanosecond); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	time.Sleep(time.Millisecond)

	if _, err := store.Load(ctx, "id-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error = %v, want ErrNotFound for an expired session", err)
	}
}

// TestMemoryStoreDeletes は、Delete が実体を消し、無い ID でもエラーにしないことを確認します。
func TestMemoryStoreDeletes(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Save(ctx, "id-1", map[string]string{"k": "v"}, time.Hour); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if err := store.Delete(ctx, "id-1"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Load(ctx, "id-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() after Delete = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, "id-1"); err != nil {
		t.Fatalf("Delete() of a missing ID error = %v, want nil", err)
	}
}

// TestSessionCookieAttributes は、Handler が発行するセッションクッキーに防御属性が
// 載ることを確認します。属性は落ちても機能が動くので気付けません。HttpOnly が外れた
// クッキーでもログインは通り、壊れているのは XSS に対する防御だけです。
func TestSessionCookieAttributes(t *testing.T) {
	t.Parallel()

	h := &Handler{store: newTestStore(), sessionName: "s", isSecureCookie: true, cfgSessionMaxAge: time.Hour}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	s := newSession()
	s.values[DefaultUserSessionKey] = "user@example.com"

	if err := h.saveSession(rr, req, s); err != nil {
		t.Fatalf("saveSession() error = %v", err)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	got := cookies[0]
	if !got.HttpOnly || !got.Secure || got.SameSite != http.SameSiteLaxMode || got.Path != "/" || got.MaxAge != 3600 {
		t.Errorf("cookie attributes = %+v", got)
	}
	// クッキーが運ぶのは不透明な ID だけで、中身は載りません。
	if got.Value != s.id || !isValidSessionID(got.Value) || strings.Contains(got.Value, "example.com") {
		t.Errorf("cookie value = %q（発行した ID ではありません）", got.Value)
	}
}

// TestLoadSessionIgnoresUnknownID は、保存されていない ID を採用しないことを確認します。
//
// ★ これがセッション固定攻撃への防御です。ID はクッキー経由で攻撃者が指定できるので、
// 採用してしまうと「攻撃者が選んだ ID のセッションを被害者が使う」状態を作れます。
// 形の合う ID で試すのは、形の合わないものは Load の手前で捨てられるためです。
func TestLoadSessionIgnoresUnknownID(t *testing.T) {
	t.Parallel()

	h := &Handler{store: newTestStore(), sessionName: "s"}
	planted, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "s", Value: planted})

	s, err := h.loadSession(req)
	if err != nil {
		t.Fatalf("loadSession() error = %v", err)
	}
	if s.id != "" {
		t.Fatalf("id = %q、保存されていない ID を採用しています", s.id)
	}

	// 保存すると、攻撃者の知らない ID が振られること。
	rr := httptest.NewRecorder()
	if err := h.saveSession(rr, req, s); err != nil {
		t.Fatalf("saveSession() error = %v", err)
	}
	if s.id == "" || s.id == planted {
		t.Errorf("id = %q, want 新しい ID", s.id)
	}
}

// TestLoadSessionRejectsMalformedIDBeforeTheStore は、形の合わない ID がストアへ
// 渡らないことを確認します。unavailableStore は呼ばれれば必ずエラーを返すので、
// エラー無しで戻れば呼ばれていません。
func TestLoadSessionRejectsMalformedIDBeforeTheStore(t *testing.T) {
	t.Parallel()

	h := &Handler{store: unavailableStore{}, sessionName: "s"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "s", Value: "sessions/../other/doc"})

	s, err := h.loadSession(req)
	if err != nil {
		t.Fatalf("loadSession() error = %v, want nil（ストアに触れていない）", err)
	}
	if s.id != "" {
		t.Fatalf("id = %q, want empty", s.id)
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

// TestFirestoreStoreRejectsMalformedIDBeforeTheRPC は、形の合わない ID が Firestore へ
// 渡らないことを確認します。Handler も手前で捨てますが、Store は公開 API なので
// 自分でも確かめます。
//
// client を nil にしてあるのが検証そのものです。問い合わせに進めば nil 参照で
// パニックするので、素通りするようになれば必ずここで落ちます。
func TestFirestoreStoreRejectsMalformedIDBeforeTheRPC(t *testing.T) {
	t.Parallel()

	store := &firestoreStore{collection: "sessions"}
	ctx := context.Background()

	if _, err := store.Load(ctx, "sessions/../other/doc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error = %v, want ErrNotFound（実体が無いのと同じ扱い）", err)
	}
	if err := store.Save(ctx, "sessions/../other/doc", map[string]string{}, time.Hour); err == nil {
		t.Fatal("Save() error = nil, want error: 手で入れた ID を書いてはいけない")
	}
	if err := store.Delete(ctx, "sessions/../other/doc"); err == nil {
		t.Fatal("Delete() error = nil, want error")
	}
}
