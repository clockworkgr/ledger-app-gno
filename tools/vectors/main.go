// Command vectors prints gno.land signature payloads, one per supported message
// type, as rendered by upstream gno. The app's tests replay these bytes, so the
// device is checked against what the chain verifies rather than a hand-written
// imitation of amino JSON.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gnolang/gno/gno.land/pkg/sdk/vm"
	gno "github.com/gnolang/gno/gnovm/pkg/gnolang"
	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/gnolang/gno/tm2/pkg/crypto/bip39"
	"github.com/gnolang/gno/tm2/pkg/crypto/hd"
	"github.com/gnolang/gno/tm2/pkg/crypto/secp256k1"
	"github.com/gnolang/gno/tm2/pkg/sdk/auth"
	"github.com/gnolang/gno/tm2/pkg/sdk/bank"
	"github.com/gnolang/gno/tm2/pkg/std"
)

// speculosMnemonic is the seed Speculos boots with unless told otherwise.
const speculosMnemonic = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

const derivationPath = "44'/118'/0'/0/0"

type vector struct {
	Name      string `json:"name"`
	SignBytes string `json:"sign_bytes"`
	Signature string `json:"signature"`
}

type output struct {
	Mnemonic string   `json:"mnemonic"`
	Path     string   `json:"path"`
	PubKey   string   `json:"pubkey"`
	Address  string   `json:"address"`
	Vectors  []vector `json:"vectors"`
}

func main() {
	master, chainCode := hd.ComputeMastersFromSeed(bip39.NewSeed(speculosMnemonic, ""))
	derived, err := hd.DerivePrivateKeyForPath(master, chainCode, derivationPath)
	if err != nil {
		panic(err)
	}
	key := secp256k1.PrivKeySecp256k1(derived)
	pub := key.PubKey().(secp256k1.PubKeySecp256k1)
	signer := pub.Address()
	other := crypto.MustAddressFromString("g1jg8mtutu9khhfwc4nxmuhcpftf0pajdhfvsqf5")
	sessionKey := secp256k1.GenPrivKeySecp256k1([]byte("session")).PubKey()
	ugnot := func(n int64) std.Coins { return std.NewCoins(std.NewCoin("ugnot", n)) }

	pkg := &std.MemPackage{
		Name: "hello",
		Path: "gno.land/r/demo/hello",
		Files: []*std.MemFile{
			{Name: "gnomod.toml", Body: "module = \"gno.land/r/demo/hello\"\ngno = \"0.9\"\n"},
			{Name: "hello.gno", Body: "package hello\n\nfunc Render(_ string) string { return \"<b>hi</b> & \\\"bye\\\"\" }\n"},
		},
		Type: gno.MPUserProd,
	}
	// A realm whose review must surface its imports and the addresses it
	// spells out, but not those in comments, tests or non-Gno files.
	treasurer := secp256k1.GenPrivKeySecp256k1([]byte("treasurer")).PubKey().Address()
	retired := secp256k1.GenPrivKeySecp256k1([]byte("retired")).PubKey().Address()
	tipjar := &std.MemPackage{
		Name: "tipjar",
		Path: "gno.land/r/demo/tipjar",
		Files: []*std.MemFile{
			{Name: "README.md", Body: "Tips go to " + retired.String() + ". Don't \"import\" this.\n"},
			{Name: "gnomod.toml", Body: "module = \"gno.land/r/demo/tipjar\"\ngno = \"0.9\"\n"},
			{Name: "render.gno", Body: "package tipjar\n\nimport \"strings\"\n\nfunc Render(_ string) string { return strings.Repeat(\"*\", 3) }\n"},
			{Name: "tipjar.gno", Body: "package tipjar\n\nimport (\n\t\"chain/banker\"\n\t\"chain/runtime\"\n\n\tufmt \"gno.land/p/nt/ufmt\"\n)\n\n" +
				"// Formerly paid to " + retired.String() + ".\n" +
				"const treasurer = address(\"" + treasurer.String() + "\")\n\n" +
				"var admin = address(`" + signer.String() + "`)\n\n" +
				"/* quote: ' */ var quote = '\"'\n\n" +
				"func Withdraw(cur realm) string {\n\tif runtime.PreviousRealm().Address() != admin {\n\t\tpanic(\"admin only\")\n\t}\n" +
				"\tb := banker.NewBanker(banker.BankerTypeRealmSend)\n\tb.SendCoins(runtime.CurrentRealm().Address(), treasurer, b.GetCoins(runtime.CurrentRealm().Address()))\n" +
				"\treturn ufmt.Sprintf(\"%c\", quote)\n}\n"},
			{Name: "tipjar_test.gno", Body: "package tipjar\n\nimport \"testing\"\n\nvar alice = address(\"" + retired.String() + "\")\n\nfunc TestRender(t *testing.T) {}\n"},
		},
		Type: gno.MPUserProd,
	}

	// A package at the review's limits: more imports, addresses and files than
	// the device lists, to exercise the overflow notices and its memory.
	var imports, addrs strings.Builder
	for i := range 17 {
		fmt.Fprintf(&imports, "\t\"gno.land/p/demo/very/long/import/path/for/limits/number/%02d\"\n", i)
	}
	for i := range 9 {
		a := secp256k1.GenPrivKeySecp256k1([]byte(fmt.Sprintf("limit-%d", i))).PubKey().Address()
		fmt.Fprintf(&addrs, "var a%d = address(\"%s\")\n", i, a)
	}
	limits := &std.MemPackage{
		Name: "limits",
		Path: "gno.land/r/demo/limits",
		Files: []*std.MemFile{
			{Name: "gnomod.toml", Body: "module = \"gno.land/r/demo/limits\"\ngno = \"0.9\"\n"},
			{Name: "limits.gno", Body: "package limits\n\nimport (\n" + imports.String() + ")\n\n" + addrs.String()},
		},
		Type: gno.MPUserAll,
	}
	for i := range 18 {
		limits.Files = append(limits.Files, &std.MemFile{
			Name: fmt.Sprintf("part_%02d.gno", i),
			Body: "package limits\n",
		})
	}

	run := &std.MemPackage{
		Name:  "main",
		Path:  "gno.land/e/" + signer.String() + "/run",
		Files: []*std.MemFile{{Name: "main.gno", Body: "package main\n\nfunc main() { println(\"hi\") }\n"}},
		Type:  gno.MPUserProd,
	}

	cases := []struct {
		name string
		fee  std.Fee
		memo string
		msgs []std.Msg
	}{
		{"send", std.NewFee(100000, std.NewCoin("ugnot", 1000)), "", []std.Msg{
			bank.MsgSend{FromAddress: signer, ToAddress: other, Amount: ugnot(1234567)},
		}},
		{"send_zero_fee_memo", std.NewFee(100000, std.Coin{}), "thanks", []std.Msg{
			bank.MsgSend{FromAddress: signer, ToAddress: other, Amount: ugnot(1)},
		}},
		{"call", std.NewFee(2000000, std.NewCoin("ugnot", 1000000)), "", []std.Msg{
			vm.MsgCall{Caller: signer, PkgPath: "gno.land/r/demo/boards", Func: "CreateThread", Args: []string{"1", "Hello", "World"}},
		}},
		{"call_send_no_args", std.NewFee(2000000, std.NewCoin("ugnot", 1000000)), "", []std.Msg{
			vm.MsgCall{Caller: signer, Send: ugnot(5), MaxDeposit: ugnot(7), PkgPath: "gno.land/r/demo/wugnot", Func: "Deposit"},
		}},
		{"two_msgs", std.NewFee(200000, std.NewCoin("ugnot", 2000)), "", []std.Msg{
			bank.MsgSend{FromAddress: signer, ToAddress: other, Amount: ugnot(1)},
			bank.MsgSend{FromAddress: signer, ToAddress: other, Amount: ugnot(2)},
		}},
		{"enable_pkg", std.NewFee(2000000, std.NewCoin("ugnot", 1000000)), "", []std.Msg{
			vm.MsgEnablePackage{Approver: signer, PkgPath: "gno.land/r/demo/hello", PkgHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", PkgHeight: 42},
		}},
		{"reject_pkg", std.NewFee(2000000, std.NewCoin("ugnot", 1000000)), "", []std.Msg{
			vm.MsgRejectPackage{Sender: signer, PkgPath: "gno.land/r/demo/hello"},
		}},
		{"create_session", std.NewFee(200000, std.NewCoin("ugnot", 1000)), "", []std.Msg{
			auth.MsgCreateSession{Creator: signer, SessionKey: sessionKey, ExpiresAt: 1798761600, AllowPaths: []string{"vm/exec:gno.land/r/demo/boards"}, SpendLimit: ugnot(5000000), SpendPeriod: 86400},
		}},
		{"create_session_minimal", std.NewFee(200000, std.NewCoin("ugnot", 1000)), "", []std.Msg{
			auth.MsgCreateSession{Creator: signer, SessionKey: sessionKey, AllowPaths: []string{"*"}},
		}},
		{"revoke_session", std.NewFee(200000, std.NewCoin("ugnot", 1000)), "", []std.Msg{
			auth.MsgRevokeSession{Creator: signer, SessionKey: sessionKey},
		}},
		{"revoke_all_sessions", std.NewFee(200000, std.NewCoin("ugnot", 1000)), "", []std.Msg{
			auth.MsgRevokeAllSessions{Creator: signer},
		}},
		{"addpkg", std.NewFee(5000000, std.NewCoin("ugnot", 5000000)), "", []std.Msg{
			vm.MsgAddPackage{Creator: signer, Package: pkg, MaxDeposit: ugnot(10000000)},
		}},
		{"run", std.NewFee(5000000, std.NewCoin("ugnot", 5000000)), "", []std.Msg{
			vm.MsgRun{Caller: signer, Package: run},
		}},
		{"addpkg_highlights", std.NewFee(5000000, std.NewCoin("ugnot", 5000000)), "", []std.Msg{
			vm.MsgAddPackage{Creator: signer, Package: tipjar, Send: ugnot(1000000)},
		}},
		{"addpkg_limits", std.NewFee(5000000, std.NewCoin("ugnot", 5000000)), strings.Repeat("m", 256), []std.Msg{
			vm.MsgAddPackage{Creator: signer, Package: limits, MaxDeposit: ugnot(10000000)},
		}},
	}

	out := output{
		Mnemonic: speculosMnemonic,
		Path:     derivationPath,
		PubKey:   hex.EncodeToString(pub[:]),
		Address:  signer.String(),
	}
	for _, c := range cases {
		bz, err := std.GetSignaturePayload(std.SignDoc{
			ChainID: "test-chain", AccountNumber: 7, Sequence: 3, Fee: c.fee, Msgs: c.msgs, Memo: c.memo,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, c.name, err)
			os.Exit(1)
		}
		sig, err := key.Sign(bz)
		if err != nil {
			panic(err)
		}
		out.Vectors = append(out.Vectors, vector{c.name, string(bz), hex.EncodeToString(sig)})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
