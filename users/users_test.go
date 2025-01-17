package users_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burlingtonbertie99/mykeys"
	"github.com/burlingtonbertie99/mykeys/dstore"
	"github.com/burlingtonbertie99/mykeys/http"
	"github.com/burlingtonbertie99/mykeys/tsutil"
	"github.com/burlingtonbertie99/mykeys/user"
	"github.com/burlingtonbertie99/mykeys/user/services"
	"github.com/burlingtonbertie99/mykeys/users"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}

func testdata(t *testing.T, path string) []byte {
	b, err := ioutil.ReadFile(filepath.Join("..", path))
	require.NoError(t, err)
	b = bytes.ReplaceAll(b, []byte{'\r'}, []byte{})
	return b
}

func TestCheckNoUsers(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	sc := keys.NewSigchain(sk.ID())

	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	usrs := users.New(ds, scs, users.Clock(clock))

	result, err := usrs.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.Nil(t, result)

	rk := keys.GenerateEdX25519Key()
	result, err = usrs.Update(context.TODO(), rk.ID())
	require.NoError(t, err)
	require.Nil(t, result)
}

func TestCheckFailure(t *testing.T) {
	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	usrs := users.New(ds, scs, users.Clock(clock))

	usr := &user.User{
		Name:    "gabriel",
		KID:     keys.ID("kex1d69g7mzjjn8cfm3ssdr9u8z8mh2d35cvjzsrwrndt4d006uhh69qyx2k5x"),
		Seq:     1,
		Service: "twitter",
		URL:     "https://twitter.com/boboloblaw/status/1259188857846632448",
	}
	result := usrs.RequestVerify(context.TODO(), services.Twitter, usr)
	require.Equal(t, usr.Name, result.User.Name)
	require.Equal(t, result.Status, user.StatusFailure)
	require.Equal(t, result.Err, "path invalid (name mismatch) for url https://twitter.com/boboloblaw/status/1259188857846632448")
}

func TestSigchainUsersUpdate(t *testing.T) {
	// users.SetLogger(users.NewLogger(users.DebugLevel))
	// user.SetLogger(users.NewLogger(users.DebugLevel))
	// link.SetLogger(users.NewLogger(users.DebugLevel))

	kid := keys.ID("kex1e26rq9vrhjzyxhep0c5ly6rudq7m2cexjlkgknl2z4lqf8ga3uasz3s48m")
	sc := keys.NewSigchain(kid)

	b := testdata(t, "testdata/twitter/statement.json")
	var st keys.Statement
	err := json.Unmarshal(b, &st)
	require.NoError(t, err)

	err = sc.Add(&st)
	require.NoError(t, err)

	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)

	usrs := users.New(ds, scs, users.Clock(clock))

	usrs.Client().SetProxy("", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(testdata(t, "testdata/twitter/1222706272849391616.json"))}
	})

	err = scs.Save(sc)
	require.NoError(t, err)

	result, err := usrs.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusOK, result.Status)
}

func TestSigchainRevokeUpdate(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)

	usrs := users.New(ds, scs, users.Clock(clock))

	sk := keys.GenerateEdX25519Key()
	kid := sk.ID()
	sc := keys.NewSigchain(kid)

	// Update
	usr, err := user.NewForSigning(kid, "twitter", "gabriel")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)

	stu, err := user.New(kid, "twitter", "gabriel", "https://mobile.twitter.com/gabriel/status/1", 1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	usrs.Client().SetProxy("", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(twitterMock("gabriel", "1", msg))}
	})

	err = scs.Save(sc)
	require.NoError(t, err)

	result, err := usrs.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.Equal(t, user.StatusOK, result.Status)

	// Revoke
	_, err = sc.Revoke(1, sk)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)
	// Don't update here to test revoke + new statement updates correctly

	// Update #2
	stu2, err := user.New(kid, "twitter", "gabriel", "https://mobile.twitter.com/gabriel/status/2", 3)
	require.NoError(t, err)
	st2, err := user.NewSigchainStatement(sc, stu2, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	usrs.Client().SetProxy("", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(twitterMock("gabriel", "2", msg))}
	})

	err = scs.Save(sc)
	require.NoError(t, err)

	result, err = usrs.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusOK, result.Status)
}

func TestCheckForExisting(t *testing.T) {
	var err error

	clock := tsutil.NewTestClock()

	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	usrs := users.New(ds, scs, users.Clock(clock))

	sk1 := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	sc1 := keys.NewSigchain(sk1.ID())
	_, err = mockStatement(sk1, sc1, "alice", "echo", usrs.Client(), clock)
	require.NoError(t, err)
	kid, err := usrs.CheckForExisting(context.TODO(), sc1)
	require.NoError(t, err)
	require.Empty(t, kid)
	err = scs.Save(sc1)
	require.NoError(t, err)
	_, err = usrs.Update(context.TODO(), sk1.ID())
	require.NoError(t, err)

	sk2 := keys.NewEdX25519KeyFromSeed(testSeed(0x02))
	sc2 := keys.NewSigchain(sk2.ID())
	_, err = mockStatement(sk2, sc2, "alice", "echo", usrs.Client(), clock)
	require.NoError(t, err)
	kid, err = usrs.CheckForExisting(context.TODO(), sc2)
	require.NoError(t, err)
	require.Equal(t, kid, sk1.ID())

}

func mockStatement(key *keys.EdX25519Key, sc *keys.Sigchain, name string, service string, client http.Client, clock tsutil.Clock) (*keys.Statement, error) {
	us, err := user.NewForSigning(key.ID(), service, name)
	if err != nil {
		return nil, err
	}
	msg, err := us.Sign(key)
	if err != nil {
		return nil, err
	}

	id := hex.EncodeToString(sha256.New().Sum([]byte(service + "/" + name))[:8])

	urs := ""
	switch service {
	case "github":
		urs = fmt.Sprintf("https://gist.github.com/%s/%s", name, id)
	case "echo":
		urs = "test://echo/" + name + "/" + key.ID().String() + "/" + url.QueryEscape(strings.ReplaceAll(msg, "\n", " "))
	case "https":
		urs = "https://" + name
	default:
		return nil, errors.Errorf("unsupported service for mock")
	}

	usr, err := user.New(key.ID(), service, name, urs, sc.LastSeq()+1)
	if err != nil {
		return nil, err
	}
	st, err := user.NewSigchainStatement(sc, usr, key, clock.Now())
	if err != nil {
		return nil, err
	}

	client.SetProxy("", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		// TODO: Set based on url
		return http.ProxyResponse{Body: []byte(msg)}
	})

	if err := sc.Add(st); err != nil {
		return nil, err
	}

	return st, nil
}
