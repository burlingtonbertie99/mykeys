package services_test

import (
	"context"
	"testing"

	"github.com/burlingtonbertie99/mykeys"
	"github.com/burlingtonbertie99/mykeys/http"
	"github.com/burlingtonbertie99/mykeys/user"
	"github.com/burlingtonbertie99/mykeys/user/services"
	"github.com/stretchr/testify/require"
)

func TestReddit(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	// services.SetLogger(user.NewLogger(user.DebugLevel))

	kid := keys.ID("kex164gsfjpcfcugtcv28hmv5jl8yl7nzs06l09aw2245phy06j7ygqs9u9zyd")

	usr, err := user.New(kid, "reddit", "gabrlh", "https://www.reddit.com/user/gabrlh/comments/ogdh94/keyspub/", 1)
	require.NoError(t, err)
	client := http.NewClient()
	result := services.Verify(context.TODO(), services.Reddit, client, usr)
	require.Equal(t, user.StatusOK, result.Status)
	expected := `BEGIN MESSAGE.
tm8882H30GKybLj cOvOw3ezalNCV4z HIeF7ZIDa53DM5l m43v3AdpuM5xtqTZDGIhyQbA863bYk fiIRdpUYVzMTCKq 6Xr2MZHgg4bh2Wj m5fbDX2FnO9rt6TWzS6zMQo6Pf4PXS De2cdyxT0J3mPah X4cThM1A4yFIFaF lo99DSnDd3LOLwUrP9mdKCnNdvKkl1 WLZZaBlQZWXAisM CCwny21.
END MESSAGE.`
	require.Equal(t, expected, result.Statement)
}
