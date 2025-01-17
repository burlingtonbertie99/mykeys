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

func TestKeysPub(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	// services.SetLogger(user.NewLogger(user.DebugLevel))

	kid := keys.ID("kex1mnseg28xu6g3j4wur7hqwk8ag3fu3pmr2t5lync26xmgff0dtryqupf80c")
	urs := "https://gist.github.com/gabriel/ceea0f3b675bac03425472692273cf52"

	usr, err := user.New(kid, "github", "gabriel", urs, 1)
	require.NoError(t, err)

	client := http.NewClient()

	result := services.Verify(context.TODO(), services.KeysPub, client, usr)
	require.Equal(t, user.StatusOK, result.Status)
	expected := `BEGIN MESSAGE.
kdZaJI1U5AS7G6i VoUxdP8OtPzEoM6 pYhVl0YQZJnotVE wLg9BDb5SUO05pm
abUSeCvBfdPoRpP J8wrcF5PP3wTCKq 6Xr2MZHgg6m2Qal gJCD6vMqlBQfIg6
QsfB27aP5DMuXlJ AUVIAvMDHIoptmS riNMzfpwBjRShVL WH70a0GOEqD6L8b
kC5EFOwCedvHFpc AQVqULHjcSpeCfZ EIOaQ2IP.
END MESSAGE.`
	require.Equal(t, expected, result.Statement)
}
