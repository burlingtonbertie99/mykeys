package http_test

import (
	"context"
	"testing"

	"github.com/burlingtonbertie99/mykeys/encoding"
	"github.com/burlingtonbertie99/mykeys/http"
	"github.com/stretchr/testify/require"
)

func TestGithubRequest(t *testing.T) {
	client := http.NewClient()
	urs := "https://gist.github.com/gabriel/ceea0f3b675bac03425472692273cf52"
	req, err := http.NewRequest("GET", urs, nil)
	require.NoError(t, err)
	res, err := client.Request(context.TODO(), req)
	require.NoError(t, err)

	out, brand := encoding.FindSaltpack(string(res), true)
	out = encoding.TrimSaltpack(out, nil)
	require.Equal(t, "kdZaJI1U5AS7G6iVoUxdP8OtPzEoM6pYhVl0YQZJnotVEwLg9BDb5SUO05pmabUSeCvBfdPoRpPJ8wrcF5PP3wTCKq6Xr2MZHgg6m2QalgJCD6vMqlBQfIg6QsfB27aP5DMuXlJAUVIAvMDHIoptmSriNMzfpwBjRShVLWH70a0GOEqD6L8bkC5EFOwCedvHFpcAQVqULHjcSpeCfZEIOaQ2IP", out)
	require.Equal(t, "", brand)
}
