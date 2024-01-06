package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/burlingtonbertie99/mykeys/http"
	"github.com/burlingtonbertie99/mykeys/user"
	"github.com/burlingtonbertie99/mykeys/user/validate"
	"github.com/pkg/errors"
)

// TwitterID is the id for twitter.
const TwitterID = "twitter"

type twitter struct {
	bearerToken string
}

// Twitter ..
var Twitter = &twitter{
	bearerToken: os.Getenv("TWITTER_BEARER_TOKEN"),
}

// SetBearerToken for auth.
func (s *twitter) SetBearerToken(bearerToken string) {
	s.bearerToken = bearerToken
}

func (s *twitter) ID() string {
	return TwitterID
}

func (s *twitter) Request(ctx context.Context, client http.Client, usr *user.User) (user.Status, []byte, error) {
	apiURL, err := validate.Twitter.APIURL(usr.Name, usr.URL)
	if err != nil {
		return user.StatusFailure, nil, err
	}
	headers := s.headers()
	return Request(ctx, client, apiURL, headers)
}

func (s *twitter) Verify(ctx context.Context, b []byte, usr *user.User) (user.Status, *Verified, error) {
	var tweet tweet
	if err := json.Unmarshal(b, &tweet); err != nil {
		return user.StatusContentInvalid, nil, err
	}
	logger.Debugf("Tweet: %+v", tweet)

	// TODO: Double check tweet id matches

	found := false
	authorID := tweet.Data.AuthorID
	for _, tweetUser := range tweet.Includes.Users {
		if authorID == tweetUser.ID {
			tweetUserName := validate.Twitter.NormalizeName(tweetUser.Username)
			if tweetUserName != usr.Name {
				return user.StatusContentInvalid, nil, errors.Errorf("invalid tweet username %s", tweetUser.Username)
			}
			found = true
		}
	}
	if !found {
		return user.StatusContentInvalid, nil, errors.Errorf("tweet username not found")
	}

	msg := tweet.Data.Text
	status, statement, err := user.FindVerify(usr, []byte(msg), false)
	if err != nil {
		return status, nil, err
	}
	return status, &Verified{Statement: statement}, nil
}

func (s *twitter) headers() []http.Header {
	if s.bearerToken == "" {
		return nil
	}
	return []http.Header{
		{
			Name:  "Authorization",
			Value: fmt.Sprintf("Bearer %s", s.bearerToken),
		},
	}
}

type tweet struct {
	Data struct {
		ID       string `json:"id"`
		Text     string `json:"text"`
		AuthorID string `json:"author_id"`
	} `json:"data"`
	Includes struct {
		Users []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"users"`
	} `json:"includes"`
}
