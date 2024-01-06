package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/burlingtonbertie99/mykeys-ext/http"
	"github.com/burlingtonbertie99/mykeys-ext/user"
	"github.com/burlingtonbertie99/mykeys-ext/user/validate"
	"github.com/pkg/errors"
)

type reddit struct{}

// Reddit service.
var Reddit = &reddit{}

func (s *reddit) ID() string {
	return "reddit"
}

func (s *reddit) Request(ctx context.Context, client http.Client, usr *user.User) (user.Status, []byte, error) {
	apiURL, err := validate.Reddit.APIURL(usr.Name, usr.URL)
	if err != nil {
		return user.StatusFailure, nil, err
	}
	headers, err := s.headers(apiURL)
	if err != nil {
		return user.StatusFailure, nil, err
	}
	return Request(ctx, client, apiURL, headers)
}

func (s *reddit) checkContent(name string, b []byte) ([]byte, error) {
	var posts redditPosts

	if err := json.Unmarshal(b, &posts); err != nil {
		return nil, err
	}
	logger.Debugf("Reddit unmarshaled posts: %+v", posts)
	if len(posts) == 0 {
		return nil, errors.Errorf("no posts")
	}

	if len(posts[0].Data.Children) == 0 {
		return nil, errors.Errorf("no listing children")
	}

	if posts[0].Data.Children[0].Data.SubredditType != "user" {
		return nil, errors.Errorf("invalid subreddit type")
	}

	author := posts[0].Data.Children[0].Data.Author
	if name != strings.ToLower(author) {
		return nil, errors.Errorf("invalid author %s", author)
	}
	subreddit := strings.ToLower(posts[0].Data.Children[0].Data.Subreddit)
	if fmt.Sprintf("u_%s", name) != subreddit {
		return nil, errors.Errorf("invalid subreddit %s", subreddit)
	}
	selftext := posts[0].Data.Children[0].Data.Selftext
	return []byte(selftext), nil
}

func (s *reddit) Verify(ctx context.Context, b []byte, usr *user.User) (user.Status, *Verified, error) {
	msg, err := s.checkContent(usr.Name, b)
	if err != nil {
		return user.StatusContentInvalid, nil, err
	}
	status, statement, err := user.FindVerify(usr, msg, false)
	if err != nil {
		return status, nil, err
	}
	return status, &Verified{Statement: statement}, nil
}

func (s *reddit) headers(urs string) ([]http.Header, error) {
	ur, err := url.Parse(urs)
	if err != nil {
		return nil, err
	}
	// Not sure if this is required anymore.
	if strings.HasSuffix(ur.Host, ".reddit.com") {
		return []http.Header{{Name: "Host", Value: "reddit.com"}}, nil
	}
	return nil, nil
}

type redditPosts []struct {
	Kind string `json:"kind"`
	Data struct {
		Modhash  string `json:"modhash"`
		Dist     int    `json:"dist"`
		Children []struct {
			Kind string `json:"kind"`
			Data struct {
				Subreddit     string `json:"subreddit"`
				SubredditType string `json:"subreddit_type"`
				Selftext      string `json:"selftext"`
				Author        string `json:"author"`
			} `json:"data"`
		} `json:"children"`
		After  interface{} `json:"after"`
		Before interface{} `json:"before"`
	} `json:"data"`
}
