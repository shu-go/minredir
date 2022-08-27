package minredir_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/shu-go/gotwant"
	"github.com/shu-go/minredir"
)

func TestHTTP(t *testing.T) {
	c := make(chan string)
	ctx := context.Background()

	t.Run("One", func(t *testing.T) {
		err, errChan := minredir.Serve(ctx, ":12345", c)
		gotwant.TestError(t, err, nil)

		go func() {
			http.PostForm("http://localhost:12345/", url.Values{"code": {"hogehoge"}})
		}()

		result := <-c
		gotwant.Test(t, result, "hogehoge")
		err = <-errChan
		gotwant.TestError(t, err, http.ErrServerClosed)
	})
	t.Run("Two", func(t *testing.T) {
		err, errChan := minredir.Serve(ctx, ":12345", c)
		gotwant.TestError(t, err, nil)

		go func() {
			http.PostForm("http://localhost:12345/", url.Values{"code": {"hogehoge"}})
		}()

		result := <-c
		gotwant.Test(t, result, "hogehoge")
		err = <-errChan
		gotwant.TestError(t, err, http.ErrServerClosed)
	})

	t.Run("N", func(t *testing.T) {
		count := 1000
		t.Log(count)

		for i := 0; i < count; i++ {
			s := "hogehoge" + strconv.Itoa(i)

			err, errChan := minredir.Serve(ctx, ":12345", c)
			gotwant.TestError(t, err, nil)

			go func() {
				http.PostForm("http://localhost:12345/", url.Values{"code": {s}})
			}()

			result := <-c
			gotwant.Test(t, result, s)
			err = <-errChan
			gotwant.TestError(t, err, http.ErrServerClosed)
			t.Log(s)
		}
	})
}

func TestHTTPS(t *testing.T) {
	c := make(chan string)
	ctx := context.Background()

	tr := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{
		Transport: &tr,
	}

	t.Run("One", func(t *testing.T) {
		err, errChan := minredir.ServeTLS(ctx, ":12345", c)
		gotwant.TestError(t, err, nil)

		go func() {
			_, err := client.PostForm("https://localhost:12345/", url.Values{"code": {"hogehoge"}})
			gotwant.TestError(t, err, nil)
		}()

		result := <-c
		gotwant.Test(t, result, "hogehoge")
		err = <-errChan
		gotwant.TestError(t, err, http.ErrServerClosed)
	})
	t.Run("Two", func(t *testing.T) {
		err, errChan := minredir.ServeTLS(ctx, ":12345", c)
		gotwant.TestError(t, err, nil)

		go func() {
			_, err := client.PostForm("https://localhost:12345/", url.Values{"code": {"hogehoge"}})
			gotwant.TestError(t, err, nil)
		}()

		result := <-c
		gotwant.Test(t, result, "hogehoge")
		err = <-errChan
		gotwant.TestError(t, err, http.ErrServerClosed)
	})

	t.Run("N", func(t *testing.T) {
		count := 100
		t.Log(count)

		for i := 0; i < count; i++ {
			s := "hogehoge" + strconv.Itoa(i)

			err, errChan := minredir.ServeTLS(ctx, ":12345", c)
			gotwant.TestError(t, err, nil)

			go func() {
				_, err := client.PostForm("https://localhost:12345/", url.Values{"code": {s}})
				gotwant.TestError(t, err, nil)
			}()

			result := <-c
			gotwant.Test(t, result, s)
			err = <-errChan
			gotwant.TestError(t, err, http.ErrServerClosed)
			t.Log(s)
		}
	})
}
