// Package conn holds the connection to the Keyvault server and provides a single RPC call type.
package conn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"reflect"

	"github.com/Azure/go-autorest/autorest"
	"github.com/google/uuid"
)

// Conn provides connectivity to a Keyvault instance.
type Conn struct {
	endpoint string
	base     *url.URL
	auth     autorest.Authorizer
	client   *http.Client
}

// New returns a new conn object.
func New(endpoint string, auth autorest.Authorizer) (*Conn, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("could not parse the endpoint(%s): %s", endpoint, err)
	}

	c := &Conn{
		auth:   auth,
		client: &http.Client{},
		base:   u,
	}

	return c, nil
}

type CallType string

const (
	Get    CallType = "GET"
	Put    CallType = "PUT"
	Post   CallType = "POST"
	Patch  CallType = "PATCH"
	Delete CallType = "DELETE"
)

// Call connects to the REST endpoint at path (the REST RPC path) passing the HTTP query values and JSON conversion
// of body in the HTTP body. It automatically handles compression and decompression with gzip. The response is JSON
// unmarshalled into resp. resp must be a pointer to a struct.
func (c *Conn) Call(ctx context.Context, ct CallType, path string, queryValues url.Values, body interface{}, resp interface{}) error {
	t := reflect.ValueOf(resp)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return fmt.Errorf("bug: conn.Call() resp argument must be a *struct, was %T", resp)
	}

	ref, err := url.Parse(path)
	if err != nil {
		return fmt.Errorf("grpc.Call(): could not parse path URL(%s): %w", path, err)
	}

	fullPath := c.base.ResolveReference(ref).String()

	if queryValues == nil {
		queryValues = url.Values{}
	}
	// TODO(jdoak): They reject based on version.
	// I'm faking .Net compatibility, but this is a API issue that should get resolved.
	queryValues.Add("api-version", "7.1") //"2016-10-01"

	header := http.Header{}
	header.Add("Accept", "application/json")
	header.Add("Accept-Encoding", "gzip")
	//header.Add("x-ms-client-version", "Keyvault.Go.Client: "+version.Keyvault)
	header.Add("x-ms-client-request-id", "KGC.execute;"+uuid.New().String())

	var data []byte
	var req *http.Request

	if body == nil {
		req, err = http.NewRequestWithContext(ctx, string(ct), fullPath, nil)
		if err != nil {
			return fmt.Errorf("conn: new request creation error: %w", err)
		}
		req.Header = header
	} else {
		// TODO(jdoak): In case your wondering why I'm not gzip encoding....
		// Keyvault doesn't accept gzip and while we are allowing gzip decodes, it actually
		// doesn't send in gzip either.
		header.Add("Content-Type", "application/json; charset=utf-8")
		data, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("bug: conn.Call(): could not marshal the body object: %w", err)
		}
		header.Add("Content-Length", fmt.Sprintf("%d", len(data)))
		req, err = http.NewRequestWithContext(ctx, string(ct), fullPath, bytes.NewBuffer(data))
		if err != nil {
			return err
		}
		req.Header = header
		log.Println("request body:\n", string(data))
	}
	log.Println("request: ", req)

	u := req.URL
	u.RawQuery = queryValues.Encode()
	req.URL = u
	log.Println(u.RawQuery)
	log.Println(req.URL.String())

	prep := c.auth.WithAuthorization()
	req, err = prep(autorest.CreatePreparer()).Prepare(req)
	if err != nil {
		return fmt.Errorf("conn: problem prepping the request with our authorization information: %w", err)
	}

	reply, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("server response error: %w", err)
	}
	defer reply.Body.Close()

	switch reply.Header.Get("Content-Encoding") {
	case "gzip":
		data, _ = ioutil.ReadAll(gzipDecompress(reply.Body))
	case "":
		data, _ = ioutil.ReadAll(reply.Body)
	default:
		return fmt.Errorf("bug: conn.call(): content was send with unsupported content-encoding %s", reply.Header.Get("Content-Encoding"))
	}

	// Depending on what method is used to talk to Keyvault (why does no one just use post), we can get varying valid
	// status codes.
	switch ct {
	case Get:
		switch reply.StatusCode {
		case 200, 201:
		default:
			return fmt.Errorf("reply status code was %d:\n%s", reply.StatusCode, string(data))
		}
	case Put:
		if reply.StatusCode != 200 {
			return fmt.Errorf("reply status code was %d:\n%s", reply.StatusCode, string(data))
		}
	case Delete:
		switch reply.StatusCode {
		case 200, 204, 404:
		default:
			return fmt.Errorf("reply status code was %d:\n%s", reply.StatusCode, string(data))
		}
	case Post:
		if reply.StatusCode != 200 {
			return fmt.Errorf("reply status code was %d:\n%s", reply.StatusCode, string(data))
		}
	case Patch:
		if reply.StatusCode != 200 {
			return fmt.Errorf("reply status code was %d\n%s", reply.StatusCode, string(data))
		}
	}

	if resp != nil {
		log.Println(string(data))
		if err := json.Unmarshal(data, resp); err != nil {
			return fmt.Errorf("json decode error: %w\nraw message was: %s", err, string(data))
		}
	}
	return nil
}
