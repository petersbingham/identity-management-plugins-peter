package httpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

var (
	ErrUnexpectedStatusCode = errors.New("unexpected status code")
)

// DecodeResponse decodes the HTTP response body into the provided type T.
func DecodeResponse[T any](
	ctx context.Context,
	apiName string,
	resp *http.Response,
	expectedStatus int,
) (*T, error) {
	var (
		respErr error
		result  T
	)

	if resp.StatusCode == expectedStatus {
		respErr = json.NewDecoder(resp.Body).Decode(&result)
	} else {
		respErr = fmt.Errorf("%w %s", ErrUnexpectedStatusCode, resp.Status)
	}

	if respErr != nil {
		respBody, _ := io.ReadAll(resp.Body)
		slog.DebugContext(ctx, "body of unexpected response from "+apiName+": "+string(respBody))

		return nil, fmt.Errorf("invalid response from %s: %w", apiName, respErr)
	}

	return &result, nil
}
