package v2

import (
	"net/http"
	"regexp"

	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/opencontainers/go-digest"
)

var (
	nameParameterDescriptor = ParameterDescriptor{
		Name:     "name",
		Type:     "string",
		Required: true,
	}

	referenceParameterDescriptor = ParameterDescriptor{
		Name:     "reference",
		Type:     "string",
		Required: true,
	}

	uuidParameterDescriptor = ParameterDescriptor{
		Name:     "uuid",
		Type:     "opaque",
		Required: true,
	}

	digestPathParameter = ParameterDescriptor{
		Name:     "digest",
		Type:     "path",
		Required: true,
	}

	hostHeader = ParameterDescriptor{
		Name:     "Host",
		Type:     "string",
		Format:   "<registry host>",
		Examples: []string{"registry-1.docker.io"},
	}

	authHeader = ParameterDescriptor{
		Name:     "Authorization",
		Type:     "string",
		Format:   "<scheme> <token>",
		Examples: []string{"Bearer dGhpcyBpcyBhIGZha2UgYmVhcmVyIHRva2VuIQ=="},
	}

	authChallengeHeader = ParameterDescriptor{
		Name:   "WWW-Authenticate",
		Type:   "string",
		Format: `<scheme> realm="<realm>", ..."`,
		Examples: []string{
			`Bearer realm="https://auth.docker.com/", service="registry.docker.com", scopes="repository:library/ubuntu:pull"`,
		},
	}

	contentLengthZeroHeader = ParameterDescriptor{
		Name:   "Content-Length",
		Type:   "integer",
		Format: "0",
	}

	dockerUploadUUIDHeader = ParameterDescriptor{
		Name:   "Docker-Upload-UUID",
		Type:   "uuid",
		Format: "<uuid>",
	}

	digestHeader = ParameterDescriptor{
		Name:   "Docker-Content-Digest",
		Type:   "digest",
		Format: "<digest>",
	}

	linkHeader = ParameterDescriptor{
		Name:   "Link",
		Type:   "link",
		Format: `<<url>?n=<last n value>&last=<last entry from response>>; rel="next"`,
	}

	paginationParameters = []ParameterDescriptor{
		{
			Name:     "n",
			Type:     "integer",
			Format:   "<integer>",
			Required: false,
		},
		{
			Name:     "last",
			Type:     "string",
			Format:   "<integer>",
			Required: false,
		},
	}

	unauthorizedResponseDescriptor = ResponseDescriptor{
		Name:       "Authentication Required",
		StatusCode: http.StatusUnauthorized,
		Headers: []ParameterDescriptor{
			authChallengeHeader,
			{
				Name:   "Content-Length",
				Type:   "integer",
				Format: "<length>",
			},
		},
		Body: BodyDescriptor{
			ContentType: "application/json; charset=utf-8",
		},
		ErrorCodes: []errcode.ErrorCode{
			errcode.ErrorCodeUnauthorized,
		},
	}

	repositoryNotFoundResponseDescriptor = ResponseDescriptor{
		Name:       "No Such Repository Error",
		StatusCode: http.StatusNotFound,
		Headers: []ParameterDescriptor{
			{
				Name:   "Content-Length",
				Type:   "integer",
				Format: "<length>",
			},
		},
		Body: BodyDescriptor{
			ContentType: "application/json; charset=utf-8",
		},
		ErrorCodes: []errcode.ErrorCode{
			ErrorCodeNameUnknown,
		},
	}

	deniedResponseDescriptor = ResponseDescriptor{
		Name:       "Access Denied",
		StatusCode: http.StatusForbidden,
		Headers: []ParameterDescriptor{
			{
				Name:   "Content-Length",
				Type:   "integer",
				Format: "<length>",
			},
		},
		Body: BodyDescriptor{
			ContentType: "application/json; charset=utf-8",
		},
		ErrorCodes: []errcode.ErrorCode{
			errcode.ErrorCodeDenied,
		},
	}

	tooManyRequestsDescriptor = ResponseDescriptor{
		Name:       "Too Many Requests",
		StatusCode: http.StatusTooManyRequests,
		Headers: []ParameterDescriptor{
			{
				Name:   "Content-Length",
				Type:   "integer",
				Format: "<length>",
			},
		},
		Body: BodyDescriptor{
			ContentType: "application/json; charset=utf-8",
		},
		ErrorCodes: []errcode.ErrorCode{
			errcode.ErrorCodeTooManyRequests,
		},
	}
)

// APIDescriptor exports descriptions of the layout of the v2 registry API.
var APIDescriptor = struct {
	// RouteDescriptors provides a list of the routes available in the API.
	RouteDescriptors []RouteDescriptor
}{
	RouteDescriptors: routeDescriptors,
}

// RouteDescriptor describes a route specified by name.
type RouteDescriptor struct {
	// Name is the name of the route, as specified in RouteNameXXX exports.
	// These names a should be considered a unique reference for a route. If
	// the route is registered with gorilla, this is the name that will be
	// used.
	Name string

	// Path is a gorilla/mux-compatible regexp that can be used to match the
	// route. For any incoming method and path, only one route descriptor
	// should match.
	Path string

	// Entity should be a short, human-readalbe description of the object
	// targeted by the endpoint.
	Entity string

	// Methods should describe the various HTTP methods that may be used on
	// this route, including request and response formats.
	Methods []MethodDescriptor
}

// MethodDescriptor provides a description of the requests that may be
// conducted with the target method.
type MethodDescriptor struct {

	// Method is an HTTP method, such as GET, PUT or POST.
	Method string

	// Requests is a slice of request descriptors enumerating how this
	// endpoint may be used.
	Requests []RequestDescriptor
}

// RequestDescriptor covers a particular set of headers and parameters that
// can be carried out with the parent method. Its most helpful to have one
// RequestDescriptor per API use case.
type RequestDescriptor struct {
	// Name provides a short identifier for the request, usable as a title or
	// to provide quick context for the particular request.
	Name string

	// Headers describes headers that must be used with the HTTP request.
	Headers []ParameterDescriptor

	// PathParameters enumerate the parameterized path components for the
	// given request, as defined in the route's regular expression.
	PathParameters []ParameterDescriptor

	// QueryParameters provides a list of query parameters for the given
	// request.
	QueryParameters []ParameterDescriptor

	// Body describes the format of the request body.
	Body BodyDescriptor

	// Successes enumerates the possible responses that are considered to be
	// the result of a successful request.
	Successes []ResponseDescriptor

	// Failures covers the possible failures from this particular request.
	Failures []ResponseDescriptor
}

// ResponseDescriptor describes the components of an API response.
type ResponseDescriptor struct {
	// Name provides a short identifier for the response, usable as a title or
	// to provide quick context for the particular response.
	Name string

	// StatusCode specifies the status received by this particular response.
	StatusCode int

	// Headers covers any headers that may be returned from the response.
	Headers []ParameterDescriptor

	// Fields describes any fields that may be present in the response.
	Fields []ParameterDescriptor

	// ErrorCodes enumerates the error codes that may be returned along with
	// the response.
	ErrorCodes []errcode.ErrorCode

	// Body describes the body of the response, if any.
	Body BodyDescriptor
}

// BodyDescriptor describes a request body and its expected content type. For
// the most  part, it should be example json or some placeholder for body
// data in documentation.
type BodyDescriptor struct {
	ContentType string
	Format      string
}

// ParameterDescriptor describes the format of a request parameter, which may
// be a header, path parameter or query parameter.
type ParameterDescriptor struct {
	// Name is the name of the parameter, either of the path component or
	// query parameter.
	Name string

	// Type specifies the type of the parameter, such as string, integer, etc.
	Type string

	// Required means the field is required when set.
	Required bool

	// Format is a specifying the string format accepted by this parameter.
	Format string

	// Regexp is a compiled regular expression that can be used to validate
	// the contents of the parameter.
	Regexp *regexp.Regexp

	// Examples provides multiple examples for the values that might be valid
	// for this parameter.
	Examples []string
}

var routeDescriptors = []RouteDescriptor{
	{
		Name:   RouteNameBase,
		Path:   "/v2/",
		Entity: "Base",
		Methods: []MethodDescriptor{
			{
				Method: "GET",
				Requests: []RequestDescriptor{
					{
						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
						},
						Successes: []ResponseDescriptor{
							{
								StatusCode: http.StatusOK,
							},
						},
						Failures: []ResponseDescriptor{
							{

								StatusCode: http.StatusNotFound,
							},
							unauthorizedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
				},
			},
		},
	},
	{
		Name:   RouteNameTags,
		Path:   "/v2/{name:" + reference.NameRegexp + "}/tags/list",
		Entity: "Tags",

		Methods: []MethodDescriptor{
			{
				Method: "GET",
				Requests: []RequestDescriptor{
					{
						Name: "Tags",

						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
						},
						Successes: []ResponseDescriptor{
							{
								StatusCode: http.StatusOK,

								Headers: []ParameterDescriptor{
									{
										Name:   "Content-Length",
										Type:   "integer",
										Format: "<length>",
									},
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
									Format: `{
    "name": <name>,
    "tags": [
        <tag>,
        ...
    ]
}`,
								},
							},
						},
						Failures: []ResponseDescriptor{
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
					{
						Name: "Tags Paginated",

						PathParameters:  []ParameterDescriptor{nameParameterDescriptor},
						QueryParameters: paginationParameters,
						Successes: []ResponseDescriptor{
							{
								StatusCode: http.StatusOK,

								Headers: []ParameterDescriptor{
									{
										Name:   "Content-Length",
										Type:   "integer",
										Format: "<length>",
									},
									linkHeader,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
									Format: `{
    "name": <name>,
    "tags": [
        <tag>,
        ...
    ],
}`,
								},
							},
						},
						Failures: []ResponseDescriptor{
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
				},
			},
		},
	},
	{
		Name:   RouteNameManifest,
		Path:   "/v2/{name:" + reference.NameRegexp + "}/manifests/{reference:" + reference.TagRegexp.String() + "|" + digest.DigestRegexp.String() + "}",
		Entity: "Manifest",

		Methods: []MethodDescriptor{
			{
				Method: "GET",

				Requests: []RequestDescriptor{
					{
						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							referenceParameterDescriptor,
						},
						Successes: []ResponseDescriptor{
							{

								StatusCode: http.StatusOK,
								Headers: []ParameterDescriptor{
									digestHeader,
								},
								Body: BodyDescriptor{
									ContentType: "<media type of manifest>",
								},
							},
						},
						Failures: []ResponseDescriptor{
							{

								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeNameInvalid,
									ErrorCodeTagInvalid,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
				},
			},
			{
				Method: "PUT",

				Requests: []RequestDescriptor{
					{
						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							referenceParameterDescriptor,
						},
						Body: BodyDescriptor{
							ContentType: "<media type of manifest>",
						},
						Successes: []ResponseDescriptor{
							{

								StatusCode: http.StatusCreated,
								Headers: []ParameterDescriptor{
									{
										Name:   "Location",
										Type:   "url",
										Format: "<url>",
									},
									contentLengthZeroHeader,
									digestHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{
								Name: "Invalid Manifest",

								StatusCode: http.StatusBadRequest,
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeNameInvalid,
									ErrorCodeTagInvalid,
									ErrorCodeManifestInvalid,
									ErrorCodeManifestUnverified,
									ErrorCodeBlobUnknown,
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
							{
								Name: "Missing Layer(s)",

								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeBlobUnknown,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
									Format: `{
    "errors:" [{
            "code": "BLOB_UNKNOWN",
            "message": "blob unknown to registry",
            "detail": {
                "digest": "<digest>"
            }
        },
        ...
    ]
}`,
								},
							},
							{
								Name: "Not allowed",

								StatusCode: http.StatusMethodNotAllowed,
								ErrorCodes: []errcode.ErrorCode{
									errcode.ErrorCodeUnsupported,
								},
							},
						},
					},
				},
			},
			{
				Method: "DELETE",

				Requests: []RequestDescriptor{
					{
						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							referenceParameterDescriptor,
						},
						Successes: []ResponseDescriptor{
							{
								StatusCode: http.StatusAccepted,
							},
						},
						Failures: []ResponseDescriptor{
							{
								Name: "Invalid Name or Reference",

								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeNameInvalid,
									ErrorCodeTagInvalid,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
							{
								Name: "Unknown Manifest",

								StatusCode: http.StatusNotFound,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeNameUnknown,
									ErrorCodeManifestUnknown,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							{
								Name: "Not allowed",

								StatusCode: http.StatusMethodNotAllowed,
								ErrorCodes: []errcode.ErrorCode{
									errcode.ErrorCodeUnsupported,
								},
							},
						},
					},
				},
			},
		},
	},

	{
		Name:   RouteNameBlob,
		Path:   "/v2/{name:" + reference.NameRegexp + "}/blobs/{digest:" + digest.DigestRegexp.String() + "}",
		Entity: "Blob",

		Methods: []MethodDescriptor{
			{
				Method: "GET",

				Requests: []RequestDescriptor{
					{
						Name: "Fetch Blob",
						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							digestPathParameter,
						},
						Successes: []ResponseDescriptor{
							{

								StatusCode: http.StatusOK,
								Headers: []ParameterDescriptor{
									{
										Name:   "Content-Length",
										Type:   "integer",
										Format: "<length>",
									},
									digestHeader,
								},
								Body: BodyDescriptor{
									ContentType: "application/octet-stream",
									Format:      "<blob binary data>",
								},
							},
							{

								StatusCode: http.StatusTemporaryRedirect,
								Headers: []ParameterDescriptor{
									{
										Name:   "Location",
										Type:   "url",
										Format: "<blob location>",
									},
									digestHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{

								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeNameInvalid,
									ErrorCodeDigestInvalid,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							{

								StatusCode: http.StatusNotFound,
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeNameUnknown,
									ErrorCodeBlobUnknown,
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
					{
						Name: "Fetch Blob Part",

						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
							{
								Name:   "Range",
								Type:   "string",
								Format: "bytes=<start>-<end>",
							},
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							digestPathParameter,
						},
						Successes: []ResponseDescriptor{
							{

								StatusCode: http.StatusPartialContent,
								Headers: []ParameterDescriptor{
									{
										Name:   "Content-Length",
										Type:   "integer",
										Format: "<length>",
									},
									{
										Name:   "Content-Range",
										Type:   "byte range",
										Format: "bytes <start>-<end>/<size>",
									},
								},
								Body: BodyDescriptor{
									ContentType: "application/octet-stream",
									Format:      "<blob binary data>",
								},
							},
						},
						Failures: []ResponseDescriptor{
							{

								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeNameInvalid,
									ErrorCodeDigestInvalid,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							{
								StatusCode: http.StatusNotFound,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeNameUnknown,
									ErrorCodeBlobUnknown,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							{

								StatusCode: http.StatusRequestedRangeNotSatisfiable,
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
				},
			},
			{
				Method: "DELETE",

				Requests: []RequestDescriptor{
					{
						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							digestPathParameter,
						},
						Successes: []ResponseDescriptor{
							{
								StatusCode: http.StatusAccepted,
								Headers: []ParameterDescriptor{
									{
										Name:   "Content-Length",
										Type:   "integer",
										Format: "0",
									},
									digestHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{
								Name:       "Invalid Name or Digest",
								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeDigestInvalid,
									ErrorCodeNameInvalid,
								},
							},
							{

								StatusCode: http.StatusNotFound,
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeNameUnknown,
									ErrorCodeBlobUnknown,
								},
							},
							{

								StatusCode: http.StatusMethodNotAllowed,
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
								ErrorCodes: []errcode.ErrorCode{
									errcode.ErrorCodeUnsupported,
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
				},
			},

			// TODO(stevvooe): We may want to add a PUT request here to
			// kickoff an upload of a blob, integrated with the blob upload
			// API.
		},
	},

	{
		Name:   RouteNameBlobUpload,
		Path:   "/v2/{name:" + reference.NameRegexp + "}/blobs/uploads/",
		Entity: "Initiate Blob Upload",

		Methods: []MethodDescriptor{
			{
				Method: "POST",

				Requests: []RequestDescriptor{
					{
						Name: "Initiate Monolithic Blob Upload",

						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
							{
								Name:   "Content-Length",
								Type:   "integer",
								Format: "<length of blob>",
							},
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
						},
						QueryParameters: []ParameterDescriptor{
							{
								Name:   "digest",
								Type:   "query",
								Format: "<digest>",
								Regexp: digest.DigestRegexp,
							},
						},
						Body: BodyDescriptor{
							ContentType: "application/octect-stream",
							Format:      "<binary data>",
						},
						Successes: []ResponseDescriptor{
							{

								StatusCode: http.StatusCreated,
								Headers: []ParameterDescriptor{
									{
										Name:   "Location",
										Type:   "url",
										Format: "<blob location>",
									},
									contentLengthZeroHeader,
									dockerUploadUUIDHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{
								Name:       "Invalid Name or Digest",
								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeDigestInvalid,
									ErrorCodeNameInvalid,
								},
							},
							{
								Name: "Not allowed",

								StatusCode: http.StatusMethodNotAllowed,
								ErrorCodes: []errcode.ErrorCode{
									errcode.ErrorCodeUnsupported,
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
					{
						Name: "Initiate Resumable Blob Upload",

						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
							contentLengthZeroHeader,
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
						},
						Successes: []ResponseDescriptor{
							{

								StatusCode: http.StatusAccepted,
								Headers: []ParameterDescriptor{
									contentLengthZeroHeader,
									{
										Name:   "Location",
										Type:   "url",
										Format: "/v2/<name>/blobs/uploads/<uuid>",
									},
									{
										Name:   "Range",
										Format: "0-0",
									},
									dockerUploadUUIDHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{
								Name:       "Invalid Name or Digest",
								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeDigestInvalid,
									ErrorCodeNameInvalid,
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
					{
						Name: "Mount Blob",

						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
							contentLengthZeroHeader,
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
						},
						QueryParameters: []ParameterDescriptor{
							{
								Name:   "mount",
								Type:   "query",
								Format: "<digest>",
								Regexp: digest.DigestRegexp,
							},
							{
								Name:   "from",
								Type:   "query",
								Format: "<repository name>",
							},
						},
						Successes: []ResponseDescriptor{
							{

								StatusCode: http.StatusCreated,
								Headers: []ParameterDescriptor{
									{
										Name:   "Location",
										Type:   "url",
										Format: "<blob location>",
									},
									contentLengthZeroHeader,
									dockerUploadUUIDHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{
								Name:       "Invalid Name or Digest",
								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeDigestInvalid,
									ErrorCodeNameInvalid,
								},
							},
							{
								Name: "Not allowed",

								StatusCode: http.StatusMethodNotAllowed,
								ErrorCodes: []errcode.ErrorCode{
									errcode.ErrorCodeUnsupported,
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
				},
			},
		},
	},

	{
		Name:   RouteNameBlobUploadChunk,
		Path:   "/v2/{name:" + reference.NameRegexp + "}/blobs/uploads/{uuid:[a-zA-Z0-9-_.=]+}",
		Entity: "Blob Upload",

		Methods: []MethodDescriptor{
			{
				Method: "GET",

				Requests: []RequestDescriptor{
					{

						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							uuidParameterDescriptor,
						},
						Successes: []ResponseDescriptor{
							{
								Name: "Upload Progress",

								StatusCode: http.StatusNoContent,
								Headers: []ParameterDescriptor{
									{
										Name:   "Range",
										Type:   "header",
										Format: "0-<offset>",
									},
									contentLengthZeroHeader,
									dockerUploadUUIDHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{

								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeDigestInvalid,
									ErrorCodeNameInvalid,
									ErrorCodeBlobUploadInvalid,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							{

								StatusCode: http.StatusNotFound,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeBlobUploadUnknown,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
				},
			},
			{
				Method: "PATCH",

				Requests: []RequestDescriptor{
					{
						Name: "Stream upload",

						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							uuidParameterDescriptor,
						},
						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
						},
						Body: BodyDescriptor{
							ContentType: "application/octet-stream",
							Format:      "<binary data>",
						},
						Successes: []ResponseDescriptor{
							{
								Name: "Data Accepted",

								StatusCode: http.StatusNoContent,
								Headers: []ParameterDescriptor{
									{
										Name:   "Location",
										Type:   "url",
										Format: "/v2/<name>/blobs/uploads/<uuid>",
									},
									{
										Name:   "Range",
										Type:   "header",
										Format: "0-<offset>",
									},
									contentLengthZeroHeader,
									dockerUploadUUIDHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{

								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeDigestInvalid,
									ErrorCodeNameInvalid,
									ErrorCodeBlobUploadInvalid,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							{

								StatusCode: http.StatusNotFound,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeBlobUploadUnknown,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
					{
						Name: "Chunked upload",

						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							uuidParameterDescriptor,
						},
						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
							{
								Name:     "Content-Range",
								Type:     "header",
								Format:   "<start of range>-<end of range, inclusive>",
								Required: true,
							},
							{
								Name:   "Content-Length",
								Type:   "integer",
								Format: "<length of chunk>",
							},
						},
						Body: BodyDescriptor{
							ContentType: "application/octet-stream",
							Format:      "<binary chunk>",
						},
						Successes: []ResponseDescriptor{
							{
								Name: "Chunk Accepted",

								StatusCode: http.StatusNoContent,
								Headers: []ParameterDescriptor{
									{
										Name:   "Location",
										Type:   "url",
										Format: "/v2/<name>/blobs/uploads/<uuid>",
									},
									{
										Name:   "Range",
										Type:   "header",
										Format: "0-<offset>",
									},
									contentLengthZeroHeader,
									dockerUploadUUIDHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{

								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeDigestInvalid,
									ErrorCodeNameInvalid,
									ErrorCodeBlobUploadInvalid,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							{

								StatusCode: http.StatusNotFound,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeBlobUploadUnknown,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							{

								StatusCode: http.StatusRequestedRangeNotSatisfiable,
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
				},
			},
			{
				Method: "PUT",

				Requests: []RequestDescriptor{
					{

						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
							{
								Name:   "Content-Length",
								Type:   "integer",
								Format: "<length of data>",
							},
						},
						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							uuidParameterDescriptor,
						},
						QueryParameters: []ParameterDescriptor{
							{
								Name:     "digest",
								Type:     "string",
								Format:   "<digest>",
								Regexp:   digest.DigestRegexp,
								Required: true,
							},
						},
						Body: BodyDescriptor{
							ContentType: "application/octet-stream",
							Format:      "<binary data>",
						},
						Successes: []ResponseDescriptor{
							{
								Name: "Upload Complete",

								StatusCode: http.StatusNoContent,
								Headers: []ParameterDescriptor{
									{
										Name:   "Location",
										Type:   "url",
										Format: "<blob location>",
									},
									{
										Name:   "Content-Range",
										Type:   "header",
										Format: "<start of range>-<end of range, inclusive>",
									},
									contentLengthZeroHeader,
									digestHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{

								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeDigestInvalid,
									ErrorCodeNameInvalid,
									ErrorCodeBlobUploadInvalid,
									errcode.ErrorCodeUnsupported,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							{

								StatusCode: http.StatusNotFound,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeBlobUploadUnknown,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
				},
			},
			{
				Method: "DELETE",

				Requests: []RequestDescriptor{
					{

						PathParameters: []ParameterDescriptor{
							nameParameterDescriptor,
							uuidParameterDescriptor,
						},
						Headers: []ParameterDescriptor{
							hostHeader,
							authHeader,
							contentLengthZeroHeader,
						},
						Successes: []ResponseDescriptor{
							{
								Name: "Upload Deleted",

								StatusCode: http.StatusNoContent,
								Headers: []ParameterDescriptor{
									contentLengthZeroHeader,
								},
							},
						},
						Failures: []ResponseDescriptor{
							{

								StatusCode: http.StatusBadRequest,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeNameInvalid,
									ErrorCodeBlobUploadInvalid,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							{

								StatusCode: http.StatusNotFound,
								ErrorCodes: []errcode.ErrorCode{
									ErrorCodeBlobUploadUnknown,
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
							unauthorizedResponseDescriptor,
							repositoryNotFoundResponseDescriptor,
							deniedResponseDescriptor,
							tooManyRequestsDescriptor,
						},
					},
				},
			},
		},
	},
	{
		Name:   RouteNameCatalog,
		Path:   "/v2/_catalog",
		Entity: "Catalog",

		Methods: []MethodDescriptor{
			{
				Method: "GET",

				Requests: []RequestDescriptor{
					{
						Name: "Catalog Fetch",

						Successes: []ResponseDescriptor{
							{

								StatusCode: http.StatusOK,
								Headers: []ParameterDescriptor{
									{
										Name:   "Content-Length",
										Type:   "integer",
										Format: "<length>",
									},
								},
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
							},
						},
					},
					{
						Name: "Catalog Fetch Paginated",

						QueryParameters: paginationParameters,
						Successes: []ResponseDescriptor{
							{
								StatusCode: http.StatusOK,
								Body: BodyDescriptor{
									ContentType: "application/json; charset=utf-8",
								},
								Headers: []ParameterDescriptor{
									{
										Name:   "Content-Length",
										Type:   "integer",
										Format: "<length>",
									},
									linkHeader,
								},
							},
						},
					},
				},
			},
		},
	},
}
