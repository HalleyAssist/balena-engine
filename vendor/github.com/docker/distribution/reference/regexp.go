package reference

// DomainRegexp matches hostname or IP-addresses, optionally including a port
// number. It defines the structure of potential domain components that may be
// part of image names. This is purposely a subset of what is allowed by DNS to
// ensure backwards compatibility with Docker image names. It may be a subset of
// DNS domain name, an IPv4 address in decimal format, or an IPv6 address between
// square brackets (excluding zone identifiers as defined by [RFC 6874] or special
// addresses such as IPv4-Mapped).
//
// [RFC 6874]: https://www.rfc-editor.org/rfc/rfc6874.
var AnchoredDomainRegexp = "^" + domainAndPort + "$"

// NameRegexp is the format for the name component of references, including
// an optional domain and port, but without tag or digest suffix.
var NameRegexp = namePat

// TagRegexp matches valid tag names. From [docker/docker:graph/tags.go].
//
// [docker/docker:graph/tags.go]: https://github.com/moby/moby/blob/v1.6.0/graph/tags.go#L26-L28
var TagRegexp = tag

const (
	// alphanumeric defines the alphanumeric atom, typically a
	// component of names. This only allows lower case characters and digits.
	alphanumeric = `[a-z0-9]+`

	// separator defines the separators allowed to be embedded in name
	// components. This allows one period, one or two underscore and multiple
	// dashes. Repeated dashes and underscores are intentionally treated
	// differently. In order to support valid hostnames as name components,
	// supporting repeated dash was added. Additionally double underscore is
	// now allowed as a separator to loosen the restriction for previously
	// supported names.
	separator = `(?:[._]|__|[-]+)`

	// localhost is treated as a special value for domain-name. Any other
	// domain-name without a "." or a ":port" are considered a path component.
	localhost = `localhost`

	// domainNameComponent restricts the registry domain component of a
	// repository name to start with a component as defined by DomainRegexp.
	domainNameComponent = `(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])`

	// optionalPort matches an optional port-number including the port separator
	// (e.g. ":80").
	optionalPort = `(?::[0-9]+)?`

	// tag matches valid tag names. From docker/docker:graph/tags.go.
	tag         = `[\w][\w.-]{0,127}`
	anchoredTag = `^` + tag + `$`

	// digestPat matches well-formed digests, including algorithm (e.g. "sha256:<encoded>").
	//
	// TODO(thaJeztah): this should follow the same rules as https://pkg.go.dev/github.com/opencontainers/go-digest@v1.0.0#DigestRegexp
	// so that go-digest defines the canonical format. Note that the go-digest is
	// more relaxed:
	//   - it allows multiple algorithms (e.g. "sha256+b64:<encoded>") to allow
	//     future expansion of supported algorithms.
	//   - it allows the "<encoded>" value to use urlsafe base64 encoding as defined
	//     in [rfc4648, section 5].
	//
	// [rfc4648, section 5]: https://www.rfc-editor.org/rfc/rfc4648#section-5.
	digestPat         = `[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][[:xdigit:]]{32,}`

	// identifier is the format for a content addressable identifier using sha256.
	// These identifiers are like digests without the algorithm, since sha256 is used.
	identifier         = `([a-f0-9]{64})`
	anchoredIdentifier = `^` + identifier + `$`

	// ipv6address are enclosed between square brackets and may be represented
	// in many ways, see rfc5952. Only IPv6 in compressed or uncompressed format
	// are allowed, IPv6 zone identifiers (rfc6874) or Special addresses such as
	// IPv4-Mapped are deliberately excluded.
	ipv6address = `\[(?:[a-fA-F0-9:]+)\]`

	// domainName defines the structure of potential domain components
	// that may be part of image names. This is purposely a subset of what is
	// allowed by DNS to ensure backwards compatibility with Docker image
	// names. This includes IPv4 addresses on decimal format.
	domainName = domainNameComponent + `(?:` + `\.` + domainNameComponent + `)*`

	// host defines the structure of potential domains based on the URI
	// Host subcomponent on rfc3986. It may be a subset of DNS domain name,
	// or an IPv4 address in decimal format, or an IPv6 address between square
	// brackets (excluding zone identifiers as defined by rfc6874 or special
	// addresses such as IPv4-Mapped).
	host = `(?:` + domainName + `|` + ipv6address + `)`

	// allowed by the URI Host subcomponent on rfc3986 to ensure backwards
	// compatibility with Docker image names.
	domainAndPort = host + optionalPort

	// pathComponent restricts path-components to start with an alphanumeric
	// character, with following parts able to be separated by a separator
	// (one period, one or two underscore and multiple dashes).
	pathComponent = alphanumeric + "(?:" + (separator + alphanumeric) + ")*"

	// remoteName matches the remote-name of a repository. It consists of one
	// or more forward slash (/) delimited path-components:
	//
	//	pathComponent[[/pathComponent] ...] // e.g., "library/ubuntu"
	remoteName = pathComponent + `(?:/` + pathComponent + ")*"
	namePat    = "(?:" + domainAndPort + `/` + ")?" + remoteName

	anchoredName = "^(?:(" + domainAndPort + ")/(" + remoteName + "))?$"

	referencePat = "^(" + namePat + ")(?:" + `:(` + tag + "))?(?:" + `@(` + digestPat + "))?$"
)
