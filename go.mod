module github.com/burlingtonbertie99/mykeys

go 1.13

require (
	github.com/ScaleFT/sshkeys v0.0.0-20200327173127-6142f742bca5
	github.com/burlingtonbertie99/mykeys-ext v0.0.0-00010101000000-000000000000
	github.com/danieljoos/wincred v1.1.0
	github.com/davecgh/go-spew v1.1.1
	github.com/dchest/blake2b v1.0.0
	github.com/flynn/noise v1.0.0
	github.com/godbus/dbus v4.1.0+incompatible
	github.com/google/go-cmp v0.5.6
	github.com/keybase/go-keychain v0.0.0-20201121013009-976c83ec27a6
	github.com/keybase/saltpack v0.0.0-20210611181147-9dd0a21addc6
	github.com/keys-pub/secretservice v0.0.0-20200519003656-26e44b8df47f
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/vmihailenco/msgpack/v4 v4.3.12
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e
)

replace github.com/burlingtonbertie99/mykeys-ext => ./
