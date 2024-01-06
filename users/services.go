package users

import (
	"github.com/burlingtonbertie99/mykeys-ext/user"
	"github.com/burlingtonbertie99/mykeys-ext/user/services"
)

// LookupService finds service.
func LookupService(usr *user.User, opt ...UpdateOption) (services.Service, error) {
	opts := newUpdateOptions(opt...)

	if opts.Service != nil {
		service := opts.Service(usr)
		if service != nil {
			return service, nil
		}
	}

	return services.Lookup(usr.Service)
}
