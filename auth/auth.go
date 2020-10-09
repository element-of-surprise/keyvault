// Package auth provides an authorization abstraction to allow for future authorization methods lik MSAL.
// For normal use cases, using MSIAuth() in keyvault is the normal and most secure way to get an Authorization object.
package auth

import (
	"fmt"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

// Authorization provides the ADAL authorizer needed to access the resource. You can set Authorizer or
// Config, but not both.
type Authorization struct {
	// Authorizer provides an authorizer to use when talking to Kusto. If this is set, the
	// Authorizer must have its Resource (also called Resource ID) set to the endpoint passed
	// to the New() constructor. This will be something like "https://somename.westus.kusto.windows.net".
	// This package will try to set that automatically for you.
	Authorizer autorest.Authorizer
	// Config provides the authorizer's config that can create the authorizer. We recommending setting
	// this instead of Authorizer, as we will automatically set the Resource ID with the endpoint passed.
	Config auth.AuthorizerConfig
}

// Validate validates the Authorization object against the endpoint an preps it for use.
// For internal use only.
func (a *Authorization) Validate() error {
	if a.Authorizer != nil && a.Config != nil {
		return fmt.Errorf("cannot set Authoriztion.Authorizer and Authorizer.Config")
	}
	if a.Authorizer == nil && a.Config == nil {
		return fmt.Errorf("cannot leave all Authoriztion fields as zero values")
	}
	if a.Authorizer != nil {
		return nil
	}

	var err error
	a.Authorizer, err = a.Config.Authorizer()
	if err != nil {
		return err
	}
	return nil
}
