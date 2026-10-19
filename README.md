# natepage/symfony-security

Simple and opinionated security utilities

## WorkOS firewall

```yaml
security:
    firewalls:
        ui:
            oauth_workos:
                api_key: '%env(OAUTH_WORKOS_API_KEY)%'
                client_id: '%env(OAUTH_WORKOS_CLIENT_ID)%'
                organisation_id: '%env(OAUTH_WORKOS_ORGANISATION_ID)%'
                logout_redirect_route: 'dashboard'
                provider: oauth_workos
                user_class: App\Entity\User
```

`organisation_id` scopes the firewall to one WorkOS organisation. It is passed when building the AuthKit
authorisation URL, and the driver rejects any authentication whose response is for another organisation (or for
none) with `InvalidOrganisationException`, on both the login callback and the token refresh. Leave it unset for a
firewall that accepts every user of the WorkOS environment.
