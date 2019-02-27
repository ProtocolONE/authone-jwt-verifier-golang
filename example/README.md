# Demo application for authorization

The application demonstrates basic authorization scenarios and environment settings.

# Prerequisites

You will need an [auth1](https://github.com/ProtocolONE/auth1.protocol.one) and 
[ORY Hydra](https://github.com/ory/hydra) authorization server to operate.

Download Hydra and edit docker-compose.yml if necessary. The main thing you may need to 
do is to change the value of the environment variables in it:
* `OAUTH2_ISSUER_URL` - endpoint address on public hydra URL
* `OAUTH2_LOGIN_URL` - endpoint address for user login and password request (project 
auth1)
* `OAUTH2_CONSENT_URL` - endpoint address to request user scopes (project auth1)

If you want Hydra to work on non-standard ports (4444 for public requests and 4445 for 
administrative requests), change them in the `ports` section.

Also note that the endpoints of Hydra requests are also listed in the configuration file 
`config.yaml` of the auth1 project, located in the `etc` directory.

# Usage

The first step is to create the space, application and user in the auth1 project. 
To do this, use the API requests described in the project specification at 
`/spec/openapi.yaml`. You can also use the queries prepared for the [Postman](https://www.getpostman.com/downloads/) application, 
which are located in the `/spec/postman_collection` file.

Create space using `/api/space` (Postman: Management > Space > Create space). Using the 
space identifier, create an application by executing a request to `/api/app` (Postman: 
Management > Application > Create application). At creation of the application in a 
field `auth_redirect_urls ` specify an end point of your application which will validate 
the received code from a server of authorisation (for this demonstration application the 
address http://127.0.0.1:1323/auth/callback is used).

The response received after creating the application will contain a secret key that 
should be used for authorization, for example:

 ```json
{
    "id": "5c5bfc434c1efd4fb8e2d266",
    "space_id": "5c1bbe564c1efd4428629bdd",
    "name": "Test2",
    "description": "Initial application",
    "is_active": true,
    "auth_secret": "ejJu8SLQnt5Bx2DiqZSIoQbWCPK5eIeYNyjGQLsL7ZwAeipZMY1W6BnsJOBZGVpC",
    "auth_redirect_urls": [
        "http://127.0.0.1:1323/auth/callback"
    ]
}
```

Use the resulting `id`, `auth_secret` and `auth_redirect_urls` to configure your test 
application.

```go
conf := jwtverifier.Config{
    ClientID:     "",
    ClientSecret: "",
    Scopes:       []string{"openid", "offline"},
    RedirectURL:  "http://127.0.0.1:1323/auth/callback",
    AuthDomain:   "http://localhost:8080",
}
``` 

AuthDomain is the domain where ProtocolOne authorization server is located (without a slash at the end of the line, 
this is important). Change the domain name and port, if necessary.

Almost everything's ready.)

The only thing left to do is to create a user by sending a request to auth1 api at 
`/signup` (Postman: SignUp > SignUp), and then open the main page of the test 
application and click on the `Auth me` link.

After successful authentication, the user will be returned to 
http://127.0.0.1:1323/auth/callback and in the application console you will see the 
authentication tokens that can be used further in the application as you wish.
