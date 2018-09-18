## clients for oauth

golang SDK for https://github.com/huyinghuan/oauth


### init SDK

```
import Oauth "github.com/huyinghuan/oauth_sdk"

sdk = Oauth.SDK{
    ClientID:   ClientID,
    Server:     Server,
    PrivateKey: PrivateKey,
}
```

### sdk.RequestResource(token string, username string)

Get Username


### sdk.GetAuthorizedURL()

Get oauth server login url

if you can get  resource token for this url

```
ctx.StatusCode(301)
ctx.Header("Location", oauth.GetAuthorizedURL())
```

### sdk.verify(api string, httpMethod string, username string)


ask oauth server  to verify api authorize 