# Flutter Proxy for Local Web App Development

I was working on a Flutter web app that stores the backend API authentication credentials as cookies. The web app is hosted on `localhost` during development, but the API backend is still hosted on the production web server. Chrome blocks the cookies from the API backend according to the production web server's CORS policy. The production web server also requires automatic upgrade of HTTP to HTTPS.

I needed a proxy that can:

1.  Redirect the Flutter dev server URL for the web app to HTTPS.
2.  Use a self-signed CA to dynamically generate a TLS certificate for the production web server's domain.
3.  Intercept and redirect URL's for the web app to Flutter's dev server
4.  Forward API backend URL's to the production web server

I want to be able to start the proxy from a single command so I did not want to use any existing man-in-the-middle HTTPS proxies that may require complicated install and setup, so I wrote a new proxy in Go, tailored for the Flutter web app development use case.

## Install

```shell
go install github.com/erdichen/flutterproxy@latest
```

## Setup

### Create a fake CA

```shell
flutteryproxy genca --cert=secret/cert.pem --key=secret/key.pem
```

### Add the fake CA's certificate to Chrome's CA certificate store

### Linux

Chrome on Linux uses the `nssdb` certificate database from Firefox.

1.  Install `certutil`
    ```shell
    sudo apt install libnss3-tools
    ```
2.  Add the fake CA's certificate to the current user's CA certificate store
    ```shell
    certutil -d $HOME/.pki/nssdb -A -n "Fake CA" -t "CT,c,c" < secret/cert.pem
    ```

### MacOS

Import the fake CA's certificate by pressing `Shift-Command-I` (**⇧⌘I**) or clicking the `Create a new keychain item.` button to select the `secret/cert.pem` file.

![image `Keychain Access` screenshot](screenshots/macos_keychain.png)

NOTE: The new CA certificate applies to all applications. Keep the `secret/key.pem` file safe or remove the fake CA certficate after testing.

## Start the Proxy

```shell
flutteryproxy run --cert=secret/cert.pem --key=secret/key.pem --host_pair=yoursite.com:443,127.0.0.1:7777 --prefix_pair=yoursite.com:443,/api
```

Explanation of the flags:

1.  `--cert=secret/cert.pem` - the fake CA certificate
2.  `--key=secret/key.pem` - the fake CA private key
3.  `--host_pair=yoursite.com:443,127.0.0.1:7777` - redirect `yoursite.com` to the Flutter dev server
4.  `--prefix_pair=yoursite.com:443,/api` - forward requests with the `/api` path prefix to the production web server

## Run Flutter App on Chrome with the Proxy

```shell
flutter run -d chrome --web-port=7777 \
    --web-browser-flag=--proxy-server=http://127.0.0.1:9999 \
    --web-browser-flag=--proxy-bypass-list="<-loopback>" \
    --web-browser-flag=--disable-web-security \
    --web-browser-flag=--allow-running-insecure-content
```

Explanation of the flags:

1.  `-d chrome` - run the app on Chrome
2.  `--web-port=7777` - start the dev server at port 7777
3.  `--web-browser-flag=--proxy-server=http://127.0.0.1:9999` - set the Chrome proxy server URL
4.  `--web-browser-flag=--proxy-bypass-list="<-loopback>"` -  do not proxy the proxy server URL
5.  `--web-browser-flag=--disable-web-security` - enable the `--allow-running-insecure-content` flag
6.  `--web-browser-flag=--allow-running-insecure-content` - allow mixed content since the Flutter debugger connection is an insecure WebSocket endpoint