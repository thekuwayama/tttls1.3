## Usage

The examples use PEM files in `../tmp/`.

If you needed those, you could generate example PEM files, `ca.crt`, `ca.key`, `server.crt` and `server.key`, using `rake`.

```bash
$ rake gen_certs
```

The examples run as follows:

```bash
$ ruby https_client.rb

$ ruby https_client.rb localhost:4433
```

Note that `https_server.rb` requires PEM files of certificate and private key.

```bash
$ ruby https_server.rb

$ ruby https_server.rb 4433
```
