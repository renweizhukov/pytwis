# pytwis

A twitter clone using Python and Redis

To get the help information,

```bash
$ ./pytwis_clt.py -h
```

## 1. Connect to the twitter clone.

(1) Connect to the local Redis server at the default port 6379 with no password.

```bash
$ ./pytwis_clt.py 
```

(2) Connect to a remote Redis server with IP = xxx.xxx.xxx.xxx at port yyyy with password zzzzzz.

```bash
$ ./pytwis_clt.py -d xxx.xxx.xxx.xxx -t yyyy -p zzzzzz
```

## 2. Online commands after successfully connecting to the twitter clone.

(1) Register a new user xxxxxx with password yyyyyy.

```bash
> register xxxxxx yyyyyy
```

(2) Log into a user xxxxxxx with password yyyyyy.

```bash
> login xxxxxx yyyyyy
```

(3) Log out.

```bash
> logout
```

(4) Exit the console program.

```bash
> exit
```

or 

```bash
> quit
```