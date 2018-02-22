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

Note that the following commands have to be executed after a successful log-in.

* logout
* changepassword
* follow
* unfollow
* followers
* followings

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

(4) Change the password. Assume that the old password is yyyyyy and the new password is zzzzzz.

```bash
> changepassword yyyyyy zzzzzz zzzzzz
```

(5) Follow a user xxxxxx.

```bash
> follow xxxxxx
```

(6) Unfollow a user.

```bash
> unfollow xxxxxx
```

(7) Get the follower list of a user.

```bash
> followers
```

(8) Get the following list of a user.

```bash
> followings
```

(9) Exit the console program.

```bash
> exit
```

or 

```bash
> quit
```