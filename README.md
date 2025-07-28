# lsend
inspired by [localsend](https://localsend.org/)'s way to share files,
this cli tool uses a tcp socket and mdns to communicate with other devices
**on your network** and share files.

all traffic is encrypted and file transfers are secure and validated.

# usage
on the client recieving a file, run
`lsend -M save ./out-dir`
which should output something like
```sh
id: 72ca57
```
this creates an out directory for files sent to this device
and displays and id used to discover your device.

on another client sending a file run
`lsend -M share -I 72ca57 test.txt`
to share `test.txt` to the client
```sh
searching for clients...
client found
found client address: 192.168.50.119:18793
connected to client
sending file
```

the first client should see
```sh
incoming file, accept? (y/n)
name: test.txt
size: 13
from: 192.168.50.119:18827
hash: ede5c0b10f2ec4979c69b52f61e42ff5b413519ce09be0f14d098dcfe5f6f98d
```

type y and press enter to accept. 

the sending client should see `sent` appear.

note that for extremely small files the sender may see sent appear
before the client accepts the file. this is OK. the client must still
accept the file before it is saved and the file will still send as usual.

and the client saving the file should see
```sh
file accepted...
transfering file...
saved to test.txt
hashes match
```

done! the saving client can keep getting files from senders
until the program closes.