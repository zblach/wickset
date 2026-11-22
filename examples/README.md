# Sample wicks

The same short message, sealed once with each algorithm, at step counts that
burn in 10 to 15 seconds with wickset on an Apple M5. The plaintexts are not
here: opening a wick is how to read one.

| files | algorithm | steps |
|---|---|---|
| `hello-01.txt.wick`, `.payload` | 0x01 Argon2id, short step | 33 |
| `hello-02.txt.wick`, `.payload` | 0x02 Argon2id, long step | 1 |
| `hello-03.txt.wick`, `.payload` | 0x03 iterated SHA-256, short step | 33 |
| `hello-04.txt.wick`, `.payload` | 0x04 iterated SHA-256, long step | 1 |

    wickset info examples/hello-03.txt.wick     # what it is; are its files intact
    wickset open examples/hello-03.txt.wick     # burn it: → examples/hello-03.txt

`hello-01.key` is the key `seal --key-out` saved for the first one: it opens
that file at once, with no burning, as a kept key would.

    wickset bypass --key examples/hello-01.key examples/hello-01.txt.payload

Keys travel apart from their wicks in real use; this one is here to show
what a key does.
