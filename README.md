# Secure Frame (SFrame)

This is the working area for the IETF [SFRAME Working Group](https://datatracker.ietf.org/wg/sframe/documents/) Internet-Draft, "Secure Frame (SFrame)".

* [Editor's Copy](https://sframe-wg.github.io/sframe/#go.draft-ietf-sframe-enc.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-sframe-enc)
* [Working Group Draft](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc)
* [Compare Editor's Copy to Working Group Draft](https://sframe-wg.github.io/sframe/#go.draft-ietf-sframe-enc.diff)


## Contributing

See the
[guidelines for contributions](https://github.com/sframe-wg/sframe/blob/master/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

## Regenerating Test Vectors

After a breaking change in the specification, the test vector script should be
updated accordingly, and used to generate new test vectors.

```sh
$ cd test-vectors
$ go run known-answer-test.go -json >../test-vectors.json
$ go run known-answer-test.go -md >../test-vectors.md
```
