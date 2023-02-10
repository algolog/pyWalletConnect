
# pyWalletConnect changes log

## 1.3.2

* Fix WC v2 RPC queries with tag
* Add a debug output for responses sent

## 1.3.0

* Add WC v2 "IRN"
* Code refactoring, separate WC versions
* Improve type check for devs
* Improve JSON decoding when error
* Use a queue internally for better message management on an external thread

## 1.2.2

* Auto-disconnect from dapp when WCv1 object is deleted

## 1.2.0

* New logo, used for v2 default
* Add session request rejection method
* Remove no message from log
* Add WalletConnect v2 (experimental)
* Can change wallet metadata and project id (for v2)

## 1.1.4

* Explicitely reject WC v2

## 1.1.3

* Improve socket closing

## 1.1.2

* Add auto reconnect when socket closed

## 1.1.1

* Test if the WebSocket was already closed

## 1.1.0

* Can work with bigger split messages

## 1.0.0

* First release
* v1 RPC Wallet implementation
