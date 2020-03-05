[TOC]

## RPC error code / HTTP mapping

### HTTP → RPC

HTTP                                | RPC
----------------------------------- | --------------------------
2xx                                 | (0)  OK
3xx                                 | (2)  UNKNOWN
400 Bad request                     | (3)  INVALID_ARGUMENT
401 Unauthorized                    | (16) UNAUTHENTICATED
403 Forbidden                       | (7)  PERMISSION_DENIED
404 Not found                       | (5)  NOT_FOUND
409 Conflict                        | (10) ABORTED
416 Requested range not satisfiable | (11) OUT_OF_RANGE
429 Too many requests               | (8)  RESOURCE_EXHAUSTED
499 Client closed request           | (1)  CANCELLED
4xx Other 4xx                       | (9)  FAILED_PRECONDITION
501 Not implemented                 | (12) UNIMPLEMENTED
503 Service unavailable             | (14) UNAVAILABLE
504 Gateway time-out                | (4)  DEADLINE_EXCEEDED
5xx Other 5xx                       | (13) INTERNAL
All others (includes 100s)          | (2)  UNKNOWN


### RPC → HTTP

RPC                       | HTTP
------------------------- | --------------------------
(0)  OK                   | 200 OK
(1)  CANCELLED            | 499 Client closed request
(2)  UNKNOWN              | 500 Internal server error
(3)  INVALID_ARGUMENT     | 400 Bad request
(4)  DEADLINE_EXCEEDED    | 504 Gateway Time-out
(5)  NOT_FOUND            | 404 Not found
(6)  ALREADY_EXISTS       | 409 Conflict
(7)  PERMISSION_DENIED    | 403 Forbidden
(8)  RESOURCE_EXHAUSTED   | 429 Too many requests
(9)  FAILED_PRECONDITION  | 400 Bad request
(10) ABORTED              | 409 Conflict
(11) OUT_OF_RANGE         | 400 Bad request
(12) UNIMPLEMENTED        | 501 Not implemented
(13) INTERNAL             | 500 Internal server error
(14) UNAVAILABLE          | 503 Service unavailable
(15) DATA_LOSS            | 500 Internal server error
(16) UNAUTHENTICATED      | 401 Unauthorized

### References

* https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto
* http://en.wikipedia.org/wiki/List_of_HTTP_status_codes
* http://www.ietf.org/rfc/rfc2616.txt
* http://www.ietf.org/rfc/rfc6585.txt
