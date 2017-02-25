(use sodium test)

(test-group "helpers"
  (test-assert "constant-time-blob=? equal blobs"
    (constant-time-blob=? #${12} #${12} (blob-size #${12})))
  (test-assert "constant-time-blob=? equal prefix"
    (constant-time-blob=? #${12} #${1234} (blob-size #${12})))
  (test-assert "constant-time-blob=? not equal"
    (not (constant-time-blob=? #${12} #${34} (blob-size #${12}))))
  (test "123abc" (bin->hex #${123abc}))
  (test "" (bin->hex #${}))
  (test #${123abc} (hex->bin "123abc"))
  (test #${} (hex->bin "")))

(test-group "generic-hash"
  (test #${b8fe9f7f6255a6fa08f668ab632a8d081ad87983c77cd274e48ce450f0b349fd}
	(generic-hash (string->blob "foo")))
  (test #${0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8}
	(generic-hash (string->blob "")))
  (test #${983ceba2afea8694cc933336b27b907f90c53a88}
	(generic-hash (string->blob "foo") size: 20))
  (test #${4f6053ca7440e1719e5f2ef651323d3923cf598b09170d10d645ab56ecec0d82}
	(generic-hash (string->blob "foo") key: (string->blob "bar")))
  (test #${0483b83116f4251fe36b0819deef370acd2b94c0}
	(generic-hash (string->blob "foo") size: 20 key: (string->blob "bar")))
  (let ((hash (generic-hash-init)))
    (generic-hash-update hash (string->blob "foo"))
    (generic-hash-update hash (string->blob "bar"))
    (test #${93a0e84a8cdd4166267dbe1263e937f08087723ac24e7dcc35b3d5941775ef47}
	  (generic-hash-final hash)))
  (let ((hash (generic-hash-init)))
    (test #${0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8}
	  (generic-hash-final hash)))
  (let ((hash (generic-hash-init size: 20)))
    (generic-hash-update hash (string->blob "foo"))
    (test #${983ceba2afea8694cc933336b27b907f90c53a88}
	  (generic-hash-final hash)))
  (let ((hash (generic-hash-init key: (string->blob "bar"))))
    (generic-hash-update hash (string->blob "foo"))
    (test #${4f6053ca7440e1719e5f2ef651323d3923cf598b09170d10d645ab56ecec0d82}
	  (generic-hash-final hash)))
  (let ((hash (generic-hash-init size: 20 key: (string->blob "bar"))))
    (generic-hash-update hash (string->blob "foo"))
    (test #${0483b83116f4251fe36b0819deef370acd2b94c0}
	  (generic-hash-final hash))))

(test-group "sign-ed25519"
  (receive (public-key secret-key) (sign-keypair)
    (test public-key
	  (sign-ed25519-secret-key->public-key secret-key))
    (let* ((data (string->blob "data"))
	   (sig (sign-detached data secret-key)))
      (test-assert (blob? sig))
      (test-assert (sign-verify-detached sig data public-key))
      (test-assert (not (sign-verify-detached
			 (string->blob "fake")
			 data
			 public-key))))))

(test-exit)
