(module sodium

;; exports
(sodium-init
 bin->hex
 generic-hash-bytes
 generic-hash-bytes-min
 generic-hash-bytes-max
 generic-hash-key-bytes
 generic-hash-key-bytes-min
 generic-hash-key-bytes-max
 generic-hash
 generic-hash-init
 generic-hash-update
 generic-hash-final
 sign-public-key-bytes
 sign-secret-key-bytes
 sign-keypair
 sign-ed25519-secret-key->public-key
 sign-bytes
 sign-detached
 sign-verify-detached
 scalarmult-curve25519-bytes
 sign-ed25519-public-key->curve25519
 sign-ed25519-secret-key->curve25519)

(import chicken scheme foreign)
(foreign-declare "#include <sodium.h>")

(use lolevel)


(define (expect-zero name output status)
  (if (= status 0)
      output
      (abort (sprintf "~A returned ~A" name status))))


(define sodium-init
  (foreign-lambda int "sodium_init"))


(define sodium_bin2hex
  (foreign-lambda c-string "sodium_bin2hex"
		  (c-pointer char)
		  (const size_t)
		  (const (c-pointer (const unsigned-char)))
		  (const size_t)))

(define (bin->hex bin)
  (if (= (string-length bin) 0)
    ""
    (let ((tmp (make-string (+ (* 2 (string-length bin)) 1))))
      (sodium_bin2hex (location tmp)
                      (string-length tmp)
                      (location bin)
                      (string-length bin)))))


(define crypto_generichash
  (foreign-lambda int "crypto_generichash"
		  (c-pointer unsigned-char)
		  size_t
		  (c-pointer (const unsigned-char))
		  unsigned-integer64
		  (c-pointer (const unsigned-char))
		  size_t))

(define generic-hash-bytes
  (foreign-value "crypto_generichash_BYTES" int))

(define generic-hash-bytes-min
  (foreign-value "crypto_generichash_BYTES_MIN" int))

(define generic-hash-bytes-max
  (foreign-value "crypto_generichash_BYTES_MAX" int))

(define generic-hash-key-bytes
  (foreign-value "crypto_generichash_KEYBYTES" int))

(define generic-hash-key-bytes-min
  (foreign-value "crypto_generichash_KEYBYTES_MIN" int))

(define generic-hash-key-bytes-max
  (foreign-value "crypto_generichash_KEYBYTES_MAX" int))

(define (generic-hash data #!optional (bytes generic-hash-bytes))
  (assert (>= bytes generic-hash-bytes-min))
  (assert (<= bytes generic-hash-bytes-max))
  (let* ((hash (make-string bytes))
	 (status (crypto_generichash (location hash) bytes
				     (and (> (string-length data) 0)
                  (location data))
             (string-length data)
				     #f 0)))
    (if (not (= status 0))
	(abort (sprintf "crypto_generichash returned ~A" status))
	hash)))

(define crypto_generichash_init
  (foreign-lambda int "crypto_generichash_init"
    c-pointer
    (c-pointer unsigned-char)
    size_t
    size_t))

(define crypto_generichash_update
  (foreign-lambda int "crypto_generichash_update"
    c-pointer
    (c-pointer unsigned-char)
    size_t))

(define crypto_generichash_final
  (foreign-lambda int "crypto_generichash_final"
    c-pointer
    (c-pointer unsigned-char)
    size_t))

;; TODO: note in docs this uses malloc and not sodium_malloc!
;; NOTE: crypto_generichash_statebytes() added in libsodium 1.0.3 and
;;       Debian Jessie ships with 1.0.0
(define (make-crypto_generichash_state)
  ((foreign-lambda* c-pointer ()
     "crypto_generichash_state *state = malloc(
          #ifdef crypto_generichash_statebytes
            crypto_generichash_statebytes()
          #else
            sizeof(crypto_generichash_state)
          #endif
      );
      C_return(state);")))

(define-record generic-hash-state
               pointer
               bytes
               done)

(define (generic-hash-init #!optional (bytes generic-hash-bytes))
  (assert (>= bytes generic-hash-bytes-min))
  (assert (<= bytes generic-hash-bytes-max))
  (let* ((s (make-crypto_generichash_state))
         (status (crypto_generichash_init s #f 0 bytes)))
    (if (not (= status 0))
      (abort (sprintf "crypto_generichash_init returned ~A" status))
      (make-generic-hash-state s bytes #f))))

(define (generic-hash-update state data)
  (assert (not (generic-hash-state-done state)))
  (let ((status (crypto_generichash_update (generic-hash-state-pointer state)
                                           (and (> (string-length data) 0)
                                                (location data))
                                           (string-length data))))
    (if (not (= status 0))
      (abort (sprintf "crypto_generichash_update returned ~A" status))
      status)))


(define (generic-hash-final state)
  (assert (not (generic-hash-state-done state)))
  (let* ((hash (make-string (generic-hash-state-bytes state)))
         (status (crypto_generichash_final (generic-hash-state-pointer state)
                                           (location hash)
                                           (string-length hash))))
    (generic-hash-state-done-set! state #t)
    (if (not (= status 0))
      (abort (sprintf "crypto_generichash_final returned ~A" status))
      hash)))

(define sign-public-key-bytes
  (foreign-value "crypto_sign_PUBLICKEYBYTES" int))

(define sign-secret-key-bytes
  (foreign-value "crypto_sign_SECRETKEYBYTES" int))

(define crypto_sign_keypair
  (foreign-lambda int "crypto_sign_keypair"
		  (c-pointer unsigned-char)
		  (c-pointer unsigned-char)))

(define (sign-keypair)
  (let* ((public-key (make-string sign-public-key-bytes))
	 (secret-key (make-string sign-secret-key-bytes))
	 (status (crypto_sign_keypair (location public-key) (location secret-key))))
    (if (not (= status 0))
	(abort (sprintf "crypto_sign_keypair returned ~A" status))
	(values public-key secret-key))))


(define crypto_sign_ed25519_sk_to_pk
  (foreign-lambda int "crypto_sign_ed25519_sk_to_pk"
		  (c-pointer unsigned-char)
		  (c-pointer (const unsigned-char))))

(define (sign-ed25519-secret-key->public-key secret-key)
  (let* ((public-key (make-string sign-public-key-bytes))
	 (status (crypto_sign_ed25519_sk_to_pk (location public-key)
					       (location secret-key))))
    (if (not (= status 0))
	(abort (sprintf "crypto_sign_ed25519_sk_to_pk returned ~A" status))
	public-key)))


(define crypto_sign_detached*
  (foreign-lambda* int
    (((c-pointer unsigned-char) sig)
     ((c-pointer unsigned-integer64) siglen)
     ((c-pointer (const unsigned-char)) m)
     (unsigned-integer64 mlen)
     ((c-pointer (const unsigned-char)) sk))
    ;; CHICKEN does not have a foreign type for unsigned long long,
    ;; and type checks are more strict for pointers, so I manually cast
    ;; to unsigned-integer64 in C
    "unsigned long long siglen2;
     int r = crypto_sign_detached(sig, &siglen2, m, mlen, sk);
     *siglen = (uint64_t)siglen2;
     C_return(r);"))

(define sign-bytes
  (foreign-value "crypto_sign_BYTES" int))

(define (sign-detached data secret-key)
  (let-location ((siglen unsigned-integer64))
    (let* ((sig (make-string sign-bytes))
	   (status (crypto_sign_detached*
		    (location sig)
		    (location siglen)
		    (location data)
		    (string-length data)
		    (location secret-key))))
      (if (not (= status 0))
	  (abort (sprintf "crypto_sign_detached returned ~A" status))
	  sig))))


(define crypto_sign_verify_detached
  (foreign-lambda int "crypto_sign_verify_detached"
		  (const (c-pointer unsigned-char))
		  (const (c-pointer unsigned-char))
		  unsigned-integer64
		  (const (c-pointer unsigned-char))))

(define (sign-verify-detached signature data public-key)
  (= 0 (crypto_sign_verify_detached
	(location signature)
	(location data)
	(string-length data)
	(location public-key))))


(define scalarmult-curve25519-bytes
  (foreign-value "crypto_scalarmult_curve25519_BYTES" int))

(define crypto_sign_ed25519_pk_to_curve25519
  (foreign-lambda int "crypto_sign_ed25519_pk_to_curve25519"
		  (c-pointer unsigned-char)
		  (c-pointer (const unsigned-char))))

(define (sign-ed25519-public-key->curve25519 ed25519-public-key)
  (let* ((curve25519-public-key (make-string scalarmult-curve25519-bytes))
	 (status (crypto_sign_ed25519_pk_to_curve25519
		  (location curve25519-public-key)
		  (location ed25519-public-key))))
    (if (not (= status 0))
	(abort (sprintf "crypto_sign_ed25519_pk_to_curve25519 returned ~A" status))
	curve25519-public-key)))

(define crypto_sign_ed25519_sk_to_curve25519
  (foreign-lambda int "crypto_sign_ed25519_sk_to_curve25519"
		  (c-pointer unsigned-char)
		  (c-pointer (const unsigned-char))))

(define (sign-ed25519-secret-key->curve25519 ed25519-secret-key)
  (let* ((curve25519-secret-key (make-string scalarmult-curve25519-bytes))
	 (status (crypto_sign_ed25519_sk_to_curve25519
		  (location curve25519-secret-key)
		  (location ed25519-secret-key))))
    (if (not (= status 0))
	(abort (sprintf "crypto_sign_ed25519_sk_to_curve25519 returned ~A" status))
	curve25519-secret-key)))

)
