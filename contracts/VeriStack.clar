;; Decentralized Identity Verification Contract
;; Version: 1.0.0
;; Author: Stacks Blockchain Developer

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-ALREADY-REGISTERED (err u101))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-PROOF (err u103))
(define-constant ERR-PERMISSION-DENIED (err u104))

;; Storage for identity records
(define-map identity-registry 
  { did: principal }
  {
    name: (string-ascii 100),
    email: (string-ascii 100),
    verification-status: bool,
    verification-timestamp: uint,
    authorized-services: (list 10 principal)
  }
)

;; Storage for service access permissions
(define-map service-access
  { 
    did: principal, 
    service: principal 
  }
  {
    access-granted: bool,
    expiration: uint
  }
)

;; Logging methods in Clarity
;; Instead of events, we'll use print and create structured logs

;; Define constants for log types
(define-constant LOG-REGISTER u1)
(define-constant LOG-VERIFY u2)
(define-constant LOG-SERVICE-UPDATE u3)

;; When registering an identity
(define-public (register-identity 
  (name (string-ascii 100))
  (email (string-ascii 100))
)
  (begin
    ;; Prevent duplicate registrations
    (asserts! (is-none (map-get? identity-registry { did: tx-sender })) 
      ERR-ALREADY-REGISTERED)
    
    ;; Create identity record
    (map-set identity-registry 
      { did: tx-sender }
      {
        name: name,
        email: email,
        verification-status: false,
        verification-timestamp: stacks-block-height,
        authorized-services: (list)
      }
    )
    
    ;; Log the registration with a structured print
    (print {
      log-type: LOG-REGISTER,
      did: tx-sender,
      name: name,
      timestamp: stacks-block-height
    })
    
    (ok true)
  )
)




;; When verifying an identity
(define-public (verify-identity 
  (did principal)
  (verification-proof (string-ascii 256))
)
  (let 
    (
      (identity (unwrap! 
        (map-get? identity-registry { did: did }) 
        ERR-NOT-REGISTERED
      ))
    )
    ;; Add complex verification logic here
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    
    ;; Update verification status
    (map-set identity-registry 
      { did: did }
      (merge identity {
        verification-status: true,
        verification-timestamp: stacks-block-height
      })
    )
    
    ;; Log the verification with a structured print
    (print {
      log-type: LOG-VERIFY,
      did: did,
      verifier: tx-sender,
      timestamp: stacks-block-height
    })
    
    (ok true)
  )
)



;; When updating service permissions
(define-public (grant-service-access 
  (did principal)
  (service principal)
  (duration uint)
)
  (let 
    (
      (identity (unwrap! 
        (map-get? identity-registry { did: did }) 
        ERR-NOT-REGISTERED
      ))
    )
    ;; Existing access control logic
    (asserts! 
      (or 
        (is-eq tx-sender did)
        (is-eq tx-sender CONTRACT-OWNER)
      ) 
      ERR-UNAUTHORIZED
    )
    
    ;; Create or update service access
    (map-set service-access 
      { did: did, service: service }
      {
        access-granted: true,
        expiration: (+ stacks-block-height duration)
      }
    )
    
    ;; Log the service permission update
    (print {
      log-type: LOG-SERVICE-UPDATE,
      did: did,
      service: service,
      duration: duration,
      timestamp: stacks-block-height
    })
    
    (ok true)
  )
)

;; Check if a service has access to an identity
(define-read-only (check-service-access 
  (did principal)
  (service principal)
)
  (match 
    (map-get? service-access { did: did, service: service })
    access 
      (and 
        (get access-granted access)
        (< stacks-block-height (get expiration access))
      )
    false
  )
)

;; Additional helper read-only functions
(define-read-only (get-identity-details (did principal))
  (map-get? identity-registry { did: did })
)

(define-read-only (is-identity-verified (did principal))
  (match 
    (map-get? identity-registry { did: did })
    identity (get verification-status identity)
    false
  )
)