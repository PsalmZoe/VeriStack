;; Decentralized Identity Verification Contract
;; Version: 1.1.0
;; Author: Stacks Blockchain Developer
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-ALREADY-REGISTERED (err u101))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-PROOF (err u103))
(define-constant ERR-PERMISSION-DENIED (err u104))
(define-constant ERR-CLAIM-EXISTS (err u105))
(define-constant ERR-CLAIM-NOT-FOUND (err u106))
(define-constant ERR-INVALID-ZKP (err u107))
(define-constant ERR-INVALID-INPUT (err u108))
(define-constant ERR-INVALID-DURATION (err u109))
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
;; Storage for ZKP claims
(define-map zkp-claims
  {
    did: principal,
    claim-type: (string-ascii 50)
  }
  {
    claim-hash: (buff 32),
    verifier: principal,
    timestamp: uint,
    expiration: uint
  }
)
;; Logging methods in Clarity
;; Instead of events, we'll use print and create structured logs
;; Define constants for log types
(define-constant LOG-REGISTER u1)
(define-constant LOG-VERIFY u2)
(define-constant LOG-SERVICE-UPDATE u3)
(define-constant LOG-ZKP-CLAIM u4)
(define-constant LOG-ZKP-VERIFY u5)
;; Input validation function for name
(define-private (validate-name (name (string-ascii 100)))
  (>= (len name) u1)
)
;; Input validation function for email
(define-private (validate-email (email (string-ascii 100)))
  (and
    (>= (len email) u3)
    (is-some (index-of email "@"))
  )
)
;; Input validation function for claim type
(define-private (validate-claim-type (claim-type (string-ascii 50)))
  (>= (len claim-type) u1)
)
;; Input validation function for duration
(define-private (validate-duration (duration uint))
  (> duration u0)
)
;; When registering an identity
(define-public (register-identity 
  (name (string-ascii 100))
  (email (string-ascii 100))
)
  (begin
    ;; Validate inputs
    (asserts! (validate-name name) ERR-INVALID-INPUT)
    (asserts! (validate-email email) ERR-INVALID-INPUT)
    
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
;; When verifying an identity - FIXED
(define-public (verify-identity 
  (did principal)
  (verification-proof (string-ascii 256))
)
  (begin
    ;; First validate authorization
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    
    ;; Validate inputs - ensure verification proof isn't empty
    (asserts! (>= (len verification-proof) u1) ERR-INVALID-PROOF)
    
    ;; Get identity safely
    (let 
      (
        (identity (unwrap! 
          (map-get? identity-registry { did: did }) 
          ERR-NOT-REGISTERED
        ))
      )
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
    
    ;; Validate inputs
    (asserts! (not (is-eq service did)) ERR-INVALID-INPUT)
    (asserts! (validate-duration duration) ERR-INVALID-DURATION)
    
    ;; Ensure service isn't the zero address
    (asserts! (not (is-eq service 'SP000000000000000000002Q6VF78)) ERR-INVALID-INPUT)
    
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
;; ZKP INTEGRATION - NEW FUNCTIONALITY
;; Register a zero-knowledge proof claim
(define-public (register-zkp-claim
  (claim-type (string-ascii 50))
  (claim-hash (buff 32))
  (expiration uint)
)
  (let (
    (did tx-sender)
    (identity (unwrap! (map-get? identity-registry { did: tx-sender }) ERR-NOT-REGISTERED))
  )
    ;; User must be registered
    (asserts! (is-some (map-get? identity-registry { did: tx-sender })) ERR-NOT-REGISTERED)
    
    ;; Validate inputs
    (asserts! (validate-claim-type claim-type) ERR-INVALID-INPUT)
    (asserts! (> (len claim-hash) u0) ERR-INVALID-INPUT)
    (asserts! (validate-duration expiration) ERR-INVALID-DURATION)
    
    ;; Register or update the claim
    (map-set zkp-claims
      { did: did, claim-type: claim-type }
      {
        claim-hash: claim-hash,
        verifier: tx-sender,
        timestamp: stacks-block-height,
        expiration: (+ stacks-block-height expiration)
      }
    )
    
    ;; Log the claim registration
    (print {
      log-type: LOG-ZKP-CLAIM,
      did: did,
      claim-type: claim-type,
      timestamp: stacks-block-height,
      expiration: (+ stacks-block-height expiration)
    })
    
    (ok true)
  )
)
;; Verify a zero-knowledge proof claim
(define-public (verify-zkp-claim
  (did principal)
  (claim-type (string-ascii 50))
  (proof-data (buff 128))
  (expected-result bool)
)
  (let (
    (claim (unwrap! (map-get? zkp-claims { did: did, claim-type: claim-type }) ERR-CLAIM-NOT-FOUND))
    (current-height stacks-block-height)
  )
    ;; Validate inputs
    (asserts! (validate-claim-type claim-type) ERR-INVALID-INPUT)
    (asserts! (> (len proof-data) u0) ERR-INVALID-PROOF)
    
    ;; Check if claim is expired
    (asserts! (< current-height (get expiration claim)) ERR-INVALID-ZKP)
    
    ;; Verify ZKP - this is a simplified implementation
    ;; In a real implementation, this would use Clarity's crypto functions to validate the ZKP
    ;; For now, we're simulating ZKP verification with a hash check
    (asserts! 
      (is-eq 
        (sha256 (concat proof-data (if expected-result 0x01 0x00)))
        (get claim-hash claim)
      ) 
      ERR-INVALID-ZKP
    )
    
    ;; Log the verification
    (print {
      log-type: LOG-ZKP-VERIFY,
      did: did,
      claim-type: claim-type,
      verifier: tx-sender,
      result: expected-result,
      timestamp: current-height
    })
    
    (ok expected-result)
  )
)
;; Get a ZKP claim
(define-read-only (get-zkp-claim
  (did principal)
  (claim-type (string-ascii 50))
)
  (map-get? zkp-claims { did: did, claim-type: claim-type })
)
;; Check if a ZKP claim exists and is valid
(define-read-only (is-zkp-claim-valid
  (did principal)
  (claim-type (string-ascii 50))
)
  (match 
    (map-get? zkp-claims { did: did, claim-type: claim-type })
    claim (< stacks-block-height (get expiration claim))
    false
  )
)
;; Verify a ZKP claim with selective disclosure - using a condition hash instead
(define-public (verify-zkp-selective-disclosure
  (did principal)
  (claim-type (string-ascii 50))
  (proof-data (buff 128))
  (condition-hash (buff 32))
)
  (let (
    (claim (unwrap! (map-get? zkp-claims { did: did, claim-type: claim-type }) ERR-CLAIM-NOT-FOUND))
    (current-height stacks-block-height)
  )
    ;; Validate inputs
    (asserts! (validate-claim-type claim-type) ERR-INVALID-INPUT)
    (asserts! (> (len proof-data) u0) ERR-INVALID-PROOF)
    (asserts! (> (len condition-hash) u0) ERR-INVALID-INPUT)
    
    ;; Check if claim is expired
    (asserts! (< current-height (get expiration claim)) ERR-INVALID-ZKP)
    
    ;; Verify ZKP with condition - simplified implementation
    ;; This approach uses a pre-computed condition hash instead of string conversion
    (asserts! 
      (is-eq 
        (sha256 (concat proof-data condition-hash))
        (get claim-hash claim)
      ) 
      ERR-INVALID-ZKP
    )
    
    ;; Log the selective disclosure verification
    (print {
      log-type: LOG-ZKP-VERIFY,
      did: did,
      claim-type: claim-type,
      verifier: tx-sender,
      timestamp: current-height
    })
    
    (ok true)
  )
)