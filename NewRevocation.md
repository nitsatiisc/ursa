### New Revocation Scheme


## Benchmarks
### Issuer Operations 
#### Registry Definition ( `max_cred_num=100,000`):
This is a one type operation performed by the issuer when initializing a 
new revocation registry. Here we consider the maximum number of 
credentials in the registry `max_cred_num` as 100000.

| Revocation Type | Repetitions | Time (s) |
|-----------------|-------------|----------|
| CKS             | 1           | 126.2    |
| VA              | 1           | 52.7     |

#### Issue Credential with Revoc (`max_cred_num=100,000`):
This operation is performed by the issuer, every time a 
new credential is issued.

| Revocation Type | Repetitions | Time (s) |
|-----------------|-------------|----------|
| CKS             | 1000        | 113.4    |
| VA              | 1000        | 131.5    |

#### Computing Registry Delta (`batch_size=100`):
This operation is performed by the issuer, whenever the state 
of the registry changes, i.e, credentials are issued or revoked.
In the CKS scheme, the state of registry changes both on issue and revocations
if `issuance_by_default` is set to `false`. Otherwise, the state 
only changes when credentials are revoked. This is the setting
for CKS scheme we consider in the benchmarks. For the VB accumulaor 
based revocation, the state of the registry only changes when 
credentials are revoked. The time(s) below indicate how long it 
takes for the issuer to compute "revocation update" for both schemes,
when the update size is 100.

| Revocation Type | Repetitions | Time (ms) |
|-----------------|-------------|-----------|
| CKS             | 10          | 2.3       |
| VA              | 10          | 245       |

### Prover Operations

#### Process Credential Signature:
This operation is performed by the prover whenever it 
receives a signature from the issuer. In the CKS scheme
it needs to update it's witness to the current registry 
state, as that is not done by the issuer. In case of VB
based scheme, there is only a minor adjustment to primary signature,
as is the case in CKS scheme too.

| Revocation Type | Repetitions | Time (s) |
|-----------------|-------------|----------|
| CKS             | 100         | 24.7     |
| VA              | 100         | 0.0      |

#### Update Witness (batch_size=100):
This operation is performed by the prover, every time it 
needs to update its witness to be consistent with the latest 
registry state. It does it by applying the `deltas` published by
the issuer. It must be performed before generating a presentation against 
latest registry state.

| Revocation Type | Repetitions | Time (ms) |
|-----------------|-------------|-----------|
| CKS             | 1000        | 2.5       |
| VA              | 100         | 92.1      |

#### Generate Proofs:
This operation is performed by the prover whenever it wants 
to generate a presentation attesting to some verification predicate.


| Revocation Type | Repetitions | Time (s) |
|-----------------|-------------|----------|
| CKS             | 100         | 5.3      |
| VA              | 100         | 3.74     |

### Verifier Operations

#### Verify Presentation:
This operation is performed by the verifier to check prover's
presentation satisfies the verification predicate.

| Revocation Type | Repetitions | Time (s) |
|-----------------|-------------|----------|
| CKS             | 100         | 4.86     |
| VA              | 100         | 2.31     |
