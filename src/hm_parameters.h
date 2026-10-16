#pragma once

/* Binding security parameter shared by plain and ZK commitments.
 * SHA-256 provides half this many bits of collision resistance. */
#define HM_BINDING_SECURITY_BITS 256u
