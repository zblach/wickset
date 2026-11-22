// wickset's iterated SHA-256 on hashcat's (hashcat/inc_hash_sha256.cl):
// many independent steps, one thread each. A step's state is a 32-byte
// digest as 8 big-endian words; each iteration replaces it with SHA-256 of
// itself, one padded block. A dispatch runs job->iters iterations, so the host
// can report progress and stop between dispatches.

#include "inc_hash_sha256.cl"

typedef struct wickset_sha_job
{
  u32 count; // steps in the batch
  u32 iters; // iterations this dispatch

} wickset_sha_job_t;

KERNEL_FQ void wickset_sha256_iter (CONSTANT_AS const wickset_sha_job_t *job, GLOBAL_AS u32 *state WICKSET_THREAD_PARAMS)
{
  const u64 gid = get_global_id (0);

  if (gid >= job->count) return;

  u32 d[8];

  for (int i = 0; i < 8; i++) d[i] = state[(gid * 8) + i];

  for (u32 n = job->iters; n > 0; n--)
  {
    u32 w0[4] = { d[0], d[1], d[2], d[3] };
    u32 w1[4] = { d[4], d[5], d[6], d[7] };
    u32 w2[4] = { 0x80000000, 0, 0, 0 };
    u32 w3[4] = { 0, 0, 0, 256 };

    d[0] = SHA256M_A;
    d[1] = SHA256M_B;
    d[2] = SHA256M_C;
    d[3] = SHA256M_D;
    d[4] = SHA256M_E;
    d[5] = SHA256M_F;
    d[6] = SHA256M_G;
    d[7] = SHA256M_H;

    sha256_transform (w0, w1, w2, w3, d);
  }

  for (int i = 0; i < 8; i++) state[(gid * 8) + i] = d[i];
}
