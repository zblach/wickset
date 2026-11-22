// chainlock's entry points into hashcat's Argon2 (hashcat/inc_hash_argon2.cl):
// many independent evaluations of one parameter set, one instance each, with
// one lane (p = 1). The Argon2 itself is hashcat's, unmodified; this file only
// says which instance a thread works on. It is written in hashcat's portable
// macros (KERNEL_FQ, GLOBAL_AS, ...), so it builds wherever hashcat's kernels
// do.
//
//   chainlock_argon2_init   one thread per instance: H0 and the first two blocks
//   chainlock_argon2_fill   one group of 32 threads per instance: one segment
//                           (pass, slice) of the memory fill
//   chainlock_argon2_final  one thread per instance: the output tag

#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_hash_blake2b.cl"
#include "inc_hash_argon2.cl"

// chainlock_job is the parameter set and the batch, the same for every kernel.
typedef struct chainlock_job
{
  argon2_options_t options;

  u32 count;     // instances in the batch
  u32 input_len; // bytes per input, a multiple of 4, at most 256
  u32 salt_len;  // bytes, at most 256
  u32 salt[64];

} chainlock_job_t;

// chainlock_pos is the segment a fill dispatch computes.
typedef struct chainlock_pos
{
  u32 pass;
  u32 slice;

} chainlock_pos_t;

#if defined IS_METAL
#define CHAINLOCK_THREAD_PARAMS , KERN_ATTR_MAIN_PARAMS
#else
#define CHAINLOCK_THREAD_PARAMS
#endif

KERNEL_FQ void chainlock_argon2_init (GLOBAL_AS const chainlock_job_t *job, GLOBAL_AS const u32 *inputs, GLOBAL_AS argon2_block_t *blocks CHAINLOCK_THREAD_PARAMS)
{
  const u64 gid = get_global_id (0);

  if (gid >= job->count) return;

  const argon2_options_t options = job->options;

  const u32 input_words = job->input_len / 4;

  u32 input[64] = { 0 };
  u32 salt[64]  = { 0 };

  for (u32 i = 0; i < input_words; i++) input[i] = inputs[(gid * input_words) + i];

  for (u32 i = 0; i < (job->salt_len + 3) / 4; i++) salt[i] = job->salt[i];

  argon2_init_main (input, job->input_len, salt, job->salt_len, &options, blocks + (gid * options.memory_block_count));
}

KERNEL_FQ void chainlock_argon2_fill (GLOBAL_AS const chainlock_job_t *job, CONSTANT_AS const chainlock_pos_t *at, GLOBAL_AS argon2_block_t *blocks CHAINLOCK_THREAD_PARAMS)
{
  const u64 bid = get_group_id (0);

  // the whole group returns together, so no shuffle is left waiting
  if (bid >= job->count) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz    = get_local_size (0);

  LOCAL_VK u64 shuffle_buf[32];

  argon2_options_t options = job->options;

  argon2_pos_t pos;

  pos.pass  = at->pass;
  pos.slice = at->slice;
  pos.lane  = 0;

  argon2_fill_segment (blocks + (bid * options.memory_block_count), &options, &pos, shuffle_buf, argon2_thread, argon2_lsz);
}

KERNEL_FQ void chainlock_argon2_final (GLOBAL_AS const chainlock_job_t *job, GLOBAL_AS argon2_block_t *blocks, GLOBAL_AS u32 *outputs CHAINLOCK_THREAD_PARAMS)
{
  const u64 gid = get_global_id (0);

  if (gid >= job->count) return;

  const argon2_options_t options = job->options;

  const u32 digest_words = options.digest_len / 4;

  u32 out[16] = { 0 };

  argon2_final (blocks + (gid * options.memory_block_count), &options, out);

  for (u32 i = 0; i < digest_words; i++) outputs[(gid * digest_words) + i] = out[i];
}
