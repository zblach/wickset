// The Metal host for kernel.cl, called from metal_darwin.go. Every function
// that can fail returns NULL or -1 and sets *err to a malloc'd message.

#include <stddef.h>
#include <stdint.h>

typedef struct clm clm;
typedef struct clm_job clm_job;

// clm_open compiles source with the given macros ("NAME=VALUE" lines) on the
// default device, and makes the three pipelines.
clm *clm_open(const char *source, const char *macros, char **err);
void clm_close(clm *c);

// The device's largest buffer, and the working set it recommends.
uint64_t clm_max_buffer(clm *c);
uint64_t clm_working_set(clm *c);

// clm_begin allocates a batch of count instances and runs the init kernel.
clm_job *clm_begin(clm *c, const void *job, size_t job_len, const void *inputs, size_t inputs_len,
                   uint32_t count, uint64_t instance_bytes, size_t out_len, char **err);

// clm_segment runs one segment (pass, slice) of the fill for every instance.
int clm_segment(clm *c, clm_job *j, uint32_t pass, uint32_t slice, char **err);

// clm_end runs the final kernel and copies out_len bytes of outputs to out.
int clm_end(clm *c, clm_job *j, void *out, char **err);

void clm_free(clm_job *j);
