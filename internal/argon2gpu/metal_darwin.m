// The Metal host for kernel.cl (see metal_darwin.h). Built without ARC: every
// object made here with new or alloc is released here.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdlib.h>
#include <string.h>
#include "metal_darwin.h"

struct clm {
  id<MTLDevice> dev;
  id<MTLCommandQueue> queue;
  id<MTLComputePipelineState> init, fill, final;
};

struct clm_job {
  id<MTLBuffer> job, inputs, blocks, outputs;
  uint32_t count;
  size_t out_len;
};

static char *message(NSString *s) {
  const char *u = s.UTF8String;
  return strdup(u != NULL ? u : "unknown Metal error");
}

static char *failure(NSString *what, NSError *e) {
  return message(e != nil ? [NSString stringWithFormat:@"%@: %@", what, e.localizedDescription] : what);
}

static id<MTLComputePipelineState> pipeline(id<MTLDevice> dev, id<MTLLibrary> lib, NSString *name, char **err) {
  id<MTLFunction> f = [lib newFunctionWithName:name];
  if (f == nil) {
    *err = message([NSString stringWithFormat:@"no kernel %@", name]);
    return nil;
  }
  NSError *e = nil;
  id<MTLComputePipelineState> p = [dev newComputePipelineStateWithFunction:f error:&e];
  [f release];
  if (p == nil) *err = failure([NSString stringWithFormat:@"pipeline %@", name], e);
  return p;
}

void clm_close(clm *c) {
  if (c == NULL) return;
  [c->init release];
  [c->fill release];
  [c->final release];
  [c->queue release];
  [c->dev release];
  free(c);
}

clm *clm_open(const char *source, const char *macros, char **err) {
  @autoreleasepool {
    clm *c = calloc(1, sizeof *c);
    c->dev = MTLCreateSystemDefaultDevice();
    if (c->dev == nil) {
      *err = message(@"no Metal device");
      clm_close(c);
      return NULL;
    }
    NSMutableDictionary *defs = [NSMutableDictionary dictionary];
    for (NSString *line in [[NSString stringWithUTF8String:macros] componentsSeparatedByString:@"\n"]) {
      NSRange eq = [line rangeOfString:@"="];
      if (eq.location == NSNotFound) continue;
      defs[[line substringToIndex:eq.location]] = [line substringFromIndex:eq.location + 1];
    }
    MTLCompileOptions *opts = [MTLCompileOptions new];
    opts.preprocessorMacros = defs;
    // As hashcat does: the default level runs Apple's compiler out of room on
    // large kernels.
    if (@available(macOS 13.0, *)) opts.optimizationLevel = MTLLibraryOptimizationLevelSize;
    // hashcat's kernels are written to Metal 3, where an unqualified array
    // parameter is in thread memory. The default, the newest language
    // version, puts it in a generic address space they do not compile in.
    if (@available(macOS 15.0, *)) opts.languageVersion = MTLLanguageVersion3_2;
    NSError *e = nil;
    id<MTLLibrary> lib = [c->dev newLibraryWithSource:[NSString stringWithUTF8String:source] options:opts error:&e];
    [opts release];
    if (lib == nil) {
      *err = failure(@"compiling the kernel", e);
      clm_close(c);
      return NULL;
    }
    c->init = pipeline(c->dev, lib, @"chainlock_argon2_init", err);
    if (c->init != nil) c->fill = pipeline(c->dev, lib, @"chainlock_argon2_fill", err);
    if (c->fill != nil) c->final = pipeline(c->dev, lib, @"chainlock_argon2_final", err);
    [lib release];
    if (c->final == nil) {
      clm_close(c);
      return NULL;
    }
    // hashcat's fill exchanges words across a SIMD group of exactly 32
    // threads (simd_shuffle); any other width computes wrong blocks.
    if (c->fill.threadExecutionWidth != 32 || c->fill.maxTotalThreadsPerThreadgroup < 32) {
      *err = message([NSString stringWithFormat:@"SIMD width %lu, not 32", (unsigned long)c->fill.threadExecutionWidth]);
      clm_close(c);
      return NULL;
    }
    c->queue = [c->dev newCommandQueue];
    return c;
  }
}

uint64_t clm_max_buffer(clm *c) { return c->dev.maxBufferLength; }
uint64_t clm_working_set(clm *c) { return c->dev.recommendedMaxWorkingSetSize; }

// run encodes one dispatch of p over the buffers, commits it and waits.
// groups > 0 dispatches that many groups of 32 threads; otherwise threads
// threads in groups as large as p allows.
static int run(clm *c, id<MTLComputePipelineState> p, NSArray<id<MTLBuffer>> *bufs, const void *bytes, size_t bytes_len,
               NSUInteger bytes_index, NSUInteger threads, NSUInteger groups, char **err) {
  id<MTLCommandBuffer> cb = [c->queue commandBuffer];
  id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
  [enc setComputePipelineState:p];
  NSUInteger i = 0;
  for (id<MTLBuffer> b in bufs) {
    if (i == bytes_index && bytes != NULL) i++;
    [enc setBuffer:b offset:0 atIndex:i++];
  }
  if (bytes != NULL) [enc setBytes:bytes length:bytes_len atIndex:bytes_index];
  if (groups > 0) {
    [enc dispatchThreadgroups:MTLSizeMake(groups, 1, 1) threadsPerThreadgroup:MTLSizeMake(32, 1, 1)];
  } else {
    NSUInteger w = MIN(threads, p.maxTotalThreadsPerThreadgroup);
    [enc dispatchThreads:MTLSizeMake(threads, 1, 1) threadsPerThreadgroup:MTLSizeMake(w, 1, 1)];
  }
  [enc endEncoding];
  [cb commit];
  [cb waitUntilCompleted];
  if (cb.status != MTLCommandBufferStatusCompleted) {
    *err = failure(@"GPU command failed", cb.error);
    return -1;
  }
  return 0;
}

void clm_free(clm_job *j) {
  if (j == NULL) return;
  [j->job release];
  [j->inputs release];
  [j->blocks release];
  [j->outputs release];
  free(j);
}

clm_job *clm_begin(clm *c, const void *job, size_t job_len, const void *inputs, size_t inputs_len,
                   uint32_t count, uint64_t instance_bytes, size_t out_len, char **err) {
  @autoreleasepool {
    uint64_t blocks = instance_bytes * count;
    if (blocks > c->dev.maxBufferLength) {
      *err = message([NSString stringWithFormat:@"%u instances need %llu bytes, over the device's %lu in one buffer",
                      count, blocks, (unsigned long)c->dev.maxBufferLength]);
      return NULL;
    }
    clm_job *j = calloc(1, sizeof *j);
    j->count = count;
    j->out_len = out_len;
    j->job = [c->dev newBufferWithBytes:job length:job_len options:MTLResourceStorageModeShared];
    j->inputs = [c->dev newBufferWithBytes:inputs length:inputs_len options:MTLResourceStorageModeShared];
    // The blocks never leave the GPU: private storage, which hashcat found
    // many times faster than shared.
    j->blocks = [c->dev newBufferWithLength:blocks options:MTLResourceStorageModePrivate];
    j->outputs = [c->dev newBufferWithLength:out_len options:MTLResourceStorageModeShared];
    if (j->job == nil || j->inputs == nil || j->blocks == nil || j->outputs == nil) {
      *err = message([NSString stringWithFormat:@"could not allocate %llu bytes on the GPU", blocks]);
      clm_free(j);
      return NULL;
    }
    if (run(c, c->init, @[ j->job, j->inputs, j->blocks ], NULL, 0, 0, count, 0, err) != 0) {
      clm_free(j);
      return NULL;
    }
    return j;
  }
}

int clm_segment(clm *c, clm_job *j, uint32_t pass, uint32_t slice, char **err) {
  @autoreleasepool {
    uint32_t pos[2] = {pass, slice};
    // job is buffer 0, pos 1, blocks 2
    return run(c, c->fill, @[ j->job, j->blocks ], pos, sizeof pos, 1, 0, j->count, err);
  }
}

int clm_end(clm *c, clm_job *j, void *out, char **err) {
  @autoreleasepool {
    if (run(c, c->final, @[ j->job, j->blocks, j->outputs ], NULL, 0, 0, j->count, 0, err) != 0) return -1;
    memcpy(out, j->outputs.contents, j->out_len);
    return 0;
  }
}
