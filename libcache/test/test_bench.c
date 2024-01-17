#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "libcpu.h"

int main(int argc, char *argv[])
{
  int i, j;
  uint64_t time1, time2, t1, t2;
  void *buf[9];
  for (i = 0; i < 9; ++i)
  {
    buf[i] = calloc(getpagesize(), sizeof(uint8_t));
  }

  fprintf(stdout, "[+] Warming up...\n");
  cpu_warm_up(1000000);

  fprintf(stdout, "[+] Testing flush and rdtsc...\n");
  j = 0;
  for (i = 0; i < 1000000; ++i)
  {
    cpu_clflush(buf[0]);
    t1 = cpu_mfence_rdtsc();
    cpu_maccess((uintptr_t) buf[0]);
    t2 = cpu_mfence_rdtsc();
    time1 = t2 - t1;
    t1 = cpu_mfence_rdtsc();
    cpu_maccess((uintptr_t) buf[0]);
    t2 = cpu_mfence_rdtsc();
    time2 = t2 - t1;
    if (time2 >= time1)
    {
      ++j;
    }
  }
  fprintf(stdout, "\tTests failed: %f%%\n", (double)j * 100 / 1000000);
  j = 0;
  for (i = 0; i < 1000000; ++i)
  {
    cpu_clflush(buf[0]);
    time1 = cpu_maccess_time((uintptr_t) buf[0]);
    time2 = cpu_maccess_time((uintptr_t) buf[0]);
    if (time2 >= time1)
    {
      ++j;
    }
  }
  fprintf(stdout, "\tTests failed: %f%%\n", (double)j * 100 / 1000000);

  fprintf(stdout, "[+] Testing prime and probe functions...\n");
#define L1_WAYS 8
#define L1_SETS_LOG 6
#define L1_SETS (1 << L1_SETS_LOG)
  void *ptr, *nxt;
  for (i = 1; i < L1_WAYS; ++i)
  {
    *(void **)buf[i - 1] = buf[i];
    fprintf(stdout, "\t%p -> %p\n", buf[i - 1], buf[i]);
  }
  *(void **)buf[L1_WAYS - 1] = NULL;
  fprintf(stdout, "\t%p -> %p\n", buf[i - 1], buf[i]);
  ptr = buf[0];
  for (i = 0; i < L1_WAYS; ++i)
  {
    nxt = *(void **)ptr;
    cpu_clflush(ptr);
    ptr = nxt;
  }
  time1 = cpu_probe_pointer_chasing(buf[0]);
  time2 = cpu_probe_pointer_chasing(buf[0]);
  fprintf(stdout, "\t%lu, %lu\n", time1, time2);
  for (i = 0; i < 9; ++i)
  {
    free(buf[i]);
  }

  fprintf(stdout, "[+] Testing cache initialization\n");
  cache_t *cache = cpu_cacheInit(L1D);
  fprintf(stdout, "L1D Cache:\n\tLinesize: %d\n\tSets: %d\n\tSlices: %d\n\tWays: %d\n\tSize: %lu\n\tLinesizeLog: %d\n\tSetsLog: %d\n",
          cache->info.linesize,
          cache->info.sets,
          cache->info.slices,
          cache->info.ways,
          cache->info.size,
          cache->info.linesize_log,
          cache->info.sets_log);
  cpu_cacheFree(cache);
  cache = cpu_cacheInit(L2);
  fprintf(stdout, "L2 Cache:\n\tLinesize: %d\n\tSets: %d\n\tSlices: %d\n\tWays: %d\n\tSize: %lu\n\tLinesizeLog: %d\n\tSetsLog: %d\n",
          cache->info.linesize,
          cache->info.sets,
          cache->info.slices,
          cache->info.ways,
          cache->info.size,
          cache->info.linesize_log,
          cache->info.sets_log);
  cpu_cacheFree(cache);
  cache = cpu_cacheInit(L3);
  fprintf(stdout, "L3 Cache:\n\tLinesize: %d\n\tSets: %d\n\tSlices: %d\n\tWays: %d\n\tSize: %lu\n\tLinesizeLog: %d\n\tSetsLog: %d\n",
          cache->info.linesize,
          cache->info.sets,
          cache->info.slices,
          cache->info.ways,
          cache->info.size,
          cache->info.linesize_log,
          cache->info.sets_log);
  cpu_cacheFree(cache);
}
